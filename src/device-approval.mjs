// 11단계: 접속 앱의 기기 승인 판단. api/devices.js 가 부릅니다.
// 기기 = 이 기기의 운영체제 인증기에 만든 패스키. 본문에는 공개키(SPKI)와 자격 ID만 오고, 개인키는 인증기 밖으로 나오지 않습니다.
// 승인은 서버가 정합니다: 그 패스키로 이 등록 요청에 서명했고, 최근 10분 안에 실제로 로그인한 토큰일 때만 'approved'.
// 아니면 'pending' 으로 남기고 다시 로그인하라고 알립니다. 브라우저의 승인 버튼이나 본문 값만으로는 승인되지 않습니다.
import { ownerKeyOf } from './owner-key.mjs';
import {
  deviceIdOfCredential, publicJwkFromSpki, readDevice, readSignedRequest, useNonce, verifyAssertion,
} from './device-signature.mjs';

export const APPROVAL_WINDOW_SECONDS = 600;

try {
  process.loadEnvFile?.(resolve(process.cwd(), '.env'));
} catch {}

let loginVerifier = null;

async function getVerifier() {
  if (loginVerifier) return loginVerifier;
  const config = JSON.parse(await readFile(resolve(process.cwd(), 'aleph.config.json'), 'utf8'));
  if (process.env.SUPABASE_URL) {
    const origin = process.env.SUPABASE_URL.replace(/\/+$/, '');
    config.identityProvider = {
      issuer: `${origin}/auth/v1`,
      jwksUrl: `${origin}/auth/v1/.well-known/jwks.json`,
      audience: config.identityProvider?.audience || 'authenticated',
    };
  }
  loginVerifier = createLoginVerifier({ config, supabaseSecretKey: process.env.SUPABASE_SECRET_KEY });
  return loginVerifier;
}

export const recentlyAuthenticated = (verified, nowSeconds = Math.floor(Date.now() / 1000)) =>
  Number.isSafeInteger(verified?.authTime) && verified.authTime <= nowSeconds + 5
  && nowSeconds - verified.authTime <= APPROVAL_WINDOW_SECONDS;

const view = (row) => ({
  deviceId: row.device_id, status: row.status, label: row.label ?? null,
  createdAt: row.created_at ?? null, approvedAt: row.approved_at ?? null,
});

export async function handleDevices({ req, verified, fetchImpl = fetch, supabaseUrl, serviceKey, now = Date.now() }) {
  const ownerId = ownerKeyOf(verified);
  if (!ownerId) return { status: 401, body: { error: 'UNAUTHORIZED', message: '로그인이 필요합니다.' } };
  const headers = (extra = {}) => ({
    apikey: serviceKey, Authorization: `Bearer ${serviceKey}`, 'Content-Type': 'application/json', ...extra,
  });
  const url = (path) => `${supabaseUrl}/rest/v1/${path}`;

  if (req.method === 'GET') {
    try {
      const response = await fetchImpl(url(`device_keys?owner_id=eq.${ownerId}&select=device_id,status,label,created_at,approved_at&order=created_at.desc`), { headers: headers() });
      if (!response.ok) throw new Error('read');
      return { status: 200, body: (await response.json()).map(view) };
    } catch {
      return { status: 502, body: { error: 'DEVICE_CHECK_UNAVAILABLE', message: '기기 목록을 읽을 수 없습니다.' } };
    }
  }
  if (req.method !== 'POST') return { status: 405, body: { error: 'METHOD_NOT_ALLOWED', message: '지원하지 않는 메서드입니다.' } };

  const body = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {};
  const publicKey = publicJwkFromSpki(body.publicKey);
  const deviceId = deviceIdOfCredential(body.credentialId);
  const label = typeof body.label === 'string' ? body.label.trim().slice(0, 40) || null : null;
  if (!publicKey || !deviceId) {
    return { status: 400, body: { error: 'INVALID_DEVICE_KEY', message: 'P-256 패스키의 공개키(SPKI)와 자격 ID만 등록할 수 있습니다.' } };
  }

  // 등록하려는 패스키로 이 요청 자체에 서명했는지 확인합니다(경로·본문이 바뀌면 실패).
  const signed = readSignedRequest(req, now);
  if (!signed.ok) return { status: signed.status, body: { error: signed.error, message: signed.message } };
  if (signed.deviceId !== deviceId || !verifyAssertion(publicKey, signed)) {
    return { status: 403, body: { error: 'DEVICE_SIGNATURE_MISMATCH', message: '등록할 키의 서명이 요청과 맞지 않습니다.' } };
  }

  let existing;
  try {
    existing = await readDevice({ fetchImpl, supabaseUrl, serviceKey, deviceId });
  } catch {
    return { status: 502, body: { error: 'DEVICE_CHECK_UNAVAILABLE', message: '기기 상태를 확인할 수 없습니다.' } };
  }
  if (existing && String(existing.owner_id).toLowerCase() !== ownerId.toLowerCase()) {
    return { status: 409, body: { error: 'DEVICE_OWNER_CONFLICT', message: '다른 계정에 등록된 기기 키입니다.' } };
  }
  if (existing?.status === 'revoked') {
    return { status: 403, body: { error: 'DEVICE_REVOKED', message: '회수된 기기입니다. 새 키로 다시 요청하세요.' } };
  }
  const used = await useNonce({ fetchImpl, supabaseUrl, serviceKey, deviceId, nonce: signed.nonce });
  if (!used.ok) return { status: used.status, body: { error: used.error, message: used.message } };

  const approve = recentlyAuthenticated(verified, Math.floor(now / 1000));
  const status = existing?.status === 'approved' || approve ? 'approved' : 'pending';
  try {
    if (!existing) {
      const response = await fetchImpl(url('device_keys'), {
        method: 'POST', headers: headers({ Prefer: 'return=representation' }),
        body: JSON.stringify({
          device_id: deviceId, owner_id: ownerId, public_key: publicKey, status, label,
          approved_at: status === 'approved' ? new Date(now).toISOString() : null,
        }),
      });
      if (!response.ok) throw new Error('insert');
      existing = (await response.json())[0];
    } else if (existing.status !== status) {
      const response = await fetchImpl(url(`device_keys?device_id=eq.${deviceId}&owner_id=eq.${ownerId}&status=eq.pending`), {
        method: 'PATCH', headers: headers({ Prefer: 'return=representation' }),
        body: JSON.stringify({ status, approved_at: new Date(now).toISOString() }),
      });
      if (!response.ok) throw new Error('update');
      existing = (await response.json())[0] ?? existing;
    }
  } catch {
    return { status: 502, body: { error: 'DEVICE_CHECK_UNAVAILABLE', message: '기기를 등록할 수 없습니다.' } };
  }
  if (status !== 'approved') {
    return {
      status: 403,
      body: { error: 'REAUTH_REQUIRED', message: '최근 10분 안에 다시 로그인해야 이 기기를 승인할 수 있습니다.', device: view(existing) },
    };
  }
  return { status: 200, body: { device: view(existing) } };
}

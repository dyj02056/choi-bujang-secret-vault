import { createHash, createPublicKey, verify } from 'node:crypto';

// 11단계: 접속 앱(설치형 웹앱)의 기기 서명. 보호 요청마다 기기 키로 아래 문자열에 서명합니다.
//   aleph.device.v1 \n 메서드 \n 경로(쿼리 포함) \n 본문 SHA-256 \n 시각(ms) \n 일회용 번호 \n 기기 ID
// 서버는 실제로 받은 메서드·경로·본문으로 같은 문자열을 다시 만들어 검증하므로, 서명한 뒤 경로나 본문을
// 바꾸면 서명이 맞지 않습니다. 기기 공개키와 승인 상태는 서버 표 device_keys 에만 있습니다.
// 브라우저가 보낸 "승인됨" 같은 값은 믿지 않습니다. 개인키는 서버로 오지 않고 저장하지도 않습니다.
export const SIGNATURE_SCHEME = 'aleph.device.v1';
export const MAX_SKEW_MS = 60_000;
export const DEVICE_ID = /^[0-9a-f]{16}$/u;
const NONCE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/u; // P-256 서명 64바이트(r||s)의 base64url
const TIMESTAMP = /^[0-9]{13}$/u;
const B64URL_32 = /^[A-Za-z0-9_-]{43}$/u;

export const HEADERS = Object.freeze({
  device: 'x-aleph-device', timestamp: 'x-aleph-timestamp', nonce: 'x-aleph-nonce', signature: 'x-aleph-signature',
});

const sha256 = (text) => createHash('sha256').update(text, 'utf8').digest('hex');

// 서명할 본문 문자열. 본문이 없으면 빈 문자열, 문자열이면 그대로, JSON이면 JSON.stringify 결과입니다.
// 브라우저가 JSON.stringify(값)으로 보낸 본문은 서버가 해석한 뒤 다시 문자열로 만들어도 같습니다.
export function canonicalBody(body) {
  if (body === undefined || body === null || body === '') return '';
  if (typeof body === 'string') return body;
  if (Buffer.isBuffer(body)) return body.toString('utf8');
  return JSON.stringify(body);
}
export const bodySha256 = (body) => sha256(canonicalBody(body));

// 공개키(JWK)는 P-256 의 kty·crv·x·y 네 값만 받습니다. 개인키 값(d)이 들어 있으면 거부합니다.
export function publicJwkOf(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  if ('d' in value || value.kty !== 'EC' || value.crv !== 'P-256'
      || !B64URL_32.test(value.x ?? '') || !B64URL_32.test(value.y ?? '')) return null;
  return { crv: 'P-256', kty: 'EC', x: value.x, y: value.y };
}

// 기기 ID = 공개키(JWK 정규형)의 SHA-256 앞 16자리. 반 엔진 계약의 deviceId 형식(16자리 소문자 16진수)과 같습니다.
export function deviceIdOf(jwk) {
  const key = publicJwkOf(jwk);
  if (!key) return null;
  return sha256(JSON.stringify({ crv: key.crv, kty: key.kty, x: key.x, y: key.y })).slice(0, 16);
}

export function signingString({ method, path, bodyHash, timestamp, nonce, deviceId }) {
  return [SIGNATURE_SCHEME, String(method).toUpperCase(), path, bodyHash, timestamp, nonce, deviceId].join('\n');
}

export function verifySignature(jwk, text, signature) {
  const key = publicJwkOf(jwk);
  if (!key || !SIGNATURE.test(signature ?? '')) return false;
  try {
    return verify('sha256', Buffer.from(text, 'utf8'),
      { key: createPublicKey({ key, format: 'jwk' }), dsaEncoding: 'ieee-p1363' },
      Buffer.from(signature, 'base64url'));
  } catch {
    return false;
  }
}

// 요청이 실제로 가리키는 경로(쿼리 포함). 서명은 이 값과 비교합니다.
export function requestPath(req) {
  const raw = typeof req.url === 'string' ? req.url : '';
  try {
    const url = new URL(raw, 'https://app.invalid');
    return `${url.pathname}${url.search}`;
  } catch {
    return '';
  }
}

const header = (req, name) => {
  const value = req.headers?.[name];
  return typeof value === 'string' ? value.trim() : '';
};

// 서명 머리글을 읽고 형식과 시각을 확인합니다. 키 확인은 하지 않습니다.
export function readSignedRequest(req, now = Date.now()) {
  const deviceId = header(req, HEADERS.device);
  const timestamp = header(req, HEADERS.timestamp);
  const nonce = header(req, HEADERS.nonce).toLowerCase();
  const signature = header(req, HEADERS.signature);
  if (!deviceId && !timestamp && !nonce && !signature) {
    return { ok: false, status: 401, error: 'DEVICE_SIGNATURE_REQUIRED', message: '접속 앱의 기기 서명이 필요합니다.' };
  }
  if (!DEVICE_ID.test(deviceId) || !TIMESTAMP.test(timestamp) || !NONCE.test(nonce) || !SIGNATURE.test(signature)) {
    return { ok: false, status: 401, error: 'DEVICE_SIGNATURE_INVALID', message: '기기 서명 형식이 올바르지 않습니다.' };
  }
  if (Math.abs(now - Number(timestamp)) > MAX_SKEW_MS) {
    return { ok: false, status: 401, error: 'DEVICE_SIGNATURE_EXPIRED', message: '기기 서명 시각이 너무 오래되었습니다.' };
  }
  let bodyHash;
  try {
    bodyHash = bodySha256(req.body); // 본문을 해석하지 못하면(깨진 JSON) 서명 확인도 하지 않습니다.
  } catch {
    return { ok: false, status: 400, error: 'BAD_REQUEST', message: '요청 본문을 읽을 수 없습니다.' };
  }
  const text = signingString({ method: req.method, path: requestPath(req), bodyHash, timestamp, nonce, deviceId });
  return { ok: true, deviceId, nonce, signature, text };
}

const db = (supabaseUrl, serviceKey) => ({
  url: (path) => `${supabaseUrl}/rest/v1/${path}`,
  headers: (extra = {}) => ({
    apikey: serviceKey, Authorization: `Bearer ${serviceKey}`, 'Content-Type': 'application/json', ...extra,
  }),
});

// 일회용 번호는 기기마다 한 번만 쓸 수 있습니다(같은 서명을 다시 보내면 거부).
export async function useNonce({ fetchImpl = fetch, supabaseUrl, serviceKey, deviceId, nonce }) {
  const store = db(supabaseUrl, serviceKey);
  try {
    const response = await fetchImpl(store.url('device_nonces'), {
      method: 'POST', headers: store.headers({ Prefer: 'return=minimal' }),
      body: JSON.stringify({ device_id: deviceId, nonce }),
    });
    if (response.ok) return { ok: true };
    if (response.status === 409) {
      return { ok: false, status: 403, error: 'DEVICE_SIGNATURE_REPLAYED', message: '이미 사용한 기기 서명입니다.' };
    }
  } catch { /* 아래에서 실패로 처리 */ }
  return { ok: false, status: 502, error: 'DEVICE_CHECK_UNAVAILABLE', message: '기기 서명을 확인할 수 없습니다.' };
}

export async function readDevice({ fetchImpl = fetch, supabaseUrl, serviceKey, deviceId }) {
  const store = db(supabaseUrl, serviceKey);
  const response = await fetchImpl(
    store.url(`device_keys?device_id=eq.${deviceId}&select=device_id,owner_id,public_key,status,label,created_at,approved_at`),
    { headers: store.headers() },
  );
  if (!response.ok) throw new Error('DEVICE_READ_FAILED');
  const rows = await response.json();
  return Array.isArray(rows) ? (rows[0] ?? null) : null;
}

// 보호 요청 검사: 로그인한 소유자의 "승인된" 기기가, 실제 메서드·경로·본문에 서명했는지 확인합니다.
// 결과 { ok: true, deviceId } 또는 { ok: false, status, error, message }
export async function checkRequestSignature({ req, ownerId, fetchImpl = fetch, supabaseUrl, serviceKey, now = Date.now() }) {
  const signed = readSignedRequest(req, now);
  if (!signed.ok) return signed;
  let device;
  try {
    device = await readDevice({ fetchImpl, supabaseUrl, serviceKey, deviceId: signed.deviceId });
  } catch {
    return { ok: false, status: 502, error: 'DEVICE_CHECK_UNAVAILABLE', message: '기기 서명을 확인할 수 없습니다.' };
  }
  if (!device || String(device.owner_id).toLowerCase() !== String(ownerId).toLowerCase()
      || device.status !== 'approved') {
    return { ok: false, status: 403, error: 'DEVICE_NOT_APPROVED', message: '이 계정에서 승인된 기기가 아닙니다.' };
  }
  if (!verifySignature(device.public_key, signed.text, signed.signature)) {
    return { ok: false, status: 403, error: 'DEVICE_SIGNATURE_MISMATCH', message: '서명한 요청과 받은 요청(경로·본문)이 다릅니다.' };
  }
  const used = await useNonce({ fetchImpl, supabaseUrl, serviceKey, deviceId: signed.deviceId, nonce: signed.nonce });
  if (!used.ok) return used;
  return { ok: true, deviceId: signed.deviceId };
}

// 핸들러에서 한 줄로 쓰기 위한 도우미. 실패하면 응답을 보내고 false 를 돌려줍니다.
export async function requireSignedDevice(req, res, context) {
  const result = await checkRequestSignature({ req, ...context });
  if (result.ok) return true;
  res.status(result.status).json({ error: result.error, message: result.message });
  return false;
}

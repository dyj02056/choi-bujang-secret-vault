import { createHash, createPublicKey, verify } from 'node:crypto';

// 11단계: 접속 앱(설치형 웹앱)의 기기 서명. 기기 키는 운영체제 인증기(패스키, WebAuthn) 안에만 있고,
// 화면 코드·브라우저 저장소·서버·Git·제출물 어디에도 키 값이 없습니다. 서버는 등록 때 받은 공개키만 가집니다.
// 보호 요청마다 앱은 아래 문자열의 SHA-256 을 패스키 도전값(challenge)으로 넣어 인증기 서명을 받습니다.
//   aleph.device.v2 \n 메서드 \n 경로(쿼리 포함) \n 본문 SHA-256 \n 시각(ms) \n 일회용 번호
// 서버는 실제로 받은 메서드·경로·본문으로 같은 문자열을 다시 만들어 도전값을 비교하고 서명을 검증하므로,
// 서명한 뒤 경로나 본문을 바꾸면 거부됩니다. 승인 상태는 서버 표 device_keys 에만 있습니다.
export const SIGNATURE_SCHEME = 'aleph.device.v2';
export const MAX_SKEW_MS = 60_000;
export const DEVICE_ID = /^[0-9a-f]{16}$/u;
const NONCE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SIGNATURE = /^[A-Za-z0-9_-]{60,120}$/u; // ES256 DER 서명의 base64url
const B64URL = /^[A-Za-z0-9_-]+$/u;
const TIMESTAMP = /^[0-9]{13}$/u;
const B64URL_32 = /^[A-Za-z0-9_-]{43}$/u;

export const HEADERS = Object.freeze({
  device: 'x-aleph-device',
  timestamp: 'x-aleph-timestamp',
  nonce: 'x-aleph-nonce',
  signature: 'x-aleph-signature',
  authenticatorData: 'x-aleph-authenticator-data',
  clientData: 'x-aleph-client-data',
});

const sha256 = (data) => createHash('sha256').update(data).digest();
const sha256Hex = (text) => createHash('sha256').update(text, 'utf8').digest('hex');

// 서명할 본문 문자열. 본문이 없으면 빈 문자열, 문자열이면 그대로, JSON이면 JSON.stringify 결과입니다.
export function canonicalBody(body) {
  if (body === undefined || body === null || body === '') return '';
  if (typeof body === 'string') return body;
  if (Buffer.isBuffer(body)) return body.toString('utf8');
  return JSON.stringify(body);
}
export const bodySha256 = (body) => sha256Hex(canonicalBody(body));

export function signingString({ method, path, bodyHash, timestamp, nonce }) {
  return [SIGNATURE_SCHEME, String(method).toUpperCase(), path, bodyHash, timestamp, nonce].join('\n');
}
export const challengeOf = (text) => sha256(Buffer.from(text, 'utf8')).toString('base64url');

// 저장된 공개키는 P-256 의 kty·crv·x·y 네 값만 씁니다. 개인키 값(d)이 들어 있으면 거부합니다.
export function publicJwkOf(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  if ('d' in value || value.kty !== 'EC' || value.crv !== 'P-256'
      || !B64URL_32.test(value.x ?? '') || !B64URL_32.test(value.y ?? '')) return null;
  return { crv: 'P-256', kty: 'EC', x: value.x, y: value.y };
}

// 패스키 등록 응답의 공개키(SPKI, base64url)를 P-256 공개키 JWK로 바꿉니다. 다른 형식이면 null.
export function publicJwkFromSpki(spkiB64url) {
  if (typeof spkiB64url !== 'string' || !B64URL.test(spkiB64url) || spkiB64url.length > 400) return null;
  try {
    const key = createPublicKey({ key: Buffer.from(spkiB64url, 'base64url'), format: 'der', type: 'spki' });
    if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') return null;
    return publicJwkOf(key.export({ format: 'jwk' }));
  } catch {
    return null;
  }
}

// 기기 ID = 패스키 자격 ID(credential ID) 바이트의 SHA-256 앞 16자리. ALEPH SDP 엔진 계약의 deviceId 형식과 같습니다.
export function deviceIdOfCredential(credentialIdB64url) {
  if (typeof credentialIdB64url !== 'string' || !B64URL.test(credentialIdB64url)) return null;
  const raw = Buffer.from(credentialIdB64url, 'base64url');
  if (raw.length < 16 || raw.length > 1023) return null;
  return sha256(raw).toString('hex').slice(0, 16);
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

// 패스키는 앱 주소(호스트)에 묶입니다. 요청을 받은 호스트의 https 주소만 출처로 인정합니다.
export function expectedOrigin(req) {
  const forwarded = req.headers?.['x-forwarded-host'];
  const host = String((typeof forwarded === 'string' && forwarded) || req.headers?.host || '').split(',')[0].trim().toLowerCase();
  if (!/^[a-z0-9.-]+(?::[0-9]{1,5})?$/u.test(host)) return null;
  const hostname = host.replace(/:[0-9]+$/u, '');
  const local = hostname === 'localhost' || hostname === '127.0.0.1';
  return { origin: `${local ? 'http' : 'https'}://${host}`, rpId: hostname };
}

const header = (req, name) => {
  const value = req.headers?.[name];
  return typeof value === 'string' ? value.trim() : '';
};

// 서명 머리글을 읽고 형식·시각을 확인한 뒤, 실제로 받은 요청으로 도전값을 만듭니다. 키 확인은 하지 않습니다.
export function readSignedRequest(req, now = Date.now()) {
  const values = Object.fromEntries(Object.entries(HEADERS).map(([key, name]) => [key, header(req, name)]));
  if (Object.values(values).every((value) => !value)) {
    return { ok: false, status: 401, error: 'DEVICE_SIGNATURE_REQUIRED', message: '접속 앱의 기기 서명이 필요합니다.' };
  }
  const nonce = values.nonce.toLowerCase();
  if (!DEVICE_ID.test(values.device) || !TIMESTAMP.test(values.timestamp) || !NONCE.test(nonce)
      || !SIGNATURE.test(values.signature) || !B64URL.test(values.authenticatorData)
      || values.authenticatorData.length > 1400 || !B64URL.test(values.clientData) || values.clientData.length > 2800) {
    return { ok: false, status: 401, error: 'DEVICE_SIGNATURE_INVALID', message: '기기 서명 형식이 올바르지 않습니다.' };
  }
  if (Math.abs(now - Number(values.timestamp)) > MAX_SKEW_MS) {
    return { ok: false, status: 401, error: 'DEVICE_SIGNATURE_EXPIRED', message: '기기 서명 시각이 너무 오래되었습니다.' };
  }
  let bodyHash;
  try {
    bodyHash = bodySha256(req.body); // 본문을 해석하지 못하면(깨진 JSON) 서명 확인도 하지 않습니다.
  } catch {
    return { ok: false, status: 400, error: 'BAD_REQUEST', message: '요청 본문을 읽을 수 없습니다.' };
  }
  const text = signingString({ method: req.method, path: requestPath(req), bodyHash, timestamp: values.timestamp, nonce });
  return {
    ok: true, deviceId: values.device, nonce, challenge: challengeOf(text), target: expectedOrigin(req),
    signature: values.signature, authenticatorData: values.authenticatorData, clientData: values.clientData,
  };
}

// WebAuthn 서명(assertion) 검증: 도전값·출처·종류·호스트·사용자 확인 표시와 ES256 서명.
export function verifyAssertion(jwk, signed) {
  const key = publicJwkOf(jwk);
  if (!key || !signed.target) return false;
  try {
    const clientDataJSON = Buffer.from(signed.clientData, 'base64url');
    const clientData = JSON.parse(clientDataJSON.toString('utf8'));
    if (clientData.type !== 'webauthn.get' || clientData.challenge !== signed.challenge
        || clientData.origin !== signed.target.origin || clientData.crossOrigin === true) return false;
    const authenticatorData = Buffer.from(signed.authenticatorData, 'base64url');
    if (authenticatorData.length < 37
        || !authenticatorData.subarray(0, 32).equals(sha256(Buffer.from(signed.target.rpId, 'utf8')))
        || (authenticatorData[32] & 0x01) !== 0x01) return false; // 사용자 존재(UP) 표시가 있어야 합니다.
    const data = Buffer.concat([authenticatorData, sha256(clientDataJSON)]);
    return verify('sha256', data, createPublicKey({ key, format: 'jwk' }), Buffer.from(signed.signature, 'base64url'));
  } catch {
    return false;
  }
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
  if (!verifyAssertion(device.public_key, signed)) {
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

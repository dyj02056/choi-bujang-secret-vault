import { randomUUID } from 'node:crypto';
import { checkRequestSignature, requestPath } from './device-signature.mjs';
import { detect } from './detect.mjs';
import { ownerKeyOf } from './owner-key.mjs';

// 12단계: 보호 API 앞의 공통 관문. 로그인 확인 뒤 아래 순서로 검사하고, 결과를 접근 사건으로 남깁니다.
//   1) 요청 ID를 정해 응답 머리글 x-aleph-request-id 로 돌려줌
//   2) 회수된 신원이면 403 IDENTITY_REVOKED (기기 서명이 맞아도 거부)
//   3) 승인된 기기의 서명이 실제 요청(메서드·경로·본문)과 맞지 않으면 401/403 (11단계 규칙)
//   4) GET 이면 9단계 탐지 규칙(10분 안 GET 120건 초과)을 서버 기록에 적용해, 넘으면 그 신원을 회수하고 403
// 기록하거나 확인할 수 없으면 허용하지 않습니다(502). 사건에는 경로 모양만 남기고 메모 ID·본문·토큰은 남기지 않습니다.
// access_events.outcome 은 관문의 결정입니다("gate_passed" = 관문 통과, API 가 200 이라는 뜻이 아님).
// 핸들러가 뒤에서 거절할 수 있으므로(예: 남의 메모 403), 응답을 보내기 직전에 최종 HTTP 상태를 access_results 에 남깁니다.
export const REQUEST_ID_HEADER = 'x-aleph-request-id';
export const DETECTION_WINDOW_MS = 10 * 60 * 1000;
const UUID_SEGMENT = /\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=\/|$)/giu;

// "/api/notes/<uuid>?x" → "GET /notes/:id"
export function routeShape(method, req) {
  const path = requestPath(req).split('?')[0].replace(/^\/api(?=\/)/u, '').replace(UUID_SEGMENT, '/:id');
  return `${String(method).toUpperCase()} ${path}`.slice(0, 80);
}

const store = (supabaseUrl, serviceKey) => ({
  url: (path) => `${supabaseUrl}/rest/v1/${path}`,
  headers: (extra = {}) => ({
    apikey: serviceKey, Authorization: `Bearer ${serviceKey}`, 'Content-Type': 'application/json', ...extra,
  }),
});

export async function readRevocation({ fetchImpl = fetch, supabaseUrl, serviceKey, ownerId }) {
  const db = store(supabaseUrl, serviceKey);
  const response = await fetchImpl(db.url(`identity_revocations?owner_id=eq.${ownerId}&select=reason,revoked_at`), { headers: db.headers() });
  if (!response.ok) throw new Error('REVOCATION_READ_FAILED');
  const rows = await response.json();
  return Array.isArray(rows) ? (rows[0] ?? null) : null;
}

async function recordEvent(db, fetchImpl, event) {
  const response = await fetchImpl(db.url('access_events'), {
    method: 'POST', headers: db.headers({ Prefer: 'return=minimal' }), body: JSON.stringify(event),
  });
  if (!response.ok) throw new Error('EVENT_WRITE_FAILED');
}

// 회수: 신원을 회수 표에 올리고 그 신원의 기기를 모두 'revoked' 로 바꿉니다. 이미 회수돼 있으면 그대로 둡니다.
export async function revokeIdentity({ fetchImpl = fetch, supabaseUrl, serviceKey, ownerId, reason, requestId = null }) {
  const db = store(supabaseUrl, serviceKey);
  const added = await fetchImpl(db.url('identity_revocations?on_conflict=owner_id'), {
    method: 'POST', headers: db.headers({ Prefer: 'resolution=ignore-duplicates,return=minimal' }),
    body: JSON.stringify({ owner_id: ownerId, reason, request_id: requestId }),
  });
  if (!added.ok) throw new Error('REVOCATION_WRITE_FAILED');
  const devices = await fetchImpl(db.url(`device_keys?owner_id=eq.${ownerId}&status=neq.revoked`), {
    method: 'PATCH', headers: db.headers({ Prefer: 'return=minimal' }), body: JSON.stringify({ status: 'revoked' }),
  });
  if (!devices.ok) throw new Error('DEVICE_REVOKE_FAILED');
}

// 서버 기록에 9단계 탐지 규칙을 그대로 적용합니다. 사건의 sub 는 소유자 가명 키입니다.
async function burstDetected(db, fetchImpl, ownerId, now) {
  const since = new Date(now - DETECTION_WINDOW_MS).toISOString();
  const response = await fetchImpl(
    db.url(`access_events?owner_id=eq.${ownerId}&method=eq.GET&at=gte.${since}&select=at,method&order=at.desc&limit=200`),
    { headers: db.headers() },
  );
  if (!response.ok) throw new Error('EVENT_READ_FAILED');
  const rows = await response.json();
  const events = rows.map((row) => ({ at: row.at, method: row.method, identity: { sub: ownerId } }));
  return detect(events).action === 'propose_revocation';
}

// 결과: { ok: true, ownerId, requestId, deviceId } 또는 { ok: false, status, error, message, requestId }
export async function checkAccess({ req, verified, fetchImpl = fetch, supabaseUrl, serviceKey, now = Date.now() }) {
  const requestId = randomUUID();
  const ownerId = ownerKeyOf(verified);
  const fail = (status, error, message) => ({ ok: false, status, error, message, requestId });
  if (!ownerId) return fail(401, 'UNAUTHORIZED', '로그인이 필요합니다.');
  const db = store(supabaseUrl, serviceKey);
  const method = String(req.method || 'GET').toUpperCase();
  const route = routeShape(method, req);
  const log = (outcome, deviceId = null) => recordEvent(db, fetchImpl, {
    request_id: requestId, owner_id: ownerId, method, route, outcome, device_id: deviceId,
  });

  try {
    const revoked = await readRevocation({ fetchImpl, supabaseUrl, serviceKey, ownerId });
    if (revoked) {
      await log('identity_revoked');
      return { ...fail(403, 'IDENTITY_REVOKED', '회수된 신원입니다. 이 신원으로는 다시 접속할 수 없습니다.'), logged: true };
    }
    const signed = await checkRequestSignature({ req, ownerId, fetchImpl, supabaseUrl, serviceKey, now });
    if (!signed.ok) {
      if (signed.status === 502) return { ...signed, requestId };
      await log(signed.error.toLowerCase());
      return { ...signed, requestId, logged: true };
    }
    await log('gate_passed', signed.deviceId);
    if (method === 'GET' && await burstDetected(db, fetchImpl, ownerId, now)) {
      await revokeIdentity({ fetchImpl, supabaseUrl, serviceKey, ownerId, reason: 'burst_read', requestId });
      await log('identity_revoked_burst_read', signed.deviceId);
      return { ...fail(403, 'IDENTITY_REVOKED', '짧은 시간에 너무 많이 조회해 이 신원을 회수했습니다.'), logged: true };
    }
    return { ok: true, ownerId, requestId, deviceId: signed.deviceId, logged: true };
  } catch {
    return fail(502, 'ACCESS_CHECK_UNAVAILABLE', '접근 기록을 확인할 수 없어 허용하지 않습니다.');
  }
}

// 로그인 전 거절(401)에도 요청 ID 를 돌려줍니다. 사건 표에는 남기지 않습니다(계정이 없으므로).
// 관문을 지나면 guardRequest 가 기록된 요청 ID 로 바꿉니다.
export function tagRequest(res) {
  res.setHeader(REQUEST_ID_HEADER, randomUUID());
}

// 최종 결과 한 줄. 사건 줄(access_events)이 있는 요청만 남깁니다.
export async function recordResult({ fetchImpl = fetch, supabaseUrl, serviceKey, requestId, status, error = null }) {
  const db = store(supabaseUrl, serviceKey);
  const code = typeof error === 'string' && /^[A-Z_]{3,40}$/u.test(error) ? error : null;
  const response = await fetchImpl(db.url('access_results'), {
    method: 'POST', headers: db.headers({ Prefer: 'return=minimal' }),
    body: JSON.stringify({ request_id: requestId, status: Number(status), error: code }),
  });
  if (!response.ok) throw new Error('RESULT_WRITE_FAILED');
}

// 핸들러용 도우미. 실패하면 응답을 보내고 null, 통과하면 검사 결과를 돌려줍니다.
// 통과한 요청은 res.json 을 감싸, 핸들러가 정한 최종 상태(예: 200, 403 FORBIDDEN)를 기록한 뒤 응답을 보냅니다.
export async function guardRequest(req, res, context) {
  const result = await checkAccess({ req, ...context });
  res.setHeader(REQUEST_ID_HEADER, result.requestId);
  const finish = (status, error) => (result.logged
    ? recordResult({ ...context, requestId: result.requestId, status, error }).catch(() => {})
    : Promise.resolve());
  if (!result.ok) {
    await finish(result.status, result.error);
    res.status(result.status).json({ error: result.error, message: result.message, requestId: result.requestId });
    return null;
  }
  const send = res.json.bind(res);
  res.json = (body) => {
    res.json = send;
    const status = res.statusCode || 200;
    return finish(status, status >= 400 ? body?.error : null).then(() => send(body));
  };
  return result;
}

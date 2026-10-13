import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createVirtualDevice } from '../src/device-client.mjs';
import { createHash } from 'node:crypto';
import { ACTION_ROUTES, RESOURCE_METHODS, RULE_IDS } from '../src/decider.mjs';

// 12단계: 작전실 화면 수치와 가린 서버 기록을 같은 시점에 맞춰 남깁니다.
//   npm run ops:snapshot
// 1) 시험 계정 A로 로그인해(POST /api/session, 또는 ALEPH_CHECK_TOKEN_A) 가상 패스키 기기를 승인받고
// 2) 서명한 GET /api/ops/summary 를 실제로 보내 응답(요청 ID 포함)을 받은 뒤, 다른 요청 없이 바로
// 3) 서버 키로 같은 계정의 서버 원본 줄(접근 사건, 감사 기록, 기기, 회수, 사본)을 가린 채로 직접 읽고,
//    화면 API 와 다른 코드로 같은 기준 시각(응답의 generatedAt)에서 다시 셉니다. 원본 줄도 함께 남겨 누구나 다시 셀 수 있게 합니다.
//    계정은 owner_ + SHA-256 앞 10자리(audit/step10 과 같은 가명), 메모 ID 는 note_ + SHA-256 앞 10자리로 가립니다.
// 둘을 항목별로 대조해 audit/step12/ops-snapshot-<UTC>.json(덮어쓰지 않음)에 남기고,
// 화면이 보여 줄 실측 응답을 public/ops-summary.json 에 둡니다. 응답이 없으면 아무 수치도 만들지 않습니다.
// 비밀번호·토큰·서버 키·계정 ID 원문·메모 본문은 파일에 쓰지 않습니다.
const ROOT = resolve(import.meta.dirname, '..');
try {
  process.loadEnvFile?.(resolve(ROOT, '.env'));
} catch {}

const fail = (message) => { throw new Error(message); };
const canonical = (value) => JSON.stringify(value, (key, inner) => (inner && typeof inner === 'object' && !Array.isArray(inner)
  ? Object.fromEntries(Object.keys(inner).sort().map((name) => [name, inner[name]])) : inner));

try {
  const config = JSON.parse(readFileSync(resolve(ROOT, 'aleph.config.json'), 'utf8'));
  const app = new URL(config.publicAppUrl);
  const supabaseUrl = process.env.SUPABASE_URL?.replace(/\/+$/u, '');
  const serviceKey = process.env.SUPABASE_SECRET_KEY;
  if (!supabaseUrl || !serviceKey) fail('서버 기록을 읽으려면 .env 에 SUPABASE_URL, SUPABASE_SECRET_KEY 가 필요합니다.');

  const call = async (path, { method = 'GET', token, body, device } = {}) => {
    const headers = {};
    if (token) headers.Authorization = `Bearer ${token}`;
    if (device) Object.assign(headers, device.signHeaders({ method, path, body }));
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    const response = await fetch(new URL(path, app), {
      method, headers, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'error', signal: AbortSignal.timeout(15000),
    });
    return { status: response.status, requestId: response.headers.get('x-aleph-request-id'), data: await response.json().catch(() => ({})) };
  };

  // 로그인: 시험 계정 이메일·비밀번호로 새로 로그인하는 것을 먼저 쓰고, 없을 때만 셸의 토큰을 씁니다(만료됐으면 중단).
  let token = null;
  let ownerId = null;
  const email = process.env.ALEPH_CHECK_EMAIL_A;
  const password = process.env.ALEPH_CHECK_PASSWORD_A;
  if (email && password) {
    const login = await call('/api/session', { method: 'POST', body: { action: 'login', email, password } });
    if (login.status !== 200 || !login.data.accessToken) fail(`로그인 실패 HTTP ${login.status}`);
    token = login.data.accessToken;
    ownerId = login.data.user?.id ?? null;
  } else {
    token = process.env.ALEPH_CHECK_TOKEN_A;
    if (!token) fail('셸에 ALEPH_CHECK_EMAIL_A, ALEPH_CHECK_PASSWORD_A(시험 계정 A)를 넣어 주세요.');
    let exp = null;
    try { exp = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8')).exp; } catch { exp = null; }
    if (Number.isSafeInteger(exp) && exp * 1000 <= Date.now() + 30_000) {
      fail('ALEPH_CHECK_TOKEN_A 가 만료되었습니다. Remove-Item Env:ALEPH_CHECK_TOKEN_A 로 지우고 이메일·비밀번호를 넣어 주세요.');
    }
  }
  if (!ownerId) {
    // 직접 받은 토큰이면 그 계정 번호(sub)로 서버 기록을 셉니다. 검증은 API가 이미 합니다.
    try { ownerId = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8')).sub; } catch { ownerId = null; }
  }
  if (!/^[0-9a-f-]{36}$/iu.test(ownerId ?? '')) fail('시험 계정 번호를 확인할 수 없습니다.');

  const device = createVirtualDevice({ origin: app.origin });
  const approval = await call('/api/devices', { method: 'POST', token, device, body: { ...device.registration(), label: 'ops snapshot' } });
  if (approval.status !== 200) fail(`기기 승인 실패 HTTP ${approval.status} ${approval.data.error ?? ''}`);

  // 실제 API 응답. 이 뒤로는 서버 기록을 바꾸는 요청을 보내지 않습니다.
  const api = await call('/api/ops/summary', { token, device });
  if (api.status !== 200) fail(`작전실 요약 실패 HTTP ${api.status} ${api.data.error ?? ''} (요청 ID ${api.requestId ?? '없음'})`);
  const reference = Date.parse(api.data.generatedAt);
  const hash10 = (value) => createHash('sha256').update(String(value).toLowerCase()).digest('hex').slice(0, 10);
  const owner = `owner_${hash10(ownerId)}`;
  const note = (id) => (id ? `note_${hash10(id)}` : null);
  const read = async (path) => {
    const response = await fetch(`${supabaseUrl}/rest/v1/${path}`, { headers: { apikey: serviceKey, Authorization: `Bearer ${serviceKey}` }, signal: AbortSignal.timeout(15000) });
    if (!response.ok) fail(`${path.split('?')[0]} 을(를) 읽지 못했습니다 (HTTP ${response.status}).`);
    return response.json();
  };
  const since = new Date(reference - 10 * 60 * 1000).toISOString();
  const until = new Date(reference).toISOString();
  const [recentRows, windowRows, auditRows, deviceRows, revocationRows, backupRows] = await Promise.all([
    read(`access_events?owner_id=eq.${ownerId}&at=lte.${until}&select=seq,request_id,method,route,outcome,at&order=seq.desc&limit=20`),
    read(`access_events?owner_id=eq.${ownerId}&method=eq.GET&at=gte.${since}&at=lte.${until}&select=request_id,at&order=seq.asc&limit=500`),
    read(`secret_notes_restore_log?owner_id=eq.${ownerId}&select=seq,note_id,mode,reason,restored_at&order=seq.asc`),
    read(`device_keys?owner_id=eq.${ownerId}&select=status&order=created_at.asc`),
    read(`identity_revocations?owner_id=eq.${ownerId}&select=reason,revoked_at`),
    read(`secret_notes_backup?owner_id=eq.${ownerId}&select=id&order=id.asc`),
  ]);
  const eventIds = recentRows.map((row) => row.request_id);
  // 결과 줄은 요약 응답 뒤에 생기므로, 화면과 같은 시점이 되도록 요약 요청 자신의 결과 줄은 빼고 셉니다.
  const resultRows = eventIds.length
    ? (await read(`access_results?request_id=in.(${eventIds.join(',')})&select=request_id,status,error`)).filter((row) => row.request_id !== api.requestId)
    : [];
  const maskedRecords = {
    owner,
    referenceTime: api.data.generatedAt,
    accessEventsLatest20: recentRows.map((row) => ({ seq: row.seq, requestId: row.request_id, method: row.method, route: row.route, outcome: row.outcome, at: row.at })),
    accessResultsOfLatest20: resultRows.map((row) => ({ requestId: row.request_id, status: row.status, error: row.error ?? null }))
      .sort((x, y) => eventIds.indexOf(x.requestId) - eventIds.indexOf(y.requestId)),
    getEventsLast10Minutes: windowRows.map((row) => ({ requestId: row.request_id, at: row.at })),
    restoreAuditRows: auditRows.map((row) => ({ seq: row.seq, mode: row.mode, reason: row.reason ?? null, note: note(row.note_id), at: row.restored_at })),
    deviceStatuses: deviceRows.map((row) => row.status),
    revocations: revocationRows.map((row) => ({ reason: row.reason, revokedAt: row.revoked_at })),
    backups: backupRows.map((row) => note(row.id)),
  };
  // 원본 줄에서 다시 센 값(화면 API 와 다른 코드)
  const tally = (values) => values.reduce((acc, value) => ({ ...acc, [value]: (acc[value] ?? 0) + 1 }), {});
  const restores = maskedRecords.restoreAuditRows.filter((row) => ['updated', 'reinserted', 'unchanged', 'refused'].includes(row.mode));
  const latest = restores.length ? restores[restores.length - 1] : null;
  // 최종 결과 이름은 화면 API 와 같은 규칙(2xx·3xx allowed, 그 밖은 오류 코드, 줄 없음 not_recorded)을 여기서 따로 계산합니다.
  // 요약 요청 자신도 결과 줄이 없으므로 not_recorded 입니다.
  const resultById = Object.fromEntries(maskedRecords.accessResultsOfLatest20.map((row) => [row.requestId, row]));
  const events = maskedRecords.accessEventsLatest20.map(({ requestId, route, outcome, at }) => {
    const r = resultById[requestId];
    const label = r ? (r.status < 400 ? 'allowed' : String(r.error ?? `http_${r.status}`).toLowerCase()) : 'not_recorded';
    return { requestId, route, gate: outcome, status: r ? r.status : null, outcome: label, at };
  });
  const server = {
    rules: {
      source: api.data.rules.source,
      ruleIds: [...RULE_IDS],
      resourceMethods: Object.fromEntries(Object.entries(RESOURCE_METHODS).map(([zone, methods]) => [zone, [...methods]])),
      actionRoutes: [...ACTION_ROUTES],
    },
    detection: {
      source: api.data.detection.source, windowMinutes: 10, limit: 120,
      recentGetCount: maskedRecords.getEventsLast10Minutes.length,
      recentEvents: events,
      outcomeCounts: tally(events.map((row) => row.outcome)),
    },
    revocation: {
      revoked: maskedRecords.revocations.length > 0,
      reason: maskedRecords.revocations[0]?.reason ?? null,
      revokedAt: maskedRecords.revocations[0]?.revokedAt ?? null,
      devices: { approved: 0, pending: 0, revoked: 0, ...tally(maskedRecords.deviceStatuses) },
    },
    restore: {
      auditRows: maskedRecords.restoreAuditRows.length,
      byMode: tally(maskedRecords.restoreAuditRows.map((row) => row.mode)),
      backups: maskedRecords.backups.length,
      latest: latest ? { seq: latest.seq, mode: latest.mode, reason: latest.reason, note: latest.note, at: latest.at } : null,
    },
  };

  const fields = {
    'rules': [api.data.rules, server.rules],
    'detection.recentGetCount': [api.data.detection.recentGetCount, server.detection.recentGetCount],
    'detection.outcomeCounts': [api.data.detection.outcomeCounts, server.detection.outcomeCounts],
    'detection.recentEvents': [api.data.detection.recentEvents, server.detection.recentEvents],
    'revocation': [api.data.revocation, server.revocation],
    'restore': [api.data.restore, server.restore],
  };
  const comparison = Object.fromEntries(Object.entries(fields).map(([name, [shown, recorded]]) => [name, canonical(shown) === canonical(recorded)]));
  const allMatch = Object.values(comparison).every(Boolean);
  const { requestId: bodyRequestId, source, ...shown } = api.data;
  const snapshot = {
    schema: 'aleph.ops.snapshot.v1',
    app: app.origin,
    account: 'test account A (owner masked)',
    api: { route: 'GET /api/ops/summary', status: api.status, requestId: api.requestId ?? bodyRequestId, receivedAt: new Date().toISOString(), body: shown },
    serverRecord: { source: 'masked raw server rows of the same account (maskedRecords), recounted by scripts/ops-snapshot.mjs at the same reference time', body: server },
    maskedRecords,
    comparison, allMatch,
  };
  const text = JSON.stringify(snapshot);
  if (/eyJ[A-Za-z0-9_-]{12,}\.|BEGIN [A-Z ]*PRIVATE|sb_secret_/u.test(text) || text.includes(ownerId)) fail('기록에 비밀값이나 계정 번호가 있어 쓰지 않습니다.');

  const stamp = snapshot.api.receivedAt.replace(/[-:]/gu, '').replace(/\.\d+Z$/u, 'Z');
  mkdirSync(resolve(ROOT, 'audit', 'step12'), { recursive: true });
  writeFileSync(resolve(ROOT, 'audit', 'step12', `ops-snapshot-${stamp}.json`), `${JSON.stringify(snapshot, null, 2)}\n`, { encoding: 'utf8', flag: 'wx' });
  writeFileSync(resolve(ROOT, 'public', 'ops-summary.json'), `${JSON.stringify({
    schema: snapshot.schema, app: snapshot.app, api: snapshot.api, comparison, allMatch,
    serverRecordFile: `audit/step12/ops-snapshot-${stamp}.json`,
    // 화면이 API 응답 값 옆에 같은 시점의 가린 서버 기록 값을 나란히 보여 줄 수 있게 함께 둡니다.
    serverRecord: snapshot.serverRecord.body,
    // 다시 센 값의 근거가 된 가린 원본 줄(같은 계정, 같은 기준 시각)
    maskedRecords,
  }, null, 2)}\n`, 'utf8');
  process.stdout.write(`작전실 실측: 요청 ID ${snapshot.api.requestId} · 서버 기록 대조 ${allMatch ? '모두 일치' : '불일치 있음'}\n`
    + Object.entries(comparison).map(([name, ok]) => `  ${ok ? '일치' : '불일치'} ${name}`).join('\n')
    + `\n  audit/step12/ops-snapshot-${stamp}.json · public/ops-summary.json\n`);
  if (!allMatch) process.exitCode = 2;
} catch (error) {
  process.stderr.write(`작전실 실측 첫 오류: ${error.message}\n`);
  process.exitCode = 1;
}

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createVirtualDevice } from '../src/device-client.mjs';
import { buildOpsSummary } from '../src/ops-summary.mjs';

// 12단계: 작전실 화면 수치와 가린 서버 기록을 같은 시점에 맞춰 남깁니다.
//   npm run ops:snapshot
// 1) 시험 계정 A로 로그인해(POST /api/session, 또는 ALEPH_CHECK_TOKEN_A) 가상 패스키 기기를 승인받고
// 2) 서명한 GET /api/ops/summary 를 실제로 보내 응답(요청 ID 포함)을 받은 뒤, 다른 요청 없이 바로
// 3) 서버 키로 같은 계정의 가린 서버 기록을 같은 기준 시각(응답의 generatedAt)으로 다시 셉니다.
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

  // 로그인: 토큰을 직접 주거나, 시험 계정 이메일·비밀번호로 서버 로그인
  let token = process.env.ALEPH_CHECK_TOKEN_A;
  let ownerId = null;
  if (!token) {
    const email = process.env.ALEPH_CHECK_EMAIL_A;
    const password = process.env.ALEPH_CHECK_PASSWORD_A;
    if (!email || !password) fail('셸에 ALEPH_CHECK_EMAIL_A, ALEPH_CHECK_PASSWORD_A(시험 계정 A)를 넣어 주세요.');
    const login = await call('/api/session', { method: 'POST', body: { action: 'login', email, password } });
    if (login.status !== 200 || !login.data.accessToken) fail(`로그인 실패 HTTP ${login.status}`);
    token = login.data.accessToken;
    ownerId = login.data.user?.id ?? null;
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
  const server = await buildOpsSummary({ supabaseUrl, serviceKey, ownerId, now: Date.parse(api.data.generatedAt) });

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
    serverRecord: { source: 'buildOpsSummary over the masked server tables, same account, same reference time', body: { ...server, source: undefined } },
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
  }, null, 2)}\n`, 'utf8');
  process.stdout.write(`작전실 실측: 요청 ID ${snapshot.api.requestId} · 서버 기록 대조 ${allMatch ? '모두 일치' : '불일치 있음'}\n`
    + Object.entries(comparison).map(([name, ok]) => `  ${ok ? '일치' : '불일치'} ${name}`).join('\n')
    + `\n  audit/step12/ops-snapshot-${stamp}.json · public/ops-summary.json\n`);
  if (!allMatch) process.exitCode = 2;
} catch (error) {
  process.stderr.write(`작전실 실측 첫 오류: ${error.message}\n`);
  process.exitCode = 1;
}

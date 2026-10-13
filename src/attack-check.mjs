// Student self-check: runs after a restore and records only requests that were really sent.
// Anything that could not be sent is written as "Not run: <reason>", never as a result.
//
// Login checks need two test accounts (A, B) and one note owned by each, set in the student's own shell:
//   $env:ALEPH_CHECK_NOTE_A = '<A note UUID>'   (also _B)
// and either fresh tokens
//   $env:ALEPH_CHECK_TOKEN_A = '<token>'         (also _B)
// or the test accounts' login, used once through POST /api/session to get fresh tokens:
//   $env:ALEPH_CHECK_EMAIL_A = '<email>'; $env:ALEPH_CHECK_PASSWORD_A = '<password>'   (also _B)
// Optional third, already revoked test account for the step 12 revoked-identity check: _TOKEN_C or _EMAIL_C/_PASSWORD_C.
// Tokens and passwords are used only in requests and are never printed or stored.
// Every login request is signed by a virtual passkey authenticator (its key lives only in this process),
// registered and approved through POST /api/devices first. Approval needs a recent login.
//
// runAttackChecks(config, { details }) also pushes one structured row per check into `details`
// (step, normal/forbidden, expected, observed HTTP result, server request ID, check time) for the step 12 table.
import { randomUUID } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import { checkAccess } from './access-guard.mjs';
import { decide } from './decider.mjs';
import { detect } from './detect.mjs';
import { createVirtualDevice } from './device-client.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const cut = (text) => (text.length > 290 ? `${text.slice(0, 287)}...` : text);
const entry = (attackId, expected, observed) => ({ attackId, expected: cut(expected), observed: cut(observed) });
const notRun = (reason) => `Not run: ${reason}`;

// device signs the request; signAs lets a check sign one path/body and then send another (tampering).
async function send(app, path, { method = 'GET', token, body, base, device, signAs } = {}) {
  const url = base ?? new URL(path, app);
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (device) {
    Object.assign(headers, device.signHeaders({ method, path: url.pathname + url.search, body, ...signAs }));
  }
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const response = await fetch(url, {
    method, headers, body: body === undefined ? undefined : JSON.stringify(body),
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  let data;
  try { data = await response.json(); } catch { /* body is not JSON */ }
  return {
    status: response.status, error: data?.error, mode: data?.mode, audit: data?.audit, deviceStatus: data?.device?.status,
    requestId: response.headers.get('x-aleph-request-id') ?? null, accessToken: data?.accessToken,
  };
}

const describe = (r) => `HTTP ${r.status}${r.error ? ` ${r.error}` : ''}${r.deviceStatus ? ` device=${r.deviceStatus}` : ''}${r.mode ? ` mode=${r.mode}` : ''}${r.audit ? ` audit=${r.audit.recorded ? `#${r.audit.seq}` : 'missing'}` : ''}`;
const denied = (status) => (r) => r.status === status;
// Reads only the expiry time of a token from the shell, to avoid sending an expired one. Nothing else is trusted.
function tokenExpiry(token) {
  try {
    const exp = JSON.parse(Buffer.from(String(token).split('.')[1], 'base64url').toString('utf8')).exp;
    return Number.isSafeInteger(exp) ? exp : null;
  } catch {
    return null;
  }
}
const rejected = (r) => r.status === 401 || r.status === 403;

// Step 12: the operations room shows a check table and a screen snapshot recorded by `npm run ops:record`
// (checks first, then the snapshot of the server state they left). If `npm run bundle` sent the requests again,
// the server records would move past what the screen shows. So by default the bundle copies those recorded
// results (real requests, with their request IDs and times) instead of sending new ones. Set ALEPH_CHECK_LIVE=1
// to send live requests instead. A missing or older table means the checks run live as before.
const ROOT = resolve(import.meta.dirname, '..');
function readJson(path) {
  try {
    return existsSync(path) ? JSON.parse(readFileSync(path, 'utf8')) : null;
  } catch {
    return null;
  }
}
export function recordedAttackChecks(config) {
  const table = readJson(resolve(ROOT, 'public', 'ops-checks.json'));
  const snap = readJson(resolve(ROOT, 'public', 'ops-summary.json'));
  if (!table || table.schema !== 'aleph.ops.checks.v1' || table.step !== config.step || !Array.isArray(table.rows)) return null;
  if (!snap?.api?.body?.generatedAt || Date.parse(snap.api.body.generatedAt) < Date.parse(table.finishedAt)) return null;
  const order = [...new Set(table.rows.map((row) => row.attackId))];
  if (order.length !== table.selfChecks?.checks) return null;
  const source = `recorded by npm run ops:checks at ${table.finishedAt}; screen snapshot req=${snap.api.requestId}`;
  return order.map((attackId) => {
    const rows = table.rows.filter((row) => row.attackId === attackId);
    const expected = rows[0].expected;
    if (rows.some((row) => row.verdict === 'not_run')) return entry(attackId, expected, notRun(`${rows[0].notRunReason ?? 'not sent'} [${source}]`));
    const local = rows.every((row) => row.verdict === 'local_as_expected');
    const ok = rows.every((row) => row.verdict === 'as_expected' || row.verdict === 'local_as_expected');
    const text = rows.map((row) => (local ? row.observed : `${rows.length > 1 ? `${row.request}: ` : ''}${row.observed} req=${row.requestId}`)).join('; ');
    const head = ok ? (local ? 'As expected (local virtual run)' : 'As expected') : 'Needs review';
    return entry(attackId, expected, `${head}: ${text} at ${rows.at(-1).checkedAt} [${source}]`);
  });
}

export async function runAttackChecks(config, { details = [], sendLive = process.env.ALEPH_CHECK_LIVE === '1' } = {}) {
  if (config.step !== 12) throw new Error('Current step requires updating src/attack-check.mjs.');
  if (!sendLive) {
    const recorded = recordedAttackChecks(config);
    if (recorded) return recorded;
  }
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json must contain a valid public app URL.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json must contain a valid public app URL.');
  }

  const results = [];
  const record = (meta, expected, observed, rows) => {
    results.push(entry(meta.id, expected, observed));
    for (const row of rows) details.push({ attackId: meta.id, step: meta.step, kind: meta.kind, expected, ...row });
  };
  // One live check: one or more requests, all judged together. Each request gets its own row in `details`.
  const live = async (meta, expected, steps) => {
    const rows = [];
    try {
      let ok = true;
      for (const { run, accept, label } of steps) {
        const result = await run();
        const at = new Date().toISOString();
        const fine = accept(result);
        ok &&= fine;
        rows.push({ request: label, observed: describe(result), requestId: result.requestId ?? 'none', checkedAt: at, verdict: fine ? 'as_expected' : 'needs_review' });
      }
      const text = rows.map((row) => `${steps.length > 1 ? `${row.request}: ` : ''}${row.observed} req=${row.requestId}`).join('; ');
      record(meta, expected, `${ok ? 'As expected' : 'Needs review'}: ${text} at ${rows.at(-1).checkedAt}`, rows);
    } catch (error) {
      const at = new Date().toISOString();
      rows.push({ request: 'error', observed: `Could not be checked (${error.name})`, requestId: 'none', checkedAt: at, verdict: 'error' });
      record(meta, expected, `Could not be checked (${error.name}) at ${at}`, rows);
    }
  };
  const skip = (meta, expected, reason) => record(meta, expected, notRun(reason),
    [{ request: '-', observed: 'not run', requestId: 'none', checkedAt: null, verdict: 'not_run', reason }]);
  const local = async (meta, expected, checks) => {
    const parts = [];
    let ok = true;
    for (const [wanted, run] of checks) {
      let got;
      try { got = await run(); } catch (error) { got = `error ${error.name}`; }
      ok &&= got === wanted;
      parts.push(got);
    }
    const at = new Date().toISOString();
    record(meta, expected, `${ok ? 'As expected' : 'Needs review'} (local virtual run): ${parts.join('; ')}`,
      [{ request: 'local virtual run', observed: parts.join('; '), requestId: 'local', checkedAt: at, verdict: ok ? 'local_as_expected' : 'needs_review' }]);
  };

  // Login: a fresh login through POST /api/session with the test accounts comes first; a token from the shell is used
  // only when no login is given, and only while it has not expired (an expired token is reported, never sent).
  const env = process.env;
  const tokenProblems = [];
  const loginFor = async (suffix) => {
    const email = env[`ALEPH_CHECK_EMAIL_${suffix}`];
    const password = env[`ALEPH_CHECK_PASSWORD_${suffix}`];
    if (email && password) {
      try {
        const r = await send(app, '/api/session', { method: 'POST', body: { action: 'login', email, password } });
        if (r.status === 200 && typeof r.accessToken === 'string') return r.accessToken;
        tokenProblems.push(`login ${suffix} failed (HTTP ${r.status})`);
      } catch (error) {
        tokenProblems.push(`login ${suffix} failed (${error.name})`);
      }
      return null;
    }
    const token = env[`ALEPH_CHECK_TOKEN_${suffix}`];
    if (!token) return null;
    const exp = tokenExpiry(token);
    if (exp !== null && exp * 1000 <= Date.now() + 30_000) {
      tokenProblems.push(`ALEPH_CHECK_TOKEN_${suffix} has expired`);
      return null;
    }
    return token;
  };
  const tokenA = await loginFor('A');
  const tokenB = await loginFor('B');
  const tokenC = await loginFor('C');
  const noteA = env.ALEPH_CHECK_NOTE_A;
  const noteB = env.ALEPH_CHECK_NOTE_B;
  const loginReady = Boolean(tokenA && tokenB) && UUID.test(noteA ?? '') && UUID.test(noteB ?? '');
  const missing = `${tokenProblems.length ? `${tokenProblems.join(', ')}. ` : ''}set ALEPH_CHECK_NOTE_A/B and ALEPH_CHECK_EMAIL_/PASSWORD_A/B (or fresh ALEPH_CHECK_TOKEN_A/B) for the test accounts.`;
  const restorePath = config.restoreRoute;
  const restoreUsable = typeof restorePath === 'string' && restorePath.startsWith('/api/');

  // 0) Step 11: each test account gets one virtual device, approved by the server (recent login required).
  const deviceA = createVirtualDevice({ origin: app.origin });
  const deviceB = createVirtualDevice({ origin: app.origin });
  const approval = (device, token) => send(app, '/api/devices', {
    method: 'POST', token, device, body: { ...device.registration(), label: 'bundle self-check' },
  });
  const approvalMeta = { id: 's11_device_approval', step: '11', kind: 'normal' };
  const approvalExpected = 'A virtual passkey that signs its own registration, with a recent login, is approved: HTTP 200, device=approved';
  if (loginReady) {
    await live(approvalMeta, approvalExpected, [
      { label: 'A approval', run: () => approval(deviceA, tokenA), accept: (r) => r.status === 200 && r.deviceStatus === 'approved' },
      { label: 'B approval', run: () => approval(deviceB, tokenB), accept: (r) => r.status === 200 && r.deviceStatus === 'approved' },
    ]);
  } else skip(approvalMeta, approvalExpected, missing);

  // 1) Restore first, so every check below runs after the data came back.
  const restoreMeta = { id: 's10_restore_own_note', step: '10', kind: 'normal' };
  const restoreExpected = 'Account B restores its own note: HTTP 200, mode updated/reinserted/unchanged, and an audit record number';
  if (loginReady && restoreUsable) {
    await live(restoreMeta, restoreExpected, [{
      label: 'B restore', run: () => send(app, restorePath, { method: 'POST', token: tokenB, device: deviceB, body: { id: noteB } }),
      accept: (r) => r.status === 200 && ['updated', 'reinserted', 'unchanged'].includes(r.mode) && r.audit?.recorded === true,
    }]);
  } else skip(restoreMeta, restoreExpected, loginReady ? 'restoreRoute is not set in aleph.config.json.' : missing);

  // 2) Step 12 focus: right after the restore, an unsigned change request and an out-of-zone read.
  const afterMeta = { id: 's12_after_restore_unsigned_write_and_out_of_zone', step: '12 (10+11+8)', kind: 'forbidden' };
  const afterExpected = 'After the restore: B unsigned update of its own note is rejected (401 DEVICE_SIGNATURE_REQUIRED), then B signed read of A note is rejected (403)';
  if (loginReady) {
    await live(afterMeta, afterExpected, [
      { label: 'unsigned update', run: () => send(app, `/api/notes/${noteB}`, { method: 'PUT', token: tokenB, body: { title: 'unsigned change' } }),
        accept: (r) => r.status === 401 && r.error === 'DEVICE_SIGNATURE_REQUIRED' },
      { label: 'out-of-zone read', run: () => send(app, `/api/notes/${noteA}`, { token: tokenB, device: deviceB }), accept: denied(403) },
    ]);
  } else skip(afterMeta, afterExpected, missing);

  // 3) Normal requests after the restore.
  await live({ id: 's1_public_page_normal', step: '1', kind: 'normal' }, 'The public page still opens: HTTP 200',
    [{ label: 'public page', run: () => send(app, '/'), accept: (r) => r.status === 200 }]);
  const ownMeta = { id: 's8_own_note_read_after_restore', step: '8', kind: 'normal' };
  if (loginReady) {
    await live(ownMeta, 'Account A reads its own note: HTTP 200',
      [{ label: 'A own read', run: () => send(app, `/api/notes/${noteA}`, { token: tokenA, device: deviceA }), accept: (r) => r.status === 200 }]);
  } else skip(ownMeta, 'Account A reads its own note: HTTP 200', missing);

  // 4) Step 12 focus: an anonymous read and another user's note read sent back to back in the same run.
  const pairMeta = { id: 's12_anonymous_then_cross_read', step: '12 (1-4+8)', kind: 'forbidden' };
  const pairExpected = 'Back to back: anonymous read of A note is rejected (401), then B signed read of the same A note is rejected (403)';
  if (loginReady) {
    await live(pairMeta, pairExpected, [
      { label: 'anonymous read', run: () => send(app, `/api/notes/${noteA}`), accept: denied(401) },
      { label: 'cross read', run: () => send(app, `/api/notes/${noteA}`, { token: tokenB, device: deviceB }), accept: denied(403) },
    ]);
  } else skip(pairMeta, pairExpected, missing);

  // 5) Forbidden requests that need no login at all.
  await live({ id: 's1_anonymous_notes_list', step: '1', kind: 'forbidden' }, 'Anonymous list request is rejected with HTTP 401 or 403',
    [{ label: 'anonymous list', run: () => send(app, '/api/notes'), accept: rejected }]);
  await live({ id: 's2_4_anonymous_note_by_id', step: '2-4', kind: 'forbidden' }, 'Anonymous single-note request is rejected with HTTP 401 or 403',
    [{ label: 'anonymous note', run: () => send(app, `/api/notes/${randomUUID()}`), accept: rejected }]);
  await live({ id: 's8_anonymous_announcement_write', step: '8', kind: 'forbidden' }, 'Anonymous announcement update is rejected with HTTP 401 or 403',
    [{ label: 'anonymous announcement write', run: () => send(app, `/api/announcements/${randomUUID()}`, { method: 'PUT', body: { title: 'x' } }), accept: rejected }]);
  const anonRestoreMeta = { id: 's10_anonymous_restore_call', step: '10', kind: 'forbidden' };
  if (restoreUsable) {
    await live(anonRestoreMeta, 'Anonymous restore call is rejected with HTTP 401 or 403',
      [{ label: 'anonymous restore', run: () => send(app, restorePath, { method: 'POST', body: { id: randomUUID() } }), accept: rejected }]);
  } else skip(anonRestoreMeta, 'Anonymous restore call is rejected with HTTP 401 or 403', 'restoreRoute is not set in aleph.config.json.');
  const originalMeta = { id: 's5_original_api_without_key', step: '5', kind: 'forbidden' };
  const originalExpected = 'The original table API rejects a request that carries no key: HTTP 401 or 403';
  if (typeof config.originalApiUrl === 'string' && config.originalApiUrl.startsWith('https://')) {
    await live(originalMeta, originalExpected,
      [{ label: 'original API', run: () => send(app, '', { base: new URL(config.originalApiUrl) }), accept: rejected }]);
  } else skip(originalMeta, originalExpected, 'originalApiUrl is not set.');

  // 6) Forbidden requests that need two test logins.
  const login2 = [
    [{ id: 's8_cross_zone_note_read', step: '8', kind: 'forbidden' }, 'Account B reading account A note is rejected with HTTP 403',
      { label: 'cross read', run: () => send(app, `/api/notes/${noteA}`, { token: tokenB, device: deviceB }), accept: denied(403) }],
    [{ id: 's8_announcement_write_non_instructor', step: '8', kind: 'forbidden' }, 'A non-instructor announcement update is rejected with HTTP 403',
      { label: 'non-instructor write', run: () => send(app, `/api/announcements/${randomUUID()}`, { method: 'PUT', token: tokenA, device: deviceA, body: { title: 'x' } }), accept: denied(403) }],
    [{ id: 's10_restore_other_users_note', step: '10', kind: 'forbidden' }, 'Account A restoring account B note is rejected with HTTP 403',
      { label: 'other restore', run: () => send(app, restorePath, { method: 'POST', token: tokenA, device: deviceA, body: { id: noteB } }), accept: denied(403) }],
    [{ id: 's11_unsigned_protected_request', step: '11', kind: 'forbidden' }, 'A logged-in protected request without a device signature is rejected: HTTP 401 DEVICE_SIGNATURE_REQUIRED',
      { label: 'unsigned read', run: () => send(app, `/api/notes/${noteA}`, { token: tokenA }), accept: (r) => r.status === 401 && r.error === 'DEVICE_SIGNATURE_REQUIRED' }],
    [{ id: 's11_signed_path_changed', step: '11', kind: 'forbidden' }, 'A request signed for one note and sent to another path is rejected: HTTP 403 DEVICE_SIGNATURE_MISMATCH',
      { label: 'path changed', run: () => send(app, '/api/notes', { token: tokenA, device: deviceA, signAs: { path: `/api/notes/${noteA}` } }), accept: (r) => r.status === 403 && r.error === 'DEVICE_SIGNATURE_MISMATCH' }],
    // The body check targets a random note ID, so nothing can change even if the signature were not checked.
    [{ id: 's11_signed_body_changed', step: '11', kind: 'forbidden' }, 'An update whose body changed after signing is rejected: HTTP 403 DEVICE_SIGNATURE_MISMATCH',
      { label: 'body changed', run: () => send(app, `/api/notes/${randomUUID()}`, { method: 'PUT', token: tokenA, device: deviceA, body: { title: 'changed after signing' }, signAs: { body: { title: 'signed title' } } }), accept: (r) => r.status === 403 && r.error === 'DEVICE_SIGNATURE_MISMATCH' }],
  ];
  for (const [meta, expected, step] of login2) {
    if (!loginReady || (meta.id === 's10_restore_other_users_note' && !restoreUsable)) skip(meta, expected, loginReady ? 'restoreRoute is not set in aleph.config.json.' : missing);
    else await live(meta, expected, [step]);
  }

  // 7) Step 12 focus: a request from an unregistered device, then a request from a revoked identity.
  const revokedMeta = { id: 's12_unregistered_device_then_revoked_identity', step: '12 (6+9+11)', kind: 'forbidden' };
  const revokedExpected = 'A signed request from a never-approved device is rejected (403 DEVICE_NOT_APPROVED); then a revoked identity is rejected (403 IDENTITY_REVOKED)';
  if (loginReady) {
    const stranger = createVirtualDevice({ origin: app.origin });
    const steps = [{ label: 'unregistered device', run: () => send(app, `/api/notes/${noteA}`, { token: tokenA, device: stranger }), accept: (r) => r.status === 403 && r.error === 'DEVICE_NOT_APPROVED' }];
    if (tokenC) {
      // C is a test account the student revoked beforehand (npm run ops:revoke). Its device cannot be approved any more.
      const deviceC = createVirtualDevice({ origin: app.origin });
      steps.push({ label: 'revoked identity', run: () => send(app, '/api/notes', { token: tokenC, device: deviceC }), accept: (r) => r.status === 403 && r.error === 'IDENTITY_REVOKED' });
      await live(revokedMeta, revokedExpected, steps);
    } else {
      await live(revokedMeta, `${revokedExpected}. Revoked part not run live: no revoked test account C`, steps);
    }
  } else skip(revokedMeta, revokedExpected, missing);

  // 8) Local practice with virtual requests and events (the decider, detector and access guard run in this process).
  const { normal, suspicious } = fixtureRequests();
  await local({ id: 's6_s7_decider_local', step: '6-7', kind: 'forbidden' },
    'Unregistered device is denied; unusual region, network and hour ask for extra verification (local practice)', [
      ['deny device_not_registered', async () => { const r = await decide({ ...normal, requestId: randomUUID(), deviceRegistered: false }); return `${r.decision} ${r.reasonCode}`; }],
      ['step_up step_up_required', async () => { const r = await decide({ ...suspicious, requestId: randomUUID() }); return `${r.decision} ${r.reasonCode}`; }],
    ]);
  const start = Date.UTC(2026, 9, 1);
  const reads = (count) => Array.from({ length: count }, (_, i) => ({
    at: new Date(start + i * 2000).toISOString(), method: 'GET', identity: { sub: 'learner_fixture' },
  }));
  await local({ id: 's9_s12_detector_and_revocation_local', step: '9, 12', kind: 'forbidden' },
    '121 reads in 10 minutes propose a revocation, 30 are only observed, and the access guard refuses a revoked identity (local practice)', [
      ['propose_revocation burst_read', async () => { const r = detect(reads(121)); return `${r.action} ${r.reasonCode}`; }],
      ['observe', async () => detect(reads(30)).action],
      ['403 IDENTITY_REVOKED', async () => {
        const fakeDb = async (url) => ({ ok: true, status: 200, json: async () => (String(url).includes('identity_revocations') ? [{ reason: 'manual' }] : []) });
        const r = await checkAccess({ req: { method: 'GET', url: '/api/notes', headers: {} }, verified: { kind: 'student', userId: randomUUID() }, fetchImpl: fakeDb, supabaseUrl: 'https://local.invalid', serviceKey: 'local-practice' });
        return `${r.status} ${r.error}`;
      }],
    ]);

  return results;
}

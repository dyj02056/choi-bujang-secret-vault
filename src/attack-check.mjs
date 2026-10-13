// Student self-check: runs after a restore and records only requests that were really sent.
// Anything that could not be sent is written as "Not run: <reason>", never as a result.
//
// Optional login checks read test tokens from the student's own shell, for example
//   $env:ALEPH_CHECK_TOKEN_A = '<test account A token>'   (also _B)
//   $env:ALEPH_CHECK_NOTE_A  = '<A note UUID>'            (also _B)
// Tokens are used only in the Authorization header and are never printed or stored.
// Step 11: every login request is signed by a virtual passkey authenticator (its key lives only in this process),
// registered and approved through POST /api/devices first. Approval needs a recent login, so use fresh tokens.
import { randomUUID } from 'node:crypto';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
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
  return { status: response.status, error: data?.error, mode: data?.mode, audit: data?.audit, deviceStatus: data?.device?.status };
}

// Sends one request and judges it with `accept`. A network failure is reported as such.
async function live(id, expected, accept, run) {
  try {
    const result = await run();
    const text = `HTTP ${result.status}${result.error ? ` ${result.error}` : ''}${result.deviceStatus ? ` device=${result.deviceStatus}` : ''}${result.mode ? ` mode=${result.mode}` : ''}${result.audit ? ` audit=${result.audit.recorded ? `#${result.audit.seq}` : 'missing'}` : ''}`;
    return entry(id, expected, `${accept(result) ? 'As expected' : 'Needs review'}: ${text} at ${new Date().toISOString()}`);
  } catch (error) {
    return entry(id, expected, `Could not be checked (${error.name}) at ${new Date().toISOString()}`);
  }
}

const denied = (status) => (r) => r.status === status;
const rejected = (r) => r.status === 401 || r.status === 403;

export async function runAttackChecks(config) {
  if (config.step !== 11) throw new Error('Current step requires updating src/attack-check.mjs.');
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

  const env = process.env;
  const tokenA = env.ALEPH_CHECK_TOKEN_A;
  const tokenB = env.ALEPH_CHECK_TOKEN_B;
  const noteA = env.ALEPH_CHECK_NOTE_A;
  const noteB = env.ALEPH_CHECK_NOTE_B;
  const validIds = UUID.test(noteA ?? '') && UUID.test(noteB ?? '');
  const loginReady = Boolean(tokenA && tokenB) && validIds;
  const missing = notRun('set ALEPH_CHECK_TOKEN_A/B and ALEPH_CHECK_NOTE_A/B (test accounts) in your shell first.');
  const restorePath = config.restoreRoute;
  const restoreUsable = typeof restorePath === 'string' && restorePath.startsWith('/api/');
  const noRestoreRoute = notRun('restoreRoute is not set in aleph.config.json.');
  const results = [];

  // 0) Step 11: each test account gets one virtual device, approved by the server (recent login required).
  const deviceA = createVirtualDevice({ origin: app.origin });
  const deviceB = createVirtualDevice({ origin: app.origin });
  const approval = (device, token) => send(app, '/api/devices', {
    method: 'POST', token, device, body: { ...device.registration(), label: 'bundle self-check' },
  });
  const approvalExpected = 'A virtual passkey that signs its own registration, with a recent login, is approved: HTTP 200, device=approved';
  results.push(loginReady
    ? await live('s11_device_approval', approvalExpected,
      (r) => r.status === 200 && r.deviceStatus === 'approved', () => approval(deviceA, tokenA))
    : entry('s11_device_approval', approvalExpected, missing));
  if (loginReady) await approval(deviceB, tokenB).catch(() => null); // B's result shows up in the B checks below.

  // 1) Restore first, so every check below runs after the data came back.
  const restoreExpected = 'Account B restores its own note: HTTP 200, mode updated/reinserted/unchanged, and an audit record number';
  results.push(loginReady && restoreUsable
    ? await live('s10_restore_own_note', restoreExpected,
      (r) => r.status === 200 && ['updated', 'reinserted', 'unchanged'].includes(r.mode) && r.audit?.recorded === true,
      () => send(app, restorePath, { method: 'POST', token: tokenB, device: deviceB, body: { id: noteB } }))
    : entry('s10_restore_own_note', restoreExpected, loginReady ? noRestoreRoute : missing));

  // 2) Normal requests after the restore.
  results.push(await live('s1_public_page_normal', 'The public page still opens: HTTP 200',
    (r) => r.status === 200, () => send(app, '/')));
  results.push(loginReady
    ? await live('s8_own_note_read_after_restore', 'Account A reads its own note: HTTP 200',
      (r) => r.status === 200, () => send(app, `/api/notes/${noteA}`, { token: tokenA, device: deviceA }))
    : entry('s8_own_note_read_after_restore', 'Account A reads its own note: HTTP 200', missing));

  // 3) Forbidden requests that need no login at all.
  results.push(await live('s1_anonymous_notes_list', 'Anonymous list request is rejected with HTTP 401 or 403',
    rejected, () => send(app, '/api/notes')));
  results.push(await live('s2_4_anonymous_note_by_id', 'Anonymous single-note request is rejected with HTTP 401 or 403',
    rejected, () => send(app, `/api/notes/${randomUUID()}`)));
  results.push(await live('s8_anonymous_announcement_write', 'Anonymous announcement update is rejected with HTTP 401 or 403',
    rejected, () => send(app, `/api/announcements/${randomUUID()}`, { method: 'PUT', body: { title: 'x' } })));
  const anonRestoreExpected = 'Anonymous restore call is rejected with HTTP 401 or 403';
  results.push(restoreUsable
    ? await live('s10_anonymous_restore_call', anonRestoreExpected,
      rejected, () => send(app, restorePath, { method: 'POST', body: { id: randomUUID() } }))
    : entry('s10_anonymous_restore_call', anonRestoreExpected, noRestoreRoute));
  const originalExpected = 'The original table API rejects a request that carries no key: HTTP 401 or 403';
  results.push(typeof config.originalApiUrl === 'string' && config.originalApiUrl.startsWith('https://')
    ? await live('s5_original_api_without_key', originalExpected,
      rejected, () => send(app, '', { base: new URL(config.originalApiUrl) }))
    : entry('s5_original_api_without_key', originalExpected, notRun('originalApiUrl is not set.')));

  // 4) Forbidden requests that need two test logins.
  results.push(loginReady
    ? await live('s8_cross_zone_note_read', 'Account B reading account A note is rejected with HTTP 403',
      denied(403), () => send(app, `/api/notes/${noteA}`, { token: tokenB, device: deviceB }))
    : entry('s8_cross_zone_note_read', 'Account B reading account A note is rejected with HTTP 403', missing));
  results.push(loginReady
    ? await live('s8_announcement_write_non_instructor', 'A non-instructor announcement update is rejected with HTTP 403',
      denied(403), () => send(app, `/api/announcements/${randomUUID()}`, { method: 'PUT', token: tokenA, device: deviceA, body: { title: 'x' } }))
    : entry('s8_announcement_write_non_instructor', 'A non-instructor announcement update is rejected with HTTP 403', missing));
  const otherRestoreExpected = 'Account A restoring account B note is rejected with HTTP 403';
  results.push(loginReady && restoreUsable
    ? await live('s10_restore_other_users_note', otherRestoreExpected,
      denied(403), () => send(app, restorePath, { method: 'POST', token: tokenA, device: deviceA, body: { id: noteB } }))
    : entry('s10_restore_other_users_note', otherRestoreExpected, loginReady ? noRestoreRoute : missing));

  // 5) Step 11: protected requests from the access app must carry a signature that matches what is sent.
  const unsignedExpected = 'A logged-in protected request without a device signature is rejected: HTTP 401 DEVICE_SIGNATURE_REQUIRED';
  results.push(loginReady
    ? await live('s11_unsigned_protected_request', unsignedExpected,
      (r) => r.status === 401 && r.error === 'DEVICE_SIGNATURE_REQUIRED', () => send(app, `/api/notes/${noteA}`, { token: tokenA }))
    : entry('s11_unsigned_protected_request', unsignedExpected, missing));
  const pathExpected = 'A request signed for one note and sent to another path is rejected: HTTP 403 DEVICE_SIGNATURE_MISMATCH';
  results.push(loginReady
    ? await live('s11_signed_path_changed', pathExpected,
      (r) => r.status === 403 && r.error === 'DEVICE_SIGNATURE_MISMATCH',
      () => send(app, '/api/notes', { token: tokenA, device: deviceA, signAs: { path: `/api/notes/${noteA}` } }))
    : entry('s11_signed_path_changed', pathExpected, missing));
  // The body check targets a random note ID, so nothing can change even if the signature were not checked.
  const bodyExpected = 'An update whose body changed after signing is rejected: HTTP 403 DEVICE_SIGNATURE_MISMATCH';
  results.push(loginReady
    ? await live('s11_signed_body_changed', bodyExpected,
      (r) => r.status === 403 && r.error === 'DEVICE_SIGNATURE_MISMATCH',
      () => send(app, `/api/notes/${randomUUID()}`, {
        method: 'PUT', token: tokenA, device: deviceA, body: { title: 'changed after signing' },
        signAs: { body: { title: 'signed title' } },
      }))
    : entry('s11_signed_body_changed', bodyExpected, missing));

  // 6) Local practice with virtual events (the decider and detector run in this process; not a judge result).
  const local = async (id, expected, wanted, run) => {
    try {
      const got = await run();
      return entry(id, expected, `${got === wanted ? 'As expected' : 'Needs review'} (local virtual run): ${got}`);
    } catch (error) {
      return entry(id, expected, `Could not be checked (${error.name})`);
    }
  };
  const { normal, suspicious } = fixtureRequests();
  results.push(await local('s6_unregistered_device_denied', 'Unregistered device is denied (local practice)', 'deny device_not_registered', async () => {
    const r = await decide({ ...normal, requestId: randomUUID(), deviceRegistered: false });
    return `${r.decision} ${r.reasonCode}`;
  }));
  results.push(await local('s7_unusual_access_step_up', 'Unusual region, network and hour together ask for extra verification (local practice)', 'step_up step_up_required', async () => {
    const r = await decide({ ...suspicious, requestId: randomUUID() });
    return `${r.decision} ${r.reasonCode}`;
  }));
  const start = Date.UTC(2026, 9, 1);
  const reads = (count) => Array.from({ length: count }, (_, i) => ({
    at: new Date(start + i * 2000).toISOString(), method: 'GET', identity: { sub: 'learner_fixture' },
  }));
  results.push(await local('s9_burst_read_proposes_revocation', '121 reads in 10 minutes propose a revocation (local practice)', 'propose_revocation burst_read', async () => {
    const r = detect(reads(121));
    return `${r.action}${r.reasonCode ? ` ${r.reasonCode}` : ''}`;
  }));
  results.push(await local('s9_normal_reads_observed', '30 normal reads are only observed (local practice)', 'observe', async () => detect(reads(30)).action));

  return results;
}

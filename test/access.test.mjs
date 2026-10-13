import assert from 'node:assert/strict';
import { createPublicKey } from 'node:crypto';
import { test } from 'node:test';
import { checkAccess, routeShape } from '../src/access-guard.mjs';
import { createVirtualDevice } from '../src/device-client.mjs';
import { buildOpsSummary } from '../src/ops-summary.mjs';
import { ownerKeyOf } from '../src/owner-key.mjs';

// 메모리 안의 가짜 PostgREST. 실제 네트워크나 서버 키는 쓰지 않습니다.
const HOST = 'byteback-test.vercel.app';
const ORIGIN = `https://${HOST}`;
const USER_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const USER_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const NOTE = '11111111-1111-4111-8111-111111111111';
const BASE = { supabaseUrl: 'https://example.invalid', serviceKey: 'test-key-not-real' };
const verifiedA = { kind: 'student', userId: USER_A };

function makeDb() {
  const db = { events: [], revocations: [], devices: [], nonces: [], audit: [], backups: [], failEvents: false };
  db.fetch = async (url, options = {}) => {
    const parsed = new URL(url);
    const table = parsed.pathname.split('/').pop();
    const method = options.method ?? 'GET';
    const q = (name) => parsed.searchParams.get(name);
    const eq = (name) => q(name)?.replace(/^eq\./u, '');
    const reply = (status, body) => ({ ok: status < 300, status, json: async () => body });
    const body = options.body ? JSON.parse(options.body) : null;
    const owned = (rows) => rows.filter((row) => !q('owner_id') || row.owner_id === eq('owner_id'));
    if (table === 'access_events') {
      if (method === 'POST') {
        if (db.failEvents) return reply(503, {});
        db.events.push({ seq: db.events.length + 1, at: new Date().toISOString(), ...body });
        return reply(201, null);
      }
      let rows = owned(db.events);
      if (q('method')) rows = rows.filter((row) => row.method === eq('method'));
      if (q('at')) rows = rows.filter((row) => row.at >= q('at').replace(/^gte\./u, ''));
      rows = [...rows].sort((x, y) => y.seq - x.seq).slice(0, Number(q('limit') ?? 1000));
      return reply(200, rows);
    }
    if (table === 'identity_revocations') {
      if (method === 'POST') {
        if (!db.revocations.some((row) => row.owner_id === body.owner_id)) db.revocations.push({ revoked_at: new Date().toISOString(), ...body });
        return reply(201, null);
      }
      return reply(200, owned(db.revocations));
    }
    if (table === 'device_keys') {
      if (method === 'PATCH') {
        db.devices.filter((row) => row.owner_id === eq('owner_id') && row.status !== 'revoked').forEach((row) => Object.assign(row, body));
        return reply(204, null);
      }
      const rows = q('device_id') ? db.devices.filter((row) => row.device_id === eq('device_id')) : owned(db.devices);
      return reply(200, rows.map((row) => ({ ...row })));
    }
    if (table === 'device_nonces') {
      if (db.nonces.includes(`${body.device_id}:${body.nonce}`)) return reply(409, {});
      db.nonces.push(`${body.device_id}:${body.nonce}`);
      return reply(201, null);
    }
    if (table === 'secret_notes_restore_log') return reply(200, owned(db.audit));
    if (table === 'secret_notes_backup') return reply(200, owned(db.backups));
    return reply(404, {});
  };
  return db;
}

const approve = (db, userId = USER_A) => {
  const device = createVirtualDevice({ origin: ORIGIN });
  const jwk = createPublicKey({ key: Buffer.from(device.registration().spki, 'base64url'), format: 'der', type: 'spki' }).export({ format: 'jwk' });
  db.devices.push({ device_id: device.id, owner_id: ownerKeyOf({ kind: 'student', userId }), public_key: { crv: 'P-256', kty: 'EC', x: jwk.x, y: jwk.y }, status: 'approved', approved_at: 'now' });
  return device;
};
const signedGet = (device, path) => ({ method: 'GET', url: path, headers: { host: HOST, ...device.signHeaders({ path }) } });
const access = (db, req, verified = verifiedA) => checkAccess({ req, verified, fetchImpl: db.fetch, ...BASE });

test('로그인이 없으면 401이고 접근 사건을 남기지 않는다', async () => {
  const db = makeDb();
  const result = await access(db, { method: 'GET', url: `/api/notes/${NOTE}`, headers: { host: HOST } }, null);
  assert.equal(result.status, 401);
  assert.equal(db.events.length, 0);
});

test('승인된 기기의 정상 요청은 통과하고 요청 ID와 경로 모양만 기록된다', async () => {
  const db = makeDb();
  const device = approve(db);
  const result = await access(db, signedGet(device, `/api/notes/${NOTE}`));
  assert.equal(result.ok, true);
  assert.match(result.requestId, /^[0-9a-f-]{36}$/u);
  assert.deepEqual(db.events.map((row) => [row.request_id, row.route, row.outcome]), [[result.requestId, 'GET /notes/:id', 'allowed']]);
  assert.equal(JSON.stringify(db.events).includes(NOTE), false, '메모 ID 는 기록하지 않습니다');
});

test('미등록 기기 요청 뒤 회수된 신원으로 다시 보내면 둘 다 거부된다', async () => {
  const db = makeDb();
  const stranger = createVirtualDevice({ origin: ORIGIN });
  const first = await access(db, signedGet(stranger, `/api/notes/${NOTE}`));
  assert.equal(first.error, 'DEVICE_NOT_APPROVED');
  const device = approve(db);
  db.revocations.push({ owner_id: ownerKeyOf(verifiedA), reason: 'manual' });
  const second = await access(db, signedGet(device, `/api/notes/${NOTE}`));
  assert.equal(second.status, 403);
  assert.equal(second.error, 'IDENTITY_REVOKED', '승인된 기기의 올바른 서명이어도 회수된 신원은 거부됩니다');
  assert.deepEqual(db.events.map((row) => row.outcome), ['device_not_approved', 'identity_revoked']);
});

test('서명 없는 변경 요청은 거부되고 그 사실이 기록된다', async () => {
  const db = makeDb();
  approve(db);
  const result = await access(db, { method: 'PUT', url: `/api/notes/${NOTE}`, headers: { host: HOST }, body: { title: 'x' } });
  assert.equal(result.status, 401);
  assert.equal(result.error, 'DEVICE_SIGNATURE_REQUIRED');
  assert.deepEqual(db.events.map((row) => [row.route, row.outcome]), [['PUT /notes/:id', 'device_signature_required']]);
});

test('10분 안 GET 121번째에서 신원이 회수되고 기기도 회수되며 이후 요청은 거부된다', async () => {
  const db = makeDb();
  const device = approve(db);
  const owner = ownerKeyOf(verifiedA);
  const recent = new Date().toISOString();
  for (let i = 0; i < 120; i += 1) db.events.push({ seq: i + 1, owner_id: owner, method: 'GET', route: 'GET /notes', outcome: 'allowed', at: recent });
  const flagged = await access(db, signedGet(device, '/api/notes'));
  assert.equal(flagged.error, 'IDENTITY_REVOKED');
  assert.equal(db.revocations[0].reason, 'burst_read');
  assert.equal(db.devices[0].status, 'revoked');
  const later = await access(db, signedGet(device, '/api/notes'));
  assert.equal(later.error, 'IDENTITY_REVOKED');
});

test('정확히 120번째 GET 은 회수하지 않는다', async () => {
  const db = makeDb();
  const device = approve(db);
  const owner = ownerKeyOf(verifiedA);
  const recent = new Date().toISOString();
  for (let i = 0; i < 119; i += 1) db.events.push({ seq: i + 1, owner_id: owner, method: 'GET', route: 'GET /notes', outcome: 'allowed', at: recent });
  assert.equal((await access(db, signedGet(device, '/api/notes'))).ok, true);
  assert.equal(db.revocations.length, 0);
});

test('접근 기록을 남길 수 없으면 허용하지 않는다', async () => {
  const db = makeDb();
  const device = approve(db);
  db.failEvents = true;
  const result = await access(db, signedGet(device, '/api/notes'));
  assert.equal(result.status, 502);
  assert.equal(result.error, 'ACCESS_CHECK_UNAVAILABLE');
});

test('한 사람이 회수돼도 다른 사람은 그대로 접속한다', async () => {
  const db = makeDb();
  approve(db);
  const deviceB = approve(db, USER_B);
  db.revocations.push({ owner_id: ownerKeyOf(verifiedA), reason: 'manual' });
  assert.equal((await access(db, signedGet(deviceB, '/api/notes'), { kind: 'student', userId: USER_B })).ok, true);
});

test('경로 모양은 메모 ID와 쿼리를 지운다', () => {
  assert.equal(routeShape('get', { url: `/api/notes/${NOTE}?x=1` }), 'GET /notes/:id');
  assert.equal(routeShape('POST', { url: '/api/restore/notes' }), 'POST /restore/notes');
});

test('작전실 요약 수치는 가린 서버 기록과 같고 메모 본문이 없다', async () => {
  const db = makeDb();
  const device = approve(db);
  const owner = ownerKeyOf(verifiedA);
  await access(db, signedGet(device, '/api/notes'));
  await access(db, { method: 'PUT', url: `/api/notes/${NOTE}`, headers: { host: HOST }, body: { title: '비밀 제목' } });
  db.audit.push({ owner_id: owner, seq: 1, note_id: NOTE, mode: 'edited', restored_at: 't1' }, { owner_id: owner, seq: 2, note_id: NOTE, mode: 'updated', restored_at: 't2' });
  db.backups.push({ owner_id: owner, id: NOTE });
  const summary = await buildOpsSummary({ fetchImpl: db.fetch, ...BASE, ownerId: owner });
  assert.deepEqual(summary.rules.ruleIds, ['device_registered', 'step_up_required', 'resource_zone_route']);
  assert.equal(summary.detection.recentGetCount, 1);
  assert.deepEqual(summary.detection.outcomeCounts, { allowed: 1, device_signature_required: 1 });
  assert.equal(summary.detection.recentEvents.length, db.events.length);
  assert.deepEqual(summary.revocation, { revoked: false, reason: null, revokedAt: null, devices: { approved: 1, pending: 0, revoked: 0 } });
  assert.deepEqual(summary.restore.byMode, { edited: 1, updated: 1 });
  assert.equal(summary.restore.backups, 1);
  assert.equal(summary.restore.latest.seq, 2);
  assert.match(summary.restore.latest.note, /^note_[0-9a-f]{10}$/u);
  const text = JSON.stringify(summary);
  assert.equal(text.includes(NOTE) || text.includes('비밀 제목') || text.includes(USER_A), false);
});

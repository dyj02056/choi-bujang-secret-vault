import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkRequestSignature, deviceIdOf } from '../src/device-signature.mjs';
import { createVirtualDevice } from '../src/device-client.mjs';
import { handleDevices } from '../src/device-approval.mjs';

// 메모리 안의 가짜 PostgREST(device_keys, device_nonces). 실제 네트워크나 서버 키는 쓰지 않습니다.
const OWNER_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const OWNER_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const NOTE = '11111111-1111-4111-8111-111111111111';
const BASE = { supabaseUrl: 'https://example.invalid', serviceKey: 'test-key-not-real' };

function makeDb() {
  const db = { devices: [], nonces: [] };
  db.fetch = async (url, options = {}) => {
    const parsed = new URL(url);
    const table = parsed.pathname.split('/').pop();
    const method = options.method ?? 'GET';
    const reply = (status, body) => ({ ok: status < 300, status, json: async () => body });
    const eq = (name) => parsed.searchParams.get(name)?.replace('eq.', '');
    if (table === 'device_nonces' && method === 'POST') {
      const body = JSON.parse(options.body);
      if (db.nonces.some((row) => row.device_id === body.device_id && row.nonce === body.nonce)) return reply(409, {});
      db.nonces.push(body);
      return reply(201, null);
    }
    if (table === 'device_keys') {
      if (method === 'GET') {
        return reply(200, db.devices.filter((row) => (!eq('device_id') || row.device_id === eq('device_id'))
          && (!eq('owner_id') || row.owner_id === eq('owner_id'))).map((row) => ({ ...row })));
      }
      if (method === 'POST') {
        const row = { created_at: new Date().toISOString(), ...JSON.parse(options.body) };
        db.devices.push(row);
        return reply(201, [row]);
      }
      if (method === 'PATCH') {
        const rows = db.devices.filter((row) => row.device_id === eq('device_id') && row.owner_id === eq('owner_id')
          && row.status === eq('status'));
        rows.forEach((row) => Object.assign(row, JSON.parse(options.body)));
        return reply(200, rows);
      }
    }
    return reply(404, {});
  };
  return db;
}

// 받은 요청을 흉내 냅니다. Vercel 처럼 JSON 본문은 해석된 값으로 들어옵니다.
const incoming = ({ method = 'GET', url, headers = {}, body }) => ({ method, url, headers, body });
const approvedDevice = (db, owner = OWNER_A) => {
  const device = createVirtualDevice();
  db.devices.push({ device_id: device.id, owner_id: owner, public_key: device.publicJwk, status: 'approved', approved_at: 'now' });
  return device;
};
const check = (db, req, ownerId = OWNER_A) => checkRequestSignature({ req, ownerId, fetchImpl: db.fetch, ...BASE });

test('서명이 없는 보호 요청은 로그인했어도 거부된다', async () => {
  const db = makeDb();
  approvedDevice(db);
  const result = await check(db, incoming({ url: `/api/notes/${NOTE}` }));
  assert.equal(result.ok, false);
  assert.equal(result.status, 401);
  assert.equal(result.error, 'DEVICE_SIGNATURE_REQUIRED');
});

test('승인된 기기가 서명한 그대로의 요청은 통과한다', async () => {
  const db = makeDb();
  const device = approvedDevice(db);
  const path = `/api/notes/${NOTE}`;
  const body = { title: '가상 제목', body: '가상 본문' };
  const read = await check(db, incoming({ url: path, headers: device.signHeaders({ path }) }));
  assert.deepEqual(read, { ok: true, deviceId: device.id });
  const edit = await check(db, incoming({ method: 'PUT', url: path, body, headers: device.signHeaders({ method: 'PUT', path, body }) }));
  assert.equal(edit.ok, true);
});

test('서명한 뒤 경로를 바꾸면 거부된다', async () => {
  const db = makeDb();
  const device = approvedDevice(db);
  const headers = device.signHeaders({ path: `/api/notes/${NOTE}` });
  for (const url of ['/api/notes', `/api/notes/22222222-2222-4222-8222-222222222222`, `/api/notes/${NOTE}?x=1`, '/api/restore/notes']) {
    const result = await check(db, incoming({ url, headers }));
    assert.equal(result.error, 'DEVICE_SIGNATURE_MISMATCH', url);
    assert.equal(result.status, 403);
  }
  const method = await check(db, incoming({ method: 'DELETE', url: `/api/notes/${NOTE}`, headers }));
  assert.equal(method.error, 'DEVICE_SIGNATURE_MISMATCH', '메서드를 바꿔도 거부됩니다');
  assert.equal(db.nonces.length, 0, '맞지 않는 서명은 일회용 번호를 쓰지 않습니다');
});

test('서명한 뒤 수정 본문을 바꾸면 거부된다', async () => {
  const db = makeDb();
  const device = approvedDevice(db);
  const path = `/api/notes/${NOTE}`;
  const headers = device.signHeaders({ method: 'PUT', path, body: { title: '원래 제목', body: '원래 본문' } });
  for (const body of [{ title: '원래 제목', body: '바뀐 본문' }, { title: '원래 제목', body: '원래 본문', owner_id: OWNER_B }, undefined]) {
    const result = await check(db, incoming({ method: 'PUT', url: path, body, headers }));
    assert.equal(result.error, 'DEVICE_SIGNATURE_MISMATCH');
  }
});

test('같은 서명을 다시 보내거나 오래된 서명은 거부된다', async () => {
  const db = makeDb();
  const device = approvedDevice(db);
  const path = '/api/notes';
  const headers = device.signHeaders({ path });
  assert.equal((await check(db, incoming({ url: path, headers }))).ok, true);
  assert.equal((await check(db, incoming({ url: path, headers }))).error, 'DEVICE_SIGNATURE_REPLAYED');
  const old = device.signHeaders({ path, timestamp: String(Date.now() - 120_000) });
  assert.equal((await check(db, incoming({ url: path, headers: old }))).error, 'DEVICE_SIGNATURE_EXPIRED');
});

test('승인 대기 기기, 다른 계정의 기기, 등록 안 된 기기는 거부된다', async () => {
  const db = makeDb();
  const pending = createVirtualDevice();
  db.devices.push({ device_id: pending.id, owner_id: OWNER_A, public_key: pending.publicJwk, status: 'pending', approved_at: null });
  const path = '/api/notes';
  assert.equal((await check(db, incoming({ url: path, headers: pending.signHeaders({ path }) }))).error, 'DEVICE_NOT_APPROVED');
  const ofB = approvedDevice(db, OWNER_B);
  assert.equal((await check(db, incoming({ url: path, headers: ofB.signHeaders({ path }) }))).error, 'DEVICE_NOT_APPROVED');
  const unknown = createVirtualDevice();
  assert.equal((await check(db, incoming({ url: path, headers: unknown.signHeaders({ path }) }))).error, 'DEVICE_NOT_APPROVED');
});

// 기기 승인
const NOW = Date.now();
const fresh = { kind: 'student', userId: OWNER_A, authTime: Math.floor(NOW / 1000) - 60 };
const stale = { kind: 'student', userId: OWNER_A, authTime: Math.floor(NOW / 1000) - 3600 };
const register = (db, verified, device, body = { publicKey: device.publicJwk }, headers) => handleDevices({
  req: incoming({ method: 'POST', url: '/api/devices', body, headers: headers ?? device.signHeaders({ method: 'POST', path: '/api/devices', body }) }),
  verified, fetchImpl: db.fetch, ...BASE, now: NOW,
});

test('최근에 로그인한 토큰과 그 키의 서명이 있어야 기기가 승인된다', async () => {
  const db = makeDb();
  const device = createVirtualDevice();
  const result = await register(db, fresh, device);
  assert.equal(result.status, 200);
  assert.equal(result.body.device.status, 'approved');
  assert.equal(result.body.device.deviceId, device.id);
  assert.equal(JSON.stringify(result.body).includes(device.publicJwk.x), false, '공개키도 응답에 다시 싣지 않습니다');
});

test('오래된 로그인으로는 대기 상태로만 남고, 다시 로그인한 뒤 승인된다', async () => {
  const db = makeDb();
  const device = createVirtualDevice();
  const first = await register(db, stale, device);
  assert.equal(first.status, 403);
  assert.equal(first.body.error, 'REAUTH_REQUIRED');
  assert.equal(db.devices[0].status, 'pending');
  const path = '/api/notes';
  assert.equal((await check(db, incoming({ url: path, headers: device.signHeaders({ path }) }))).error, 'DEVICE_NOT_APPROVED',
    '승인 요청 버튼만으로는 자료를 열 수 없습니다');
  const again = await register(db, fresh, device);
  assert.equal(again.body.device.status, 'approved');
  assert.equal((await check(db, incoming({ url: path, headers: device.signHeaders({ path }) }))).ok, true);
});

test('다른 키로 서명했거나 서명이 없거나 개인키를 보낸 등록은 거부된다', async () => {
  const db = makeDb();
  const device = createVirtualDevice();
  const other = createVirtualDevice();
  const body = { publicKey: device.publicJwk };
  const forged = await register(db, fresh, device, body, other.signHeaders({ method: 'POST', path: '/api/devices', body }));
  assert.equal(forged.body.error, 'DEVICE_SIGNATURE_MISMATCH');
  const unsigned = await register(db, fresh, device, body, {});
  assert.equal(unsigned.body.error, 'DEVICE_SIGNATURE_REQUIRED');
  const withPrivate = await register(db, fresh, device, { publicKey: { ...device.publicJwk, d: 'x'.repeat(43) } });
  assert.equal(withPrivate.body.error, 'INVALID_DEVICE_KEY');
  assert.equal(db.devices.length, 0);
});

test('다른 계정이 같은 기기 키를 가져가 승인받을 수 없다', async () => {
  const db = makeDb();
  const device = createVirtualDevice();
  await register(db, fresh, device);
  const takeover = await register(db, { kind: 'student', userId: OWNER_B, authTime: fresh.authTime }, device);
  assert.equal(takeover.status, 409);
  assert.equal(db.devices[0].owner_id, OWNER_A);
});

test('기기 ID는 공개키에서 정해지는 16자리 16진수다', () => {
  const device = createVirtualDevice();
  assert.match(device.id, /^[0-9a-f]{16}$/u);
  assert.equal(deviceIdOf(device.publicJwk), device.id);
});

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { noteHash } from '../src/note-backup.mjs';
import { restoreNote } from '../src/restore-note.mjs';

// 메모리 안의 가짜 PostgREST입니다. 실제 네트워크나 서버 키는 쓰지 않습니다.
const NOTE_B = '22222222-2222-4222-8222-222222222222';
const NOTE_A = '11111111-1111-4111-8111-111111111111';
const OWNER_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const OWNER_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';

function makeDb() {
  const original = { id: NOTE_B, owner_id: OWNER_B, title: '가상 제목', content: '가상 내용' };
  const db = {
    notes: [{ ...original }, { id: NOTE_A, owner_id: OWNER_A, title: 'A 제목', content: 'A 내용' }],
    backup: [{ ...original, content_sha256: noteHash(original.title, original.content), created_at: null }],
    log: [],
    calls: [],
    failLog: false,
  };
  db.fetch = async (url, options = {}) => {
    const parsed = new URL(url);
    const table = parsed.pathname.split('/').pop();
    const method = options.method ?? 'GET';
    db.calls.push(`${method} ${table}`);
    const store = { secret_notes: db.notes, secret_notes_backup: db.backup, secret_notes_restore_log: db.log }[table];
    const reply = (status, body) => ({ ok: status < 300, status, json: async () => body });
    if (!store) return reply(404, []);
    if (method === 'GET') {
      const id = parsed.searchParams.get('id')?.replace('eq.', '');
      return reply(200, store.filter((row) => row.id === id).map((row) => ({ ...row })));
    }
    const body = JSON.parse(options.body);
    if (method === 'POST' && table === 'secret_notes_restore_log') {
      if (db.failLog) return reply(500, {});
      const row = { seq: store.length + 1, ...body };
      store.push(row);
      return reply(201, [row]);
    }
    if (method === 'POST') {
      if (table === 'secret_notes' && store.some((row) => row.id === body.id)) return reply(409, {});
      store.push({ ...body });
      return reply(201, []);
    }
    if (method === 'PATCH') {
      const id = parsed.searchParams.get('id').replace('eq.', '');
      const owner = parsed.searchParams.get('owner_id').replace('eq.', '');
      store.filter((row) => row.id === id && row.owner_id === owner).forEach((row) => Object.assign(row, body));
      return reply(204, null);
    }
    return reply(405, {});
  };
  return db;
}

const run = (db, overrides = {}) => restoreNote({
  fetchImpl: db.fetch, supabaseUrl: 'https://example.invalid', serviceKey: 'test-key-not-real',
  ownerId: OWNER_B, id: NOTE_B, ...overrides,
});

test('변조된 B 메모는 사본의 ID·소유자·해시로 되돌아간다', async () => {
  const db = makeDb();
  db.notes[0].content = '변조된 내용';
  const result = await run(db);
  assert.equal(result.status, 200);
  assert.equal(result.body.mode, 'updated');
  assert.equal(noteHash(db.notes[0].title, db.notes[0].content), db.backup[0].content_sha256);
  assert.equal(db.notes[0].owner_id, OWNER_B);
  assert.equal(db.notes[1].content, 'A 내용', '다른 메모는 그대로여야 합니다');
  assert.equal(db.log.length, 1);
  assert.equal(result.body.audit.recorded, true);
  assert.equal(result.body.audit.seq, db.log[0].seq);
  assert.equal(JSON.stringify(result.body).includes('가상 내용'), false, '응답에 메모 내용이 없어야 합니다');
});

test('삭제된 B 메모는 같은 ID·소유자로 다시 만들어진다', async () => {
  const db = makeDb();
  db.notes.splice(0, 1);
  const result = await run(db);
  assert.equal(result.status, 200);
  assert.equal(result.body.mode, 'reinserted');
  const row = db.notes.find((note) => note.id === NOTE_B);
  assert.equal(row.owner_id, OWNER_B);
  assert.equal(noteHash(row.title, row.content), db.backup[0].content_sha256);
  assert.equal(db.notes.length, 2);
});

test('이미 같은 메모면 메모는 쓰지 않고 호출만 감사 기록에 남긴다', async () => {
  const db = makeDb();
  const result = await run(db);
  assert.equal(result.body.mode, 'unchanged');
  assert.equal(db.calls.some((call) => /^(PATCH|POST) secret_notes$/.test(call)), false);
  assert.equal(db.log.length, 1);
  assert.equal(db.log[0].mode, 'unchanged');
  assert.equal(result.body.audit.recorded, true);
});

test('다른 사용자(A)는 B 메모를 복구할 수 없다', async () => {
  const db = makeDb();
  db.notes[0].content = '변조된 내용';
  const result = await run(db, { ownerId: OWNER_A });
  assert.equal(result.status, 403);
  assert.equal(db.notes[0].content, '변조된 내용', '거부되면 쓰지 않습니다');
});

test('사본이 없거나 변조되면 복구를 중단한다', async () => {
  const none = makeDb();
  none.backup.length = 0;
  assert.equal((await run(none)).status, 404);

  const forged = makeDb();
  forged.backup[0].content = '사본 내용 변조';
  forged.notes[0].content = '변조된 내용';
  const result = await run(forged);
  assert.equal(result.status, 409);
  assert.equal(result.body.error, 'BACKUP_INTEGRITY_FAILED');
  assert.equal(forged.notes[0].content, '변조된 내용');
});

test('같은 ID가 다른 소유자로 남아 있으면 덮어쓰지 않는다', async () => {
  const db = makeDb();
  db.notes[0].owner_id = OWNER_A;
  db.notes[0].content = '다른 사람 내용';
  const result = await run(db);
  assert.equal(result.body.error, 'OWNER_CONFLICT');
  assert.equal(db.notes[0].content, '다른 사람 내용');
});

test('잘못된 ID는 DB를 읽기 전에 거부한다', async () => {
  const db = makeDb();
  for (const bad of [undefined, '', 'x', '../notes', `${NOTE_B}&owner_id=neq.x`, 42]) {
    assert.equal((await run(db, { id: bad })).status, 400);
  }
  assert.equal(db.calls.length, 0);
});

test('복구 뒤 같은 요청을 다시 보내도 상태가 늘어나지 않는다', async () => {
  const db = makeDb();
  db.notes.splice(0, 1);
  await run(db);
  const again = await run(db);
  assert.equal(again.body.mode, 'unchanged');
  assert.equal(db.notes.length, 2);
  assert.equal(db.log.length, 2, '감사 기록은 지워지지 않고 쌓입니다');
  assert.deepEqual(db.log.map((row) => row.mode), ['reinserted', 'unchanged']);
});

test('만들 때 남긴 첫 버전으로 이후 변조·삭제를 복구한다', async () => {
  const { saveFirstBackup } = await import('../src/note-backup.mjs');
  const db = makeDb();
  db.backup.length = 0;
  const saved = await saveFirstBackup({
    fetchImpl: async (url, options) => {
      const body = JSON.parse(options.body);
      db.backup.push({ ...body, created_at: null });
      return { ok: true, status: 201 };
    },
    supabaseUrl: 'https://example.invalid', serviceKey: 'test-key-not-real',
    id: NOTE_B, ownerId: OWNER_B, title: '가상 제목', content: '가상 내용',
  });
  assert.equal(saved, true);
  db.notes[0].content = '변조된 내용';
  assert.equal((await run(db)).body.mode, 'updated');
  db.notes.splice(0, 1);
  assert.equal((await run(db)).body.mode, 'reinserted');
  assert.equal(db.notes.find((note) => note.id === NOTE_B).content, '가상 내용');
});

test('사본 저장이 실패해도 예외 없이 false만 돌려준다', async () => {
  const { saveFirstBackup } = await import('../src/note-backup.mjs');
  const failed = await saveFirstBackup({
    fetchImpl: async () => { throw new Error('network'); },
    supabaseUrl: 'https://example.invalid', serviceKey: 'test-key-not-real',
    id: NOTE_B, ownerId: OWNER_B, title: 't', content: 'c',
  });
  assert.equal(failed, false);
});

test('감사 기록을 남길 수 없으면 아무것도 바꾸지 않고 중단한다', async () => {
  const db = makeDb();
  db.notes[0].content = '변조된 내용';
  db.failLog = true;
  const result = await run(db);
  assert.equal(result.status, 502);
  assert.equal(result.body.error, 'AUDIT_UNAVAILABLE');
  assert.equal(db.notes[0].content, '변조된 내용', '기록 실패 시 복구하지 않습니다');
  assert.equal(db.calls.some((call) => /^(PATCH|POST) secret_notes$/.test(call)), false);

  const gone = makeDb();
  gone.notes.splice(0, 1);
  gone.failLog = true;
  assert.equal((await run(gone)).body.error, 'AUDIT_UNAVAILABLE');
  assert.equal(gone.notes.some((note) => note.id === NOTE_B), false);
});

test('변경 없는 호출은 기록에 실패해도 자료를 건드리지 않고 결과만 알린다', async () => {
  const db = makeDb();
  db.failLog = true;
  const result = await run(db);
  assert.equal(result.status, 200);
  assert.equal(result.body.audit.recorded, false);
});

test('복구는 지정한 한 건만 바꾸고 다른 메모와 기존 감사 기록은 그대로 둔다', async () => {
  const db = makeDb();
  const other = { id: '33333333-3333-4333-8333-333333333333', owner_id: OWNER_B, title: 'B의 다른 메모', content: '변조 그대로' };
  db.notes.push(other);
  db.log.push({ seq: 1, note_id: NOTE_A, owner_id: OWNER_A, mode: 'updated' });
  db.notes[0].content = '변조된 내용';
  const before = JSON.stringify([db.notes[1], other, db.log[0]]);
  const result = await run(db);
  assert.equal(result.body.mode, 'updated');
  assert.equal(JSON.stringify([db.notes[1], other, db.log[0]]), before);
  assert.equal(db.log.length, 2);
});

test('삭제 뒤 복구해도 생성 시각과 B의 목록 순서가 그대로다', async () => {
  const db = makeDb();
  const OLD = '2026-10-01T00:00:00.000Z';
  const NEW = '2026-10-02T00:00:00.000Z';
  const newer = { id: '33333333-3333-4333-8333-333333333333', owner_id: OWNER_B, title: '더 최근 메모', content: '유지', created_at: NEW };
  db.notes[0].created_at = OLD;
  db.backup[0].created_at = OLD;
  db.notes.push(newer);
  const listOrder = () => db.notes.filter((note) => note.owner_id === OWNER_B)
    .sort((a, b) => b.created_at.localeCompare(a.created_at)).map((note) => note.id);
  const before = listOrder();
  db.notes.splice(0, 1);
  const result = await run(db);
  assert.equal(result.body.mode, 'reinserted');
  assert.deepEqual(listOrder(), before, '복구 뒤에도 목록 순서가 같아야 합니다');
  assert.equal(db.notes.find((note) => note.id === NOTE_B).created_at, OLD);
  assert.equal(db.notes.find((note) => note.id === newer.id).content, '유지');
});

test('첫 버전 사본에 생성 시각이 함께 저장된다', async () => {
  const { saveFirstBackup } = await import('../src/note-backup.mjs');
  let sent;
  await saveFirstBackup({
    fetchImpl: async (url, options) => { sent = JSON.parse(options.body); return { ok: true, status: 201 }; },
    supabaseUrl: 'https://example.invalid', serviceKey: 'test-key-not-real',
    id: NOTE_B, ownerId: OWNER_B, title: 't', content: 'c', createdAt: '2026-10-01T00:00:00.000Z',
  });
  assert.equal(sent.created_at, '2026-10-01T00:00:00.000Z');
});

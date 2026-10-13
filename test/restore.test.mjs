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

test('이미 같은 메모면 아무것도 쓰지 않는다', async () => {
  const db = makeDb();
  const result = await run(db);
  assert.equal(result.body.mode, 'unchanged');
  assert.equal(db.calls.some((call) => call.startsWith('PATCH') || call.startsWith('POST')), false);
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
  assert.equal(db.log.length, 1);
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

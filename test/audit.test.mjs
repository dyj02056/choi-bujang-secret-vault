import assert from 'node:assert/strict';
import { test } from 'node:test';
import { noteHash } from '../src/note-backup.mjs';
import { blocksChange, recordNoteEvent } from '../src/note-audit.mjs';
import { restoreNote } from '../src/restore-note.mjs';

const NOTE = '22222222-2222-4222-8222-222222222222';
const OWNER = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const URL_BASE = 'https://example.invalid';
const KEY = 'test-key-not-real';

// 메모리 안의 가짜 PostgREST: 메모 표, 사본 표, 추가 전용 감사 표. 열 검사는 006 마이그레이션 이후를 흉내 냅니다.
function makeDb({ auditColumns = true } = {}) {
  const db = { notes: [], backup: [], log: [], rejected: 0 };
  db.fetch = async (url, options = {}) => {
    const parsed = new URL(url);
    const table = parsed.pathname.split('/').pop();
    const reply = (status, body) => ({ ok: status < 300, status, json: async () => body });
    const store = { secret_notes: db.notes, secret_notes_backup: db.backup, secret_notes_restore_log: db.log }[table];
    if (!store) return reply(404, {});
    const method = options.method ?? 'GET';
    if (method === 'GET') {
      const id = parsed.searchParams.get('id')?.replace('eq.', '');
      return reply(200, store.filter((row) => row.id === id).map((row) => ({ ...row })));
    }
    const body = JSON.parse(options.body);
    if (table === 'secret_notes_restore_log') {
      if (!auditColumns && 'before_sha256' in body) { db.rejected += 1; return reply(400, {}); }
      const row = { seq: store.length + 1, ...body };
      store.push(row);
      return reply(201, [row]);
    }
    if (method === 'POST') { store.push({ ...body }); return reply(201, []); }
    if (method === 'PATCH') {
      const id = parsed.searchParams.get('id').replace('eq.', '');
      store.filter((row) => row.id === id).forEach((row) => Object.assign(row, body));
      return reply(204, null);
    }
    return reply(405, {});
  };
  return db;
}

const base = (db) => ({ fetchImpl: db.fetch, supabaseUrl: URL_BASE, serviceKey: KEY, noteId: NOTE, ownerId: OWNER });
const ORIGINAL = { title: '가상 제목', content: '가상 내용' };
const TAMPERED = { title: '가상 제목', content: '변조된 내용' };

test('생성, 수정, 삭제, 복구가 하나의 기록으로 이어지고 내용은 저장되지 않는다', async () => {
  const db = makeDb();
  // 1) 생성
  const created = await recordNoteEvent({ ...base(db), mode: 'created', before: null, after: ORIGINAL });
  db.notes.push({ id: NOTE, owner_id: OWNER, ...ORIGINAL });
  db.backup.push({ id: NOTE, owner_id: OWNER, ...ORIGINAL, content_sha256: noteHash(ORIGINAL.title, ORIGINAL.content), created_at: null });
  // 2) 수정(변조)
  await recordNoteEvent({ ...base(db), mode: 'edited', before: ORIGINAL, after: TAMPERED });
  Object.assign(db.notes[0], TAMPERED);
  // 3) 복구(변조본 덮어쓰기)
  const fixed = await restoreNote({ fetchImpl: db.fetch, supabaseUrl: URL_BASE, serviceKey: KEY, ownerId: OWNER, id: NOTE });
  // 4) 삭제
  await recordNoteEvent({ ...base(db), mode: 'deleted', before: db.notes[0], after: null });
  db.notes.splice(0, 1);
  // 5) 삭제 뒤 복구
  const again = await restoreNote({ fetchImpl: db.fetch, supabaseUrl: URL_BASE, serviceKey: KEY, ownerId: OWNER, id: NOTE });

  assert.equal(created.recorded, true);
  assert.equal(fixed.body.mode, 'updated');
  assert.equal(again.body.mode, 'reinserted');
  assert.deepEqual(db.log.map((row) => row.mode), ['created', 'edited', 'updated', 'deleted', 'reinserted']);
  assert.deepEqual(db.log.map((row) => row.seq), [1, 2, 3, 4, 5], '번호가 빠지지 않고 이어집니다');

  const h = (note) => noteHash(note.title, note.content);
  const [c, e, u, d, r] = db.log;
  assert.equal(c.before_sha256, null);
  assert.equal(c.after_sha256, h(ORIGINAL));
  assert.equal(e.before_sha256, h(ORIGINAL));
  assert.equal(e.after_sha256, h(TAMPERED));
  assert.equal(u.before_sha256, h(TAMPERED), '복구가 덮어쓴 변조본의 해시가 남습니다');
  assert.equal(u.after_sha256, h(ORIGINAL));
  assert.equal(d.before_sha256, h(ORIGINAL));
  assert.equal(d.after_sha256, null);
  assert.equal(r.before_sha256, null, '삭제된 메모를 다시 만들 때는 이전 값이 없습니다');
  assert.equal(r.after_sha256, h(ORIGINAL));
  assert.equal(JSON.stringify(db.log).includes('가상 내용'), false);
  assert.equal(JSON.stringify(db.log).includes('변조된 내용'), false);
});

test('표나 열이 준비되지 않아 기록하지 못하면 해시를 빼고 다시 쓰지 않고 수정·삭제·복구를 막는다', async () => {
  const db = makeDb({ auditColumns: false });
  for (const mode of ['updated', 'edited', 'deleted']) {
    const result = await recordNoteEvent({ ...base(db), mode, before: ORIGINAL, after: TAMPERED });
    assert.equal(result.recorded, false);
    assert.equal(blocksChange(result), true, `${mode}: 기록이 없으면 바꾸지 않습니다`);
  }
  assert.equal(db.log.length, 0, '해시 없는 줄로 바꿔 쓰지 않습니다');
  assert.equal(db.rejected, 3, '한 번씩만 시도합니다');

  const db2 = makeDb({ auditColumns: false });
  db2.notes.push({ id: NOTE, owner_id: OWNER, ...TAMPERED });
  db2.backup.push({ id: NOTE, owner_id: OWNER, ...ORIGINAL, content_sha256: noteHash(ORIGINAL.title, ORIGINAL.content), created_at: null });
  const restored = await restoreNote({ fetchImpl: db2.fetch, supabaseUrl: URL_BASE, serviceKey: KEY, ownerId: OWNER, id: NOTE });
  assert.equal(restored.status, 502);
  assert.equal(db2.notes[0].content, '변조된 내용');
});

test('거절 기록은 정해진 이유 코드만 받고, 다른 동작에는 이유를 붙이지 않는다', async () => {
  const db = makeDb();
  assert.equal((await recordNoteEvent({ ...base(db), mode: 'refused', reason: 'no_backup' })).recorded, true);
  assert.equal((await recordNoteEvent({ ...base(db), mode: 'refused', reason: 'whatever' })).recorded, false);
  assert.equal((await recordNoteEvent({ ...base(db), mode: 'refused' })).recorded, false);
  await recordNoteEvent({ ...base(db), mode: 'edited', before: ORIGINAL, after: TAMPERED, reason: 'no_backup' });
  assert.deepEqual(db.log.map((row) => [row.mode, row.reason]), [['refused', 'no_backup'], ['edited', undefined]]);
});

test('네트워크나 서버 오류로 기록하지 못하면 수정·삭제를 막는다', async () => {
  const down = await recordNoteEvent({ ...base(makeDb()), fetchImpl: async () => { throw new Error('network'); }, mode: 'deleted', before: ORIGINAL, after: null });
  assert.equal(down.recorded, false);
  assert.equal(blocksChange(down), true);

  const serverError = await recordNoteEvent({
    ...base(makeDb()), fetchImpl: async () => ({ ok: false, status: 503, json: async () => ({}) }),
    mode: 'edited', before: ORIGINAL, after: TAMPERED,
  });
  assert.equal(blocksChange(serverError), true);
});

test('알 수 없는 동작 이름은 기록하지 않는다', async () => {
  const db = makeDb();
  const result = await recordNoteEvent({ ...base(db), mode: 'purged', before: ORIGINAL, after: null });
  assert.equal(result.recorded, false);
  assert.equal(db.log.length, 0);
});

test('복구 기록 실패 시 변조된 메모를 그대로 두는 동작은 유지된다', async () => {
  const db = makeDb();
  db.notes.push({ id: NOTE, owner_id: OWNER, ...TAMPERED });
  db.backup.push({ id: NOTE, owner_id: OWNER, ...ORIGINAL, content_sha256: noteHash(ORIGINAL.title, ORIGINAL.content), created_at: null });
  const failingFetch = async (url, options) => (String(url).includes('secret_notes_restore_log')
    ? { ok: false, status: 503, json: async () => ({}) } : db.fetch(url, options));
  const result = await restoreNote({ fetchImpl: failingFetch, supabaseUrl: URL_BASE, serviceKey: KEY, ownerId: OWNER, id: NOTE });
  assert.equal(result.status, 502);
  assert.equal(result.body.error, 'AUDIT_UNAVAILABLE');
  assert.equal(db.notes[0].content, '변조된 내용');
});

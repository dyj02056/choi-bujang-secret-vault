import { resolve } from 'node:path';
import { UUID, noteHash } from '../src/note-backup.mjs';

// 침해 전에 학생이 직접 실행합니다. secret_notes의 메모를 비공개 사본 표에 한 번만 복사합니다.
// 이미 있는 사본은 덮어쓰지 않습니다. 메모 제목·내용과 서버 키는 출력하지 않습니다.
//   node scripts/backup-notes.mjs --note <메모 UUID>     (한 건만)
//   node scripts/backup-notes.mjs --all                  (소유자가 있는 모든 메모)
try {
  process.loadEnvFile?.(resolve(import.meta.dirname, '..', '.env'));
} catch {}

const args = process.argv.slice(2);
const noteIndex = args.indexOf('--note');
const noteId = noteIndex >= 0 ? args[noteIndex + 1] : null;
const all = args.includes('--all');

try {
  const url = process.env.SUPABASE_URL?.replace(/\/+$/u, '');
  const key = process.env.SUPABASE_SECRET_KEY;
  if (!url || !key) throw new Error('SUPABASE_URL과 SUPABASE_SECRET_KEY를 .env 또는 환경변수에 설정해 주세요.');
  if (!all && !(noteId && UUID.test(noteId))) throw new Error('--note <메모 UUID> 또는 --all 중 하나를 지정해 주세요.');

  const headers = { apikey: key, Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' };
  const filter = all ? 'owner_id=not.is.null' : `id=eq.${noteId}&owner_id=not.is.null`;
  const read = await fetch(`${url}/rest/v1/secret_notes?${filter}&select=id,owner_id,title,content,created_at`, { headers });
  if (!read.ok) throw new Error(`메모를 읽지 못했습니다 (HTTP ${read.status}).`);
  const rows = (await read.json()).map((row) => ({
    id: row.id, owner_id: row.owner_id, title: row.title, content: row.content,
    content_sha256: noteHash(row.title, row.content), created_at: row.created_at,
  }));
  if (!rows.length) throw new Error('복사할 메모가 없습니다.');

  const write = await fetch(`${url}/rest/v1/secret_notes_backup?on_conflict=id`, {
    method: 'POST', headers: { ...headers, Prefer: 'resolution=ignore-duplicates,return=representation' },
    body: JSON.stringify(rows),
  });
  if (!write.ok) throw new Error(`사본을 쓰지 못했습니다 (HTTP ${write.status}). 004 마이그레이션을 실행했는지 확인해 주세요.`);
  const created = await write.json();
  process.stdout.write(`사본 생성 ${created.length}건, 이미 있어 건너뜀 ${rows.length - created.length}건\n`);
} catch (error) {
  process.stderr.write(`사본 생성 첫 오류: ${error.message}\n`);
  process.exitCode = 1;
}

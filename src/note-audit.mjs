import { noteHash } from './note-backup.mjs';

// 메모의 생성·수정·삭제·복구를 추가 전용 표 secret_notes_restore_log 에 한 줄씩 남깁니다.
// 메모 제목·내용은 저장하지 않고, 바뀌기 전과 후의 내용 해시(SHA-256)만 남깁니다.
// 거절된 복구 호출도 'refused' 와 이유 코드로 남깁니다(마이그레이션 007).
export const AUDIT_MODES = Object.freeze(['created', 'edited', 'deleted', 'updated', 'reinserted', 'unchanged', 'refused']);
export const REFUSAL_REASONS = Object.freeze([
  'bad_request', 'invalid_id', 'no_backup', 'backup_integrity_failed', 'not_owner', 'owner_conflict', 'db_unavailable',
]);

const hashOf = (note) => (note ? noteHash(note.title, note.content) : null);

// before/after 는 { title, content } 또는 null(없음) 입니다. reason 은 mode 가 'refused' 일 때만 씁니다.
// 결과: { recorded: true, seq } 또는 { recorded: false }
// 기록에 실패하면 어떤 경우에도 다른 값으로 바꿔 다시 쓰거나 기록한 것처럼 돌려주지 않습니다.
export async function recordNoteEvent({
  fetchImpl = fetch, supabaseUrl, serviceKey, noteId, ownerId, mode, before = null, after = null, reason,
}) {
  if (!AUDIT_MODES.includes(mode)) return { recorded: false };
  if (mode === 'refused' && !REFUSAL_REASONS.includes(reason)) return { recorded: false };
  const row = {
    note_id: noteId ?? null, owner_id: ownerId, mode,
    before_sha256: hashOf(before), after_sha256: hashOf(after),
    ...(mode === 'refused' ? { reason } : {}),
  };
  try {
    const response = await fetchImpl(`${supabaseUrl}/rest/v1/secret_notes_restore_log`, {
      method: 'POST',
      headers: {
        apikey: serviceKey, Authorization: `Bearer ${serviceKey}`, 'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify(row),
    });
    if (!response.ok) return { recorded: false };
    const rows = await response.json();
    const seq = Array.isArray(rows) ? rows[0]?.seq : undefined;
    return seq === undefined || seq === null ? { recorded: false } : { recorded: true, seq };
  } catch {
    return { recorded: false };
  }
}

// 자료를 바꾸는 일(수정·삭제·복구)은 감사 기록이 남았을 때만 진행합니다. 예외는 없습니다.
export const blocksChange = (audit) => !audit.recorded;

export const auditField = (audit) => (audit.recorded ? { recorded: true, seq: audit.seq } : { recorded: false });

import { noteHash } from './note-backup.mjs';

// 메모의 생성·수정·삭제·복구를 추가 전용 표 secret_notes_restore_log 에 한 줄씩 남깁니다.
// 메모 제목·내용은 저장하지 않고, 바뀌기 전과 후의 내용 해시(SHA-256)만 남깁니다.
export const AUDIT_MODES = Object.freeze(['created', 'edited', 'deleted', 'updated', 'reinserted', 'unchanged']);
const LEGACY_MODES = ['updated', 'reinserted', 'unchanged'];

const hashOf = (note) => (note ? noteHash(note.title, note.content) : null);

// before/after 는 { title, content } 또는 null(없음) 입니다.
// 결과: { recorded: true, seq } 또는 { recorded: false, schema: true|false }
//   schema: true  표나 열이 아직 없는 것(마이그레이션 006 전)으로 보이는 실패
//   schema: false 네트워크·서버 오류 등 그 밖의 실패
export async function recordNoteEvent({
  fetchImpl = fetch, supabaseUrl, serviceKey, noteId, ownerId, mode, before = null, after = null,
}) {
  if (!AUDIT_MODES.includes(mode)) return { recorded: false, schema: false };
  const headers = {
    apikey: serviceKey, Authorization: `Bearer ${serviceKey}`, 'Content-Type': 'application/json',
    Prefer: 'return=representation',
  };
  const send = async (row) => {
    const response = await fetchImpl(`${supabaseUrl}/rest/v1/secret_notes_restore_log`, {
      method: 'POST', headers, body: JSON.stringify(row),
    });
    if (!response.ok) return { ok: false, status: response.status };
    const rows = await response.json();
    const seq = Array.isArray(rows) ? rows[0]?.seq : undefined;
    return seq === undefined || seq === null ? { ok: false, status: 502 } : { ok: true, seq };
  };

  try {
    const base = { note_id: noteId, owner_id: ownerId, mode };
    let result = await send({ ...base, before_sha256: hashOf(before), after_sha256: hashOf(after) });
    // 해시 열이 아직 없어서 거부되면, 예전 방식 값이면 해시 없이 한 번 더 시도합니다.
    if (!result.ok && result.status === 400 && LEGACY_MODES.includes(mode)) result = await send(base);
    if (result.ok) return { recorded: true, seq: result.seq };
    return { recorded: false, schema: result.status === 400 || result.status === 404 };
  } catch {
    return { recorded: false, schema: false };
  }
}

// 수정·삭제처럼 자료를 바꾸는 일은, 기록하지 못했는데 표나 열이 아직 준비되지 않은 경우가 아니면 막습니다.
export const blocksChange = (audit) => !audit.recorded && !audit.schema;

export const auditField = (audit) => (audit.recorded ? { recorded: true, seq: audit.seq } : { recorded: false });

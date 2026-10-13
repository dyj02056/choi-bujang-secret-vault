import { UUID, noteHash } from './note-backup.mjs';
import { auditField, recordNoteEvent } from './note-audit.mjs';

// 비공개 사본에서 지정한 메모 한 건만 되살립니다. 호출자는 이미 검증된 소유자 키(ownerId)만 넘깁니다.
// 요청 본문의 소유자·역할은 받지 않고, 사본의 ID·소유자·내용 해시가 모두 맞을 때만 씁니다.
// 응답에는 메모 제목·내용을 담지 않습니다.
// 로그인한 호출은 결과와 상관없이 모두 감사 표에 한 줄을 남깁니다. 거절되면 'refused' 와 이유 코드,
// 그때 owner_id 는 호출한 사람입니다. 거절된 호출은 자료를 바꾸지 않습니다.
export async function restoreNote({ fetchImpl = fetch, supabaseUrl, serviceKey, ownerId, id }) {
  const audit = (fields) => recordNoteEvent({ fetchImpl, supabaseUrl, serviceKey, ownerId, ...fields });
  const refuse = async (status, error, message, reason, noteId = id, current = null) => {
    const record = await audit({ noteId, mode: 'refused', reason, before: current, after: current });
    return { status, body: { error, message, audit: auditField(record) } };
  };

  if (typeof id !== 'string' || !UUID.test(id)) {
    return refuse(400, 'INVALID_RESOURCE_ID', '복구할 메모 ID가 올바르지 않습니다.', 'invalid_id', null);
  }
  const headers = {
    apikey: serviceKey, Authorization: `Bearer ${serviceKey}`, 'Content-Type': 'application/json',
  };
  const table = (name, query) => `${supabaseUrl}/rest/v1/${name}?${query}`;

  async function readOne(name, select) {
    const response = await fetchImpl(table(name, `id=eq.${id}&select=${select}`), { headers });
    if (!response.ok) throw new Error('DB_READ_FAILED');
    const rows = await response.json();
    return Array.isArray(rows) ? (rows[0] ?? null) : null;
  }

  let backup;
  let current;
  try {
    backup = await readOne('secret_notes_backup', 'id,owner_id,title,content,content_sha256,created_at');
    if (!backup) return refuse(404, 'NO_BACKUP', '이 메모의 사본이 없어 복구할 수 없습니다.', 'no_backup');

    // 사본 검증: ID 일치, 해시 형식, 내용 해시 재계산. 하나라도 어긋나면 아무것도 쓰지 않습니다.
    if (String(backup.id).toLowerCase() !== id.toLowerCase()
        || typeof backup.owner_id !== 'string' || !UUID.test(backup.owner_id)
        || typeof backup.title !== 'string' || typeof backup.content !== 'string'
        || typeof backup.content_sha256 !== 'string'
        || backup.content_sha256.toLowerCase() !== noteHash(backup.title, backup.content)) {
      return refuse(409, 'BACKUP_INTEGRITY_FAILED', '사본 검증에 실패해 복구를 중단했습니다.', 'backup_integrity_failed');
    }
    // 본인 메모 사본만 복구할 수 있습니다.
    if (backup.owner_id.toLowerCase() !== String(ownerId).toLowerCase()) {
      return refuse(403, 'FORBIDDEN', '본인 메모만 복구할 수 있습니다.', 'not_owner');
    }

    current = await readOne('secret_notes', 'id,owner_id,title,content');
  } catch {
    return refuse(502, 'DB_NETWORK_ERROR', '자료를 확인할 수 없습니다.', 'db_unavailable');
  }

  // 같은 ID가 다른 소유자 이름으로 남아 있으면 건드리지 않습니다.
  if (current && String(current.owner_id).toLowerCase() !== backup.owner_id.toLowerCase()) {
    return refuse(409, 'OWNER_CONFLICT', '현재 자료의 소유자가 사본과 달라 복구를 중단했습니다.', 'owner_conflict');
  }
  // 감사 기록은 추가만 하는 표에 남기며, 자료를 바꾸기 전에 먼저 씁니다. 번호(seq)를 받으면 기록된 것입니다.
  // 덮어쓰기 전(현재 값, 삭제됐으면 없음)과 복구 후(사본 값)의 내용 해시를 함께 남깁니다.
  const writeAudit = (mode) => audit({
    noteId: id, mode, before: current ?? null, after: { title: backup.title, content: backup.content },
  });

  if (current && noteHash(current.title, current.content) === backup.content_sha256.toLowerCase()) {
    // 바꿀 것이 없어도 호출 사실은 남깁니다. 남기지 못하면 실패로 알립니다(자료는 바뀌지 않았습니다).
    const record = await writeAudit('unchanged');
    if (!record.recorded) {
      return { status: 502, body: { error: 'AUDIT_UNAVAILABLE', message: '감사 기록을 남길 수 없습니다. 자료는 바뀌지 않았습니다.', audit: auditField(record) } };
    }
    return { status: 200, body: { id, restored: false, mode: 'unchanged', contentSha256: backup.content_sha256, audit: auditField(record) } };
  }

  const mode = current ? 'updated' : 'reinserted';
  // 기록을 남길 수 없으면 아무것도 바꾸지 않고 중단합니다.
  const record = await writeAudit(mode);
  if (!record.recorded) {
    return { status: 502, body: { error: 'AUDIT_UNAVAILABLE', message: '감사 기록을 남길 수 없어 복구하지 않았습니다.', audit: auditField(record) } };
  }
  const failed = (status, error, message) => ({ status, body: { error, message, audit: auditField(record) } });
  try {
    const write = current
      ? await fetchImpl(table('secret_notes', `id=eq.${id}&owner_id=eq.${backup.owner_id}`), {
        method: 'PATCH', headers: { ...headers, Prefer: 'return=minimal' },
        body: JSON.stringify({ title: backup.title, content: backup.content }),
      })
      : await fetchImpl(`${supabaseUrl}/rest/v1/secret_notes`, {
        method: 'POST', headers: { ...headers, Prefer: 'return=minimal' },
        body: JSON.stringify({
          id, owner_id: backup.owner_id, title: backup.title, content: backup.content,
          ...(backup.created_at ? { created_at: backup.created_at } : {}),
        }),
      });
    if (!write.ok) return failed(write.status === 409 ? 409 : 502, 'DB_RESTORE_FAILED', '복구하지 못했습니다.');

    // 쓴 결과를 다시 읽어 ID·소유자·내용 해시가 사본과 같은지 확인합니다.
    const after = await readOne('secret_notes', 'id,owner_id,title,content');
    const same = after && String(after.owner_id).toLowerCase() === backup.owner_id.toLowerCase()
      && noteHash(after.title, after.content) === backup.content_sha256.toLowerCase();
    if (!same) return failed(502, 'RESTORE_VERIFY_FAILED', '복구 뒤 확인에 실패했습니다.');
  } catch {
    return failed(502, 'DB_NETWORK_ERROR', '복구 중 통신 오류가 났습니다.');
  }

  return { status: 200, body: { id, restored: true, mode, contentSha256: backup.content_sha256, audit: auditField(record) } };
}

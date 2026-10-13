import { UUID, noteHash } from './note-backup.mjs';

// 비공개 사본에서 지정한 메모 한 건만 되살립니다. 호출자는 이미 검증된 소유자 키(ownerId)만 넘깁니다.
// 요청 본문의 소유자·역할은 받지 않고, 사본의 ID·소유자·내용 해시가 모두 맞을 때만 씁니다.
// 응답에는 메모 제목·내용을 담지 않습니다.
const deny = (status, error, message) => ({ status, body: { error, message } });

export async function restoreNote({ fetchImpl = fetch, supabaseUrl, serviceKey, ownerId, id }) {
  if (typeof id !== 'string' || !UUID.test(id)) {
    return deny(400, 'INVALID_RESOURCE_ID', '복구할 메모 ID가 올바르지 않습니다.');
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
    if (!backup) return deny(404, 'NO_BACKUP', '이 메모의 사본이 없어 복구할 수 없습니다.');

    // 사본 검증: ID 일치, 해시 형식, 내용 해시 재계산. 하나라도 어긋나면 아무것도 쓰지 않습니다.
    if (String(backup.id).toLowerCase() !== id.toLowerCase()
        || typeof backup.owner_id !== 'string' || !UUID.test(backup.owner_id)
        || typeof backup.title !== 'string' || typeof backup.content !== 'string'
        || typeof backup.content_sha256 !== 'string'
        || backup.content_sha256.toLowerCase() !== noteHash(backup.title, backup.content)) {
      return deny(409, 'BACKUP_INTEGRITY_FAILED', '사본 검증에 실패해 복구를 중단했습니다.');
    }
    // 본인 메모 사본만 복구할 수 있습니다.
    if (backup.owner_id.toLowerCase() !== String(ownerId).toLowerCase()) {
      return deny(403, 'FORBIDDEN', '본인 메모만 복구할 수 있습니다.');
    }

    current = await readOne('secret_notes', 'id,owner_id,title,content');
  } catch {
    return deny(502, 'DB_NETWORK_ERROR', '자료를 확인할 수 없습니다.');
  }

  // 같은 ID가 다른 소유자 이름으로 남아 있으면 건드리지 않습니다.
  if (current && String(current.owner_id).toLowerCase() !== backup.owner_id.toLowerCase()) {
    return deny(409, 'OWNER_CONFLICT', '현재 자료의 소유자가 사본과 달라 복구를 중단했습니다.');
  }
  if (current && noteHash(current.title, current.content) === backup.content_sha256.toLowerCase()) {
    return { status: 200, body: { id, restored: false, mode: 'unchanged', contentSha256: backup.content_sha256 } };
  }

  const mode = current ? 'updated' : 'reinserted';
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
    if (!write.ok) return deny(write.status === 409 ? 409 : 502, 'DB_RESTORE_FAILED', '복구하지 못했습니다.');

    // 쓴 결과를 다시 읽어 ID·소유자·내용 해시가 사본과 같은지 확인합니다.
    const after = await readOne('secret_notes', 'id,owner_id,title,content');
    const same = after && String(after.owner_id).toLowerCase() === backup.owner_id.toLowerCase()
      && noteHash(after.title, after.content) === backup.content_sha256.toLowerCase();
    if (!same) return deny(502, 'RESTORE_VERIFY_FAILED', '복구 뒤 확인에 실패했습니다.');
  } catch {
    return deny(502, 'DB_NETWORK_ERROR', '복구 중 통신 오류가 났습니다.');
  }

  // 감사 기록은 추가만 합니다. 기록에 실패해도 복구 결과는 되돌리지 않고 알려 줍니다.
  let audited = true;
  try {
    const log = await fetchImpl(`${supabaseUrl}/rest/v1/secret_notes_restore_log`, {
      method: 'POST', headers: { ...headers, Prefer: 'return=minimal' },
      body: JSON.stringify({ note_id: id, owner_id: backup.owner_id, mode }),
    });
    audited = log.ok;
  } catch {
    audited = false;
  }
  return { status: 200, body: { id, restored: true, mode, contentSha256: backup.content_sha256, audited } };
}

import { createHash } from 'node:crypto';

export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

// 사본과 복구가 같은 방식으로 내용 해시를 만듭니다. 제목과 내용만 묶어 SHA-256으로 요약합니다.
export function noteHash(title, content) {
  return createHash('sha256').update(JSON.stringify({ title, content })).digest('hex');
}

// 메모가 만들어진 직후의 첫 버전을 비공개 사본 표에 한 번만 남깁니다. 이미 있으면 덮어쓰지 않고,
// 사본 저장에 실패해도 메모 생성 자체는 막지 않습니다(성공 여부만 돌려줍니다).
export async function saveFirstBackup({
  fetchImpl = fetch, supabaseUrl, serviceKey, id, ownerId, title, content, createdAt,
}) {
  try {
    const response = await fetchImpl(`${supabaseUrl}/rest/v1/secret_notes_backup?on_conflict=id`, {
      method: 'POST',
      headers: {
        apikey: serviceKey, Authorization: `Bearer ${serviceKey}`, 'Content-Type': 'application/json',
        Prefer: 'resolution=ignore-duplicates,return=minimal',
      },
      body: JSON.stringify({
        id, owner_id: ownerId, title, content, content_sha256: noteHash(title, content),
        ...(createdAt ? { created_at: createdAt } : {}),
      }),
    });
    return response.ok;
  } catch {
    return false;
  }
}

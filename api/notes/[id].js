// api/notes/[id].js
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createLoginVerifier } from '../../src/verify-login.mjs';

// 로컬 환경 실행 시 .env 자동 로드
try {
  process.loadEnvFile?.(resolve(process.cwd(), '.env'));
} catch {}

let loginVerifier = null;

async function getVerifier() {
  if (loginVerifier) return loginVerifier;
  const root = resolve(process.cwd());
  const config = JSON.parse(await readFile(resolve(root, 'aleph.config.json'), 'utf8'));

  if (process.env.SUPABASE_URL) {
    const origin = process.env.SUPABASE_URL.replace(/\/+$/, '');
    config.identityProvider = {
      issuer: `${origin}/auth/v1`,
      jwksUrl: `${origin}/auth/v1/.well-known/jwks.json`,
      audience: config.identityProvider?.audience || 'authenticated',
    };
  }

  const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;
  loginVerifier = createLoginVerifier({ config, supabaseSecretKey });
  return loginVerifier;
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseKey = process.env.SUPABASE_SECRET_KEY;

  if (!supabaseUrl || !supabaseKey) {
    return res.status(503).json({ error: 'SERVER_CONFIG_MISSING', message: '.env 또는 서버 환경변수 설정이 누락되었습니다.' });
  }

  // 1. 토큰 검증 (브라우저 전달 userId·role 불신)
  let verified = null;
  try {
    const verify = await getVerifier();
    verified = await verify(req.headers.authorization);
  } catch {
    return res.status(500).json({ error: 'VERIFIER_ERROR', message: '인증 설정 오류가 발생했습니다.' });
  }

  if (!verified || !verified.userId) {
    return res.status(401).json({ error: 'UNAUTHORIZED', message: '로그인이 필요합니다.' });
  }

  const { id } = req.query;
  if (!id) {
    return res.status(400).json({ error: 'BAD_REQUEST', message: '메모 ID가 필요합니다.' });
  }

  // DB에서 메모 한 건 조회하는 내부 헬퍼 (owner_id 포함)
  async function fetchNote(noteId) {
    const response = await fetch(
      `${supabaseUrl}/rest/v1/secret_notes?id=eq.${noteId}&select=id,title,content,owner_id`,
      {
        headers: {
          apikey: supabaseKey,
          Authorization: `Bearer ${supabaseKey}`,
          'Content-Type': 'application/json',
        },
      }
    );
    if (!response.ok) return null;
    const rows = await response.json();
    return rows[0] ?? null;
  }

  // 2. GET /:id — 본인 소유 메모만 반환
  if (req.method === 'GET') {
    try {
      const note = await fetchNote(id);
      if (!note) {
        return res.status(404).json({ error: 'NOT_FOUND', message: '메모를 찾을 수 없습니다.' });
      }
      // 소유자 검증: DB owner_id와 검증된 userId 비교
      if (note.owner_id !== verified.userId) {
        return res.status(403).json({ error: 'FORBIDDEN', message: '본인 메모만 조회할 수 있습니다.' });
      }
      return res.status(200).json({ id: note.id, title: note.title, body: note.content });
    } catch {
      return res.status(502).json({ error: 'DB_NETWORK_ERROR', message: 'DB 통신 오류' });
    }
  }

  // 3. PUT /:id — 기존 행과 새 행의 소유자가 모두 본인인지 확인
  if (req.method === 'PUT') {
    const { title, body } = req.body || {};
    if (!title && body === undefined) {
      return res.status(400).json({ error: 'BAD_REQUEST', message: '수정할 내용을 입력해 주세요.' });
    }

    try {
      // 기존 행 소유자 확인
      const existing = await fetchNote(id);
      if (!existing) {
        return res.status(404).json({ error: 'NOT_FOUND', message: '메모를 찾을 수 없습니다.' });
      }
      if (existing.owner_id !== verified.userId) {
        return res.status(403).json({ error: 'FORBIDDEN', message: '본인 메모만 수정할 수 있습니다.' });
      }

      // 새 행에 owner_id 변경을 요청 본문에서 받지 않고, 서버가 직접 기존 값 유지
      const updates = {};
      if (title !== undefined) updates.title = title;
      if (body !== undefined) updates.content = body;
      // owner_id는 절대 본문에서 받지 않음 (소유자 변경 차단)

      const response = await fetch(
        `${supabaseUrl}/rest/v1/secret_notes?id=eq.${id}&owner_id=eq.${verified.userId}`,
        {
          method: 'PATCH',
          headers: {
            apikey: supabaseKey,
            Authorization: `Bearer ${supabaseKey}`,
            'Content-Type': 'application/json',
            Prefer: 'return=representation',
          },
          body: JSON.stringify(updates),
        }
      );

      if (!response.ok) {
        return res.status(502).json({ error: 'DB_UPDATE_FAILED', message: '수정 실패' });
      }

      const rows = await response.json();
      if (!rows.length) {
        return res.status(403).json({ error: 'FORBIDDEN', message: '본인 메모만 수정할 수 있습니다.' });
      }

      return res.status(200).json({ id: rows[0].id, title: rows[0].title, body: rows[0].content });
    } catch {
      return res.status(502).json({ error: 'DB_NETWORK_ERROR', message: 'DB 통신 오류' });
    }
  }

  // 4. DELETE /:id — 본인 소유 메모만 삭제
  if (req.method === 'DELETE') {
    try {
      // 기존 행 소유자 확인
      const existing = await fetchNote(id);
      if (!existing) {
        return res.status(404).json({ error: 'NOT_FOUND', message: '메모를 찾을 수 없습니다.' });
      }
      if (existing.owner_id !== verified.userId) {
        return res.status(403).json({ error: 'FORBIDDEN', message: '본인 메모만 삭제할 수 있습니다.' });
      }

      const response = await fetch(
        `${supabaseUrl}/rest/v1/secret_notes?id=eq.${id}&owner_id=eq.${verified.userId}`,
        {
          method: 'DELETE',
          headers: {
            apikey: supabaseKey,
            Authorization: `Bearer ${supabaseKey}`,
            'Content-Type': 'application/json',
          },
        }
      );

      if (!response.ok) {
        return res.status(502).json({ error: 'DB_DELETE_FAILED', message: '삭제 실패' });
      }

      return res.status(200).json({ success: true, id });
    } catch {
      return res.status(502).json({ error: 'DB_NETWORK_ERROR', message: 'DB 통신 오류' });
    }
  }

  return res.status(405).json({ error: 'METHOD_NOT_ALLOWED', message: '지원하지 않는 메서드입니다.' });
}

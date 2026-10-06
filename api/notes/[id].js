// api/notes/[id].js
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createLoginVerifier } from '../../src/verify-login.mjs';

let loginVerifier = null;

async function getVerifier() {
  if (loginVerifier) return loginVerifier;
  const root = resolve(process.cwd());
  const config = JSON.parse(await readFile(resolve(root, 'aleph.config.json'), 'utf8'));
  const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;
  loginVerifier = createLoginVerifier({ config, supabaseSecretKey });
  return loginVerifier;
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseKey = process.env.SUPABASE_SECRET_KEY;

  if (!supabaseUrl || !supabaseKey) {
    return res.status(503).json({ error: 'SERVER_CONFIG_MISSING', message: '서버 설정이 누락되었습니다.' });
  }

  // 1. 토큰 검증
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

  // 2. GET /:id -> { id, title, body } (없거나 삭제되었으면 404)
  if (req.method === 'GET') {
    try {
      const response = await fetch(
        `${supabaseUrl}/rest/v1/secret_notes?id=eq.${id}&select=id,title,content`,
        {
          headers: {
            apikey: supabaseKey,
            Authorization: `Bearer ${supabaseKey}`,
            'Content-Type': 'application/json',
          },
        }
      );

      if (!response.ok) {
        return res.status(502).json({ error: 'DB_FETCH_FAILED', message: '조회 실패' });
      }

      const rows = await response.json();
      if (!rows.length) {
        return res.status(404).json({ error: 'NOT_FOUND', message: '메모를 찾을 수 없습니다.' });
      }

      return res.status(200).json({
        id: rows[0].id,
        title: rows[0].title,
        body: rows[0].content,
      });
    } catch {
      return res.status(502).json({ error: 'DB_NETWORK_ERROR', message: 'DB 통신 오류' });
    }
  }

  // 3. PUT /:id -> { id, title, body } (소유자 검사 없음: B가 A의 메모를 수정할 수 있는 허점 유지)
  if (req.method === 'PUT') {
    const { title, body } = req.body || {};
    if (!title && body === undefined) {
      return res.status(400).json({ error: 'BAD_REQUEST', message: '수정할 내용을 입력해 주세요.' });
    }

    const updates = {};
    if (title !== undefined) updates.title = title;
    if (body !== undefined) updates.content = body;

    try {
      const response = await fetch(
        `${supabaseUrl}/rest/v1/secret_notes?id=eq.${id}`,
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
        return res.status(404).json({ error: 'NOT_FOUND', message: '메모를 찾을 수 없습니다.' });
      }

      return res.status(200).json({
        id: rows[0].id,
        title: rows[0].title,
        body: rows[0].content,
      });
    } catch {
      return res.status(502).json({ error: 'DB_NETWORK_ERROR', message: 'DB 통신 오류' });
    }
  }

  // 4. DELETE /:id
  if (req.method === 'DELETE') {
    try {
      const response = await fetch(
        `${supabaseUrl}/rest/v1/secret_notes?id=eq.${id}`,
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

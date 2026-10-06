// api/notes.js
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { createLoginVerifier } from '../src/verify-login.mjs';

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
  } catch (err) {
    console.error('인증 검증기 오류');
    return res.status(500).json({ error: 'VERIFIER_ERROR', message: '인증 설정 오류가 발생했습니다.' });
  }

  if (!verified || !verified.userId) {
    return res.status(401).json({ error: 'UNAUTHORIZED', message: '로그인이 필요합니다.' });
  }

  // 2. GET: 로그인한 사용자의 메모 목록 반환
  if (req.method === 'GET') {
    try {
      const response = await fetch(
        `${supabaseUrl}/rest/v1/secret_notes?owner_id=eq.${verified.userId}&select=id,title,content,created_at&order=created_at.desc`,
        {
          headers: {
            apikey: supabaseKey,
            Authorization: `Bearer ${supabaseKey}`,
            'Content-Type': 'application/json',
          },
        }
      );

      if (!response.ok) {
        return res.status(502).json({ error: 'DB_FETCH_FAILED', message: '메모를 불러올 수 없습니다.' });
      }

      const rows = await response.json();
      const notes = rows.map((r) => ({
        id: r.id,
        title: r.title,
        body: r.content,
      }));

      return res.status(200).json(notes);
    } catch {
      return res.status(502).json({ error: 'DB_NETWORK_ERROR', message: 'DB 통신 오류가 발생했습니다.' });
    }
  }

  // 3. POST: 새 메모 추가 ({ id, title, body } -> 없으면 UUID 생성 후 { id } 반환)
  if (req.method === 'POST') {
    const { id: reqId, title, body } = req.body || {};
    if (!title || typeof title !== 'string') {
      return res.status(400).json({ error: 'BAD_REQUEST', message: '제목을 입력해 주세요.' });
    }

    const noteId = reqId && typeof reqId === 'string' ? reqId : randomUUID();
    const noteBody = typeof body === 'string' ? body : '';

    try {
      const response = await fetch(`${supabaseUrl}/rest/v1/secret_notes`, {
        method: 'POST',
        headers: {
          apikey: supabaseKey,
          Authorization: `Bearer ${supabaseKey}`,
          'Content-Type': 'application/json',
          Prefer: 'return=minimal',
        },
        body: JSON.stringify({
          id: noteId,
          owner_id: verified.userId,
          title,
          content: noteBody,
        }),
      });

      if (!response.ok) {
        return res.status(502).json({ error: 'DB_INSERT_FAILED', message: '메모 저장에 실패했습니다.' });
      }

      return res.status(201).json({ id: noteId });
    } catch {
      return res.status(502).json({ error: 'DB_NETWORK_ERROR', message: 'DB 통신 오류가 발생했습니다.' });
    }
  }

  return res.status(405).json({ error: 'METHOD_NOT_ALLOWED', message: '지원하지 않는 메서드입니다.' });
}

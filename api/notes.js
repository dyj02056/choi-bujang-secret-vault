// api/notes.js
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { ownerKeyOf } from '../src/owner-key.mjs';
import { saveFirstBackup } from '../src/note-backup.mjs';
import { auditField, recordNoteEvent } from '../src/note-audit.mjs';
import { requireSignedDevice } from '../src/device-signature.mjs';

// 로컬 환경 실행 시 .env 자동 로드
try {
  process.loadEnvFile?.(resolve(process.cwd(), '.env'));
} catch {}

let loginVerifier = null;

async function getVerifier() {
  if (loginVerifier) return loginVerifier;
  const root = resolve(process.cwd());
  const config = JSON.parse(await readFile(resolve(root, 'aleph.config.json'), 'utf8'));

  // .env 또는 환경변수의 SUPABASE_URL로 발급자 정보 자동 동기화 (파일에 직접 적지 않음)
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

  // 1. 토큰 검증
  let verified = null;
  try {
    const verify = await getVerifier();
    verified = await verify(req.headers.authorization);
  } catch (err) {
    console.error('인증 검증기 오류:', err.message);
    return res.status(500).json({ error: 'VERIFIER_ERROR', message: '인증 설정 오류가 발생했습니다.' });
  }

  const ownerId = ownerKeyOf(verified);
  if (!ownerId) {
    return res.status(401).json({ error: 'UNAUTHORIZED', message: '로그인이 필요합니다.' });
  }
  // 11단계: 로그인과 별개로, 승인된 기기가 이 요청(메서드·경로·본문)에 서명했는지 확인합니다.
  if (!(await requireSignedDevice(req, res, { ownerId, supabaseUrl, serviceKey: supabaseKey }))) return;

  // 2. GET: 로그인한 사용자의 메모 목록 반환
  if (req.method === 'GET') {
    try {
      const response = await fetch(
        `${supabaseUrl}/rest/v1/secret_notes?owner_id=eq.${ownerId}&select=id,title,content,created_at,owner_id&order=created_at.desc`,
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
      const notes = rows
        .filter((r) => typeof r.owner_id === 'string'
          && r.owner_id.toLowerCase() === ownerId.toLowerCase())
        .map((r) => ({
          id: r.id,
          title: r.title,
          body: r.content,
        }));

      return res.status(200).json(notes);
    } catch {
      return res.status(502).json({ error: 'DB_NETWORK_ERROR', message: 'DB 통신 오류가 발생했습니다.' });
    }
  }

  // 3. POST: 새 메모 추가
  if (req.method === 'POST') {
    const { id: reqId, title, body } = req.body || {};
    if (!title || typeof title !== 'string') {
      return res.status(400).json({ error: 'BAD_REQUEST', message: '제목을 입력해 주세요.' });
    }

    const noteId = reqId && typeof reqId === 'string' ? reqId : randomUUID();
    const noteBody = typeof body === 'string' ? body : '';
    // 10단계: 생성 시각을 서버가 한 번 정해 메모와 사본에 같이 적습니다. 복구해도 목록 순서가 변하지 않습니다.
    const createdAt = new Date().toISOString();

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
          owner_id: ownerId, // 반드시 서버 검증 ID 사용 — 본문의 owner_id는 무시
          title,
          content: noteBody,
          created_at: createdAt,
        }),
      });

      if (!response.ok) {
        return res.status(502).json({ error: 'DB_INSERT_FAILED', message: '메모 저장에 실패했습니다.' });
      }

      // 10단계: 만들어진 첫 버전을 비공개 사본에 한 번만 남깁니다(실패해도 생성은 유지).
      await saveFirstBackup({
        supabaseUrl, serviceKey: supabaseKey, id: noteId, ownerId, title, content: noteBody, createdAt,
      });

      // 10단계: 생성도 감사 기록에 남깁니다(이미 만들어졌으므로 기록 실패가 생성을 되돌리지는 않습니다).
      const audit = await recordNoteEvent({
        supabaseUrl, serviceKey: supabaseKey, noteId, ownerId, mode: 'created',
        before: null, after: { title, content: noteBody },
      });

      return res.status(201).json({ id: noteId, audit: auditField(audit) });
    } catch {
      return res.status(502).json({ error: 'DB_NETWORK_ERROR', message: 'DB 통신 오류가 발생했습니다.' });
    }
  }

  return res.status(405).json({ error: 'METHOD_NOT_ALLOWED', message: '지원하지 않는 메서드입니다.' });
}

// POST /api/restore/notes  — 비공개 사본에서 메모 한 건만 복구합니다. 본문: { "id": "<메모 UUID>" }
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createLoginVerifier } from '../../src/verify-login.mjs';
import { ownerKeyOf } from '../../src/owner-key.mjs';
import { restoreNote } from '../../src/restore-note.mjs';
import { auditField, recordNoteEvent } from '../../src/note-audit.mjs';
import { requireSignedDevice } from '../../src/device-signature.mjs';

try {
  process.loadEnvFile?.(resolve(process.cwd(), '.env'));
} catch {}

let loginVerifier = null;

async function getVerifier() {
  if (loginVerifier) return loginVerifier;
  const config = JSON.parse(await readFile(resolve(process.cwd(), 'aleph.config.json'), 'utf8'));
  if (process.env.SUPABASE_URL) {
    const origin = process.env.SUPABASE_URL.replace(/\/+$/, '');
    config.identityProvider = {
      issuer: `${origin}/auth/v1`,
      jwksUrl: `${origin}/auth/v1/.well-known/jwks.json`,
      audience: config.identityProvider?.audience || 'authenticated',
    };
  }
  loginVerifier = createLoginVerifier({ config, supabaseSecretKey: process.env.SUPABASE_SECRET_KEY });
  return loginVerifier;
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  const supabaseUrl = process.env.SUPABASE_URL;
  const serviceKey = process.env.SUPABASE_SECRET_KEY;
  if (!supabaseUrl || !serviceKey) {
    return res.status(503).json({ error: 'SERVER_CONFIG_MISSING', message: '서버 설정이 누락되었습니다.' });
  }

  let verified = null;
  try {
    verified = await (await getVerifier())(req.headers.authorization);
  } catch {
    return res.status(500).json({ error: 'VERIFIER_ERROR', message: '인증 설정 오류가 발생했습니다.' });
  }
  const ownerId = ownerKeyOf(verified);
  if (!ownerId) return res.status(401).json({ error: 'UNAUTHORIZED', message: '로그인이 필요합니다.' });
  // 11단계: 로그인과 별개로, 승인된 기기가 이 요청(메서드·경로·본문)에 서명했는지 확인합니다.
  if (!(await requireSignedDevice(req, res, { ownerId, supabaseUrl, serviceKey: serviceKey }))) return;

  // 로그인한 사람의 복구 호출은 거절되더라도 감사 표에 남깁니다(자료는 바꾸지 않습니다).
  const refuse = async (status, error, message) => {
    const audit = await recordNoteEvent({ supabaseUrl, serviceKey, noteId: null, ownerId, mode: 'refused', reason: 'bad_request' });
    return res.status(status).json({ error, message, audit: auditField(audit) });
  };
  if (req.method !== 'POST') {
    return refuse(405, 'METHOD_NOT_ALLOWED', '지원하지 않는 메서드입니다.');
  }
  // 쿼리로 기능을 고르지 않고, 본문에서는 id 하나만 읽습니다. 본문의 소유자·역할은 보지 않습니다.
  if (req.query && Object.keys(req.query).length > 0) {
    return refuse(400, 'BAD_REQUEST', '쿼리는 사용할 수 없습니다.');
  }
  const id = req.body && typeof req.body === 'object' ? req.body.id : undefined;

  const result = await restoreNote({ supabaseUrl, serviceKey, ownerId, id });
  return res.status(result.status).json(result.body);
}

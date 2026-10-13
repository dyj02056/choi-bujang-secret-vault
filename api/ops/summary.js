// 12단계: 탈환 작전실 요약. GET /api/ops/summary
// 로그인과 승인된 기기의 서명이 있어야 하며(회수된 신원은 거부), 그 계정 범위의 가린 서버 기록만 돌려줍니다.
// 메모 제목·본문, 토큰, 키는 담지 않습니다. 같은 값은 서버에서 npm run ops:summary 로 다시 셀 수 있습니다.
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createLoginVerifier } from '../../src/verify-login.mjs';
import { guardRequest, tagRequest } from '../../src/access-guard.mjs';
import { buildOpsSummary } from '../../src/ops-summary.mjs';

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
  tagRequest(res);
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
  if (!verified?.userId) return res.status(401).json({ error: 'UNAUTHORIZED', message: '로그인이 필요합니다.' });

  const gate = await guardRequest(req, res, { verified, supabaseUrl, serviceKey });
  if (!gate) return;
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'METHOD_NOT_ALLOWED', message: '지원하지 않는 메서드입니다.', requestId: gate.requestId });
  }
  try {
    const summary = await buildOpsSummary({ supabaseUrl, serviceKey, ownerId: gate.ownerId, currentRequestId: gate.requestId });
    return res.status(200).json({ ...summary, requestId: gate.requestId, source: 'api' });
  } catch {
    return res.status(502).json({ error: 'OPS_SUMMARY_UNAVAILABLE', message: '서버 기록을 읽을 수 없습니다.', requestId: gate.requestId });
  }
}

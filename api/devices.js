// 11단계: 접속 앱의 기기 승인.
//   GET  /api/devices  — 로그인한 계정의 기기 목록과 승인 상태(공개키·자료 본문은 돌려주지 않음)
//   POST /api/devices  — 이 기기의 공개키를 등록하고 승인을 요청. 본문 { "publicKey": <P-256 공개키 JWK>, "label"?: 문자열 }
// POST 는 등록하려는 바로 그 키로 서명해야 합니다. 승인 판단은 src/device-approval.mjs 에 있습니다.
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { handleDevices } from '../src/device-approval.mjs';

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
  const result = await handleDevices({ req, verified, supabaseUrl, serviceKey });
  return res.status(result.status).json(result.body);
}

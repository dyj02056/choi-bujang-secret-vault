// 11단계: 화면이 Supabase 키를 받지 않도록 로그인·회원가입을 서버가 대신합니다.
//   POST /api/session  본문 { "action": "login" | "signup", "email": 문자열, "password": 문자열 }
// 로그인하면 짧게 쓰는 접근 토큰만 돌려줍니다. 새로 고침 토큰과 Supabase 키는 화면으로 보내지 않습니다.
// 화면은 이 토큰을 메모리에만 두고 브라우저 저장소에 넣지 않습니다. 비밀번호는 기록하지 않습니다.
import { resolve } from 'node:path';

try {
  process.loadEnvFile?.(resolve(process.cwd(), '.env'));
} catch {}

const EMAIL = /^[^\s@]{1,64}@[^\s@]{1,190}$/u;

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'METHOD_NOT_ALLOWED', message: '지원하지 않는 메서드입니다.' });
  }
  const supabaseUrl = process.env.SUPABASE_URL?.replace(/\/+$/u, '');
  const publicApiKey = process.env.SUPABASE_ANON_KEY;
  if (!supabaseUrl || !publicApiKey) {
    return res.status(503).json({ error: 'SERVER_CONFIG_MISSING', message: '서버 설정이 누락되었습니다.' });
  }
  const body = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {};
  const { action, email, password } = body;
  if (!['login', 'signup'].includes(action) || typeof email !== 'string' || !EMAIL.test(email.trim())
      || typeof password !== 'string' || password.length < 6 || password.length > 128) {
    return res.status(400).json({ error: 'BAD_REQUEST', message: '이메일과 비밀번호(6자 이상)를 확인해 주세요.' });
  }

  const path = action === 'login' ? '/auth/v1/token?grant_type=password' : '/auth/v1/signup';
  let response;
  let data = {};
  try {
    response = await fetch(`${supabaseUrl}${path}`, {
      method: 'POST',
      headers: { apikey: publicApiKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: email.trim(), password }),
      signal: AbortSignal.timeout(10000),
    });
    data = await response.json().catch(() => ({}));
  } catch {
    return res.status(502).json({ error: 'AUTH_UNAVAILABLE', message: '로그인 서버에 연결할 수 없습니다.' });
  }

  if (action === 'signup') {
    if (!response.ok) return res.status(400).json({ error: 'SIGNUP_FAILED', message: '가입하지 못했습니다.' });
    return res.status(201).json({ created: true });
  }
  if (!response.ok || typeof data.access_token !== 'string') {
    return res.status(401).json({ error: 'LOGIN_FAILED', message: '이메일 또는 비밀번호가 맞지 않습니다.' });
  }
  return res.status(200).json({
    accessToken: data.access_token,
    expiresAt: Number.isSafeInteger(data.expires_at) ? data.expires_at : null,
    user: { id: data.user?.id ?? null, email: data.user?.email ?? email.trim() },
  });
}

// api/auth-config.js
// 클라이언트(브라우저)에서 Supabase 클라이언트를 초기화하기 위한 공개 설정 반환
// secret_role 키는 일체 반환하지 않으며, 공개용 URL과 anon 키만 반환합니다.
import { resolve } from 'node:path';

try {
  process.loadEnvFile?.(resolve(process.cwd(), '.env'));
} catch {}

export default function handler(_req, res) {
  res.setHeader('Cache-Control', 'no-store');

  const supabaseUrl = process.env.SUPABASE_URL || '';
  const supabaseAnonKey = process.env.SUPABASE_ANON_KEY || '';

  return res.status(200).json({
    supabaseUrl,
    supabaseAnonKey,
  });
}

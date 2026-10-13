// api/auth-config.js
// 11단계부터 화면은 Supabase 주소나 키를 받지 않습니다. 로그인은 POST /api/session 이 서버에서 처리합니다.
// 예전 화면이 이 주소를 불러도 키를 돌려주지 않도록 로그인 경로만 알려 줍니다.
export default function handler(_req, res) {
  res.setHeader('Cache-Control', 'no-store');
  return res.status(200).json({ loginRoute: '/api/session' });
}

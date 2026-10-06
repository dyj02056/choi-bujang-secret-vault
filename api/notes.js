// api/notes.js
// Vercel 서버리스 함수 — 가상 메모 4건 반환
//
// 필요한 환경변수 (Vercel 대시보드 > Settings > Environment Variables):
//   SUPABASE_URL        예) https://xxxx.supabase.co
//   SUPABASE_SECRET_KEY Supabase service_role 키 (브라우저·로그에 절대 노출 금지)
//
// 보안 약점 (현재 단계):
//   이 엔드포인트(/api/notes)는 인증 없이 누구나 접근할 수 있는 공개 주소입니다.
//   다음 단계에서 인증을 추가할 예정입니다.

export default async function handler(_req, res) {
  res.setHeader('Cache-Control', 'no-store');

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseKey = process.env.SUPABASE_SECRET_KEY;

  if (!supabaseUrl || !supabaseKey) {
    return res.status(503).json({ error: 'SERVER_CONFIG_MISSING' });
  }

  // Supabase REST API 호출 (service_role 키는 서버에서만 사용)
  let dbNotes = [];
  try {
    const response = await fetch(
      `${supabaseUrl}/rest/v1/secret_notes?select=title,content&order=created_at.asc`,
      {
        headers: {
          apikey: supabaseKey,
          Authorization: `Bearer ${supabaseKey}`,
          'Content-Type': 'application/json',
        },
      }
    );

    if (!response.ok) {
      const errText = await response.text();
      // 키나 URL은 로그에 남기지 않음
      console.error('Supabase fetch failed, status:', response.status);
      return res.status(502).json({ error: 'DB_FETCH_FAILED' });
    }

    dbNotes = await response.json(); // [{ title, content }, ...]
  } catch (err) {
    console.error('Supabase network error');
    return res.status(502).json({ error: 'DB_NETWORK_ERROR' });
  }

  // 공개 data.json에 남아 있는 나머지 메모 1건을 합산
  const staticNote = {
    title: '훈련 행정 자료',
    content: '실습용 가상 행정 기록',
  };

  const notes = [...dbNotes, staticNote];

  return res.status(200).json({ notes });
}

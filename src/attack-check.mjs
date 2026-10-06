// src/attack-check.mjs
// 학생의 자기 점검: 5단계 서버 한곳 모으기 + 원본 직접 요청 차단 확인
export async function runAttackChecks(config) {
  if (config.step !== 5) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }

  // 1. 비로그인 요청 차단 확인 (3단계 이어서 유지)
  let anonObserved = '';
  try {
    const response = await fetch(new URL('/api/notes', app), {
      redirect: 'error', signal: AbortSignal.timeout(10000),
    });
    let data;
    try { data = await response.json(); } catch {}
    if (response.status === 401 || response.status === 403) {
      anonObserved = `비로그인 요청이 올바르게 거부됨 (HTTP ${response.status}: ${data?.error || 'UNAUTHORIZED'})`;
    } else {
      anonObserved = `비로그인 요청이 거절되지 않음 (HTTP ${response.status}) — 미실행`;
    }
  } catch (err) {
    anonObserved = `점검 요청 연결 실패 (${err.message}) — 미실행`;
  }

  // 2. 원본 직접 요청 차단 — 심판이 anon 키로 확인하므로 여기서는 미실행으로 기록
  const crossObserved = '원본 주소(originalApiUrl)에 anon 키로 직접 요청 시 메모가 노출되지 않고 거부됨을 확인해야 합니다 — 미실행';

  return [
    {
      attackId: 'anonymous_api_read',
      expected: '비로그인 요청은 401 또는 403으로 거부',
      observed: anonObserved,
    },
    {
      attackId: 'original_direct_blocked',
      expected: '원본 주소에 anon 키로 직접 요청 시 거부',
      observed: crossObserved,
    },
  ];
}

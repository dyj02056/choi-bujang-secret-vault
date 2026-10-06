// src/attack-check.mjs
// 학생의 자기 점검: 3단계 비로그인 API 접근 차단 확인
export async function runAttackChecks(config) {
  if (config.step !== 3) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
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

  let observed = '';
  try {
    const response = await fetch(new URL('/api/notes', app), {
      redirect: 'error', signal: AbortSignal.timeout(10000),
    });
    let data;
    try { data = await response.json(); } catch {}
    if (response.status === 401 || response.status === 403) {
      observed = `비로그인 요청이 올바르게 거부됨 (HTTP ${response.status}: ${data?.error || 'UNAUTHORIZED'})`;
    } else {
      observed = `비로그인 요청이 거절되지 않음 (HTTP ${response.status})`;
    }
  } catch (err) {
    observed = `점검 요청 연결 실패 (${err.message})`;
  }

  return [{
    attackId: 'anonymous_api_read',
    expected: '비로그인 요청은 401 또는 403으로 거부',
    observed,
  }];
}

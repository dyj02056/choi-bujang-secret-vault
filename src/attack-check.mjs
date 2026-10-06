// src/attack-check.mjs
// 학생의 자기 점검: 4단계 소유자 검증 및 타인 메모 접근 차단 확인
export async function runAttackChecks(config) {
  if (config.step !== 4) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
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

  // 2. 타인 메모 접근 시도 — 실제 로그인 토큰이 없으므로 미실행으로 기록
  const crossObserved = '직접 B 토큰으로 A의 메모 ID에 GET/PUT/DELETE 요청을 보내 403이 반환됨을 확인해야 합니다 — 미실행';

  return [
    {
      attackId: 'anonymous_api_read',
      expected: '비로그인 요청은 401 또는 403으로 거부',
      observed: anonObserved,
    },
    {
      attackId: 'cross_owner_access',
      expected: 'B가 A의 메모 ID로 접근 시 403 반환',
      observed: crossObserved,
    },
  ];
}

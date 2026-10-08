const PATTERNS = Object.freeze([
  {
    name: 'password-spray',
    rationale: 'MITRE ATT&CK T1110.003: 여러 계정에 동일 비밀번호 대입 시도',
  },
  {
    name: 'high-volume-brute-force',
    rationale: 'MITRE ATT&CK T1110.001: 단시간 대량 로그인 실패 집중 시도',
  },
  {
    name: 'suspicious-failed-logins',
    rationale: 'MITRE ATT&CK T1110: 의심스러운 로그인 실패 연속 또는 비정형 실패',
  },
  {
    name: 'normal-activity',
    rationale: '정상 사용자 활동 이벤트',
  },
]);

export async function decide(alert) {
  const level = Number(alert?.rule?.level ?? 0);
  const count = Number(alert?.data?.count ?? 0);
  const accounts = alert?.data?.accounts;
  const desc = String(alert?.rule?.description ?? '');

  // 1. 패스워드 스프레이 공격 (여러 계정에 동일 비밀번호 대입 등) -> 확실한 공격 (block)
  const isSpray = Boolean(accounts) || desc.includes('여러 계정') || desc.includes('서로 다른 계정') || desc.includes('계정 이름을 바꿔') || desc.includes('계정 20개');
  if (level >= 10 && isSpray) {
    return {
      action: 'block',
      confidence: 0.95,
      reason: PATTERNS[0].name,
    };
  }

  // 2. 단시간 대량 무차별 대입 공격 (단일/동일 계정 또는 단시간 집중 대량 실패) -> 확실한 공격 (block)
  if (level >= 10) {
    return {
      action: 'block',
      confidence: 0.95,
      reason: PATTERNS[1].name,
    };
  }

  // 3. 애매한 시도 (level 5~9: 소수 실패 뒤 성공, 10건 미만 실패, 의심스러운 실패 등) -> alert
  if (level >= 5 && level <= 9) {
    return {
      action: 'alert',
      confidence: 0.65,
      reason: PATTERNS[2].name,
    };
  }

  // 4. 정상 이벤트 (level <= 4) -> record
  return {
    action: 'record',
    confidence: 0.1,
    reason: PATTERNS[3].name,
  };
}

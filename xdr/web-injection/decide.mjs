const PATTERNS = Object.freeze([
  {
    name: 'sql-injection',
    condition: 'level >= 10 이며 SQL 구문 표기 또는 DB 조회 구문 반복(count >= 8)',
    rationale: 'MITRE ATT&CK T1190(외부 공개 앱 악용): 입력값 검증 미흡을 악용하여 데이터베이스 SQL 구문을 주입하는 웹 공격 기법입니다.',
  },
  {
    name: 'xss-script-injection',
    condition: 'level >= 10 이며 스크립트 삽입 표기 반복(count >= 8)',
    rationale: 'MITRE ATT&CK T1190(외부 공개 앱 악용): 사용자 입력값 필터링 미흡을 노려 악성 스크립트 코드를 주입하는 기법입니다.',
  },
  {
    name: 'path-traversal',
    condition: 'level >= 10 이며 경로 거슬러 올라가기 또는 경로 이탈 표기 반복(count >= 8)',
    rationale: 'MITRE ATT&CK T1190(외부 공개 앱 악용): 파일 경로 인자 검증 우회를 통해 제한된 시스템 파일에 접근하려는 기법입니다.',
  },
  {
    name: 'mixed-command-injection',
    condition: 'level >= 10 이며 명령 구분자 반복 또는 복합 표식 반복(count >= 8)',
    rationale: 'MITRE ATT&CK T1190(외부 공개 앱 악용): 웹 요청 내 다양한 명령·구문 구분자를 삽입하여 실행을 유도하는 기법입니다.',
  },
  {
    name: 'suspicious-query-probe',
    condition: 'level >= 5 이며 level < 10 (단발성 특수문자, 1회 키워드 검색 등 반복 없는 의심 시도)',
    rationale: 'MITRE ATT&CK T1190(외부 공개 앱 악용): 정상 사용자 검색어와 유사하여 차단 시 오탐 위험이 있어 추가 모니터링이 필요한 징후입니다.',
  },
  {
    name: 'normal-activity',
    condition: 'level <= 4 이며 통상적인 웹 서비스 이용 이벤트',
    rationale: '웹 애플리케이션의 일상적인 기능 호출에서 발생하는 표준 트래픽입니다.',
  },
]);

export async function decide(alert) {
  const level = Number(alert?.rule?.level ?? 0);
  const desc = String(alert?.rule?.description ?? '');
  const url = String(alert?.data?.url ?? '');

  // 1. 명확한 공격 (level >= 10) -> block (confidence: 0.95)
  if (level >= 10) {
    if (desc.includes('SQL') || desc.includes('데이터베이스') || url.includes('sql')) {
      return {
        action: 'block',
        confidence: 0.95,
        reason: PATTERNS[0].name,
      };
    }
    if (desc.includes('스크립트') || url.includes('script')) {
      return {
        action: 'block',
        confidence: 0.95,
        reason: PATTERNS[1].name,
      };
    }
    if (desc.includes('경로') || desc.includes('거슬러') || desc.includes('이탈') || url.includes('up-repeat')) {
      return {
        action: 'block',
        confidence: 0.95,
        reason: PATTERNS[2].name,
      };
    }
    return {
      action: 'block',
      confidence: 0.95,
      reason: PATTERNS[3].name,
    };
  }

  // 2. 애매한 시도 또는 단발성 의심 쿼리 (level 5 ~ 9) -> alert (confidence: 0.65)
  if (level >= 5 && level <= 9) {
    return {
      action: 'alert',
      confidence: 0.65,
      reason: PATTERNS[4].name,
    };
  }

  // 3. 정상 웹 트래픽 (level <= 4) -> record (confidence: 0.1)
  return {
    action: 'record',
    confidence: 0.1,
    reason: PATTERNS[5].name,
  };
}

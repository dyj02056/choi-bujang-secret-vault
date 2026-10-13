// 권한 가로채기(MITRE ATT&CK T1068 권한 상승 악용, T1078 정상 계정 도용) 판단 모듈.
// 심판은 인터넷 없이 이 파일 하나만 불러와 경보마다 decide(alert) 를 부릅니다. 그래서 import 문을 두지 않고,
// 파일을 읽거나 쓰지 않고, 바깥에 묻지 않습니다. 패턴은 xdr/privilege/patterns.json 을 아래 상수로 옮겨 적었습니다.
// 알림 기록(xdr/alerts.log)과 판정기 연결은 respond.mjs 가 맡고, 이 파일은 판단 결과만 돌려줍니다.

const PATTERNS = Object.freeze([
  {
    name: 'admin-group-add',
    condition: 'MITRE T1078 경보이고, 경보의 그룹 값(data.group)이 관리자 그룹(administrators)임. 설명 글자의 "관리자 그룹"은 보지 않음("관리자 그룹은 아닙니다" 같은 부정문이 있음)',
    match: { mitre: ['T1078'], groupIn: ['administrators'] },
    confidence: { add: 0.3 },
    rationale: 'MITRE ATT&CK T1078(정상 계정 도용): 손에 넣은 평범한 계정을 관리자 그룹에 넣어 정상 관리자처럼 권한을 쓰는 형태입니다.',
  },
  {
    name: 'unfamiliar-admin-command',
    condition: 'MITRE T1068 또는 T1078 경보이고, 설명에 관리자 명령·권한 명령·관리자 권한 전환이 있으면서, 처음 보는 주소·방금 관리자가 된 계정·다른 계정의 권한 가운데 하나가 함께 있음',
    match: { mitre: ['T1068', 'T1078'], descriptionIncludes: ['관리자 명령', '권한 명령', '관리자 권한'], descriptionAlsoIncludes: ['처음 보는', '처음 봅', '방금 관리자가 된', '다른 계정의 권한'] },
    confidence: { add: 0.3 },
    rationale: 'MITRE ATT&CK T1068(권한 상승 악용)·T1078: 평소와 다른 주소·계정·권한으로 갑자기 관리자 명령을 실행하는 것은 가로챈 권한을 쓰는 형태입니다.',
  },
  {
    name: 'off-hours-privilege-use',
    condition: 'MITRE T1068 또는 T1078 경보이고, 설명에 수업 시간 밖·업무 시간 밖·업무처럼 보이지 않는 시각이라고 적혀 있음("수업 시간에"·"수업 중"은 세지 않음)',
    match: { mitre: ['T1068', 'T1078'], descriptionIncludes: ['수업 시간 밖', '업무 시간 밖', '업무처럼 보이지 않는 시각'] },
    confidence: { add: 0.15 },
    rationale: 'MITRE ATT&CK T1078: 도용한 정상 계정은 주인이 쓰지 않는 시각에 권한을 쓰는 경우가 많아, 시각이 평소와 다르면 의심 신호가 됩니다.',
  },
  {
    name: 'repeated-admin-grant',
    condition: '관리자 그룹 추가(admin-group-add)이고, 같은 경보의 반복 횟수(count)가 2 이상임(여러 계정 동시 추가, 빠졌다가 다시 추가)',
    match: { mitre: ['T1078'], groupIn: ['administrators'], countAtLeast: 2 },
    confidence: { add: 0.15 },
    rationale: 'MITRE ATT&CK T1078: 여러 계정을 한꺼번에 관리자로 만들거나, 지워진 관리자 권한을 곧바로 되살리는 것은 권한을 붙잡아 두려는 형태입니다.',
  },
  {
    name: 'exploit-with-valid-account',
    condition: '한 경보에 MITRE T1068 과 T1078 표시가 함께 있음',
    match: { mitreAll: ['T1068', 'T1078'] },
    confidence: { add: 0.15 },
    rationale: 'MITRE ATT&CK T1068 + T1078: 도용한 정상 계정으로 들어온 뒤 권한 상승까지 이어지면 같은 공격의 두 단계가 한 경보에 함께 나타납니다.',
  },
  {
    name: 'unverified-privilege-change',
    condition: 'MITRE T1068 또는 T1078 경보이고 규칙 수준이 5 이상(위 신호가 없으면 알림까지). 규칙 수준이 10 미만이면 다른 신호가 있어도 차단까지 가지 않음',
    match: { mitre: ['T1068', 'T1078'], levelAtLeast: 5, blockNeedsLevelAtLeast: 10 },
    confidence: { base: 0.6, capBelowBlockLevel: 0.84 },
    rationale: 'MITRE ATT&CK T1068·T1078: 수업 중 권한 창, 관리자 그룹이 아닌 그룹 변경, 평소 주소의 관리자 명령도 같은 경보를 만들 수 있어 막지 않고 알림으로만 남깁니다.',
  },
]);

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;
const MAX_CONFIDENCE = 0.99;
const BASE = PATTERNS.find((pattern) => pattern.name === 'unverified-privilege-change');
const SIGNALS = PATTERNS.filter((pattern) => pattern !== BASE);

const text = (value) => (typeof value === 'string' ? value : '');
const round = (value) => Math.round(value * 100) / 100;
const actionFor = (confidence) => (confidence >= BLOCK_AT ? 'block' : confidence >= ALERT_AT ? 'alert' : 'record');

// 패턴 하나의 조건을 경보에 대어 봅니다. 조건에 적힌 항목이 모두 맞아야 맞은 것으로 셉니다.
function matches(pattern, { mitre, description, group, count }) {
  const m = pattern.match;
  if (m.mitre && !m.mitre.some((id) => mitre.includes(id))) return false;
  if (m.mitreAll && !m.mitreAll.every((id) => mitre.includes(id))) return false;
  if (m.groupIn && !m.groupIn.includes(group)) return false;
  if (m.descriptionIncludes && !m.descriptionIncludes.some((word) => description.includes(word))) return false;
  if (m.descriptionAlsoIncludes && !m.descriptionAlsoIncludes.some((word) => description.includes(word))) return false;
  if (m.countAtLeast && !(count >= m.countAtLeast)) return false;
  return true;
}

export function decide(alert) {
  const data = alert && typeof alert.data === 'object' && alert.data !== null ? alert.data : {};
  const rule = alert && typeof alert.rule === 'object' && alert.rule !== null ? alert.rule : {};
  const facts = {
    mitre: Array.isArray(rule.mitre) ? rule.mitre.filter((id) => typeof id === 'string') : [],
    description: text(rule.description),
    group: text(data.group).trim().toLowerCase(),
    count: Number(data.count) || 1,
  };
  const level = Number(rule.level) || 0;

  // 1) T1068·T1078 표시와 규칙 수준이 기준에 못 미치면 기록만 남깁니다(로그인·로그아웃·평소 관리 계정 사용 등).
  if (!BASE.match.mitre.some((id) => facts.mitre.includes(id)) || level < BASE.match.levelAtLeast) {
    return { action: 'record', confidence: 0, reason: '맞는 패턴 없음' };
  }

  // 2) 출발점 0.6(알림)에서, 맞는 뚜렷한 신호마다 확신도를 더합니다.
  const matched = SIGNALS.filter((pattern) => matches(pattern, facts));
  let confidence = BASE.confidence.base + matched.reduce((sum, pattern) => sum + pattern.confidence.add, 0);

  // 3) 규칙 수준이 낮은 경보는 신호가 있어도 차단 아래에 머뭅니다(정상 사용자를 막지 않기 위한 안전장치).
  if (level < BASE.match.blockNeedsLevelAtLeast) confidence = Math.min(confidence, BASE.confidence.capBelowBlockLevel);
  confidence = round(Math.min(confidence, MAX_CONFIDENCE));

  const reason = matched.length ? matched.map((pattern) => pattern.name).join(', ') : BASE.name;
  return { action: actionFor(confidence), confidence, reason };
}

// 몰래 심어진 지속성 프로그램(MITRE ATT&CK T1543 시스템 프로세스 생성·변경, T1053 예약 작업) 판단 모듈.
// 심판은 인터넷 없이 이 파일 하나만 불러와 경보마다 decide(alert) 를 부릅니다. 그래서 import 문을 두지 않고,
// 파일을 읽거나 쓰지 않고, 바깥에 묻지 않습니다. 패턴은 xdr/persistence/patterns.json 을 아래 상수로 옮겨 적었습니다.
// 알림 기록(xdr/alerts.log)과 판정기 연결은 respond.mjs 가 맡고, 이 파일은 판단 결과만 돌려줍니다.

const PATTERNS = Object.freeze([
  {
    name: 'unsigned-new-service',
    condition: 'MITRE T1543 경보이고, 설명에 서비스 실행 파일의 서명이 없다고 적혀 있음("서명 없는"·"서명이 없"). "서명은 확인되지 않았습니다"·"아직 모릅니다"는 서명 없음으로 세지 않음',
    match: { mitre: ['T1543'], descriptionIncludes: ['서명 없는', '서명이 없'] },
    confidence: { add: 0.15 },
    rationale: 'MITRE ATT&CK T1543(시스템 프로세스 생성·변경): 공격자는 다시 켜도 살아남도록 서명 없는 실행 파일을 새 서비스로 등록합니다.',
  },
  {
    name: 'unfamiliar-persistence-entry',
    condition: 'MITRE T1053 또는 T1543 경보이고, 설명에 처음 보는 항목·평소 목록에 없는 항목·임의 문자열 이름이라고 적혀 있음',
    match: { mitre: ['T1053', 'T1543'], descriptionIncludes: ['처음 보는', '평소 목록에 없는', '임의 문자열'] },
    confidence: { add: 0.15 },
    rationale: 'MITRE ATT&CK T1053(예약 작업)·T1543: 지속성용 예약 작업과 서비스는 평소 목록에 없던 이름이나 무작위 이름으로 새로 생깁니다.',
  },
  {
    name: 'user-writable-executable',
    condition: 'MITRE T1543 또는 T1053 경보이고, 가리키는 실행 파일(path)이 사용자 임시 폴더(\\AppData\\Local\\Temp\\)의 .exe 임',
    match: { mitre: ['T1543', 'T1053'], pathRegex: '\\\\AppData\\\\Local\\\\Temp\\\\[^\\\\]+\\.exe$', flags: 'i' },
    confidence: { add: 0.15 },
    rationale: 'MITRE ATT&CK T1543·T1053: 지속성 서비스·예약 작업은 아무 사용자나 쓸 수 있는 임시 폴더에 내려 둔 실행 파일을 자주 가리킵니다.',
  },
  {
    name: 'startup-folder-change',
    condition: 'MITRE T1543 또는 T1053 경보이고, 가리키는 실행 파일(path)이 시작 폴더(\\Start Menu\\Programs\\Startup\\) 안에 있음',
    match: { mitre: ['T1543', 'T1053'], pathIncludes: ['\\Start Menu\\Programs\\Startup\\'] },
    confidence: { add: 0.3 },
    rationale: 'MITRE ATT&CK T1543(이 경보 묶음의 표시 기준): 시작 폴더에 넣은 프로그램은 로그인할 때마다 다시 실행되는 지속성 수단입니다.',
  },
  {
    name: 'repeated-service-registration',
    condition: 'MITRE T1543 경보이고, 같은 경보의 반복 횟수(count)가 2 이상임',
    match: { mitre: ['T1543'], countAtLeast: 2 },
    confidence: { add: 0.15 },
    rationale: 'MITRE ATT&CK T1543: 원격에서 서비스 등록을 연달아 시도하는 것은 지속성 프로그램을 심는 자동화된 형태입니다.',
  },
  {
    name: 'combined-persistence',
    condition: '한 경보에 MITRE T1543 과 T1053 표시가 함께 있음',
    match: { mitreAll: ['T1543', 'T1053'] },
    confidence: { add: 0.15 },
    rationale: 'MITRE ATT&CK T1543 + T1053: 한 프로그램을 여러 지속성 수단에 함께 걸어 두면 하나를 지워도 살아남습니다.',
  },
  {
    name: 'unverified-persistence-change',
    condition: 'MITRE T1543 또는 T1053 경보이고 규칙 수준이 5 이상(위 신호가 없으면 알림까지). 규칙 수준이 10 미만이면 다른 신호가 있어도 차단까지 가지 않음',
    match: { mitre: ['T1543', 'T1053'], levelAtLeast: 5, blockNeedsLevelAtLeast: 10 },
    confidence: { base: 0.6, capBelowBlockLevel: 0.84 },
    rationale: 'MITRE ATT&CK T1543·T1053: 수업 도구나 평소 업데이트도 같은 경보를 만들 수 있어, 서명·위치·반복 같은 뚜렷한 신호 없이 막지 않고 알림으로만 남깁니다.',
  },
]);

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;
const MAX_CONFIDENCE = 0.99;
const BASE = PATTERNS.find((pattern) => pattern.name === 'unverified-persistence-change');
const SIGNALS = PATTERNS.filter((pattern) => pattern !== BASE);

const text = (value) => (typeof value === 'string' ? value : '');
const round = (value) => Math.round(value * 100) / 100;
const actionFor = (confidence) => (confidence >= BLOCK_AT ? 'block' : confidence >= ALERT_AT ? 'alert' : 'record');

// 패턴 하나의 조건을 경보에 대어 봅니다. 조건에 적힌 항목이 모두 맞아야 맞은 것으로 셉니다.
function matches(pattern, { mitre, description, path, count }) {
  const m = pattern.match;
  if (m.mitre && !m.mitre.some((id) => mitre.includes(id))) return false;
  if (m.mitreAll && !m.mitreAll.every((id) => mitre.includes(id))) return false;
  if (m.descriptionIncludes && !m.descriptionIncludes.some((word) => description.includes(word))) return false;
  if (m.pathRegex && !new RegExp(m.pathRegex, m.flags).test(path)) return false;
  if (m.pathIncludes && !m.pathIncludes.some((part) => path.includes(part))) return false;
  if (m.countAtLeast && !(count >= m.countAtLeast)) return false;
  return true;
}

export function decide(alert) {
  const data = alert && typeof alert.data === 'object' && alert.data !== null ? alert.data : {};
  const rule = alert && typeof alert.rule === 'object' && alert.rule !== null ? alert.rule : {};
  const facts = {
    mitre: Array.isArray(rule.mitre) ? rule.mitre.filter((id) => typeof id === 'string') : [],
    description: text(rule.description),
    path: text(data.path),
    count: Number(data.count) || 1,
  };
  const level = Number(rule.level) || 0;

  // 1) T1543·T1053 표시와 규칙 수준이 기준에 못 미치면 기록만 남깁니다(평소 업데이트·서명된 기존 서비스 등).
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

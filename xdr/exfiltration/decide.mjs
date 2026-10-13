// 자료 빼돌리기(MITRE ATT&CK T1041 명령 통로로 유출, T1048 다른 프로토콜로 유출) 판단 모듈.
// 심판은 인터넷 없이 이 파일 하나만 불러와 경보마다 decide(alert) 를 부릅니다. 그래서 import 문을 두지 않고,
// 파일을 읽거나 쓰지 않고, 바깥에 묻지 않습니다. 패턴은 xdr/exfiltration/patterns.json 을 아래 상수로 옮겨 적었습니다.
// 알림 기록(xdr/alerts.log)과 판정기 연결은 respond.mjs 가 맡고, 이 파일은 판단 결과만 돌려줍니다.

const PATTERNS = Object.freeze([
  {
    name: 'large-volume-transfer',
    condition: 'MITRE T1041 또는 T1048 경보이고, 한 경보의 전송량(data.bytes)이 50,000,000바이트(50MB) 이상임',
    match: { mitre: ['T1041', 'T1048'], bytesAtLeast: 50000000 },
    confidence: { add: 0.15 },
    rationale: 'MITRE ATT&CK T1041(명령 통로로 유출)·T1048(다른 프로토콜로 유출): 유출은 평소 업무 전송보다 훨씬 큰 자료가 한꺼번에 밖으로 나가는 형태로 나타납니다.',
  },
  {
    name: 'first-seen-destination',
    condition: 'MITRE T1041 또는 T1048 경보이고, 설명에 처음 보는 목적지·주소 또는 외부 주소로 나갔다고 적혀 있음',
    match: { mitre: ['T1041', 'T1048'], descriptionIncludes: ['처음 보는', '처음 봅', '외부 주소'] },
    confidence: { add: 0.15 },
    rationale: 'MITRE ATT&CK T1041·T1048: 빼돌린 자료는 평소 쓰던 자료실이 아니라 공격자가 준비한 처음 보는 바깥 목적지로 보내집니다.',
  },
  {
    name: 'off-hours-transfer',
    condition: 'MITRE T1041 또는 T1048 경보이고, 설명에 수업 시간 밖·업무 시간 밖이라고 적혀 있음("수업 시간에"·"수업 끝 무렵"은 세지 않음)',
    match: { mitre: ['T1041', 'T1048'], descriptionIncludes: ['수업 시간 밖', '업무 시간 밖'] },
    confidence: { add: 0.15 },
    rationale: 'MITRE ATT&CK T1048: 다른 통로로 빼돌리는 전송은 지켜보는 사람이 없는 업무 시간 밖에 몰리는 형태로 나타납니다.',
  },
  {
    name: 'archive-exfiltration',
    condition: 'MITRE T1041 또는 T1048 경보이고, 설명에 압축 파일이 있으면서 전송량이 50MB 이상임(압축만 하고 전송이 없거나 일부만 나간 작은 전송은 세지 않음)',
    match: { mitre: ['T1041', 'T1048'], descriptionIncludes: ['압축 파일'], bytesAtLeast: 50000000 },
    confidence: { add: 0.15 },
    rationale: 'MITRE ATT&CK T1048: 많은 자료를 압축 파일 하나로 묶어 다른 통로로 한 번에 내보내는 것은 유출의 흔한 형태입니다.',
  },
  {
    name: 'repeated-transfer-same-destination',
    condition: 'MITRE T1041 또는 T1048 경보이고, 같은 경보의 반복 횟수(data.count)가 5 이상임',
    match: { mitre: ['T1041', 'T1048'], countAtLeast: 5 },
    confidence: { add: 0.15 },
    rationale: 'MITRE ATT&CK T1041: 명령 통로로 자료를 조금씩 나눠 같은 목적지에 여러 번 보내는 것은 유출을 숨기려는 형태입니다.',
  },
  {
    name: 'bulk-file-transfer',
    condition: 'MITRE T1041 또는 T1048 경보이고, 한 경보의 파일 수(data.files)가 50개 이상임',
    match: { mitre: ['T1041', 'T1048'], filesAtLeast: 50 },
    confidence: { add: 0.15 },
    rationale: 'MITRE ATT&CK T1041·T1048: 자료실의 많은 파일이 짧은 시간에 한꺼번에 밖으로 나가는 것은 대량 유출의 형태입니다.',
  },
  {
    name: 'unusual-protocol-port',
    condition: 'MITRE T1048 경보이고, 설명에 평소에 쓰지 않던 포트 또는 다른 프로토콜로 전송했다고 적혀 있음',
    match: { mitre: ['T1048'], descriptionIncludes: ['평소에 쓰지 않던 포트', '다른 프로토콜'] },
    confidence: { add: 0.15 },
    rationale: 'MITRE ATT&CK T1048(다른 프로토콜로 유출): 평소 업무 통로가 아닌 포트·프로토콜로 자료를 내보내 감시를 피하는 형태입니다.',
  },
  {
    name: 'unverified-outbound-transfer',
    condition: 'MITRE T1041 또는 T1048 경보이고 규칙 수준이 5 이상(위 신호가 없으면 알림까지). 규칙 수준이 10 미만이면 다른 신호가 있어도 차단까지 가지 않음',
    match: { mitre: ['T1041', 'T1048'], levelAtLeast: 5, blockNeedsLevelAtLeast: 10 },
    confidence: { base: 0.6, capBelowBlockLevel: 0.84 },
    rationale: 'MITRE ATT&CK T1041·T1048: 작은 파일 전송, 실패한 전송, 수업 자료 주소로의 백업도 같은 경보를 만들 수 있어 막지 않고 알림으로만 남깁니다.',
  },
]);

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;
const MAX_CONFIDENCE = 0.99;
const BASE = PATTERNS.find((pattern) => pattern.name === 'unverified-outbound-transfer');
const SIGNALS = PATTERNS.filter((pattern) => pattern !== BASE);

const text = (value) => (typeof value === 'string' ? value : '');
const number = (value) => {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : 0;
};
const round = (value) => Math.round(value * 100) / 100;
const actionFor = (confidence) => (confidence >= BLOCK_AT ? 'block' : confidence >= ALERT_AT ? 'alert' : 'record');

// 패턴 하나의 조건을 경보에 대어 봅니다. 조건에 적힌 항목이 모두 맞아야 맞은 것으로 셉니다.
function matches(pattern, { mitre, description, bytes, count, files }) {
  const m = pattern.match;
  if (m.mitre && !m.mitre.some((id) => mitre.includes(id))) return false;
  if (m.descriptionIncludes && !m.descriptionIncludes.some((word) => description.includes(word))) return false;
  if (m.bytesAtLeast && !(bytes >= m.bytesAtLeast)) return false;
  if (m.countAtLeast && !(count >= m.countAtLeast)) return false;
  if (m.filesAtLeast && !(files >= m.filesAtLeast)) return false;
  return true;
}

export function decide(alert) {
  const data = alert && typeof alert.data === 'object' && alert.data !== null ? alert.data : {};
  const rule = alert && typeof alert.rule === 'object' && alert.rule !== null ? alert.rule : {};
  const facts = {
    mitre: Array.isArray(rule.mitre) ? rule.mitre.filter((id) => typeof id === 'string') : [],
    description: text(rule.description),
    bytes: number(data.bytes),
    count: number(data.count) || 1,
    files: number(data.files),
  };
  const level = Number(rule.level) || 0;

  // 1) T1041·T1048 표시와 규칙 수준이 기준에 못 미치면 기록만 남깁니다(메모 읽기·자료실 저장·작은 동기화 등).
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

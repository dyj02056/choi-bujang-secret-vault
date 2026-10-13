// 9단계 탐지 함수(학생 작업): ALEPH SDP 엔진이 검증해 넘긴 가상 사건만 읽습니다.
// 사건에서 시각, 요청 종류, 가명 사용자(identity.sub) 세 값만 꺼내고 나머지 항목은
// 복사하거나 출력하지 않습니다. 브라우저가 보낸 사용자 번호는 받지 않습니다.
const WINDOW_MS = 10 * 60 * 1000;
const BURST_LIMIT = 120;
const MAX_SUBJECT_LENGTH = 128;

// 시각·종류·가명 사용자가 올바른 GET 사건만 남깁니다. 잘못된 사건은 세지 않습니다.
function readEvent(event) {
  if (!event || typeof event !== 'object') return null;
  const sub = event.identity?.sub;
  if (typeof sub !== 'string' || sub.length === 0 || sub.length > MAX_SUBJECT_LENGTH) return null;
  if (typeof event.method !== 'string' || event.method.toUpperCase() !== 'GET') return null;
  if (typeof event.at !== 'string') return null;
  const time = Date.parse(event.at);
  if (!Number.isFinite(time)) return null;
  return { sub, time };
}

export function detect(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');

  // 사용자별로만 묶습니다. 요청한 자원이나 세션이 달라져도 같은 sub는 같은 묶음이고,
  // 다른 사용자의 사건은 합산하지 않습니다.
  const timesBySubject = new Map();
  for (const raw of events) {
    const event = readEvent(raw);
    if (event === null) continue;
    const list = timesBySubject.get(event.sub);
    if (list) list.push(event.time);
    else timesBySubject.set(event.sub, [event.time]);
  }

  // 어느 10분 구간에서든 120건을 넘는 첫 사용자를 찾습니다. 정확히 120건은 대상이 아닙니다.
  let flagged = null;
  for (const [sub, times] of timesBySubject) {
    if (times.length <= BURST_LIMIT) continue;
    times.sort((a, b) => a - b);
    let start = 0;
    for (let end = 0; end < times.length; end += 1) {
      while (times[end] - times[start] >= WINDOW_MS) start += 1;
      if (end - start + 1 > BURST_LIMIT) {
        if (flagged === null || times[end] < flagged.time
            || (times[end] === flagged.time && sub < flagged.sub)) {
          flagged = { sub, time: times[end] };
        }
        break;
      }
    }
  }

  if (flagged === null) return { action: 'observe' };
  return { action: 'propose_revocation', reasonCode: 'burst_read', subject: flagged.sub };
}

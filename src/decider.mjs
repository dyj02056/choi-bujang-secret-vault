// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 6단계부터 규칙을 하나씩 추가합니다. 이 기본 응답은 모든 요청을 거부합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze([
  'device_registered',
  'step_up_required',
  'resource_zone_route',
]);

// Exact (service, method) pairs. The decision contract has no owner or role, so the
// policy never allows a write to class announcements (POST, PUT, PATCH, DELETE are all
// denied for everyone) and never opens a list route. Whether a single note belongs to
// the caller is compared by the API handlers, not here.
export const RESOURCE_METHODS = Object.freeze({
  notes: Object.freeze(['GET', 'PUT', 'DELETE']),
  announcements: Object.freeze(['GET']),
});

// 10단계: 비공개 사본에서 메모 한 건을 되살리는 POST 경로 하나. 자료 ID는 본문에 있고
// 소유자·사본 해시 대조는 API가 합니다. 쿼리로 기능을 고르지 않으며 :id 옆에 두지 않습니다.
export const ACTION_ROUTES = Object.freeze(['POST /restore/notes']);
const RESTORE_PATH = /^\/(?:api\/)?restore\/notes$/u;

// "/notes/<id>" or "/api/notes/<id>" only: one segment. The API handlers validate the
// real UUID, so the policy accepts any plain ID token but never dots, escapes or slashes.
const RESOURCE_PATH = /^\/(?:api\/)?(notes|announcements)\/[A-Za-z0-9_-]{1,64}$/u;

function isKnownResourceRoute(request) {
  if (request.schema !== 'aleph.decision.v1'
      || typeof request.subjectId !== 'string' || request.subjectId.length === 0
      || typeof request.deviceId !== 'string' || !/^[0-9a-f]{16}$/u.test(request.deviceId)
      || request.queryLength !== 0
      || typeof request.service !== 'string' || typeof request.method !== 'string'
      || typeof request.path !== 'string' || typeof request.route !== 'string') {
    return false;
  }
  // 복구 경로는 엔진이 붙인 서비스 이름과 상관없이 정확히 POST /restore/notes 모양일 때만 허용합니다.
  // 복구처럼 보이는 다른 요청(다른 메서드, 하위 경로, 다른 대상)은 여기서 모두 거부합니다.
  if (request.service === 'restore' || RESTORE_PATH.test(request.path)
      || /^[A-Z]+ \/(?:api\/)?restore(?:\/|$)/u.test(request.route)) {
    return request.method === 'POST' && ACTION_ROUTES.includes(request.route)
      && RESTORE_PATH.test(request.path);
  }
  if (!Object.hasOwn(RESOURCE_METHODS, request.service)
      || !RESOURCE_METHODS[request.service].includes(request.method)) return false;
  const match = RESOURCE_PATH.exec(request.path);
  // The path zone must equal the service zone, and the route must be the exact
  // shape for that service and method (no cross-zone or nested routes).
  return match !== null
    && match[1] === request.service
    && request.route === `${request.method} /${request.service}/:id`;
}

function requiresStepUp(request) {
  const signals = request.signals;
  return request.method === 'GET'
    && request.route === 'GET /notes/:id'
    && signals?.region === 'foreign'
    && signals?.network === 'unusual'
    && (signals?.hour < 6 || signals?.hour >= 22);
}

export async function decide(request) {
  if (request.deviceRegistered !== true) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: [RULE_IDS[0]],
    };
  }

  if (!isKnownResourceRoute(request)) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'resource_route_denied',
      ruleIds: [RULE_IDS[2]],
    };
  }

  if (requiresStepUp(request) && request.stepUp?.verified !== true) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'step_up',
      reasonCode: 'step_up_required',
      ruleIds: [RULE_IDS[1], RULE_IDS[2]],
    };
  }

  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'allow',
    reasonCode: 'resource_route_allowed',
    ruleIds: requiresStepUp(request)
      ? [RULE_IDS[0], RULE_IDS[1], RULE_IDS[2]]
      : [RULE_IDS[0], RULE_IDS[2]],
  };
}

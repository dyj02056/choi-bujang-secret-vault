// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 6단계부터 규칙을 하나씩 추가합니다. 이 기본 응답은 모든 요청을 거부합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze([
  'device_registered',
  'step_up_required',
  'resource_zone_route',
]);

const RESOURCE_ROUTES = Object.freeze([
  // Resource IDs are validated as UUIDs by their API handlers. The policy checks
  // the exact one-segment route shape so ordinary verified reads are not tied to
  // a particular fixture's ID representation.
  { service: 'notes', method: 'GET', route: 'GET /notes/:id', path: /^\/notes\/[^/?#]+$/u },
  { service: 'notes', method: 'PUT', route: 'PUT /notes/:id', path: /^\/notes\/[^/?#]+$/u },
  { service: 'notes', method: 'DELETE', route: 'DELETE /notes/:id', path: /^\/notes\/[^/?#]+$/u },
  { service: 'announcements', method: 'GET', route: 'GET /announcements/:id', path: /^\/announcements\/[^/?#]+$/u },
  { service: 'announcements', method: 'PUT', route: 'PUT /announcements/:id', path: /^\/announcements\/[^/?#]+$/u },
]);

function isKnownResourceRoute(request) {
  return request.schema === 'aleph.decision.v1'
    && typeof request.subjectId === 'string' && request.subjectId.length > 0
    && typeof request.deviceId === 'string' && /^[0-9a-f]{16}$/u.test(request.deviceId)
    && request.queryLength === 0
    && RESOURCE_ROUTES.some((entry) => entry.service === request.service
      && entry.method === request.method && entry.route === request.route
      && entry.path.test(request.path));
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

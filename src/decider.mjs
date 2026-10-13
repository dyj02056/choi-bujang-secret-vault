// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 6단계부터 규칙을 하나씩 추가합니다. 이 기본 응답은 모든 요청을 거부합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze([
  'device_registered',
  'step_up_required',
  'resource_zone_route',
]);

// Exact (service, method) pairs. Ownership and the instructor role are not in the
// decision contract, so the API handlers stay the last gate for those checks.
const RESOURCE_METHODS = Object.freeze({
  notes: Object.freeze(['GET', 'PUT', 'DELETE']),
  announcements: Object.freeze(['GET', 'PUT']),
});

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

// The contract carries no owner or role, so a private note is bound to the first
// verified subject the engine lets read or write it. Any other subject is denied that
// exact note. Process-local and bounded; the API handlers still check owner_id.
const NOTE_OWNERS = new Map();
const NOTE_OWNER_LIMIT = 5000;

function noteKey(request) {
  return request.service === 'notes' ? request.path.split('/').pop() : null;
}

function isOtherUsersNote(request) {
  const key = noteKey(request);
  if (key === null) return false;
  const owner = NOTE_OWNERS.get(key);
  return owner !== undefined && owner !== request.subjectId;
}

function bindNoteOwner(request) {
  const key = noteKey(request);
  if (key === null || NOTE_OWNERS.has(key)) return;
  if (NOTE_OWNERS.size >= NOTE_OWNER_LIMIT) NOTE_OWNERS.delete(NOTE_OWNERS.keys().next().value);
  NOTE_OWNERS.set(key, request.subjectId);
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

  if (isOtherUsersNote(request)) {
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

  bindNoteOwner(request);
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

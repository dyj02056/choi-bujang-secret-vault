import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fixtureRequests } from './fixture-7.mjs';

const RESPONSE_KEYS = 'decision,reasonCode,requestId,ruleIds,schema';

function validResponse(request, response, ruleIds) {
  return response && typeof response === 'object' && !Array.isArray(response)
    && Object.keys(response).sort().join(',') === RESPONSE_KEYS
    && response.schema === 'aleph.decision.v1'
    && response.requestId === request.requestId
    && ['allow', 'deny', 'step_up'].includes(response.decision)
    && typeof response.reasonCode === 'string'
    && /^[a-z][a-z0-9_]{0,63}$/u.test(response.reasonCode)
    && Array.isArray(response.ruleIds) && response.ruleIds.length > 0
    && response.ruleIds.every(id => ruleIds.includes(id));
}

// Local practice only. The class engine and the server judge validate live requests separately.
export async function checkDecider({ decide, ruleIds }) {
  if (typeof decide !== 'function' || !Array.isArray(ruleIds)
      || !ruleIds.includes('device_registered')) {
    throw new Error('6단계 device_registered 규칙을 먼저 구현하고 RULE_IDS에 적어 주세요.');
  }
  const { normal, suspicious } = fixtureRequests();
  const checks = [
    { name: '등록 기기의 정상 요청', request: normal, decision: 'allow' },
    { name: '미등록 기기의 가상 요청', request: { ...normal, requestId: randomUUID(),
      deviceRegistered: false }, decision: 'deny', reasonCode: 'device_not_registered' },
  ];
  if (ruleIds.includes('step_up_required')) {
    checks.push(
      { name: '복합 이상 접속', request: suspicious, decision: 'step_up',
        reasonCode: 'step_up_required' },
      { name: '다시 확인한 복합 이상 접속', request: { ...suspicious,
        requestId: randomUUID(), stepUp: { verified: true, authAgeSeconds: 60 } },
      decision: 'allow' },
    );
  }
  if (ruleIds.includes('resource_zone_route')) {
    checks.push(
      { name: 'owned private-note read route', request: { ...normal,
        requestId: randomUUID(), service: 'notes', path: '/api/notes/00000000-0000-4000-8000-000000000001',
        route: 'GET /notes/:id' }, decision: 'allow' },
      { name: 'announcement update is denied', request: { ...normal,
        requestId: randomUUID(), service: 'announcements', method: 'PUT',
        path: '/announcements/00000000-0000-4000-8000-000000000001', route: 'PUT /announcements/:id' },
      decision: 'deny', reasonCode: 'resource_route_denied' },
      { name: 'announcement update stays denied after step-up', request: { ...normal,
        requestId: randomUUID(), service: 'announcements', method: 'PUT',
        path: '/announcements/00000000-0000-4000-8000-000000000001', route: 'PUT /announcements/:id',
        stepUp: { verified: true, authAgeSeconds: 30 } },
      decision: 'deny', reasonCode: 'resource_route_denied' },
      { name: 'announcement read stays open', request: { ...normal,
        requestId: randomUUID(), service: 'announcements',
        path: '/announcements/00000000-0000-4000-8000-000000000001', route: 'GET /announcements/:id' },
      decision: 'allow' },
      { name: 'first subject claims its note', request: { ...normal,
        requestId: randomUUID(), subjectId: 'learner_own', path: '/api/notes/note_zone_check' },
      decision: 'allow' },
      { name: 'other subject denied that exact note', request: { ...normal,
        requestId: randomUUID(), subjectId: 'learner_other', path: '/api/notes/note_zone_check' },
      decision: 'deny', reasonCode: 'resource_route_denied' },
      { name: 'owner keeps reading own note', request: { ...normal,
        requestId: randomUUID(), subjectId: 'learner_own', path: '/api/notes/note_zone_check' },
      decision: 'allow' },
      { name: 'unknown nested resource route', request: { ...normal,
        requestId: randomUUID(), path: '/notes/demo/export', route: 'GET /notes/:id/export' },
      decision: 'deny', reasonCode: 'resource_route_denied' },
      { name: 'service and path zone mismatch', request: { ...normal,
        requestId: randomUUID(), service: 'announcements',
        path: '/api/notes/00000000-0000-4000-8000-000000000001', route: 'GET /announcements/:id' },
      decision: 'deny', reasonCode: 'resource_route_denied' },
      { name: 'announcement path under notes service', request: { ...normal,
        requestId: randomUUID(), method: 'PUT',
        path: '/api/announcements/00000000-0000-4000-8000-000000000001', route: 'PUT /notes/:id' },
      decision: 'deny', reasonCode: 'resource_route_denied' },
      { name: 'announcement delete is not an allowed method', request: { ...normal,
        requestId: randomUUID(), service: 'announcements', method: 'DELETE',
        path: '/api/announcements/00000000-0000-4000-8000-000000000001', route: 'DELETE /announcements/:id' },
      decision: 'deny', reasonCode: 'resource_route_denied' },
      { name: 'own note read with a plain non-UUID id', request: { ...normal,
        requestId: randomUUID(), path: '/api/notes/note_own_1' }, decision: 'allow' },
      { name: 'escaped traversal in resource id', request: { ...normal,
        requestId: randomUUID(), path: '/api/notes/..%2fannouncements' },
      decision: 'deny', reasonCode: 'resource_route_denied' },
      { name: 'query string on resource route', request: { ...normal,
        requestId: randomUUID(), queryLength: 12 },
      decision: 'deny', reasonCode: 'resource_route_denied' },
    );
  }
  const results = [];
  for (const item of checks) {
    const response = await decide(item.request);
    const valid = validResponse(item.request, response, ruleIds)
      && response.decision === item.decision
      && (!item.reasonCode || response.reasonCode === item.reasonCode);
    results.push({ name: item.name, passed: valid });
  }
  return results;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const { decide, RULE_IDS } = await import('../src/decider.mjs');
    const results = await checkDecider({ decide, ruleIds: RULE_IDS });
    for (const item of results) process.stdout.write(`${item.passed ? '통과' : '확인 필요'} · ${item.name}\n`);
    process.stdout.write('이 명령은 가상 요청으로 연습하며 심판 통과 증거가 아닙니다.\n');
    if (results.some(item => !item.passed)) process.exitCode = 1;
  } catch (error) {
    process.stderr.write(`판정기 연습 첫 오류: ${error.message}\n`);
    process.exitCode = 1;
  }
}

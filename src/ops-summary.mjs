import { createHash } from 'node:crypto';
import { ACTION_ROUTES, RESOURCE_METHODS, RULE_IDS } from './decider.mjs';
import { DETECTION_WINDOW_MS } from './access-guard.mjs';

// 12단계 탈환 작전실 요약. 화면(GET /api/ops/summary)과 서버 확인 스크립트(npm run ops:summary)가 같은 함수를 씁니다.
// 한 계정(소유자 키) 범위의 서버 기록만 셉니다. 메모 제목·본문, 토큰, 키, 계정 ID 원문은 담지 않습니다.
// 메모 ID 는 note_ + SHA-256 앞 10자리로 가립니다.
export const DETECTION_LIMIT = 120;
const RECENT_EVENTS = 20;

export const maskNote = (id) => (id ? `note_${createHash('sha256').update(String(id).toLowerCase()).digest('hex').slice(0, 10)}` : null);

export async function buildOpsSummary({ fetchImpl = fetch, supabaseUrl, serviceKey, ownerId, now = Date.now() }) {
  const headers = { apikey: serviceKey, Authorization: `Bearer ${serviceKey}` };
  const read = async (path) => {
    const response = await fetchImpl(`${supabaseUrl}/rest/v1/${path}`, { headers });
    if (!response.ok) throw new Error(`${path.split('?')[0]}_READ_FAILED`);
    return response.json();
  };
  const since = new Date(now - DETECTION_WINDOW_MS).toISOString();
  const [events, recentGets, revocations, devices, audit, backups] = await Promise.all([
    read(`access_events?owner_id=eq.${ownerId}&select=request_id,method,route,outcome,at&order=seq.desc&limit=${RECENT_EVENTS}`),
    read(`access_events?owner_id=eq.${ownerId}&method=eq.GET&at=gte.${since}&select=seq&limit=500`),
    read(`identity_revocations?owner_id=eq.${ownerId}&select=reason,revoked_at`),
    read(`device_keys?owner_id=eq.${ownerId}&select=status`),
    read(`secret_notes_restore_log?owner_id=eq.${ownerId}&select=seq,note_id,mode,reason,restored_at&order=seq.asc`),
    read(`secret_notes_backup?owner_id=eq.${ownerId}&select=id`),
  ]);
  const count = (rows, key) => rows.reduce((acc, row) => ({ ...acc, [row[key]]: (acc[row[key]] ?? 0) + 1 }), {});
  const restores = audit.filter((row) => ['updated', 'reinserted', 'unchanged', 'refused'].includes(row.mode));
  const latest = restores.at(-1) ?? null;
  return {
    schema: 'aleph.ops.summary.v1',
    generatedAt: new Date(now).toISOString(),
    rules: {
      source: 'src/decider.mjs (학생 판정기)',
      ruleIds: [...RULE_IDS],
      resourceMethods: Object.fromEntries(Object.entries(RESOURCE_METHODS).map(([zone, methods]) => [zone, [...methods]])),
      actionRoutes: [...ACTION_ROUTES],
    },
    detection: {
      source: 'src/detect.mjs 규칙을 서버 기록 access_events 에 적용',
      windowMinutes: DETECTION_WINDOW_MS / 60000,
      limit: DETECTION_LIMIT,
      recentGetCount: recentGets.length,
      recentEvents: events.map((row) => ({ requestId: row.request_id, route: row.route, outcome: row.outcome, at: row.at })),
      outcomeCounts: count(events, 'outcome'),
    },
    revocation: {
      revoked: revocations.length > 0,
      reason: revocations[0]?.reason ?? null,
      revokedAt: revocations[0]?.revoked_at ?? null,
      devices: { approved: 0, pending: 0, revoked: 0, ...count(devices, 'status') },
    },
    restore: {
      auditRows: audit.length,
      byMode: count(audit, 'mode'),
      backups: backups.length,
      latest: latest ? { seq: latest.seq, mode: latest.mode, reason: latest.reason ?? null, note: maskNote(latest.note_id), at: latest.restored_at } : null,
    },
  };
}

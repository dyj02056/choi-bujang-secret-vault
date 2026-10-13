import { appendFile, readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

// decide 결과를 받아 (1) block 후보만 ZTNA 판정기용 거부 규칙으로 만들고 (2) alert·block 을 xdr/alerts.log 에 한 줄씩 쌓습니다.
// decide.mjs 는 판단만 하고, 파일 쓰기와 판정기 연결은 이 파일이 맡습니다. src/decider.mjs 의 기존 규칙은 고치지 않습니다.
//
// 판정기 계약(docs/DECIDER_REQUEST.md)에는 출발 주소·머리글·쿼리 원문이 없습니다. 그래서 이 규칙은 decide(request) 가
// 직접 읽지 않고, 출발 주소를 아는 앞단(ALEPH SDP 엔진의 릴레이 등)에 넘길 거부 규칙 후보로 내보냅니다.
// 계약에 없는 request.ip 같은 값을 만들어 판정기에 붙이지 않습니다.

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(__dirname, '..', 'fixtures', 'known-cve.json');
const alertLogPath = join(__dirname, '..', 'alerts.log');
const RULE_TTL_MS = 60 * 60 * 1000;

// 경보 하나마다 판단을 붙입니다.
export async function decideAll(alerts) {
  const out = [];
  for (const alert of alerts) out.push({ alert, decision: await decide(alert) });
  return out;
}

// block 후보만 출발 주소별 거부 규칙으로 묶습니다. 근거 경보 번호와 만료 시각을 붙입니다.
// 정상 사용자 보호: 계정(srcuser)이 있는 경보로는 규칙을 만들지 않고, 같은 묶음에서 정상 이벤트(record)를 보낸 주소도 막지 않습니다.
export function toDenyRules(decided, now = new Date()) {
  const normalIps = new Set(decided
    .filter(({ alert, decision }) => decision.action === 'record' && alert?.data?.srcip)
    .map(({ alert }) => alert.data.srcip));
  const byIp = new Map();
  for (const { alert, decision } of decided) {
    const srcip = alert?.data?.srcip;
    if (decision.action !== 'block' || !srcip || alert?.data?.srcuser || normalIps.has(srcip)) continue;
    const rule = byIp.get(srcip) ?? {
      ruleId: `xdr.known_cve.deny.${srcip.replace(/[^0-9A-Za-z]/gu, '_')}`,
      decision: 'deny',
      target: { srcip },
      evidenceAlertIds: [],
      reasons: [],
      confidence: 0,
      createdAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + RULE_TTL_MS).toISOString(),
    };
    rule.evidenceAlertIds.push(alert.id);
    for (const name of decision.reason.split(', ')) if (!rule.reasons.includes(name)) rule.reasons.push(name);
    rule.confidence = Math.max(rule.confidence, decision.confidence);
    byIp.set(srcip, rule);
  }
  return [...byIp.values()];
}

// 거부 규칙을 경보에 다시 대어 봅니다(만료 전 규칙의 출발 주소와 같으면 막힘).
export function isDenied(rules, alert, now = new Date()) {
  const srcip = alert?.data?.srcip;
  return rules.some((rule) => rule.target.srcip === srcip && Date.parse(rule.expiresAt) > now.getTime());
}

// alert·block 만 한 줄씩 추가합니다. 원격 조회 구문·머리글·주소 원문은 적지 않고 패턴 이름만 적습니다.
export async function appendAlertLog(decided, now = new Date(), logPath = alertLogPath) {
  const lines = decided
    .filter(({ decision }) => decision.action === 'alert' || decision.action === 'block')
    .map(({ alert, decision }) => `[${now.toISOString()}] [${decision.action.toUpperCase()}] module=known-cve alertId=${alert.id} ip=${alert?.data?.srcip ?? 'unknown'} user=${alert?.data?.srcuser ?? 'none'} reason=${decision.reason} confidence=${decision.confidence}\n`);
  if (lines.length) await appendFile(logPath, lines.join(''), 'utf8');
  return lines.length;
}

const isMain = process.argv[1] && process.argv[1].endsWith('respond.mjs');
if (isMain) {
  const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));
  const decided = await decideAll(fixture.alerts ?? []);
  const now = new Date();
  const rules = toDenyRules(decided, now);
  const logged = await appendAlertLog(decided, now);
  console.log(`거부 규칙 후보 ${rules.length}개 (판정기 계약에 출발 주소가 없어 앞단에 넘길 후보로만 냄)`);
  for (const rule of rules) {
    console.log(`- ${rule.ruleId} 대상 ${rule.target.srcip} 근거 경보 ${rule.evidenceAlertIds.join(',')} 만료 ${rule.expiresAt}`);
  }
  console.log(`xdr/alerts.log 에 ${logged}줄 추가`);
  // 다시 흘려 보기: 같은 경보를 규칙에 대어 막히는 것과 통과하는 것을 셉니다.
  const replay = decided.map(({ alert, decision }) => ({ id: alert.id, action: decision.action, denied: isDenied(rules, alert, now) }));
  const wrong = replay.filter((row) => row.denied !== (row.action === 'block'));
  console.log(`다시 흘려 보기: 막힘 ${replay.filter((row) => row.denied).length}건 · 통과 ${replay.filter((row) => !row.denied).length}건 · 정상 이벤트 막힘 ${replay.filter((row) => row.denied && row.action === 'record').length}건 · 기대와 다름 ${wrong.length}건`);
  if (wrong.length) process.exitCode = 1;
}

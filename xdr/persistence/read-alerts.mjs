import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

// 확인용 읽기 모듈입니다. decide.mjs 는 이 파일을 불러오지 않습니다. 원본 경보 파일은 읽기만 합니다.
const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(__dirname, '..', 'fixtures', 'persistence.json');

// 비밀값처럼 보이는 값(토큰·키·비밀번호 표기)과 ${…} 구문은 출력하지 않고 가립니다. 실행 파일 경로(path)는 출력 항목이 아니라 읽지 않습니다.
const SECRET_LIKE = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/giu,
  /\bBearer\s+[A-Za-z0-9._~+/-]{8,}/giu,
  /\beyJ[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+){0,2}/gu,
  /\b(?:sb_secret|sb_publishable|sk|pk|ghp|xox[abp])[-_][A-Za-z0-9_-]{8,}/giu,
  /\b(?:password|passwd|pwd|secret|token|api[-_]?key|access[-_]?key)\s*[:=]\s*\S+/giu,
];
const LOOKUP = /\$\{[^}]*\}/gu;

export function mask(value) {
  let text = String(value ?? '');
  for (const pattern of SECRET_LIKE) text = text.replace(pattern, '[가림]');
  return text.replace(LOOKUP, '[조회 구문 가림]');
}

export async function readAlerts() {
  const parsed = JSON.parse(await readFile(fixturePath, 'utf8'));
  const alerts = Array.isArray(parsed.alerts) ? parsed.alerts : [];
  const rows = alerts.map((alert) => ({
    timestamp: mask(alert?.timestamp),
    srcip: mask(alert?.data?.srcip),
    srcuser: mask(alert?.data?.srcuser),
    level: Number(alert?.rule?.level ?? 0),
    description: mask(alert?.rule?.description),
  }));
  return { alertCount: alerts.length, rows };
}

const isMain = process.argv[1] && process.argv[1].endsWith('read-alerts.mjs');
if (isMain) {
  const { alertCount, rows } = await readAlerts();
  for (const row of rows) {
    console.log(`[${row.timestamp}] IP:${row.srcip || '-'} USER:${row.srcuser || '-'} LEVEL:${row.level} DESC:${row.description}`);
  }
  console.log(`경보 ${alertCount}건 · 뽑은 줄 ${rows.length}줄 · ${alertCount === rows.length ? '일치' : '불일치'}`);
  if (alertCount !== rows.length) process.exitCode = 1;
}

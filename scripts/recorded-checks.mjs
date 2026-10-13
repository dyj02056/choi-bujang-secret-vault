import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// 12단계: `npm run bundle`(src/attack-check.mjs)이 파일을 읽지 않고 다른 학생 파일도 불러오지 않은 채로 커밋된 실측 점검 결과를
// 옮기도록, public/ops-checks.json(점검표)과 public/ops-summary.json(작전실 실측)의 필요한 부분만 src/attack-check.mjs 의
// <recorded-checks> 구역에 씁니다(심판 실행기가 그 파일과 처음 제공된 파일만으로 불러올 수 있게).
// 값은 두 파일에 이미 있는 실제 결과 그대로이며 새로 계산하거나 채우지 않습니다. 토큰·키·메모 본문은 두 파일에도 없습니다.
const ROOT = resolve(fileURLToPath(new URL('.', import.meta.url)), '..');
const read = (path) => {
  try { return JSON.parse(readFileSync(resolve(ROOT, path), 'utf8')); } catch { return null; }
};
const BLOCK = /\/\/ <recorded-checks>\r?\n[\s\S]*?\/\/ <\/recorded-checks>/u;

export function writeRecordedChecks() {
  const table = read('public/ops-checks.json');
  const snap = read('public/ops-summary.json');
  const data = table ? {
    table: {
      schema: table.schema, step: table.step, commit: table.commit, finishedAt: table.finishedAt,
      selfChecks: { checks: table.selfChecks?.checks ?? null },
      rows: (table.rows ?? []).map(({ attackId, request, expected, observed, requestId, checkedAt, verdict, notRunReason }) => ({
        attackId, request, expected, observed, requestId, checkedAt, verdict, ...(notRunReason ? { notRunReason } : {}),
      })),
    },
    snapshot: snap?.api?.body?.generatedAt ? { requestId: snap.api.requestId, generatedAt: snap.api.body.generatedAt } : null,
  } : null;
  const file = resolve(ROOT, 'src', 'attack-check.mjs');
  const source = readFileSync(file, 'utf8');
  if (!BLOCK.test(source)) throw new Error('src/attack-check.mjs 에 <recorded-checks> 구역이 없습니다.');
  const nl = source.includes('\r\n') ? '\r\n' : '\n';
  const body = `const RECORDED = ${JSON.stringify(data, null, 2)};`.replace(/\n/gu, nl);
  writeFileSync(file, source.replace(BLOCK, () => `// <recorded-checks>${nl}${body}${nl}// </recorded-checks>`), 'utf8');
  return data;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const data = writeRecordedChecks();
  process.stdout.write(`src/attack-check.mjs 기록 구역: 점검 ${data?.table?.rows?.length ?? 0}행 · 실측 ${data?.snapshot?.requestId ?? '없음'}\n`);
}

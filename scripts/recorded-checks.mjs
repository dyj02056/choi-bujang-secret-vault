import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// 12단계: `npm run bundle`(src/attack-check.mjs)이 파일 시스템을 읽지 않고도 커밋된 실측 점검 결과를 옮기도록,
// public/ops-checks.json(점검표)과 public/ops-summary.json(작전실 실측)의 필요한 부분만 src/recorded-checks.mjs 로 씁니다.
// 값은 두 파일에 이미 있는 실제 결과 그대로이며 새로 계산하거나 채우지 않습니다. 토큰·키·메모 본문은 두 파일에도 없습니다.
const ROOT = resolve(fileURLToPath(new URL('.', import.meta.url)), '..');
const read = (path) => {
  try { return JSON.parse(readFileSync(resolve(ROOT, path), 'utf8')); } catch { return null; }
};

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
  const text = `// 자동 생성: npm run ops:checks / ops:snapshot (scripts/recorded-checks.mjs). 직접 고치지 마세요.\n`
    + `// public/ops-checks.json 과 public/ops-summary.json 에 이미 있는 실제 결과를 그대로 옮긴 것입니다.\n`
    + `export const RECORDED = ${JSON.stringify(data, null, 2)};\n`;
  writeFileSync(resolve(ROOT, 'src', 'recorded-checks.mjs'), text, 'utf8');
  return data;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const data = writeRecordedChecks();
  process.stdout.write(`src/recorded-checks.mjs: 점검 ${data?.table?.rows?.length ?? 0}행 · 실측 ${data?.snapshot?.requestId ?? '없음'}\n`);
}

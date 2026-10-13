import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { runAttackChecks } from '../src/attack-check.mjs';
import { writeRecordedChecks } from './recorded-checks.mjs';

// 12단계: 1~11단계 정상·금지 요청을 실제로 보내고, 기대 결과·실제 API 결과·요청 ID·확인 시각을 한 표로 남깁니다.
//   npm run ops:checks
// 결과: audit/step12/checks-<UTC>.json, audit/step12/checks-<UTC>.md (새 이름, 덮어쓰지 않음)
//       public/ops-checks.json (탈환 작전실 화면이 읽는 최신 표)
// 보내지 못한 점검은 not_run(미실행)으로 남깁니다. 운영 심판의 41종 시험은 여기서 실행하지 않으므로
// 통과로 표시하지 않습니다. 토큰·비밀번호·메모 본문은 표에 넣지 않습니다.
const ROOT = resolve(import.meta.dirname, '..');
const JUDGE_TESTS = 41;

try {
  const config = JSON.parse(readFileSync(resolve(ROOT, 'aleph.config.json'), 'utf8'));
  const commit = execFileSync('git', ['-C', ROOT, 'rev-parse', 'HEAD'], { encoding: 'utf8', windowsHide: true }).trim();
  const dirty = execFileSync('git', ['-C', ROOT, 'status', '--porcelain'], { encoding: 'utf8', windowsHide: true }).trim();
  const details = [];
  const startedAt = new Date().toISOString();
  const results = await runAttackChecks(config, { details, sendLive: true });
  const counts = details.reduce((acc, row) => ({ ...acc, [row.verdict]: (acc[row.verdict] ?? 0) + 1 }), {});
  const table = {
    schema: 'aleph.ops.checks.v1',
    commit, workingTreeClean: dirty === '', step: config.step, app: config.publicAppUrl, startedAt,
    finishedAt: new Date().toISOString(),
    selfChecks: { checks: results.length, requests: details.length, verdicts: counts },
    judgeTests: { total: JUDGE_TESTS, run: 0, status: 'not_run',
      note: '운영 심판의 41종 시험은 이 절차에서 실행하지 않았습니다. 결과가 없으므로 통과로 표시하지 않습니다.' },
    rows: details.map((row) => ({
      attackId: row.attackId, step: row.step, kind: row.kind, request: row.request, expected: row.expected,
      observed: row.observed, requestId: row.requestId, checkedAt: row.checkedAt, verdict: row.verdict,
      ...(row.reason ? { notRunReason: row.reason } : {}),
    })),
  };
  const text = JSON.stringify(table);
  if (/eyJ[A-Za-z0-9_-]{12,}\.|BEGIN [A-Z ]*PRIVATE|sb_secret_/u.test(text)) throw new Error('표에 비밀값으로 보이는 내용이 있어 쓰지 않습니다.');

  const stamp = table.finishedAt.replace(/[-:]/gu, '').replace(/\.\d+Z$/u, 'Z');
  const dir = resolve(ROOT, 'audit', 'step12');
  mkdirSync(dir, { recursive: true });
  writeFileSync(resolve(dir, `checks-${stamp}.json`), `${JSON.stringify(table, null, 2)}\n`, { encoding: 'utf8', flag: 'wx' });
  const esc = (value) => String(value ?? '').replace(/\|/gu, '\|');
  const md = [
    `# 1~11단계 점검표 (${table.finishedAt})`, '',
    `- 검사한 커밋: \`${commit}\`${table.workingTreeClean ? '' : ' (커밋되지 않은 변경이 있는 상태)'}`,
    `- 학생 자기 점검 ${results.length}건, 실제 요청 ${details.length}행: ${Object.entries(counts).map(([k, v]) => `${k} ${v}`).join(', ')}`,
    `- 운영 심판 41종 시험: 미실행 (이 표에 결과 없음, 통과로 표시하지 않음)`, '',
    '| 단계 | 정상/금지 | 점검 ID | 요청 | 기대 결과 | 실제 API 결과 | 요청 ID | 확인 시각 | 판정 |',
    '|---|---|---|---|---|---|---|---|---|',
    ...table.rows.map((row) => `| ${esc(row.step)} | ${row.kind === 'normal' ? '정상' : '금지'} | ${esc(row.attackId)} | ${esc(row.request)} | ${esc(row.expected)} | ${esc(row.observed)} | ${esc(row.requestId)} | ${esc(row.checkedAt ?? '-')} | ${esc(row.verdict)} |`),
    '',
  ].join('\n');
  writeFileSync(resolve(dir, `checks-${stamp}.md`), md, { encoding: 'utf8', flag: 'wx' });
  writeFileSync(resolve(ROOT, 'public', 'ops-checks.json'), `${JSON.stringify(table, null, 2)}\n`, 'utf8');
  writeRecordedChecks();
  process.stdout.write(`점검표: audit/step12/checks-${stamp}.md · public/ops-checks.json\n`
    + `  자기 점검 ${results.length}건 / 요청 ${details.length}행 · ${Object.entries(counts).map(([k, v]) => `${k} ${v}`).join(', ')}\n`
    + '  운영 심판 41종: 미실행\n');
} catch (error) {
  process.stderr.write(`점검표 첫 오류: ${error.message}\n`);
  process.exitCode = 1;
}

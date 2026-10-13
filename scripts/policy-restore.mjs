import { readFileSync, writeFileSync } from 'node:fs';
import { CONFIG, CONFIG_KEYS, currentPolicy, describe, diffPolicy, loadSafeCopy } from './policy-lib.mjs';

// 안전 사본으로 시험 정책을 되돌립니다. 기본은 미리보기이고 --yes 를 주어야 씁니다.
// 쓰는 곳은 aleph.config.json 의 allowedRoutes·restoreRoute 두 항목뿐입니다. 다른 설정과
// 판정기 밖의 서비스 규칙, 감사 기록은 건드리지 않습니다. 코드 규칙 차이는 자동으로 고치지 않고 알려 줍니다.
try {
  const copy = loadSafeCopy();
  const changes = diffPolicy(copy.policy, await currentPolicy());
  process.stdout.write(`복원 기준: 안전 정책 사본 v${copy.version} (해시 ${copy.sha256.slice(0, 12)} 검증됨)\n`);
  if (!changes.length) {
    process.stdout.write('바뀔 항목이 없습니다.\n');
  } else {
    const writable = changes.filter((change) => CONFIG_KEYS.includes(change.key));
    const manual = changes.filter((change) => !CONFIG_KEYS.includes(change.key));
    process.stdout.write('실행 전 바뀔 항목:\n');
    for (const change of writable) {
      process.stdout.write(`- ${change.key}: ${describe(change.current)} → ${describe(change.safe)}\n`);
    }
    for (const change of manual) {
      process.stdout.write(`- ${change.key}: 코드 규칙이라 자동으로 쓰지 않습니다. src/decider.mjs를 직접 확인하고 `
        + `git diff 로 안전했던 커밋과 비교해 되돌리세요.\n`);
    }
    if (!process.argv.includes('--yes')) {
      process.stdout.write('미리보기입니다. 위 항목을 확인한 뒤 실제로 쓰려면 --yes 를 붙여 다시 실행하세요.\n');
    } else if (writable.length) {
      const raw = readFileSync(CONFIG, 'utf8');
      const crlf = raw.includes('\r\n');
      const config = JSON.parse(raw);
      for (const change of writable) config[change.key] = copy.policy[change.key];
      const out = `${JSON.stringify(config, null, 2)}\n`;
      writeFileSync(CONFIG, crlf ? out.replace(/\n/gu, '\r\n') : out, 'utf8');
      process.stdout.write(`aleph.config.json 의 ${writable.map((change) => change.key).join(', ')} 를 사본 값으로 되돌렸습니다.\n`);
    }
    if (manual.length) process.exitCode = 2;
  }
} catch (error) {
  process.stderr.write(`정책 복원 중단: ${error.message}\n`);
  process.exitCode = 1;
}

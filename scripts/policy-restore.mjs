import { readFileSync, writeFileSync } from 'node:fs';
import { appendAudit } from './audit-lib.mjs';
import { CONFIG, CONFIG_KEYS, currentPolicy, describe, diffPolicy, loadSafeCopy } from './policy-lib.mjs';

// 안전 사본으로 시험 정책을 되돌립니다. 기본은 미리보기이고 --yes 를 주어야 씁니다.
// 쓰는 곳은 aleph.config.json 의 allowedRoutes·restoreRoute 두 항목뿐이고, 그 안에서도 사본과 다른 값만 고칩니다.
//   allowedRoutes: 사본에 있는데 빠진 경로만 되살립니다. 사본에 없는 경로(다른 서비스 규칙)는 그대로 두고 알리기만 하며,
//                  --remove-extra 를 함께 줄 때만 뺍니다.
//   restoreRoute : 사본 값과 다를 때만 사본 값으로 바꿉니다.
// 다른 설정, 판정기 코드 규칙, 감사 기록은 건드리지 않습니다. 코드 규칙 차이는 자동으로 고치지 않고 알려 줍니다.
const routeChange = (safe, current) => ({
  missing: safe.filter((route) => !current.includes(route)),
  extra: current.filter((route) => !safe.includes(route)),
});

try {
  const copy = loadSafeCopy();
  const changes = diffPolicy(copy.policy, await currentPolicy());
  const removeExtra = process.argv.includes('--remove-extra');
  process.stdout.write(`복원 기준: 안전 정책 사본 v${copy.version} (해시 ${copy.sha256.slice(0, 12)} 검증됨)\n`);
  const base = { policyVersion: copy.version, policyHash: copy.sha256.slice(0, 12) };
  if (!changes.length) {
    appendAudit('policy_restore_checked', { ...base, changedKeys: [], applied: false, result: 'no_difference' });
    process.stdout.write('바뀔 항목이 없습니다.\n');
  } else {
    const writable = changes.filter((change) => CONFIG_KEYS.includes(change.key));
    const manual = changes.filter((change) => !CONFIG_KEYS.includes(change.key));
    process.stdout.write('실행 전 바뀔 항목:\n');
    for (const change of writable) {
      if (change.key === 'allowedRoutes') {
        const { missing, extra } = routeChange(change.safe ?? [], change.current ?? []);
        for (const route of missing) process.stdout.write(`- allowedRoutes: 되살림 ${route}\n`);
        for (const route of extra) {
          process.stdout.write(removeExtra
            ? `- allowedRoutes: 뺌 ${route} (--remove-extra)\n`
            : `- allowedRoutes: 사본에 없는 ${route} 는 그대로 둡니다. 빼려면 --remove-extra\n`);
        }
        if (!missing.length && !extra.length) process.stdout.write('- allowedRoutes: 순서만 다릅니다. 바꾸지 않습니다.\n');
      } else {
        process.stdout.write(`- ${change.key}: ${describe(change.current)} → ${describe(change.safe)}\n`);
      }
    }
    for (const change of manual) {
      process.stdout.write(`- ${change.key}: 코드 규칙이라 자동으로 쓰지 않습니다. src/decider.mjs를 직접 확인하고 `
        + `git diff 로 안전했던 커밋과 비교해 되돌리세요.\n`);
    }
    if (!process.argv.includes('--yes')) {
      appendAudit('policy_restore_preview', { ...base, changedKeys: changes.map((change) => change.key), applied: false, result: 'preview_only' });
      process.stdout.write('미리보기입니다. 위 항목을 확인한 뒤 실제로 쓰려면 --yes 를 붙여 다시 실행하세요.\n');
    } else if (writable.length) {
      const raw = readFileSync(CONFIG, 'utf8');
      const crlf = raw.includes('\r\n');
      const config = JSON.parse(raw);
      const applied = [];
      for (const change of writable) {
        if (change.key === 'allowedRoutes') {
          const current = [...(config.allowedRoutes ?? [])];
          const { missing, extra } = routeChange(copy.policy.allowedRoutes ?? [], current);
          const kept = removeExtra ? current.filter((route) => !extra.includes(route)) : current;
          if (missing.length || (removeExtra && extra.length)) {
            config.allowedRoutes = [...kept, ...missing];
            applied.push('allowedRoutes');
          }
        } else {
          config[change.key] = copy.policy[change.key];
          applied.push(change.key);
        }
      }
      if (applied.length) {
        const out = `${JSON.stringify(config, null, 2)}\n`;
        writeFileSync(CONFIG, crlf ? out.replace(/\n/gu, '\r\n') : out, 'utf8');
      }
      appendAudit('policy_restore_applied', {
        ...base, changedKeys: applied, applied: applied.length > 0,
        result: manual.length ? 'config_restored_code_rules_manual' : (applied.length ? 'config_restored' : 'nothing_to_write'),
      });
      process.stdout.write(applied.length
        ? `aleph.config.json 의 ${applied.join(', ')} 에서 사본과 다른 값만 되돌렸습니다.\n`
        : '쓸 항목이 없습니다. 사본에 없는 경로는 그대로 두었습니다.\n');
    }
    if (manual.length) process.exitCode = 2;
  }
} catch (error) {
  process.stderr.write(`정책 복원 중단: ${error.message}\n`);
  process.exitCode = 1;
}

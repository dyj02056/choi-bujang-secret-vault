import { currentPolicy, describe, diffPolicy, loadSafeCopy } from './policy-lib.mjs';

// 읽기 전용입니다. 복원할 사본 버전과 바뀐 항목만 보여 주고 아무것도 고치지 않습니다.
// 종료 코드: 0 차이 없음 · 2 차이 있음 · 1 사본 없음 또는 검증 실패(중단)
try {
  const copy = loadSafeCopy();
  const changes = diffPolicy(copy.policy, await currentPolicy());
  process.stdout.write(`복원 기준: 안전 정책 사본 v${copy.version} (해시 ${copy.sha256.slice(0, 12)} 검증됨)\n`);
  if (!changes.length) {
    process.stdout.write('현재 시험 정책이 안전 사본과 같습니다. 바뀔 항목이 없습니다.\n');
  } else {
    for (const change of changes) {
      process.stdout.write(`- ${change.key} [${change.kind === 'code' ? '코드 규칙' : '설정 데이터'}]\n`
        + `    사본: ${describe(change.safe)}\n    현재: ${describe(change.current)}\n`);
    }
    process.exitCode = 2;
  }
} catch (error) {
  process.stderr.write(`정책 비교 중단: ${error.message}\n`);
  process.exitCode = 1;
}

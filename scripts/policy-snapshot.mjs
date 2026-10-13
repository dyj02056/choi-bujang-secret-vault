import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { appendAudit } from './audit-lib.mjs';
import { SAFE_COPY, currentPolicy, policyHash } from './policy-lib.mjs';

// 침해 전에 안전하다고 확인한 현재 정책을 사본으로 남깁니다. 이미 있으면 덮어쓰지 않습니다.
try {
  if (existsSync(SAFE_COPY)) throw new Error('안전 정책 사본이 이미 있어 덮어쓰지 않습니다. 새 버전이 필요하면 직접 확인한 뒤 파일을 옮겨 두세요.');
  const policy = await currentPolicy();
  const copy = { schema: 'aleph.policy.safe.v1', version: 1, policy, sha256: policyHash(policy) };
  mkdirSync(dirname(SAFE_COPY), { recursive: true });
  writeFileSync(SAFE_COPY, `${JSON.stringify(copy, null, 2)}\n`, { encoding: 'utf8', flag: 'wx' });
  appendAudit('policy_snapshot_created', { policyVersion: copy.version, policyHash: copy.sha256.slice(0, 12), result: 'created' });
  process.stdout.write(`안전 정책 사본 v${copy.version} 생성 · 해시 ${copy.sha256.slice(0, 12)}\n`);
} catch (error) {
  process.stderr.write(`정책 사본 첫 오류: ${error.message}\n`);
  process.exitCode = 1;
}

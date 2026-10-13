import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export const ROOT = resolve(import.meta.dirname, '..');
export const SAFE_COPY = resolve(ROOT, 'policy', 'safe-policy.json');
export const CONFIG = resolve(ROOT, 'aleph.config.json');

// 코드로 정해진 규칙(판정기)과 설정 파일의 데이터(허용 경로)를 한 덩어리 정책으로 모읍니다.
const CODE_KEYS = ['ruleIds', 'resourceMethods', 'actionRoutes'];
const CONFIG_KEYS = ['allowedRoutes', 'restoreRoute'];
export { CODE_KEYS, CONFIG_KEYS };

const sort = (value) => {
  if (Array.isArray(value)) return value.map(sort);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sort(value[key])]));
  }
  return value;
};
export const canonical = (value) => JSON.stringify(sort(value));
export const policyHash = (policy) => createHash('sha256').update(canonical(policy)).digest('hex');

export async function currentPolicy() {
  const decider = await import(pathToFileURL(resolve(ROOT, 'src', 'decider.mjs')).href);
  const config = JSON.parse(readFileSync(CONFIG, 'utf8'));
  return {
    ruleIds: [...decider.RULE_IDS],
    resourceMethods: Object.fromEntries(Object.entries(decider.RESOURCE_METHODS)
      .map(([service, methods]) => [service, [...methods]])),
    actionRoutes: [...decider.ACTION_ROUTES],
    allowedRoutes: [...(config.allowedRoutes ?? [])],
    restoreRoute: config.restoreRoute ?? null,
  };
}

// 안전 사본이 없거나 형식·해시가 맞지 않으면 예외를 던져 호출한 쪽이 중단하게 합니다.
export function loadSafeCopy(path = SAFE_COPY) {
  let raw;
  try {
    raw = readFileSync(path, 'utf8');
  } catch {
    throw new Error('검증한 안전 정책 사본(policy/safe-policy.json)이 없어 중단합니다.');
  }
  let copy;
  try {
    copy = JSON.parse(raw);
  } catch {
    throw new Error('안전 정책 사본을 읽을 수 없어 중단합니다.');
  }
  if (!copy || copy.schema !== 'aleph.policy.safe.v1' || !Number.isInteger(copy.version)
      || !copy.policy || typeof copy.policy !== 'object' || typeof copy.sha256 !== 'string') {
    throw new Error('안전 정책 사본의 형식이 맞지 않아 중단합니다.');
  }
  if (policyHash(copy.policy) !== copy.sha256.toLowerCase()) {
    throw new Error('안전 정책 사본의 해시가 맞지 않아 중단합니다. 사본이 바뀌었을 수 있습니다.');
  }
  return copy;
}

// 사본과 현재 정책에서 서로 다른 항목만 돌려줍니다.
export function diffPolicy(safe, current) {
  const changes = [];
  for (const key of [...CODE_KEYS, ...CONFIG_KEYS]) {
    if (canonical(safe[key]) !== canonical(current[key])) {
      changes.push({ key, kind: CODE_KEYS.includes(key) ? 'code' : 'config', safe: safe[key], current: current[key] });
    }
  }
  return changes;
}

export function describe(value) {
  return value === undefined ? '(없음)' : canonical(value);
}

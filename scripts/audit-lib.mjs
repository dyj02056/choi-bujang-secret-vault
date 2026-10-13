import { appendFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

// 로컬 복구 절차의 감사 이력입니다. 한 줄에 사건 하나(JSON)이며 추가만 합니다.
// 파일을 열어 덮어쓰거나 줄이지 않습니다. 메모 제목·내용, 토큰, 키는 절대 적지 않습니다.
export const AUDIT_FILE = resolve(import.meta.dirname, '..', 'audit', 'restore-audit.log');

const ALLOWED = ['policyVersion', 'policyHash', 'changedKeys', 'applied', 'noteId', 'created', 'skipped', 'result'];

export function appendAudit(action, details = {}) {
  const entry = { at: new Date().toISOString(), action };
  for (const key of ALLOWED) {
    if (details[key] !== undefined) entry[key] = details[key];
  }
  mkdirSync(dirname(AUDIT_FILE), { recursive: true });
  appendFileSync(AUDIT_FILE, `${JSON.stringify(entry)}\n`, { encoding: 'utf8', flag: 'a' });
  return entry;
}

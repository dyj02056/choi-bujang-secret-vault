import { resolve } from 'node:path';
import { appendAudit } from './audit-lib.mjs';
import { loadSafeCopy } from './policy-lib.mjs';
import { noteHash } from '../src/note-backup.mjs';

// 침해 전에 만든 사본을 다시 읽어 검증하고 결과를 audit/restore-audit.log 에 한 줄 남깁니다.
//   1) 정책 사본: policy/safe-policy.json 의 해시를 다시 계산합니다 (항상 실행).
//   2) 메모 사본: 비공개 표 secret_notes_backup 의 각 행에서 내용 해시를 다시 계산합니다.
//      SUPABASE_URL 과 SUPABASE_SECRET_KEY 가 없거나 --policy-only 이면 실행하지 않고 기록도 남기지 않습니다.
// 메모 제목·내용과 서버 키는 출력하지도, 기록하지도 않습니다.
try {
  process.loadEnvFile?.(resolve(import.meta.dirname, '..', '.env'));
} catch {}

let failed = false;

try {
  const copy = loadSafeCopy();
  appendAudit('policy_copy_verified', { policyVersion: copy.version, policyHash: copy.sha256.slice(0, 12), result: 'ok' });
  process.stdout.write(`정책 사본 v${copy.version} 검증 통과 (해시 ${copy.sha256.slice(0, 12)})\n`);
} catch (error) {
  failed = true;
  appendAudit('policy_copy_verified', { result: 'failed' });
  process.stderr.write(`정책 사본 검증 실패: ${error.message}\n`);
}

const url = process.env.SUPABASE_URL?.replace(/\/+$/u, '');
const key = process.env.SUPABASE_SECRET_KEY;
if (process.argv.includes('--policy-only') || !url || !key) {
  process.stdout.write('메모 사본 검증은 미실행입니다 (서버 설정이 없거나 --policy-only). 기록도 남기지 않았습니다.\n');
} else {
  try {
    const response = await fetch(`${url}/rest/v1/secret_notes_backup?select=id,owner_id,title,content,content_sha256`, {
      headers: { apikey: key, Authorization: `Bearer ${key}` },
    });
    if (!response.ok) throw new Error(`사본 표를 읽지 못했습니다 (HTTP ${response.status}). 004 마이그레이션을 확인하세요.`);
    const rows = await response.json();
    const bad = rows.filter((row) => typeof row.title !== 'string' || typeof row.content !== 'string'
      || String(row.content_sha256).toLowerCase() !== noteHash(row.title, row.content));
    appendAudit('note_backups_verified', { verified: rows.length - bad.length, failed: bad.length, result: bad.length ? 'failed' : 'ok' });
    process.stdout.write(`메모 사본 ${rows.length}건 중 ${rows.length - bad.length}건 검증 통과, 실패 ${bad.length}건\n`);
    if (bad.length) failed = true;
  } catch (error) {
    failed = true;
    process.stderr.write(`메모 사본 검증 첫 오류: ${error.message}\n`);
  }
}
if (failed) process.exitCode = 1;

import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { appendAudit } from './audit-lib.mjs';

// 10단계에서 일어난 기록을 audit/step10/ 에 한 번 내보냅니다. 내보낸 파일은 덮어쓰지 않고(타임스탬프 이름),
// 같은 이름이 이미 있으면 멈춥니다. 담는 것:
//   db.auditTrail  : 표 secret_notes_restore_log 의 모든 줄 (계정 ID는 가명, 내용은 해시만)
//   db.backups     : 표 secret_notes_backup 의 정보 (제목·내용은 읽지 않음, 내용 해시만)
//   git            : 10단계 저장점 커밋 이력
//   attackResults  : artifacts/submission.json 의 직접 점검 결과 (있을 때만)
// 서버 키와 메모 제목·내용, 계정 ID 원문은 읽어도 쓰지 않습니다.
const ROOT = resolve(import.meta.dirname, '..');
try {
  process.loadEnvFile?.(resolve(ROOT, '.env'));
} catch {}

const pseudonym = (value) => (value ? `owner_${createHash('sha256').update(String(value).toLowerCase()).digest('hex').slice(0, 10)}` : null);
const git = (...args) => execFileSync('git', ['-C', ROOT, ...args], { encoding: 'utf8', timeout: 8000, windowsHide: true }).trim();

const stamp = new Date().toISOString();
const name = `export-${stamp.replace(/[-:]/gu, '').replace(/\.\d+Z$/u, 'Z')}.json`;
const outDir = resolve(ROOT, 'audit', 'step10');
const outFile = resolve(outDir, name);
const result = { schema: 'aleph.audit.export.v1', exportedAt: stamp, sections: {} };
const skipped = [];

try {
  if (existsSync(outFile)) throw new Error(`${name} 이(가) 이미 있어 덮어쓰지 않습니다.`);

  // 1) 데이터베이스 기록
  const url = process.env.SUPABASE_URL?.replace(/\/+$/u, '');
  const key = process.env.SUPABASE_SECRET_KEY;
  if (url && key) {
    const headers = { apikey: key, Authorization: `Bearer ${key}` };
    const read = async (path) => {
      const response = await fetch(`${url}/rest/v1/${path}`, { headers, signal: AbortSignal.timeout(15000) });
      if (!response.ok) throw new Error(`${path.split('?')[0]} 을(를) 읽지 못했습니다 (HTTP ${response.status}).`);
      return response.json();
    };
    const trail = (await read('secret_notes_restore_log?select=*&order=seq.asc')).map((row) => ({
      seq: row.seq, noteId: row.note_id, owner: pseudonym(row.owner_id), mode: row.mode,
      beforeSha256: row.before_sha256 ?? null, afterSha256: row.after_sha256 ?? null, at: row.restored_at,
      ...(row.reason ? { reason: row.reason } : {}),
    }));
    const backups = (await read('secret_notes_backup?select=id,owner_id,content_sha256,created_at,backed_up_at&order=backed_up_at.asc'))
      .map((row) => ({ noteId: row.id, owner: pseudonym(row.owner_id), contentSha256: row.content_sha256, createdAt: row.created_at, backedUpAt: row.backed_up_at }));
    const byMode = {};
    for (const row of trail) byMode[row.mode] = (byMode[row.mode] ?? 0) + 1;
    const contiguous = trail.every((row, index) => index === 0 || row.seq > trail[index - 1].seq);
    result.sections.db = { auditTrail: trail, backups, summary: { auditRows: trail.length, byMode, seqIncreasing: contiguous, backupRows: backups.length } };
  } else {
    skipped.push('db (SUPABASE_URL / SUPABASE_SECRET_KEY 없음)');
  }

  // 2) 깃 이력 (10단계 저장점)
  const lines = git('log', '--format=%H%x09%aI%x09%s', '-n', '60').split(/\r?\n/u).filter(Boolean);
  result.sections.git = lines.map((line) => {
    const [commit, at, subject] = line.split('\t');
    return { commit, at, subject };
  }).filter((entry) => entry.subject.includes('10단계 저장점'));

  // 3) 직접 점검 결과 (제출 묶음에서 점검 항목만 복사)
  // 10~11단계만 제출 묶음의 점검 결과를 옮깁니다. 12단계부터 점검 결과의 원본은 audit/step12/ 점검표이며,
  // 제출 묶음은 그 표를 옮긴 것이라 여기서 다시 옮기면 이전 시점의 결과가 지금 기록처럼 섞일 수 있습니다.
  const submission = resolve(ROOT, 'artifacts', 'submission.json');
  const bundle = existsSync(submission) ? JSON.parse(readFileSync(submission, 'utf8')) : null;
  if (bundle && bundle.step >= 12) {
    skipped.push('attackResults (12단계부터는 audit/step12/ 점검표가 원본)');
  } else if (bundle && bundle.commit === git('rev-parse', 'HEAD')) {
    result.sections.attackResults = { commit: bundle.commit, step: bundle.step, attempts: bundle.attackAttempts };
  } else {
    skipped.push(bundle ? 'attackResults (제출 묶음이 지금 커밋 것이 아님)' : 'attackResults (artifacts/submission.json 없음)');
  }

  result.skipped = skipped;
  mkdirSync(outDir, { recursive: true });
  writeFileSync(outFile, `${JSON.stringify(result, null, 2)}\n`, { encoding: 'utf8', flag: 'wx' });

  // 이름이 고정된 추가 전용 사본: 이미 있는 줄은 그대로 두고, 새로 생긴 DB 줄만 뒤에 이어 씁니다.
  const appendNew = (file, rows, idOf) => {
    const path = resolve(outDir, file);
    const known = new Set(existsSync(path)
      ? readFileSync(path, 'utf8').split(/\r?\n/u).filter(Boolean).map((line) => String(idOf(JSON.parse(line)))) : []);
    const fresh = rows.filter((row) => !known.has(String(idOf(row))));
    if (fresh.length) appendFileSync(path, `${fresh.map((row) => JSON.stringify(row)).join('\n')}\n`, { encoding: 'utf8', flag: 'a' });
    return { total: known.size + fresh.length, added: fresh.length };
  };
  if (result.sections.db) {
    result.appended = {
      auditTrail: appendNew('db-audit-trail.jsonl', result.sections.db.auditTrail, (row) => row.seq),
      backups: appendNew('db-backups.jsonl', result.sections.db.backups, (row) => row.noteId),
    };
  }
  appendAudit('audit_exported', {
    result: skipped.length ? 'partial' : 'ok',
    created: result.sections.db?.auditTrail.length ?? 0,
    verified: result.sections.attackResults?.attempts.length ?? 0,
  });
  process.stdout.write(`내보냄: audit/step10/${name}\n`
    + `  DB 감사 기록 ${result.sections.db?.auditTrail.length ?? '미실행'}줄 · 사본 정보 ${result.sections.db?.backups.length ?? '미실행'}건`
    + ` · 저장점 커밋 ${result.sections.git.length}건 · 직접 점검 ${result.sections.attackResults?.attempts.length ?? '미실행'}개\n`);
  if (result.appended) {
    process.stdout.write(`  db-audit-trail.jsonl: 모두 ${result.appended.auditTrail.total}줄 (이번에 추가 ${result.appended.auditTrail.added})`
      + ` · db-backups.jsonl: 모두 ${result.appended.backups.total}줄 (이번에 추가 ${result.appended.backups.added})\n`);
  }
  if (skipped.length) process.stdout.write(`  건너뜀: ${skipped.join(', ')}\n`);
} catch (error) {
  process.stderr.write(`내보내기 첫 오류: ${error.message}\n`);
  process.exitCode = 1;
}

import { resolve } from 'node:path';
import { buildOpsSummary } from '../src/ops-summary.mjs';

// 서버 쪽에서 탈환 작전실 요약을 다시 셉니다. 화면(GET /api/ops/summary)의 수치와 비교하는 용도입니다.
//   npm run ops:summary -- --owner <소유자 UUID>
// SUPABASE_URL·SUPABASE_SECRET_KEY 는 .env 나 셸에서만 읽고 출력하지 않습니다. 결과에 메모 제목·본문은 없습니다.
// 화면 요약을 만든 뒤에도 요청이 기록되므로, 최근 사건 수는 화면보다 늘어나 있을 수 있습니다.
try {
  process.loadEnvFile?.(resolve(import.meta.dirname, '..', '.env'));
} catch {}

const index = process.argv.indexOf('--owner');
const ownerId = index > 0 ? process.argv[index + 1] : undefined;
try {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu.test(ownerId ?? '')) {
    throw new Error('--owner <소유자 UUID> 가 필요합니다.');
  }
  const supabaseUrl = process.env.SUPABASE_URL?.replace(/\/+$/u, '');
  const serviceKey = process.env.SUPABASE_SECRET_KEY;
  if (!supabaseUrl || !serviceKey) throw new Error('SUPABASE_URL, SUPABASE_SECRET_KEY 가 필요합니다(.env).');
  const summary = await buildOpsSummary({ supabaseUrl, serviceKey, ownerId });
  process.stdout.write(`${JSON.stringify({ ...summary, source: 'server-script' }, null, 2)}\n`);
} catch (error) {
  process.stderr.write(`작전실 요약 첫 오류: ${error.message}\n`);
  process.exitCode = 1;
}

import { resolve } from 'node:path';
import { readRevocation, revokeIdentity } from '../src/access-guard.mjs';

// 12단계: 시험 계정 하나의 신원을 직접 회수합니다(되돌릴 수 없음). 회수 상태 확인용 세 번째 시험 계정(C)에만 쓰세요.
//   npm run ops:revoke -- --owner <소유자 UUID>
// 회수 표 identity_revocations 에 'manual' 로 한 줄 추가되고, 그 계정의 기기는 모두 revoked 가 됩니다.
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
  await revokeIdentity({ supabaseUrl, serviceKey, ownerId, reason: 'manual' });
  const row = await readRevocation({ supabaseUrl, serviceKey, ownerId });
  process.stdout.write(`회수됨: reason=${row?.reason} at=${row?.revoked_at}\n`);
} catch (error) {
  process.stderr.write(`회수 첫 오류: ${error.message}\n`);
  process.exitCode = 1;
}

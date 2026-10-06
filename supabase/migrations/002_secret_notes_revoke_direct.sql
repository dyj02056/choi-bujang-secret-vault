-- ============================================================
-- 002_secret_notes_revoke_direct.sql
-- 5단계: 학습용 메모 테이블 직접 접근 권한 회수 (방어전 실습용)
--
-- 사용법: Supabase 대시보드 > SQL Editor 에 전체 붙여넣기 후 Run
-- 대상: secret_notes 한 테이블만 (다른 테이블은 건드리지 않음)
-- 주의: 서버 함수(api/notes, api/notes/[id])는 서버 전용 키로
--        접근하므로 영향 없음. 브라우저 직접 호출은 이미 없음.
-- 경고: service_role 키는 코드·Git에 절대 포함하지 마세요.
-- ============================================================

-- 1. 직접 권한 회수 (secret_notes만)
REVOKE ALL ON TABLE secret_notes FROM PUBLIC, anon, authenticated;

-- 2. 남아 있을지 모를 직접 정책 제거 (이 테이블만)
DROP POLICY IF EXISTS "owner can read own notes" ON secret_notes;

-- 3. RLS는 계속 켜둠 (정책 없음 = anon·authenticated 직접 접근 기본 거부)
ALTER TABLE secret_notes ENABLE ROW LEVEL SECURITY;

-- ============================================================
-- 적용 전후 권한 확인 (실행만 하고 결과 비교)
-- ============================================================
-- 전: anon/authenticated 줄이 있으면 직접 권한이 남아 있는 상태
-- 후: 아무 줄도 없어야 정상 (서버 전용 키로만 통과)
-- SELECT grantee, privilege_type
--   FROM information_schema.role_table_grants
--  WHERE table_name = 'secret_notes';
--
-- 전후 모두 비어 있으면 정상 (직접 정책 없음)
-- SELECT policyname, roles, cmd
--   FROM pg_policies
--  WHERE tablename = 'secret_notes';

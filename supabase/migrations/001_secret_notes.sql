-- ============================================================
-- 001_secret_notes.sql
-- 학습용 가상 메모 마이그레이션 (방어전 실습용)
--
-- 사용법: Supabase 대시보드 > SQL Editor 에 전체 붙여넣기 후 Run
-- 경고: service_role 키는 코드·Git에 절대 포함하지 마세요.
-- ============================================================

-- 1. 테이블 생성
CREATE TABLE IF NOT EXISTS secret_notes (
  id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id   uuid,                          -- 외래키 없음 (나중에 앱에서 필터용)
  title      text        NOT NULL,
  content    text        NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- 2. RLS 활성화
--    정책이 없으면 anon · authenticated 역할의 모든 접근이 기본 거부됩니다.
ALTER TABLE secret_notes ENABLE ROW LEVEL SECURITY;

-- 3. 읽기 정책 미등록
--    anon · authenticated 에 SELECT 정책을 부여하지 않습니다.
--    service_role 키(서버 전용)로만 접근할 수 있습니다.
--
--    향후 소유자 본인만 읽게 하려면 아래 주석을 해제하세요:
--    CREATE POLICY "owner can read own notes"
--      ON secret_notes FOR SELECT
--      USING (owner_id = auth.uid());


-- 4. 가상 메모 3건 삽입 (학습용 — 실제 민감 정보 없음)
INSERT INTO secret_notes (owner_id, title, content) VALUES
  (NULL, '과제',        '실습용 가상 과제 기록'),
  (NULL, '포트폴리오',  '실습용 가상 포트폴리오 기록'),
  (NULL, '아침 리추얼', '실습용 가상 리추얼 기록');

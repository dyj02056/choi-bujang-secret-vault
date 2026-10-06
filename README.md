# BYTE BACK 방어전 - 점령된 자료실 (4단계)

이 저장소는 4단계 「로그인해도 내 자료만 보이게 합니다」 기능이 적용된 상태입니다. 서버 API와 데이터베이스 RLS를 통해 인증된 사용자 본인의 메모만 조회·추가·수정·삭제할 수 있으며, 타인 메모에 대한 무단 접근이나 소유자 변경이 원천 차단됩니다.

## 4단계 현재 작동하는 기능

1. **사용자별 소유권 기반 접근 제어:**
   - 메모 생성(`POST /api/notes`) 시 브라우저가 전달한 `owner_id`는 무시하고, 서버가 검증한 토큰의 `verified.userId`를 소유자로 강제 기록합니다.
   - 단건 조회(`GET /api/notes/:id`), 수정(`PUT /api/notes/:id`), 삭제(`DELETE /api/notes/:id`) 시 DB의 `owner_id`와 요청자의 `verified.userId`를 비교하여 본인 메모가 아닌 경우 `403 Forbidden`으로 거절합니다.
   - 메모 수정 시에도 `owner_id` 필드는 변경할 수 없도록 보호되어 소유자 탈취가 불가능합니다.
2. **목록 격리 (`GET /api/notes`):**
   - 로그인된 사용자 본인의 `owner_id`와 일치하는 메모 목록만 반환되어, A 사용자와 B 사용자가 서로의 메모를 볼 수 없습니다.
3. **데이터베이스 RLS 및 최소 권한 정책:**
   - `secret_notes` 테이블의 권한을 회수하고, `authenticated` 역할에만 `auth.uid() = owner_id` 조건의 SELECT, INSERT, UPDATE, DELETE 최소 권한 RLS 정책을 적용했습니다.

## 다시 실행 및 테스트 방법

1. **로컬 빌드 검증:**
   ```powershell
   npm run build -- --local
   ```
2. **배포 및 동작 확인:**
   - A 계정으로 로그인 시 A 소유 메모(3건 등)만 목록에 나타나고 수정/삭제가 가능한지 확인
   - B 계정으로 로그인 시 B 소유 메모(1건)만 목록에 나타나고 A의 메모는 목록에 나타나지 않는지 확인
   - B 사용자가 A의 메모 ID로 직접 `GET /api/notes/:id` 또는 `PUT`, `DELETE` 요청 시 `403 Forbidden`으로 거부되는지 확인
   - 비로그인 요청 시 `401 Unauthorized`로 거부되는지 확인

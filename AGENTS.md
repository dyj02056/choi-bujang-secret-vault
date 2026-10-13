# 방어전 코딩 도구 공통 규칙

학생이 한 번에 하나의 제작 프롬프트를 줍니다. 그 요청에서 말한 변경 하나만 구현하세요. 먼저 손댈 파일과 이유를 한 줄로 알려 주세요. 앞 단계에서 작동하던 기능, 공개 가능한 가상 메모, 다른 작업은 보존하세요.

6단계부터 `src/decider.mjs`를 고칠 때는 `docs/DECIDER_REQUEST.md`의 실제 요청·응답 계약을 먼저 읽으세요. `request.deviceRegistered`, `request.stepUp`, `request.signals`처럼 계약에 있는 값만 씁니다. 현재 계약에 없는 `request.device`, `request.identity`, `request.geo`, `request.role`을 만들어 쓰지 마세요. `decide(request)`의 함수 이름·인자와 응답 다섯 항목은 바꾸지 마세요. `npm run decider:test`는 가상 요청 연습이며 실제 심판 판정으로 보고하지 마세요.

9단계 `src/detect.mjs`를 고칠 때는 `docs/DETECT_EVENTS.md`의 가상 사건 형식을 먼저 읽으세요. `npm run detect:test`가 통과해도 운영 반 엔진의 사건 전달·접속 회수가 연결됐다고 쓰지 마세요.

10단계 사본과 감사 기록: 메모 사본은 Supabase의 비공개 표 `secret_notes_backup`(메모를 만들 때 첫 버전이 자동으로 한 번만 저장됨)에 있고, 정책 사본은 `policy/safe-policy.json`(해시로 검증)입니다. 복구와 사본 작업의 기록은 두 곳입니다. 실서버의 복구 호출은 표 `secret_notes_restore_log`와 복구 응답의 `audit.seq`에 남고, 메모 API의 생성·수정·삭제와 복구는 모두 같은 표에 기록됩니다(`src/note-audit.mjs`가 바뀌기 전·후 내용 해시만 남기고 본문은 남기지 않습니다). 로그인한 사람의 복구 호출은 거절돼도 `refused`와 이유 코드로 남습니다. 수정·삭제·복구는 감사 기록이 남았을 때만 진행하며 예외가 없습니다. 사본이 없던 메모는 처음 수정·삭제되기 직전 상태가 사본이 되고, 사본을 남기지 못하면 바꾸지 않습니다. 수정·삭제 코드를 고칠 때 이 기록을 빼거나, 기록하지 못했는데 자료를 바꾸도록 만들지 마세요. 로컬 절차(`npm run backup:notes`, `backup:verify`, `policy:snapshot`, `policy:restore`)는 `audit/restore-audit.log`에 한 줄씩 추가됩니다. 이 로그 파일은 추가만 하세요. 줄을 지우거나 고치거나 파일을 덮어쓰지 말고, 실제로 실행한 작업만 기록하며, 실행하지 않은 사본 생성·검증을 기록한 것처럼 줄을 만들지 마세요. 메모 제목·본문, 토큰, 키는 기록에 넣지 마세요. 복구 코드는 지정한 메모 한 건만 바꾸고 다른 메모, 목록 순서(`created_at`), 판정기 규칙, 기존 감사 기록은 보존해야 합니다. 10단계에서 일어난 일의 전체 기록은 `audit/step10/`에 있습니다(`INDEX.md`에 파일 목록과 시간순 표, `npm run audit:export`가 만드는 `export-<UTC 시각>.json`, `deployments.json`). 내보낸 파일은 덮어쓰지 말고 새 내보내기는 새 이름으로 만드세요. 계정 ID 원문, 메모 제목·본문, 토큰, 키는 이 디렉토리에 넣지 마세요(계정은 `owner_` 가명만 씁니다). 확인되지 않은 사건은 추측해서 적지 말고 `INDEX.md`의 "확인되지 않은 것"에 남기세요. 반 엔진의 기록은 운영 측 것이라 이 저장소에는 없습니다.

11단계 접속 앱과 기기 승인: 보호 API(`/api/notes`, `/api/notes/:id`, `/api/announcements/:id`, `/api/restore/notes`)는 로그인과 함께 승인된 기기의 서명을 확인합니다(`src/device-signature.mjs`, 계약은 `docs/DEVICE_SIGNATURE.md`). 서명은 메서드·경로(쿼리 포함)·본문 해시·시각·일회용 번호·기기 ID를 덮으며, 서버는 실제로 받은 값으로 다시 검증합니다. 이 검사를 빼거나, 서명 없는 요청·서명 뒤 경로나 본문이 바뀐 요청을 통과시키지 마세요. 기기 승인은 `POST /api/devices`(`src/device-approval.mjs`)에서 서버가 최근 10분 안의 실제 로그인과 그 키의 서명을 확인할 때만 정합니다. 승인 버튼, 설치 여부, 브라우저가 보낸 값으로 승인하지 마세요. 기기 개인키는 내보낼 수 없게 만들어 화면 메모리에만 두고 브라우저 저장소에 넣지 마세요. 서비스 워커는 `/api/` 응답과 자료를 저장하지 않습니다.

비밀번호, 토큰, 서버 전용 키, 기기 개인키, 실제 개인정보를 코드·로그·답변·Git·제출 묶음에 넣지 마세요. 값이 필요하면 학생이 공식 설정 화면의 비밀 입력란에 직접 넣도록 안내하고, 값 자체를 요구하거나 다시 출력하지 마세요.

수정 뒤에는 학생이 실행할 명령 한 줄과 화면에서 누를 곳을 알려 주세요. 정상 결과와 거부되어야 할 결과를 각각 적으세요. 실제로 실행하지 않은 명령, 배포, 시험은 완료했다고 말하지 마세요. 오류가 나면 첫 오류와 이번에 바뀐 파일을 근거로 다음 한 가지 수정만 제안하세요.

학생이 되돌리기를 요청하면 `git status`와 `git diff`로 이번 단계 변경과 다른 변경을 구분하고, 사라질 내용을 먼저 보여 주세요. 다른 변경과 학습 DB 자료는 보존하세요. `git reset --hard`는 쓰지 마세요.

## 감사 기록 위치 (10단계)

10단계에서 메모를 만들고, 수정하고, 지우고, 복구한 기록은 데이터베이스(Supabase)에 쌓이고, 그 내용은 아래 파일에도 그대로 들어 있습니다. 데이터베이스를 직접 열지 않아도 이 파일들로 확인할 수 있습니다. 아래는 실제로 저장소에 있는 경로만 적었습니다.

| 무엇 | 경로 | 내용 |
|---|---|---|
| 처음 볼 문서 | `audit/step10/INDEX.md` | 파일 목록과 시간순 사건표, 확인되지 않은 것 |
| 메모 감사 기록(생성·수정·삭제·복구) | `audit/step10/db-audit-trail.jsonl` | 표 `secret_notes_restore_log`의 모든 줄. 한 줄에 사건 하나: `seq`, `noteId`, `owner`(가명), `mode`(`created`, `edited`, `deleted`, `updated`, `reinserted`, `unchanged`, `refused`), 거절 이유(`reason`), 바뀌기 전·후 내용 해시, 시각 |
| 메모 사본 정보 | `audit/step10/db-backups.jsonl` | 표 `secret_notes_backup`의 정보(메모 ID, `owner`, 내용 해시, 만든 시각). 제목과 본문은 없음 |
| 한 시점의 전체 내보내기 | `audit/step10/export-<UTC 시각>.json` | 위 두 기록과 10단계 저장점 커밋, 그 시점 `bundle`의 직접 점검 15개 결과 |
| 배포 이력 | `audit/step10/deployments.json` | 10단계 저장점의 Vercel 배포(배포 ID, 시각, 커밋, 상태) |
| 로컬 절차 기록 | `audit/restore-audit.log` | 정책 사본 검증·복원, 메모 사본 생성·검증, 내보내기를 실행한 기록 |
| 표를 만드는 SQL | `supabase/migrations/004_secret_notes_backup.sql`, `005_restore_log_unchanged.sql`, `006_note_audit_events.sql`, `007_audit_refusals_no_truncate.sql` | 사본 표, 감사 표, 추가 전용 트리거, 이벤트 이름과 해시 열, 거절 기록, 표 비우기(TRUNCATE) 금지 |
| 기록을 남기는 코드 | `src/note-audit.mjs`, `src/restore-note.mjs`, `src/note-backup.mjs`, `api/notes.js`, `api/notes/[id].js`, `api/restore/notes.js` | 생성·수정·삭제·복구(거절 포함) 때 기록과 사본을 쓰는 곳 |

- 위 `.jsonl` 파일은 `npm run audit:export`가 데이터베이스에서 새로 생긴 줄만 뒤에 이어 씁니다. 이미 있는 줄은 지우거나 고치지 않습니다.
- 계정은 `owner_` 뒤 10자리 해시로만 적습니다. 메모 제목·본문, 토큰, 키는 어느 파일에도 없습니다.
- 반 엔진(ALEPH SDP)의 기록은 운영 측이 가지고 있어서 이 저장소에 없습니다.
- 이 기록이 심판이 확인하는 감사 기록인지는 확인하지 못했습니다. 심판이 이 저장소의 파일을 읽는지, 배포된 앱을 부르는지도 확인하지 못했습니다.

## 저장점 규칙

저장점 요청을 받으면 README.md에 현재 작동하는 기능과 다시 실행하는 방법을 짧게 갱신하세요. `aleph.config.json`의 단계, 실제 배포 주소, 로그인 발급자 정보, 허용 경로, 5단계부터의 원본 API 주소를 구현과 대조하세요. `src/decider.mjs`의 `RULE_IDS`에는 실제로 구현한 규칙 이름만 남기세요.

`src/attack-check.mjs`는 `npm run bundle`이 실행하는 학생의 자기 점검입니다. 실제로 보낸 요청의 결과만 기록하고, 심판의 판정이라고 쓰지 마세요. 처음 단계의 공개 가상 메모와 이후 단계의 정상·거부 요청을 현재 자료실에 맞춰 갱신하세요. 실행하지 않은 점검은 미실행으로 남기세요.

`aleph.config.json`의 `judgeIssuer`는 운영 측이 ZIP을 만들 때 채운 심판 접수 서버 주소입니다. 학생 요청으로 바꾸거나 다른 발급자 주소로 대체하지 마세요.

커밋 전에 포함할 파일과 비밀값 검사 결과를 보여 주세요. 비밀번호·토큰·개인키·서버 전용 키·실명·메모 본문은 제출 묶음에서 제외하세요. `bundle-notes.json`과 `artifacts/submission.json`은 커밋하지 마세요. `npm run bundle`에서 오류가 나면 첫 오류만 근거로 한 가지를 고치고 다시 실행하세요.

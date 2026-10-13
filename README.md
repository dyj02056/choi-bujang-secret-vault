# BYTE BACK — secret-note vault (step 12)

## 출처: 제공 엔진과 학생 작업

| 구분 | 출처 | 무엇 | 위치 |
|---|---|---|---|
| **제공 엔진** | **ALEPH SDP 엔진** (운영 측 제공, 이 저장소에 코드 없음) | 신원·기기·경로를 먼저 확인하고 판정기를 부르는 릴레이, 사건 전달, 릴레이의 접속 회수, 심판 | 운영 측. 계약 문서만 `docs/DECIDER_REQUEST.md`, `docs/DETECT_EVENTS.md` (운영 측 제공) |
| 학생 작업 | 학생 | **판정기** | `src/decider.mjs` |
| 학생 작업 | 학생 | **탐지 규칙** (10분 GET 120건 초과 → 회수 제안, 서버 기록에 적용) | `src/detect.mjs`, `src/access-guard.mjs` |
| 학생 작업 | 학생 | **접속 앱** (설치형 화면, 패스키 기기 승인, 서명 요청, 탈환 작전실) | `public/`, `api/session.js`, `api/devices.js`, `src/device-*.mjs` |
| 학생 작업 | 학생 | **자료실** (메모·공지 API, 사본·복구, 감사 기록, 접근 관문, 작전실 요약) | `api/`, `src/`, `supabase/migrations/001`–`010` |

비밀값(비밀번호, 토큰, 서버 키, 기기 키)과 메모 본문은 이 안내와 저장소, 제출 묶음에 넣지 않습니다.
서버 키는 Vercel 환경 설정 화면과 학생 PC의 `.env`(Git 제외)에만 둡니다.

Private notes and instructor announcements are separate resource zones.
Private-note access continues to use verified login plus `owner_id` checks.
Instructor announcements use `/api/announcements/:id`; only a verified user
listed in the server-side `instructor_roles` table can modify an announcement.
The browser UI and existing note addresses are unchanged.

The decision policy accepts only exact single-resource routes with no query
string: note read, update, or delete; and announcement read. The decision
contract has no instructor role, so the policy denies every announcement write
(POST, PUT, PATCH, DELETE) for everyone and never opens a whole-list route.
Whether one note belongs to the caller is compared only at the API
(`owner_id`), and announcement updates are checked there against
`instructor_roles`. Unknown or nested routes are denied. Registered devices remain required, and a risky
private-note read still requires additional verification before it is allowed.

Step 9 adds a local burst-read detector in `src/detect.mjs`. It reads only the
time, request method and pseudonymous `identity.sub` of each virtual event.
When one subject has more than 120 `GET` events inside any 10-minute window it
returns `propose_revocation` with reason `burst_read` and that subject;
otherwise it returns `observe`. Exactly 120 events is not flagged, other
subjects are never added together, and the result keeps the same shape if the
subject keeps trying after a proposal. This code only proposes. Delivering real
events to the ALEPH SDP 엔진 and revoking access in its relay are not connected or tested here.

## Step 12: the operations room (탈환 작전실)

Sources are in the table at the top (**ALEPH SDP 엔진** provided by the operator; decider, detection rule, access app and vault by the student).

### Operations room

After a device is approved the app shows **탈환 작전실**. It first shows the **saved real response** recorded by
`npm run ops:snapshot` (`public/ops-summary.json`): that procedure logs in as test account A, sends a signed
`GET /api/ops/summary`, and right after it recounts the same account's masked server tables with the server key at the
same reference time, then stores both and a field-by-field comparison in `audit/step12/ops-snapshot-<UTC>.json`.
The screen shows the request ID and whether every field matched. "지금 실제 API로 다시 받기" replaces it with a live
response. The screen only shows values that are in a response and never computes or fills numbers itself. It shows,
for the logged-in account only: the decider rule names and zones, access
events of the last 10 minutes (request ID, route shape, outcome), revocation state and device counts, and the
restore audit summary (row counts per event, backups, last restore with a masked note reference). Every value
comes from that API response, whose request ID and server time are shown; until it is requested every box says
미실행. No note title or text is ever sent or shown. The same numbers can be recounted on the server with
`npm run ops:summary -- --owner <owner UUID>` (new requests are recorded after the screen was loaded, so the
event count can only grow).

### Access guard (every protected API)

`src/access-guard.mjs` runs after login on `/api/notes`, `/api/notes/:id`, `/api/announcements/:id`,
`/api/restore/notes` and `/api/ops/summary`. It gives each request an ID (response header `x-aleph-request-id`),
refuses a revoked identity (403 `IDENTITY_REVOKED`, even with a valid device signature), applies the step 11
device signature check, records an access event (route shape only, table `access_events`), and on a `GET`
applies the step 9 rule to those records: the 121st read within 10 minutes revokes the identity
(`identity_revocations`, reason `burst_read`) and all its devices. A revoked identity cannot approve a new device.
If the records cannot be read or written the request is refused (502).

The event's `outcome` is only the gate's decision (`gate_passed` means the gate let it through, not that the API
answered 200). The handler can still refuse (for example 403 `FORBIDDEN` for another user's note), so just before
the response is sent the server writes the final HTTP status to `access_results` (migration `010`). The operations
room shows that final result (`allowed` only for 2xx/3xx, otherwise the error code); an event without a result row is
shown as `not_recorded`, never as allowed. The summary request itself has no result row yet when it answers, so it is
`not_recorded` too; no other label is computed for it.

| Sequence | Result |
|---|---|
| Anonymous read, then another user's note read, back to back | 401, then 403 |
| Request from a device that was never approved, then from a revoked identity | 403 `DEVICE_NOT_APPROVED`, then 403 `IDENTITY_REVOKED` |
| After a restore: unsigned change request, then out-of-zone read | 401 `DEVICE_SIGNATURE_REQUIRED`, then 403 |

### The 1–11 check table

`npm run ops:record` runs `ops:checks` and then `ops:snapshot`. `npm run ops:checks` sends the normal and forbidden requests of steps 1–11 (the same 20 check IDs as
`npm run bundle`, `npm run bundle` itself sends none of them) and writes one row per request: step, normal/forbidden, expected result, observed API result,
server request ID and check time. Output: `audit/step12/checks-<UTC>.json` and `.md` (never overwritten) and
`public/ops-checks.json`, which the operations room shows. A check that could not be sent is `not_run` with its
reason. The operator's 41 judge tests are **not run** by this procedure and are shown as not run, never as passed.

### 12단계 실측 기록

`npm run ops:record`로 실제로 보낸 요청의 결과입니다. 계산해서 채운 값은 없습니다.

| 기록 | 파일 | 결과 |
|---|---|---|
| 작전실 실제 API 응답 | `public/ops-summary.json` (화면이 그대로 표시) | `GET /api/ops/summary` HTTP 200, 요청 ID `a6f8128c-c867-459f-bc35-eb522452c49f`, 서버 시각 2026-10-13T11:13:21.095Z |
| 같은 시점의 가린 서버 원본 줄 | `audit/step12/ops-snapshot-20261013T111335Z.json` (`maskedRecords`) | 계정 `owner_49c3b2ec3c`: 접근 사건 20줄, 그 사건의 최종 결과 19줄(`access_results`, 요약 요청 자신은 응답 뒤 기록이라 아직 없음), 10분 GET 6줄, 감사 기록 14줄, 기기 27줄, 사본 1줄. 최종 결과: allowed 7, forbidden 2, instructor_required 2, device_signature_mismatch 4, device_signature_required 2, device_not_approved 2, not_recorded 1(결과 줄이 없는 요약 요청 자신, 허용이나 다른 이름으로 채우지 않음). 대조 6항목 모두 일치 |
| 전체 계정의 가린 감사 기록 | `audit/step10/db-audit-trail.jsonl` | 같은 시점까지 이어 씀 (위 계정 줄은 `owner` 가 `owner_49c3b2ec3c` 인 줄) |
| 1~11단계 점검표 | `public/ops-checks.json`, `audit/step12/checks-20261013T111327Z.md` | 학생 자기 점검 20건 / 요청 24행: as_expected 22, not_run 2(회수된 시험 계정 C 요청은 보내지 않음, 6·7·9단계 규칙은 로컬 연습뿐이라 요청 없음). 익명 401 에도 요청 ID 가 붙음. `s12_ops_room_live_summary`: 작전실 API 가 이 실행에서 A 가 보낸 요청 7건을 모두 같은 HTTP 상태로 보여 줌. 검사한 커밋 `ee77b68`, 깨끗한 작업 트리 |
| 운영 심판 41종 시험 | — | **미실행** (이 저장소에서 실행하지 않음, 통과로 표시하지 않음) |

작전실 화면의 "화면 값과 가린 서버 기록 대조" 표는 위 두 기록의 같은 항목 값을 그대로 나란히 보여 줍니다.

"가린 서버 기록"은 요약이 아니라 **원본 줄**입니다. 실측 파일의 `maskedRecords`에 같은 계정(`owner_` 가명, `audit/step10`과 같은 방식)의
접근 사건 최근 20줄, 최근 10분 GET 줄, 복구 감사 기록 줄(메모는 `note_` 가명), 기기 상태, 회수 줄, 사본 목록이 그대로 있고,
`scripts/ops-snapshot.mjs`가 화면 API와 다른 코드로 이 줄들을 다시 세어 화면 값과 비교합니다. 누구나 같은 줄로 다시 셀 수 있습니다.
실측 끝에 `npm run audit:export`도 실행되어 `audit/step10/db-audit-trail.jsonl`(전체 계정의 가린 감사 기록)이 같은 시점까지 이어 쓰입니다.

순서: `npm run ops:record`가 점검표 요청을 먼저 보내고 바로 이어 작전실 실측을 받습니다. 그 기록을 커밋한 뒤 심판을 돌립니다.
`npm run bundle`(심판도 자기 실행기에서 다시 돌림)은 **실시간 요청을 하나도 보내지 않고** 20개 점검을 모두 `not_run: <이유>`로 적습니다.
그 실행에서 보낸 요청이 없으므로 예전 실측이 있어도 결과로 옮기지 않습니다. 로그인·기기 승인·익명 GET·원본 API 요청 모두 보내지 않으며,
시험 계정 값이 셸에 있어도 같습니다. 실제 요청과 그 결과(요청 ID, HTTP 결과, 확인 시각)는 로컬 점검표(`npm run ops:checks`,
`runAttackChecks(config, { allowWrites: true })`)에서만 나오고, 그 표가 `public/ops-checks.json`과 `audit/step12/checks-<UTC>`에 남아 작전실 화면에 그대로 보입니다.
점검표 요청마다 머리글 `x-aleph-attack-id`에 점검 ID를 붙이고, API 는 로그인 전 거절(401)에도 요청 ID(`x-aleph-request-id`)를 돌려줍니다.
점검표의 마지막 점검 `s12_ops_room_live_summary`가 작전실 API 를 실제로 불러, 그 실행에서 A 가 보낸 요청이 같은 HTTP 상태로 화면에 보이는지 대조합니다.
제출 묶음은 요청을 보내지 않으므로 커밋된 작전실 실측의 서버 기록을 바꾸지 않습니다.
그 전에 만든 `audit/step12/` 파일(토큰 만료로 미실행·401이 남은 실행 포함)도 실제로 일어난 기록이라 지우지 않았습니다.

### Install, run, stop, restore (from the checked commit)

| Part | Install | Run | Stop | Restore |
|---|---|---|---|---|
| Database | run `supabase/migrations/001`–`010` in order in the official Supabase SQL Editor | — | — | notes: `POST /api/restore/notes`; the audit, backup, event and revocation tables are append-only |
| Vault + access app | Vercel project from this repository; set `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `SUPABASE_SECRET_KEY` only in the Vercel environment screen | push to `main` (Vercel builds with `npm run build`) | roll back or pause the deployment in Vercel | redeploy a trusted commit; `npm run policy:diff` / `policy:restore` for routes |
| Student decider | `src/decider.mjs` | the ALEPH SDP 엔진 calls `decide(request)`; practice: `npm run decider:test` | revert the commit | `npm run policy:diff` shows rule differences from `policy/safe-policy.json` |
| Detection rule | `src/detect.mjs` | the access guard on every `GET`; practice: `npm run detect:test` | — | a revocation cannot be undone by the app; use a new test account |
| Self-check table | `npm install` | `npm run ops:checks`, then `npm run bundle` | — | — |

To check the revoked-identity path live, revoke a third test account C once with
`npm run ops:revoke -- --owner <C owner UUID>` (permanent) and give its login as `ALEPH_CHECK_EMAIL_C` /
`ALEPH_CHECK_PASSWORD_C` (or `ALEPH_CHECK_TOKEN_C`). Without it that half is reported as not run live.

No password, token, server key, device key or note text is part of this repository or the submission.

## Step 11: the access app and device approval

The page is now an installable app, **BYTE BACK 접속 앱** (`public/manifest.webmanifest`, `public/icon.svg`,
`public/sw.js`, `public/offline.html`). Installing it only makes it easier to open; it is **not** a device check.
Offline, the app shows a notice and never shows or stores notes; the service worker caches only the offline page,
icon and manifest, never `/api/` responses.

The screen keeps no key values and uses no browser storage: login and sign-up go through `POST /api/session`
on the server, which returns only a short-lived access token that the page keeps in memory (no refresh token, no
Supabase URL or key, no supabase-js in the page). `/api/auth-config` no longer returns any key. A reload therefore
asks for login again.

After login the app shows the **device approval** screen first. Notes stay hidden until the server approves
this device:

1. The device key is a **passkey** (WebAuthn, ES256) inside the operating system's authenticator (Windows Hello,
   Touch ID, phone screen lock). The page never creates, exports, shows or stores a key; it only attaches the
   authenticator's signature result. Nothing key-related goes into browser storage, Git or the submission.
2. "이 기기 등록·승인 요청" creates the passkey and sends `POST /api/devices` with its credential ID and public
   key (SPKI), signed by that same passkey. After a reload, "승인된 패스키로 자료실 열기" asks the server to check
   the existing passkey.
3. The server approves only if the login token shows a real login within the last 10 minutes; otherwise the
   device stays `pending` and the app asks for the password again. The button alone never grants access.
4. Every protected request (`/api/notes`, `/api/notes/:id`, `/api/announcements/:id`, `/api/restore/notes`)
   carries a passkey signature whose challenge is the hash of method, path with query, body SHA-256, time and a
   one-time number (the authenticator asks for confirmation each time). The server rebuilds
   that text from what it really received, so a request without a signature, or whose path or body changed after
   signing, is rejected. The full contract is in `docs/DEVICE_SIGNATURE.md`.

| Request | Result |
|---|---|
| Approved device, signed as sent | the earlier result (200 for own note, 403 for another user's note, ...) |
| Logged in, no signature | 401 `DEVICE_SIGNATURE_REQUIRED` |
| Path, query or method changed after signing, or a signature made for another site | 403 `DEVICE_SIGNATURE_MISMATCH` |
| Body changed after signing | 403 `DEVICE_SIGNATURE_MISMATCH` |
| Same signature sent again / older than 60 s | 403 `DEVICE_SIGNATURE_REPLAYED` / 401 `DEVICE_SIGNATURE_EXPIRED` |
| Pending, unknown or another account's device | 403 `DEVICE_NOT_APPROVED` |
| No login | 401 `UNAUTHORIZED` (unchanged) |

Setup: run `supabase/migrations/008_device_keys.sql` in the official Supabase SQL Editor **before deploying**
(tables `device_keys` and `device_nonces`, public keys only, no browser access). Without it every protected
request fails closed with 502. `/api/devices` is the app's own enrollment endpoint; it is not added to
`allowedRoutes` and the decider rules are unchanged.

## Step 10: restore from a verified backup

Everything here is local or server-side practice. Nothing below has been run against
the live app yet, and a passing local test is not a judge result.

### One-time setup (before any attack)

1. Run `supabase/migrations/004_secret_notes_backup.sql` in the official Supabase SQL
   Editor. It creates two private tables with no browser access: `secret_notes_backup`
   (rows cannot be changed or deleted afterwards) and `secret_notes_restore_log`
   (append only).
   After 004, also run `supabase/migrations/005_restore_log_unchanged.sql` once so that
   calls which change nothing can be recorded too, and then
   `supabase/migrations/006_note_audit_events.sql` **before deploying** the code that writes
   create, edit and delete events. 006 keeps every existing audit row and only adds two
   hash columns and the new event names. Then run
   `supabase/migrations/007_audit_refusals_no_truncate.sql` **before deploying**: it lets refused restore
   calls be recorded (`refused` with a reason code) and blocks `TRUNCATE` on the audit and backup tables.
   From this version a change is never made without its audit row, so the notes API refuses edits,
   deletes and restores until 006 and 007 are in place.
2. Every note created through `POST /api/notes` now also leaves its first version in the
   private backup automatically (once, never overwritten; a failed backup does not block
   the note). This means a restore returns a note to its **first saved version**, not to
   a later edit. A note that has no backup yet (for example one made before step 10) gets one
   automatically right before its first edit or delete through the API, so the version before the
   tampering is kept. If that backup cannot be written, the edit or delete is refused (502
   `BACKUP_UNAVAILABLE`). An existing backup is never overwritten. You can also copy a note by hand
   **before** it is tampered with.
   Put `SUPABASE_URL` and `SUPABASE_SECRET_KEY` only in your local `.env` or the
   official environment screen, then run `npm run backup:notes -- --note <B note UUID>`.
   It prints counts only, never note text, and never overwrites an existing backup row.
3. `policy/safe-policy.json` is the verified safe policy copy (version 1). It holds
   the rule names, allowed methods and routes, and its SHA-256 is checked on every use.

### Restore one note

| Item | Value |
|---|---|
| Service / route | `restore` / `POST /restore/notes` (file `api/restore/notes.js`) |
| Address | `POST /api/restore/notes` (listed as `restoreRoute` and in `allowedRoutes`) |
| Body | `{ "id": "<note UUID>" }` only. No query string, no owner or role in the body |
| Login | Required. Only the owner of the backed-up note can restore it |
| Checks | Backup row exists; its stored SHA-256 matches a fresh hash of its title and content; its owner equals the verified caller; an existing row with the same ID must have the same owner. The decision policy allows this route only as exactly `POST /restore/notes` with no query, whatever service name the engine gives it |
| Audit | Before any change the call is written to the append-only `secret_notes_restore_log` (note ID, owner, mode, time, and the content hash before and after, so the overwritten version is evidenced). If that cannot be written, nothing is changed and the call fails with 502 `AUDIT_UNAVAILABLE`. A call that changes nothing is recorded as `unchanged` (and also fails with 502 if that row cannot be written). Every refused call by a logged-in user is recorded too, as `refused` with a reason code and the caller as owner. The response carries `audit` |
| Writes | A tampered note is updated back; a deleted note is inserted again with the same ID and owner; nothing else is touched. The note is re-read and its ID, owner and hash are compared with the backup |
| Response | ID, `restored`, `mode` (`updated`, `reinserted`, `unchanged`), the hash and `audit` (`recorded`, `seq`). Never the note text |
| Refusals | 400 bad ID or query (`invalid_id`, `bad_request`), 401 no login (not recorded: no verified caller), 403 not your note (`not_owner`), 404 no backup (`no_backup`), 409 backup failed verification or owner conflict (`backup_integrity_failed`, `owner_conflict`), 502 database or audit record unavailable |

Only the note the caller names is touched, so other notes, the other account data and
the restore log are preserved. A repeated call changes nothing (`unchanged`).

### Compare and restore the policy

```powershell
npm run policy:diff      # read only: shows the safe version and only the differing items
npm run policy:restore   # preview of what would change
npm run policy:restore -- --yes
```

If the safe copy is missing, malformed or its hash does not match, both commands stop.
`--yes` writes only the items that differ from the copy, and only in `allowedRoutes` and `restoreRoute` of
`aleph.config.json`: a route missing from `allowedRoutes` is put back, while a route that is not in the
copy is shown and kept (other service rules are preserved) unless you also pass `--remove-extra`.
The copy is the step 9 policy (commit `46c9f94`) plus the one restore route; its `source` block lists
what is the same and what was added.
A difference in the decider rules (`src/decider.mjs`) is reported but never rewritten
automatically; compare it with the commit you trust and restore it by hand.

### Where the audit records are

A deployed function cannot write files into the repository, so the records live in four
places. Nothing below holds note titles, note text, tokens or keys.

| # | Record | Where | What it holds | Written by |
|---|---|---|---|---|
| 1 | Database table | `secret_notes_restore_log` in Supabase (created by `supabase/migrations/004`, widened by `005`, `006` and `007`). It is the one trail for every change to a note | note ID, owner, event, time, and the SHA-256 of the content before and after (never the text). Events: `created`, `edited`, `deleted` (written by the notes API) and `updated`, `reinserted`, `unchanged`, `refused` with `reason` (written by the restore route). Append only; update, delete and truncate are blocked by triggers (`004`, `007`) | `api/notes.js`, `api/notes/[id].js` and `src/restore-note.mjs`, through `src/note-audit.mjs`, before the change (a creation is written right after it) |
| 2 | Repository file | `audit/restore-audit.log`, one JSON line per event | time, action, policy version and hash, counts, whether anything was written | `scripts/policy-snapshot.mjs`, `policy-restore.mjs`, `backup-notes.mjs`, `backup-verify.mjs` |
| 3 | Restore response | `audit` (`recorded`, `seq`) in the body of every `POST /api/restore/notes` | the number of the row in record 1 | `src/restore-note.mjs` |
| 4 | ALEPH SDP 엔진 record | held by the operator, **not in this repository** | decisions the ALEPH SDP 엔진 made | the provided ALEPH SDP 엔진 |

### Everything that happened in step 10, kept in the repository

`audit/step10/` holds the records of what really happened in step 10, so they can be read
without opening the database. Start with `audit/step10/INDEX.md`: it lists every file and a
time-ordered table of the events, and says what is not known.

| File | What it is |
|---|---|
| `audit/step10/db-audit-trail.jsonl`, `audit/step10/db-backups.jsonl` | the database audit trail and the backup rows as append-only files with fixed names: one JSON line per event, only new lines are added by `npm run audit:export` |
| `audit/step10/export-<UTC time>.json` | the whole database audit trail (record 1), the backup rows without any note text, the step 10 save-point commits and the 15 checks of the last `npm run bundle`. Made by `npm run audit:export` |
| `audit/step10/deployments.json` | the Vercel deployments of the step 10 save points, copied as the Vercel API returned them |
| `audit/restore-audit.log` | the one-line log of the local procedures |

Run `npm run audit:export` again after any new restore, edit or delete to add a new export file;
an earlier export is never overwritten. Account IDs appear only as `owner_` plus ten characters of
their SHA-256, note text never appears, and the ALEPH SDP 엔진 record is still not in the repository.

### Where the backups and their logs are

| Backup | Where it lives | Log that it was made or checked |
|---|---|---|
| Note copies | private table `secret_notes_backup` in Supabase. The first version of every note is copied there automatically when the note is created, once, with its original `created_at` | the row itself (`backed_up_at`); for notes copied by hand, `npm run backup:notes -- --note <UUID>` adds a `note_backup_copied` line to `audit/restore-audit.log`; `npm run backup:verify` re-reads every copy, recomputes its hash and adds a `note_backups_verified` line |
| Safe policy copy | `policy/safe-policy.json` (SHA-256 checked on every use) | `policy_snapshot_created` when `npm run policy:snapshot` made it, `policy_copy_verified` each time `npm run backup:verify` re-checks it |

`audit/restore-audit.log` is only ever appended to. No script truncates or rewrites it, and
restoring the policy leaves it untouched. It records only what was really run: a verification
that could not run (for example without the server settings) writes no line. The lines
already in it came from running these scripts locally, including trials where
`allowedRoutes` was changed on purpose and then restored, and where the policy copy was
damaged on purpose and the check failed. The first policy copy was made before the log
existed, so it has no `policy_snapshot_created` line; its first line is `policy_copy_verified`.
The live restore records (record 1) are in the Supabase table, which the repository cannot show.

A restore changes only the one note that was named. Other notes, the order of the list
(`created_at` is copied into the backup and put back), the decider rules and the audit
records are not touched.

### Run after a restore (steps 1 to 9)

This README does not contain results. `npm run bundle` sends no live request at all: every row below is written as
`not_run` there. `npm run ops:checks` runs `src/attack-check.mjs` with writes allowed, which first gets one
virtual passkey authenticator approved per test account (`s11_device_approval`; its key exists only in that process), signs every
login request with it, and sends the requests below after the restore and writes only what really happened into the
submission (`attackAttempts`: expected, observed with HTTP status and time). A request
that could not be sent says `Not run: <reason>`. A result that is not the expected one
says `Needs review`; it is never turned into a pass.

| Attack ID | Step | Normal or forbidden | Expected | Needs |
|---|---|---|---|---|
| `s11_device_approval` | 11 | normal: A's virtual device is approved (runs first) | 200 approved | 2 fresh test logins |
| `s10_restore_own_note` | 10 | normal: B restores its own note | 200 | 2 test logins |
| `s1_public_page_normal` | 1 | normal: public page | 200 | nothing |
| `s8_own_note_read_after_restore` | 8 | normal: A reads its own note | 200 | 2 test logins |
| `s1_anonymous_notes_list` | 1 | forbidden: list without login | 401 or 403 | nothing |
| `s2_4_anonymous_note_by_id` | 2-4 | forbidden: one note without login | 401 or 403 | nothing |
| `s8_anonymous_announcement_write` | 8 | forbidden: announcement update without login | 401 or 403 | nothing |
| `s10_anonymous_restore_call` | 10 | forbidden: restore without login | 401 or 403 | nothing |
| `s5_original_api_without_key` | 5 | forbidden: original table API without a key | 401 or 403 | nothing |
| `s8_cross_zone_note_read` | 8 | forbidden: B reads A note | 403 | 2 test logins |
| `s8_announcement_write_non_instructor` | 8 | forbidden: non-instructor announcement update | 403 | 2 test logins |
| `s10_restore_other_users_note` | 10 | forbidden: A restores B note | 403 | 2 test logins |
| `s11_unsigned_protected_request` | 11 | forbidden: logged in, no device signature | 401 | 2 test logins |
| `s11_signed_path_changed` | 11 | forbidden: signed for A's note, sent to the list | 403 | 2 test logins |
| `s11_signed_body_changed` | 11 | forbidden: update body changed after signing (random note ID, nothing changes) | 403 | 2 test logins |
| `s6_unregistered_device_denied` | 6 | forbidden: unregistered device | deny | local practice |
| `s7_unusual_access_step_up` | 7 | forbidden: unusual region, network and hour together | step_up | local practice |
| `s9_burst_read_proposes_revocation` | 9 | forbidden: 121 reads in 10 minutes | propose_revocation | local practice |
| `s9_normal_reads_observed` | 9 | normal: 30 reads | observe | local practice |

The rows marked local practice run the decider and detector in this process with virtual
requests; they are not judge results. The rows that need two test logins are sent only when
you set these four values in your own shell (never in a file, chat or Git). Use the two test
accounts and a note owned by each. Either give their logins (the check logs in through `/api/session` itself, so the
token is always fresh) or tokens from a login **within the last 10 minutes** (device approval needs a recent login):

```powershell
$env:ALEPH_CHECK_TOKEN_A = '<test account A token>'
$env:ALEPH_CHECK_TOKEN_B = '<test account B token>'
$env:ALEPH_CHECK_NOTE_A  = '<A note UUID>'
$env:ALEPH_CHECK_NOTE_B  = '<B note UUID>'
# or, instead of the two tokens:
$env:ALEPH_CHECK_EMAIL_A = '<test account A email>'; $env:ALEPH_CHECK_PASSWORD_A = '<test account A password>'
$env:ALEPH_CHECK_EMAIL_B = '<test account B email>'; $env:ALEPH_CHECK_PASSWORD_B = '<test account B password>'
```

Order: tamper with or delete the B note, run `npm run ops:record`, commit its records, then run `npm run bundle` from that clean commit.
The restore call runs first, then every other check, so the other checks happen after the
data came back. Also run `npm run policy:diff`, `npm run decider:test`, `npm run detect:test`
`npm run test:restore` and `npm run test:audit`.

## Required database setup

Run `supabase/migrations/003_instructor_announcements.sql` in the official
Supabase SQL Editor. Then add the instructor's verified Auth user ID to
`instructor_roles` in that same official tool. Do not put account IDs,
announcement text, passwords, tokens, or server keys into this repository.

## Run and check

```powershell
npm run decider:test
npm run fixture:7
npm run detect:test
npm run test:restore
npm run test:audit
npm run test:device
npm run test:access
npm run policy:diff
npm run backup:verify -- --policy-only
npm run build -- --local
```

Expected normal result: an allowed note route or announcement route on a
registered device. Expected rejection: an unknown route, another user's note
request at the API, and a non-instructor announcement update. These commands
are local practice or build checks only; they are not live judge results.

## XDR bonus modules (student work)

`xdr/<moduleKey>/decide.mjs` answers each practice Wazuh-shaped alert in `xdr/fixtures/<moduleKey>.json` with
`{ action: block | alert | record, confidence, reason }`. Done: all six — `brute-force`, `web-injection`, `known-cve`, `persistence`, `privilege`, `exfiltration`.
`decide.mjs` has no `import`, reads and writes no file and asks nothing outside; `respond.mjs` writes `xdr/alerts.log`
(append only) and builds deny-rule candidates with an expiry time and the evidence alert IDs. The decider contract
(`docs/DECIDER_REQUEST.md`) has no source address, so those rules are candidates for the front relay; `src/decider.mjs`
is not changed by them.

`known-cve` (CVE-2021-44228 style requests, MITRE ATT&CK T1190): a complete `${jndi:<protocol>://…}` lookup in a
header or URL argument is `block` (confidence 0.9–0.99), a T1190 alert without that lookup is `alert` (0.6), anything
else is `record` (0). Patterns and their one-line evidence: `xdr/known-cve/patterns.json`.

```powershell
node xdr/known-cve/read-alerts.mjs
npm run xdr:run -- known-cve
node xdr/known-cve/respond.mjs
```

Expected: `경보 24건 · 뽑은 줄 24줄 · 일치`; `xdr/known-cve/result.json` counts block 8 · alert 8 · record 8 with no
normal event (kc-17–24) blocked; replay shows `정상 이벤트 막힘 0건`. `respond.mjs` appends 16 lines to `xdr/alerts.log`
on every run. These are local practice results, not judge results.

`persistence` (MITRE ATT&CK T1543 services and startup items, T1053 scheduled tasks): a T1543/T1053 alert at level 5 or
more starts at 0.6 (`alert`); clear signals add to it (unsigned new service, unfamiliar or random-named entry, executable
in the user Temp folder, startup folder, repeated registration, T1543 and T1053 together), and below level 10 it stays at
most 0.84, so it cannot `block`. Anything else is `record` (0). `respond.mjs` isolates one source address + account pair
per rule (never an account alone or the PC name alone, which also appear in normal events) and skips addresses seen in
normal events. Patterns and their one-line evidence: `xdr/persistence/patterns.json`.

```powershell
node xdr/persistence/read-alerts.mjs
npm run xdr:run -- persistence
node xdr/persistence/respond.mjs
```

Expected: `경보 24건 · 뽑은 줄 24줄 · 일치`; `xdr/persistence/result.json` counts block 8 · alert 8 · record 8 with no
normal event (ps-17–24, including user01's normal login) blocked; replay shows `정상 이벤트 막힘 0건`. `respond.mjs`
appends 16 lines to `xdr/alerts.log` on every run. Local practice results, not judge results.

`privilege` (MITRE ATT&CK T1068 privilege escalation, T1078 valid accounts): a T1068/T1078 alert at level 5 or more
starts at 0.6 (`alert`); clear signals add to it (the alert's group value is `administrators` — not the description
text, which can say "not the administrators group" —, an admin command together with a first-seen address, a just-promoted
account or another account's rights, use outside class or work hours, repeated admin grants, T1068 and T1078 together),
and below level 10 it stays at most 0.84, so it cannot `block`. Anything else is `record` (0). `respond.mjs` revokes
the session of one source address + account pair per rule (never a whole account: the attacked accounts also log in
normally from other addresses) and skips addresses seen in normal events. Patterns and their one-line evidence:
`xdr/privilege/patterns.json`.

```powershell
node xdr/privilege/read-alerts.mjs
npm run xdr:run -- privilege
node xdr/privilege/respond.mjs
```

Expected: `경보 26건 · 뽑은 줄 26줄 · 일치`; `xdr/privilege/result.json` counts block 9 · alert 8 · record 9 with no
normal event (pv-18–26) blocked; replay shows `정상 이벤트 막힘 0건`. `respond.mjs` appends 17 lines to
`xdr/alerts.log` on every run. Local practice results, not judge results.

`exfiltration` (MITRE ATT&CK T1041 exfiltration over the command channel, T1048 over an alternative protocol): a
T1041/T1048 alert at level 5 or more starts at 0.6 (`alert`); clear signals add 0.15 each, mostly from the alert's
numbers rather than its text (50 MB or more in `bytes`, a first-seen destination, outside class or work hours, an
archive file sent at that size, 5 or more repeats in `count`, 50 or more `files`, an unusual port or protocol), and
below level 10 it stays at most 0.84, so it cannot `block`. Anything else is `record` (0). `respond.mjs` blocks one
destination address (`dstip`) per rule — never a source address or account — and never a destination that normal
events use (the repository addresses). Patterns and their one-line evidence: `xdr/exfiltration/patterns.json`.

```powershell
node xdr/exfiltration/read-alerts.mjs
npm run xdr:run -- exfiltration
node xdr/exfiltration/respond.mjs
```

Expected: `경보 30건 · 뽑은 줄 30줄 · 일치`; `xdr/exfiltration/result.json` counts block 10 · alert 10 · record 10
with no normal event (ex-21–30) blocked; replay shows `정상 이벤트 막힘 0건`. `respond.mjs` appends 20 lines to
`xdr/alerts.log` on every run. Local practice results, not judge results.

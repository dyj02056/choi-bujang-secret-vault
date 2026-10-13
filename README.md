# BYTE BACK — secret-note vault (step 10)

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
events to the class engine and revoking access are not connected or tested here.

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
   hash columns and the new event names.
2. Every note created through `POST /api/notes` now also leaves its first version in the
   private backup automatically (once, never overwritten; a failed backup does not block
   the note). This means a restore returns a note to its **first saved version**, not to
   a later edit. For a note that already exists, copy it to the private backup **before**
   it is tampered with.
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
| Checks | Backup row exists; its stored SHA-256 matches a fresh hash of its title and content; its owner equals the verified caller; an existing row with the same ID must have the same owner |
| Audit | Before any change the call is written to the append-only `secret_notes_restore_log` (note ID, owner, mode, time, and the content hash before and after, so the overwritten version is evidenced). If that cannot be written, nothing is changed and the call fails with 502 `AUDIT_UNAVAILABLE`. A call that changes nothing is recorded as `unchanged`. The response carries `audit.seq` |
| Writes | A tampered note is updated back; a deleted note is inserted again with the same ID and owner; nothing else is touched. The note is re-read and its ID, owner and hash are compared with the backup |
| Response | ID, `restored`, `mode` (`updated`, `reinserted`, `unchanged`), the hash and `audit` (`recorded`, `seq`). Never the note text |
| Refusals | 400 bad ID, 401 no login, 403 not your note, 404 no backup, 409 backup failed verification or owner conflict, 502 audit record could not be written |

Only the note the caller names is touched, so other notes, the other account data and
the restore log are preserved. A repeated call changes nothing (`unchanged`).

### Compare and restore the policy

```powershell
npm run policy:diff      # read only: shows the safe version and only the differing items
npm run policy:restore   # preview of what would change
npm run policy:restore -- --yes
```

If the safe copy is missing, malformed or its hash does not match, both commands stop.
`--yes` rewrites only `allowedRoutes` and `restoreRoute` in `aleph.config.json`.
A difference in the decider rules (`src/decider.mjs`) is reported but never rewritten
automatically; compare it with the commit you trust and restore it by hand.

### Where the audit records are

A deployed function cannot write files into the repository, so the records live in four
places. Nothing below holds note titles, note text, tokens or keys.

| # | Record | Where | What it holds | Written by |
|---|---|---|---|---|
| 1 | Database table | `secret_notes_restore_log` in Supabase (created by `supabase/migrations/004`, widened by `005` and `006`). It is the one trail for every change to a note | note ID, owner, event, time, and the SHA-256 of the content before and after (never the text). Events: `created`, `edited`, `deleted` (written by the notes API) and `updated`, `reinserted`, `unchanged` (written by the restore route). Append only; update and delete are blocked by a trigger | `api/notes.js`, `api/notes/[id].js` and `src/restore-note.mjs`, through `src/note-audit.mjs`, before the change (a creation is written right after it) |
| 2 | Repository file | `audit/restore-audit.log`, one JSON line per event | time, action, policy version and hash, counts, whether anything was written | `scripts/policy-snapshot.mjs`, `policy-restore.mjs`, `backup-notes.mjs`, `backup-verify.mjs` |
| 3 | Restore response | `audit` (`recorded`, `seq`) in the body of every `POST /api/restore/notes` | the number of the row in record 1 | `src/restore-note.mjs` |
| 4 | Class engine record | held by the class operator, **not in this repository** | decisions the engine made | the provided ALEPH SDP engine |

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
their SHA-256, note text never appears, and the class engine record is still not in the repository.

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

This README does not contain results. `npm run bundle` runs `src/attack-check.mjs`, which
sends the requests below after the restore and writes only what really happened into the
submission (`attackAttempts`: expected, observed with HTTP status and time). A request
that could not be sent says `Not run: <reason>`. A result that is not the expected one
says `Needs review`; it is never turned into a pass.

| Attack ID | Step | Normal or forbidden | Expected | Needs |
|---|---|---|---|---|
| `s10_restore_own_note` | 10 | normal: B restores its own note (runs first) | 200 | 2 test logins |
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
| `s6_unregistered_device_denied` | 6 | forbidden: unregistered device | deny | local practice |
| `s7_unusual_access_step_up` | 7 | forbidden: unusual region, network and hour together | step_up | local practice |
| `s9_burst_read_proposes_revocation` | 9 | forbidden: 121 reads in 10 minutes | propose_revocation | local practice |
| `s9_normal_reads_observed` | 9 | normal: 30 reads | observe | local practice |

The rows marked local practice run the decider and detector in this process with virtual
requests; they are not judge results. The rows that need two test logins are sent only when
you set these four values in your own shell (never in a file, chat or Git). Use the two test
accounts, a note owned by each, and a token that is still valid:

```powershell
$env:ALEPH_CHECK_TOKEN_A = '<test account A token>'
$env:ALEPH_CHECK_TOKEN_B = '<test account B token>'
$env:ALEPH_CHECK_NOTE_A  = '<A note UUID>'
$env:ALEPH_CHECK_NOTE_B  = '<B note UUID>'
```

Order: tamper with or delete the B note, then run `npm run bundle` from a clean commit.
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
npm run policy:diff
npm run backup:verify -- --policy-only
npm run build -- --local
```

Expected normal result: an allowed note route or announcement route on a
registered device. Expected rejection: an unknown route, another user's note
request at the API, and a non-instructor announcement update. These commands
are local practice or build checks only; they are not live judge results.

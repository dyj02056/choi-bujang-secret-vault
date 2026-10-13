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
| Writes | A tampered note is updated back; a deleted note is inserted again with the same ID and owner; nothing else is touched. The note is re-read and its ID, owner and hash are compared with the backup |
| Response | ID, `restored`, `mode` (`updated`, `reinserted`, `unchanged`) and the hash. Never the note text |
| Refusals | 400 bad ID, 401 no login, 403 not your note, 404 no backup, 409 backup failed verification or owner conflict |

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

### Run after a restore (steps 1 to 9)

Record only what you actually sent. Every row is **not run** until you run it.

| Step | Normal request | Forbidden request | Expected | Status |
|---|---|---|---|---|
| 1 | Public page opens | Notes without login | 401 | not run |
| 2-4 | Logged-in note list | Missing or invalid token | 401 | not run |
| 5 | App API with login | Original Supabase table with the public key | rejected | not run |
| 6 | Registered device read | Unregistered device (`npm run decider:test`) | deny | not run |
| 7 | Normal read | Unusual region, network and hour together | step-up | not run |
| 8 | Own note read | B reads A note; announcement write by anyone | 403 | not run |
| 9 | Normal reads (`npm run detect:test`) | More than 120 reads in 10 minutes | revocation proposal | not run |
| 10 | Restore B note, then read it | Restore as another user, or after a damaged backup | 403 / 409 | not run |

Order: tamper with the B note, call the restore route, read the B note and compare,
send the step 1 to 9 forbidden requests again, then run `npm run policy:diff` and the
local checks (`npm run decider:test`, `npm run detect:test`, `npm run test:restore`).

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
npm run policy:diff
npm run build -- --local
```

Expected normal result: an allowed note route or announcement route on a
registered device. Expected rejection: an unknown route, another user's note
request at the API, and a non-instructor announcement update. These commands
are local practice or build checks only; they are not live judge results.

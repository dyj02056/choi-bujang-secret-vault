# BYTE BACK — secret-note vault (step 9)

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
npm run build -- --local
```

Expected normal result: an allowed note route or announcement route on a
registered device. Expected rejection: an unknown route, another user's note
request at the API, and a non-instructor announcement update. These commands
are local practice or build checks only; they are not live judge results.

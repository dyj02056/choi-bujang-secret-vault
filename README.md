# BYTE BACK — secret-note vault (step 6)

This app protects private notes with verified Supabase login and server-side
ownership checks. The browser calls only `/api/notes` and `/api/notes/:id`;
the server permits access only when `owner_id` matches the verified user.
Direct browser access to the `secret_notes` table remains blocked.

Step 6 adds one decision policy: requests from a registered device are allowed;
requests from an unregistered device are denied. The policy uses only the
engine-provided `deviceRegistered` value and does not store device details,
credentials, or note contents.

## Run and check

```powershell
npm run decider:test
```

Expected normal result: a virtual request with `deviceRegistered: true` is
allowed. Expected rejection: the same request with `deviceRegistered: false`
is denied with `device_not_registered`.

`npm run decider:test` is local practice only; it is not a live judge result.

To check the existing UI, start the app using the project's normal local
workflow, sign in, and open the note list. Your own notes should be visible.
Requests without a valid login should return `401`, and another user's note
ID should return `403`.

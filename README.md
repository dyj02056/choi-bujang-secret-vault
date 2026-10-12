# BYTE BACK — secret-note vault (step 7)

This app protects private notes with verified Supabase login and server-side
ownership checks. The browser calls only `/api/notes` and `/api/notes/:id`;
the server permits access only when `owner_id` matches the verified user.
Direct browser access to the `secret_notes` table remains blocked.

Registered devices are allowed by the decision policy. A registered-device
read request from a foreign region, on an unusual network, during an unusual
hour requires a fresh additional verification. After that verification, the
same request is allowed. An unregistered device remains denied.

The policy uses only the engine-provided `deviceRegistered`, `signals`, and
`stepUp` request values. It does not store device details, credentials, or
note contents, and it does not make external location or network lookups.

## Run and check

```powershell
npm run decider:test
npm run fixture:7
```

Expected normal result: a virtual registered-device request is allowed.
Expected additional-verification result: the suspicious virtual read returns
`step_up`, then is allowed after `stepUp.verified` is true. An unregistered
virtual request is denied with `device_not_registered`.

These commands are local practice only; they are not live judge results.

To check the existing UI, start the app using the project's normal local
workflow, sign in, and open the note list. Your own notes should be visible.
Requests without a valid login should return `401`, and another user's note
ID should return `403`.

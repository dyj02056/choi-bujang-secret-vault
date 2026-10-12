-- Step 8: separate instructor announcements from private student notes.
-- Run this file in the official Supabase SQL Editor. Do not add real account
-- identifiers, announcement text, or service-role keys to this repository.

CREATE TABLE IF NOT EXISTS instructor_roles (
  user_id uuid PRIMARY KEY,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS instructor_announcements (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  title text NOT NULL,
  content text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE instructor_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE instructor_announcements ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE instructor_roles FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE instructor_announcements FROM PUBLIC, anon, authenticated;

-- After this migration, add the instructor's verified Auth user ID only in the
-- official Supabase SQL Editor. Keep that identifier out of source control.

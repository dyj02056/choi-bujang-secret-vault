-- Step 12: access events (what the detector reads) and revoked identities (what the APIs refuse).
-- Run this file in the official Supabase SQL Editor BEFORE deploying the step 12 code:
-- from step 12 every protected API reads and writes these tables and fails closed without them.
-- No note titles or text, tokens, keys or raw account names are stored here.

-- One row per logged-in request to a protected API, written by the server before the handler runs.
-- route is the shape only (for example "GET /notes/:id"), never the note ID or query text.
CREATE TABLE IF NOT EXISTS access_events (
  seq        bigserial PRIMARY KEY,
  request_id uuid NOT NULL UNIQUE,
  owner_id   uuid NOT NULL,
  method     text NOT NULL CHECK (method ~ '^[A-Z]{3,7}$'),
  route      text NOT NULL CHECK (char_length(route) <= 80),
  outcome    text NOT NULL CHECK (outcome ~ '^[a-z_]{3,40}$'),
  device_id  text CHECK (device_id IS NULL OR device_id ~ '^[0-9a-f]{16}$'),
  at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS access_events_owner_at ON access_events (owner_id, at DESC);

-- A revoked identity stays revoked: rows can be added but never changed or removed.
CREATE TABLE IF NOT EXISTS identity_revocations (
  owner_id   uuid PRIMARY KEY,
  reason     text NOT NULL CHECK (reason IN ('burst_read', 'manual')),
  request_id uuid,
  revoked_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE access_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_revocations ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE access_events FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE identity_revocations FROM PUBLIC, anon, authenticated;
REVOKE ALL ON SEQUENCE access_events_seq_seq FROM PUBLIC, anon, authenticated;

-- Append only, using the function from 004.
DROP TRIGGER IF EXISTS access_events_no_change ON access_events;
CREATE TRIGGER access_events_no_change
  BEFORE UPDATE OR DELETE ON access_events
  FOR EACH ROW EXECUTE FUNCTION secret_notes_backup_immutable();
DROP TRIGGER IF EXISTS access_events_no_truncate ON access_events;
CREATE TRIGGER access_events_no_truncate
  BEFORE TRUNCATE ON access_events
  FOR EACH STATEMENT EXECUTE FUNCTION secret_notes_backup_immutable();

DROP TRIGGER IF EXISTS identity_revocations_no_change ON identity_revocations;
CREATE TRIGGER identity_revocations_no_change
  BEFORE UPDATE OR DELETE ON identity_revocations
  FOR EACH ROW EXECUTE FUNCTION secret_notes_backup_immutable();
DROP TRIGGER IF EXISTS identity_revocations_no_truncate ON identity_revocations;
CREATE TRIGGER identity_revocations_no_truncate
  BEFORE TRUNCATE ON identity_revocations
  FOR EACH STATEMENT EXECUTE FUNCTION secret_notes_backup_immutable();

-- Step 10: private backup copy of virtual notes and an append-only restore log.
-- Run this file in the official Supabase SQL Editor. Do not add real account
-- identifiers, note text, or service-role keys to this repository.

CREATE TABLE IF NOT EXISTS secret_notes_backup (
  id             uuid PRIMARY KEY,
  owner_id       uuid NOT NULL,
  title          text NOT NULL,
  content        text NOT NULL,
  content_sha256 text NOT NULL CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
  created_at     timestamptz,
  backed_up_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS secret_notes_restore_log (
  seq         bigserial PRIMARY KEY,
  note_id     uuid NOT NULL,
  owner_id    uuid NOT NULL,
  mode        text NOT NULL CHECK (mode IN ('updated', 'reinserted')),
  restored_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE secret_notes_backup ENABLE ROW LEVEL SECURITY;
ALTER TABLE secret_notes_restore_log ENABLE ROW LEVEL SECURITY;

-- No policies and no grants: only the server-only key used by the API can reach these tables.
REVOKE ALL ON TABLE secret_notes_backup FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE secret_notes_restore_log FROM PUBLIC, anon, authenticated;
REVOKE ALL ON SEQUENCE secret_notes_restore_log_seq_seq FROM PUBLIC, anon, authenticated;

-- A backup row can be inserted once; later changes and deletes are refused even for the server key.
CREATE OR REPLACE FUNCTION secret_notes_backup_immutable() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'secret_notes_backup rows are immutable';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS secret_notes_backup_no_change ON secret_notes_backup;
CREATE TRIGGER secret_notes_backup_no_change
  BEFORE UPDATE OR DELETE ON secret_notes_backup
  FOR EACH ROW EXECUTE FUNCTION secret_notes_backup_immutable();

-- The restore log is append-only too.
DROP TRIGGER IF EXISTS secret_notes_restore_log_no_change ON secret_notes_restore_log;
CREATE TRIGGER secret_notes_restore_log_no_change
  BEFORE UPDATE OR DELETE ON secret_notes_restore_log
  FOR EACH ROW EXECUTE FUNCTION secret_notes_backup_immutable();

-- Step 10 follow-up: record refused restore calls too, and protect the audit trail and the
-- backups from being emptied. Run this file in the official Supabase SQL Editor after 004,
-- 005 and 006, BEFORE deploying the code that writes 'refused' rows.
-- Existing audit rows and backups stay as they are: no row is updated or deleted here.
-- Note titles and text are never stored in the audit table, only SHA-256 hashes.

-- A refused call may name no valid note (for example a malformed ID), so the note ID may be empty.
-- For a refused call owner_id is the verified caller.
ALTER TABLE secret_notes_restore_log
  ALTER COLUMN note_id DROP NOT NULL,
  ADD COLUMN IF NOT EXISTS reason text;

ALTER TABLE secret_notes_restore_log
  DROP CONSTRAINT IF EXISTS secret_notes_restore_log_mode_check,
  DROP CONSTRAINT IF EXISTS secret_notes_restore_log_reason_check;

ALTER TABLE secret_notes_restore_log
  ADD CONSTRAINT secret_notes_restore_log_mode_check
    CHECK (mode IN ('created', 'edited', 'deleted', 'updated', 'reinserted', 'unchanged', 'refused')),
  ADD CONSTRAINT secret_notes_restore_log_reason_check
    CHECK (
      (mode = 'refused' AND reason IN ('bad_request', 'invalid_id', 'no_backup', 'backup_integrity_failed',
                                       'not_owner', 'owner_conflict', 'db_unavailable'))
      OR (mode <> 'refused' AND reason IS NULL)
    );

-- Row triggers from 004 already refuse UPDATE and DELETE. TRUNCATE skips row triggers,
-- so refuse it with statement triggers on both tables.
DROP TRIGGER IF EXISTS secret_notes_restore_log_no_truncate ON secret_notes_restore_log;
CREATE TRIGGER secret_notes_restore_log_no_truncate
  BEFORE TRUNCATE ON secret_notes_restore_log
  FOR EACH STATEMENT EXECUTE FUNCTION secret_notes_backup_immutable();

DROP TRIGGER IF EXISTS secret_notes_backup_no_truncate ON secret_notes_backup;
CREATE TRIGGER secret_notes_backup_no_truncate
  BEFORE TRUNCATE ON secret_notes_backup
  FOR EACH STATEMENT EXECUTE FUNCTION secret_notes_backup_immutable();

-- Step 10 follow-up: one append-only audit trail for create, edit, delete and restore.
-- Run this file in the official Supabase SQL Editor after 004 and 005, BEFORE deploying the code
-- that writes these events. Existing audit rows stay as they are: only a column check is
-- widened and two nullable hash columns are added. The append-only triggers are untouched.
-- Note titles and text are never stored here, only SHA-256 hashes.

ALTER TABLE secret_notes_restore_log
  ADD COLUMN IF NOT EXISTS before_sha256 text,
  ADD COLUMN IF NOT EXISTS after_sha256 text;

ALTER TABLE secret_notes_restore_log
  DROP CONSTRAINT IF EXISTS secret_notes_restore_log_before_sha256_check,
  DROP CONSTRAINT IF EXISTS secret_notes_restore_log_after_sha256_check,
  DROP CONSTRAINT IF EXISTS secret_notes_restore_log_mode_check;

ALTER TABLE secret_notes_restore_log
  ADD CONSTRAINT secret_notes_restore_log_before_sha256_check
    CHECK (before_sha256 IS NULL OR before_sha256 ~ '^[0-9a-f]{64}$'),
  ADD CONSTRAINT secret_notes_restore_log_after_sha256_check
    CHECK (after_sha256 IS NULL OR after_sha256 ~ '^[0-9a-f]{64}$'),
  ADD CONSTRAINT secret_notes_restore_log_mode_check
    CHECK (mode IN ('created', 'edited', 'deleted', 'updated', 'reinserted', 'unchanged'));

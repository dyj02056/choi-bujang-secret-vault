-- Step 10 follow-up: record restore calls that changed nothing as well.
-- Run this file in the official Supabase SQL Editor after 004. It only widens the
-- allowed values of one column; existing audit rows and the append-only triggers stay as they are.

ALTER TABLE secret_notes_restore_log
  DROP CONSTRAINT IF EXISTS secret_notes_restore_log_mode_check;

ALTER TABLE secret_notes_restore_log
  ADD CONSTRAINT secret_notes_restore_log_mode_check
  CHECK (mode IN ('updated', 'reinserted', 'unchanged'));

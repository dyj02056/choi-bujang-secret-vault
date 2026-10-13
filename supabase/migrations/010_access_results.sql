-- Step 12 fix: the final HTTP result of each protected request.
-- access_events.outcome is what the access gate decided BEFORE the handler ran ("gate_passed" means the
-- gate let it through, not that the API answered 200). The handler can still refuse (for example 403 for
-- another user's note), so the server also writes the final status here just before the response is sent.
-- The operations room shows this final result. Run this file in the official Supabase SQL Editor
-- BEFORE deploying the code that uses it. No note titles or text, tokens, keys or raw account names.
CREATE TABLE IF NOT EXISTS access_results (
  request_id uuid PRIMARY KEY REFERENCES access_events (request_id),
  status     smallint NOT NULL CHECK (status BETWEEN 100 AND 599),
  error      text CHECK (error IS NULL OR error ~ '^[A-Z_]{3,40}$'),
  at         timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE access_results ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE access_results FROM PUBLIC, anon, authenticated;

-- Append only, using the function from 004.
DROP TRIGGER IF EXISTS access_results_no_change ON access_results;
CREATE TRIGGER access_results_no_change
  BEFORE UPDATE OR DELETE ON access_results
  FOR EACH ROW EXECUTE FUNCTION secret_notes_backup_immutable();
DROP TRIGGER IF EXISTS access_results_no_truncate ON access_results;
CREATE TRIGGER access_results_no_truncate
  BEFORE TRUNCATE ON access_results
  FOR EACH STATEMENT EXECUTE FUNCTION secret_notes_backup_immutable();

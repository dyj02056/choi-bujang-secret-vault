-- Step 11: device approval and signed protected requests for the access app.
-- Run this file in the official Supabase SQL Editor BEFORE deploying the step 11 code:
-- from step 11 every protected API reads these tables, so without them protected requests fail closed.
-- Only public keys are stored. Private device keys never leave the device and must never be put here.

CREATE TABLE IF NOT EXISTS device_keys (
  device_id   text PRIMARY KEY CHECK (device_id ~ '^[0-9a-f]{16}$'),
  owner_id    uuid NOT NULL,
  public_key  jsonb NOT NULL CHECK (
    public_key ?& ARRAY['kty', 'crv', 'x', 'y'] AND NOT public_key ? 'd'
    AND public_key->>'kty' = 'EC' AND public_key->>'crv' = 'P-256'
  ),
  status      text NOT NULL CHECK (status IN ('pending', 'approved', 'revoked')),
  label       text CHECK (label IS NULL OR char_length(label) <= 40),
  created_at  timestamptz NOT NULL DEFAULT now(),
  approved_at timestamptz,
  CHECK ((status = 'approved') = (approved_at IS NOT NULL) OR status = 'revoked')
);
CREATE INDEX IF NOT EXISTS device_keys_owner ON device_keys (owner_id);

-- One row per signature that was accepted, so the same signed request cannot be sent twice.
CREATE TABLE IF NOT EXISTS device_nonces (
  device_id text NOT NULL CHECK (device_id ~ '^[0-9a-f]{16}$'),
  nonce     uuid NOT NULL,
  used_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (device_id, nonce)
);

ALTER TABLE device_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_nonces ENABLE ROW LEVEL SECURITY;

-- No policies and no grants: only the server-only key used by the API can reach these tables.
REVOKE ALL ON TABLE device_keys FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE device_nonces FROM PUBLIC, anon, authenticated;

-- The public key and owner of a device can never be swapped after registration.
CREATE OR REPLACE FUNCTION device_keys_fixed_identity() RETURNS trigger AS $$
BEGIN
  IF NEW.device_id <> OLD.device_id OR NEW.owner_id <> OLD.owner_id OR NEW.public_key <> OLD.public_key THEN
    RAISE EXCEPTION 'device key identity is fixed';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS device_keys_fixed_identity ON device_keys;
CREATE TRIGGER device_keys_fixed_identity
  BEFORE UPDATE ON device_keys
  FOR EACH ROW EXECUTE FUNCTION device_keys_fixed_identity();

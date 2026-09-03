-- Front Porch Economics — D1 Schema
--
-- Fresh install (new database):
--   npx wrangler d1 execute front-porch-economics --remote --file=worker/migrate.sql
--
-- Existing database:
--   Run the ALTER TABLE statements at the bottom once for any missing columns.
--   The CREATE TABLE IF NOT EXISTS blocks are safe to re-run.

CREATE TABLE IF NOT EXISTS signups (
  email              TEXT PRIMARY KEY,
  name               TEXT,
  neighborhood       TEXT,
  building           TEXT,
  phone               TEXT,
  pin                 TEXT,
  pin_expires_at      INTEGER,
  pin_attempts        INTEGER NOT NULL DEFAULT 0,
  pin_requested_at    INTEGER,
  created_at          INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS sessions (
  id          TEXT PRIMARY KEY,
  email       TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS saved_links (
  id          TEXT PRIMARY KEY,
  email       TEXT NOT NULL,
  url         TEXT NOT NULL,
  title       TEXT,
  notes       TEXT,
  listing_id  TEXT,
  link_type   TEXT NOT NULL DEFAULT 'external',
  created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS passkey_credentials (
  credential_id  TEXT    PRIMARY KEY,
  email          TEXT    NOT NULL,
  public_key     TEXT    NOT NULL,
  sign_count     INTEGER NOT NULL DEFAULT 0,
  transports     TEXT,
  created_at     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_passkey_email ON passkey_credentials (email);

-- Existing DB only: add missing columns to signups.
-- Run each statement once; SQLite will error if a column already exists.
-- ALTER TABLE signups ADD COLUMN phone TEXT;
-- ALTER TABLE signups ADD COLUMN pin TEXT;
-- ALTER TABLE signups ADD COLUMN pin_expires_at INTEGER;
-- ALTER TABLE signups ADD COLUMN pin_attempts INTEGER NOT NULL DEFAULT 0;
-- ALTER TABLE signups ADD COLUMN pin_requested_at INTEGER;
-- ALTER TABLE signups ADD COLUMN webauthn_challenge TEXT;
-- ALTER TABLE signups ADD COLUMN webauthn_challenge_exp INTEGER;

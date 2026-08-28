-- Front Porch Economics — D1 Schema
--
-- Fresh install (new database):
--   npx wrangler d1 execute front-porch-economics --remote --file=worker/migrate.sql
--
-- Existing database (already has signups table without phone/pin columns):
--   Run only the ALTER TABLE lines at the bottom of this file.
--   The CREATE TABLE IF NOT EXISTS blocks are safe to re-run — they skip existing tables.

CREATE TABLE IF NOT EXISTS signups (
  email            TEXT PRIMARY KEY,
  name             TEXT,
  neighborhood     TEXT,
  building         TEXT,
  phone            TEXT,
  pin              TEXT,
  pin_expires_at   INTEGER,
  created_at       INTEGER NOT NULL DEFAULT (unixepoch())
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

-- Existing DB only: add missing columns to signups.
-- These error if columns already exist — safe to ignore those errors.
-- ALTER TABLE signups ADD COLUMN phone TEXT;
-- ALTER TABLE signups ADD COLUMN pin TEXT;
-- ALTER TABLE signups ADD COLUMN pin_expires_at INTEGER;

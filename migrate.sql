-- Run these in Cloudflare D1 dashboard or via wrangler d1 execute

-- Add phone, pin, pin_expires_at to signups
ALTER TABLE signups ADD COLUMN phone TEXT;
ALTER TABLE signups ADD COLUMN pin TEXT;
ALTER TABLE signups ADD COLUMN pin_expires_at INTEGER;

-- Sessions table
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

-- Saved links table
CREATE TABLE IF NOT EXISTS saved_links (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  url TEXT NOT NULL,
  title TEXT,
  notes TEXT,
  listing_id TEXT,
  link_type TEXT NOT NULL DEFAULT 'external',
  created_at INTEGER NOT NULL
);

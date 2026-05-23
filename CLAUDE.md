# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Front Porch Economics is a community platform connecting mission-driven builders in Boston. It is a minimal, two-layer Cloudflare app: a static HTML frontend and a Cloudflare Worker API backed by Cloudflare D1 (SQLite).

Live: https://front-porch-economics.pages.dev

## Architecture

```
public/index.html       — Single-file static frontend (HTML + CSS + JS inlined)
worker/src/worker.js    — Cloudflare Worker API (handles /signup POST)
worker/wrangler.toml    — Worker deploy config (used by CI and direct deploys from worker/)
wrangler.toml           — Root config pointing to worker/src/worker.js
worker/migrate.sql      — D1 schema migrations (run manually)
.github/workflows/deploy.yml — CI/CD: deploys Worker then Pages on push to main
```

**Data flow:** The frontend POSTs signup form data to the hardcoded `WORKER_URL` in `public/index.html`. The Worker validates, inserts into the D1 `signups` table, and returns JSON.

**D1 Database** (`front-porch-economics`, id `86bd6964-3270-4c00-9bdc-2e8299c08c52`):
- `signups` — core table (email, name, neighborhood, building, phone, pin, pin_expires_at)
- `sessions` — for planned SMS PIN + JWT auth
- `saved_links` — for planned member directory features

**Auth (in development):** SMS PIN via Twilio → short-lived PIN stored in `signups` → JWT in session cookie, tracked in `sessions` table.

## Deployment

CI/CD auto-deploys on push to `main` via GitHub Actions (`CLOUDFLARE_API_TOKEN` secret required). Deployment is two-step: Worker first, then Pages.

### Manual deploy commands

```bash
# Deploy the Worker
cd worker && npx wrangler deploy

# Deploy the frontend to Pages
npx wrangler pages deploy public --project-name=front-porch-economics

# Local Worker dev (with D1 binding)
cd worker && npx wrangler dev
```

### Database migrations

```bash
# Apply migrations to remote D1
npx wrangler d1 execute front-porch-economics --remote --file=worker/migrate.sql

# Apply to local dev DB
npx wrangler d1 execute front-porch-economics --file=worker/migrate.sql

# Query D1 directly
npx wrangler d1 execute front-porch-economics --remote --command="SELECT * FROM signups LIMIT 10"
```

## Key Details

- The `WORKER_URL` in `public/index.html` is hardcoded to `https://01-front-porch-economics.asialakaygrady-6d4.workers.dev` — update it if the Worker is redeployed under a new name.
- There is no build step. The frontend is a single static file; the Worker is vanilla JS with no bundler.
- No `package.json` — `wrangler` is expected to be available globally (`npx wrangler` works without it).
- The root `wrangler.toml` and `worker/wrangler.toml` both reference the same D1 database but use different worker names (`01-front-porch-economics` vs `front-porch-economics-api`). CI deploys from `worker/` using `worker/wrangler.toml`.

# Front Porch Economics

A community platform for mission-driven builders in Boston and beyond — connecting organizers, cooperatives, independent media makers, students, and civic technologists who are already doing the work.

**Live:** [front-porch-economics.pages.dev](https://front-porch-economics.pages.dev)

---

## What It Is

Front Porch Economics is infrastructure for people who don't need to be convinced that community matters — they need to find each other. The platform centers builders operating outside institutional visibility: cooperative developers, community organizers, independent media makers, civic scholars, and cultural workers.

> "The front porch is where decisions get made before they go inside."

---

## Current State

The platform is in active development, building in public starting in Roxbury, MA.

| Layer | Status |
|---|---|
| Landing page + early access form | ✅ Live |
| Member directory | 🔧 In development |
| Auth system (SMS PIN + JWT) | 🔧 In development |
| Community features | 📋 Planned |

---

## Stack

| Layer | Technology |
|---|---|
| Frontend | HTML, CSS, JavaScript |
| Backend | Cloudflare Workers |
| Database | Cloudflare D1 |
| Hosting | Cloudflare Pages |
| Auth | Twilio SMS PIN, JWT session cookies |
| CI/CD | GitHub Actions |

---

## Repo Structure
front-porch-economics/
├── public/                   # Static frontend assets
├── worker/                   # Cloudflare Worker source
├── .github/workflows/        # GitHub Actions CI/CD
├── front-porch-economics.html # Main frontend
├── worker.js                 # Worker entrypoint
└── wrangler.toml             # Cloudflare deployment config

Daily costs and benefits over time

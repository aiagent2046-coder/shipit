# Drydock — Web Frontend

A standalone [Next.js](https://nextjs.org) (App Router) frontend for Drydock,
the production-readiness auditor for vibe-coded apps. It is a **pure API
client**: it has no backend or database of its own and talks over HTTP to the
existing FastAPI backend (the `app/` package at the repo root, deployed
separately). This directory is meant to be deployed independently (e.g. to
Vercel).

## Pages

- `/` — Landing hero with the audit input (GitHub URL or `.zip` upload) plus a
  zero-interaction **example report** rendered from realistic sample data.
- `/audit/[id]` — Audit results: score ring, per-category bars,
  severity-scored findings, and a link to the full HTML report.
- `/pricing` — Free vs Pro comparison and two payment paths: a Telegram Stars
  deep link and a USDT/TRC20 invoice flow.
- A persistent header widget for pasting an `sk_live_...` API key (stored in
  `localStorage`) which resolves your tier via `GET /v1/account`.

## Local development

```bash
cd web
cp .env.example .env.local   # optional — sensible defaults are baked in
npm install
npm run dev                  # http://localhost:3000
```

`npm run build` produces the production build; `npm run start` serves it.

## Environment variables

All are client-side (`NEXT_PUBLIC_*`) — set them in `.env.local` locally and in
the Vercel project settings for deploys.

| Variable | Default | Purpose |
| --- | --- | --- |
| `NEXT_PUBLIC_API_BASE_URL` | `https://api.drydock.co` | Base URL of the live FastAPI backend. Override to point at a local backend. |
| `NEXT_PUBLIC_TELEGRAM_BOT_USERNAME` | *(blank)* | Telegram bot username (no `@`) for the Stars deep link `https://t.me/<username>`. The backend code hardcodes no username, so you must supply your real bot's handle. Left blank, the Pay-with-Stars button renders an "unconfigured" state rather than guessing a fake handle. |

## Backend API used

- `POST /v1/audits` — multipart `archive` **or** form field `repo_url`.
  Completes **synchronously** (can take up to ~2 min) and returns the full
  result inline, which the form stashes in `sessionStorage` for the results
  page. Optional `Authorization: Bearer sk_live_...`.
- `GET /v1/audits/{id}` — the persisted row (fallback for shared links/reloads).
- `GET /v1/audits/{id}/report` — full HTML report (opened in a new tab).
- `GET /v1/account` — tier + entitlements (with or without a key).
- `POST /v1/billing/usdt/invoice` and `GET /v1/billing/usdt/invoice/{id}` —
  USDT/TRC20 invoice create + poll.

Telegram Stars has **no** frontend-callable endpoint (checkout is bot-driven),
so the frontend only deep-links into the bot.

## Honesty: entitlements

Per `app/accounts.py`, the **daily audit limit** (free = 5, pro = 100) is the
only entitlement, and it is enforced.

This paragraph used to say that `private_repos_allowed` and `priority_queue`
are returned but gate nothing, and that "the pricing page labels them 'not
enforced yet'". The pricing page never mentioned either one, so the sentence
described a disclaimer that did not exist — an inaccuracy about our own
honesty. Both flags have since been removed from the payload, so there is
nothing left to disclaim.

## What was verified vs. not

**Verified from this sandbox:**

- `npm run build` succeeds (Next.js 14.2.35, all routes compile, type-check
  passes).
- The live backend is reachable: `GET /healthz` → `{"status":"ok"}`, and
  `GET /v1/account` returns the real free-tier shape
  (`{"tier":"free","authenticated":false,"entitlements":{...}}`).

**Not yet proven (until this frontend is deployed):**

- **Cross-origin (CORS) calls from a browser.** An `OPTIONS` preflight against
  `/v1/account` currently returns **405**, i.e. the backend's CORS support is
  not deployed yet. Until the backend is updated and its
  `CORS_ALLOWED_ORIGINS` (and/or `CORS_ALLOW_VERCEL_PREVIEWS`) includes this
  frontend's real Vercel URL, browser calls will be blocked by CORS even
  though the API itself is up. Server-side reachability (as tested here with
  curl) is not affected by CORS.
- The real **USDT** and **Telegram Stars** payment flows end-to-end from the
  UI (invoice → on-chain confirmation → key reveal; Stars checkout in the bot).

## Security note

Pinned to `next@14.2.35` (latest 14.2.x patch). `npm audit` still flags several
Next.js advisories that its database only marks fixed in Next 15/16; these are
server-side (RSC/middleware/image-optimization DoS, SSRF) issues and upgrading
to Next 16 is a breaking change deferred out of this change. Revisit when
upgrading the major version.

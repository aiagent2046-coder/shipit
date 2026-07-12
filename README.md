# ShipIt

Autonomous rescue for vibe-coded apps: free production-readiness audit,
paid Fix Packs executed by agents and verified in a sandbox, delivered
as a pull request via GitHub sync.

Architecture: see `docs/shipit-architecture.md` (v0.2).

## Status: phase 1 (Audit Engine) done, phase 2 (Deploy Pack) mostly done, deployed to a production VPS

Live deployment: `https://45-10-40-169.sslip.io` (Timeweb VPS, systemd +
Caddy; see "Production deployment" below). Confirmed there for real on
2026-07-12: healthz over TLS, full audit round trip persisted to
Supabase and read back, LLM scan through AITunnel (2 rubric prompts, 4
findings, all grep-verified), hourly preview reaper via systemd timer.

Implemented:
- `app/ingest/validators.py` — hostile-archive validation (size, file
  count, symlinks, path traversal, zip bombs by ratio and by total size)
- `app/ingest/stack_detect.py` — Next.js / Vite+React / FastAPI
  detection, honest `unsupported` otherwise
- `app/ratelimit.py` — in-memory fixed-window rate limit per client IP
  (`AUDIT_RATE_LIMIT_PER_DAY`, default 5), enforced before any archive
  bytes are read
- `POST /v1/audits` — intake endpoint (rate limit + validation + stack
  detection + static scan + LLM auth/security scan when providers are
  configured)
- `app/deploypack/generate.py` — Deploy Pack, minimal scope: generates
  Dockerfile / docker-compose.yml / .env.example / CI workflow for
  `fastapi` and `vite-react` only (Next.js deferred — no real Next.js
  export validated yet). Detects poetry vs pip, Postgres usage, and
  Vite build-time `VITE_*` env vars (wired as Docker build args, since
  Vite inlines them at build time, not runtime).
- `app/deploypack/sandbox.py` — real `docker build` + `docker run` +
  `curl` verification, never trusts a generated Pack without booting
  it. **Confirmed end-to-end** on a real GitHub Actions runner (this
  dev sandbox has no `docker` binary itself) — see
  `.github/workflows/smoke-deploy-pack.yml` / `scripts/smoke_verify_deploy_pack.py`.
  Both `fastapi_sample` and `vite_sample` verified=True.
- `app/deploypack/delivery.py` — opens a real PR (branch + commit via
  the Git Data API) for a verified Pack, auth-agnostic (accepts
  whatever token it's given). **Confirmed end-to-end**: dogfooded on
  this repo itself — [PR #1](https://github.com/aiagent2046-coder/shipit/pull/1)
  is a real branch + real commit + real PR opened by this exact code.
  One honest nuance found doing that: `.env.example` didn't show up in
  the PR diff — not a bug, `_merge_env_example` correctly produced
  identical content to what shipit already had (no Postgres, so
  nothing new to add), and git/GitHub correctly show zero diff for an
  unchanged file.
- `app/deploypack/github_app.py` — GitHub App installation-token auth,
  used instead of the single-operator `GITHUB_PR_TOKEN` when
  `GITHUB_APP_ID` + `GITHUB_APP_PRIVATE_KEY` are set — works for any
  repo the App is installed on, not just the operator's own. **Confirmed
  end-to-end against the real GitHub API**: App id 4278482
  (`aiagent2046-coder`), installed on this repo, real installation
  token minted and used for a real authenticated `GET /repos/...` call
  — see `scripts/verify_github_app_locally.py` (run locally, never
  sends the private key anywhere).
- `app/deploypack/preview.py` + `POST /v1/fixpacks` `want_preview=true`
  — keeps a verified container alive (24h TTL, 256MB RAM cap, 1 live
  preview per client) instead of tearing it down, returns a `local_url`.
  **Confirmed end-to-end** on a real GitHub Actions Docker runner — see
  `scripts/smoke_verify_preview.py`. Does NOT include the public
  `{job_id}.preview.shipit.app` URL (needs a real domain + Caddy on a
  real server, neither of which exist yet — see the module docstring).
- `POST /internal/preview/reap` + `.github/workflows/preview-reaper.yml`
  — bearer-token-protected endpoint plus an hourly scheduled workflow
  that calls it. **Confirmed end-to-end**: the endpoint's auth and
  wiring were proven for real over HTTP against a live uvicorn process
  (`scripts/smoke_verify_reap_endpoint.py`); the schedule itself needs
  `PREVIEW_BASE_URL` / `PREVIEW_REAP_TOKEN` repo secrets pointing at a
  real deployment, which doesn't exist yet — every scheduled run fails
  loudly with that exact message until it does.
- `POST /v1/fixpacks` — Deploy Pack, free/unpaid preview (no payment
  gate yet). Optional `deliver_to="owner/repo"` form field opens a real
  PR once verified; refuses to deliver an unverified Pack.
- `app/db.py` + `migrations/0001_audits_and_fixpack_jobs.sql` —
  Postgres persistence for `audits` and `fixpack_jobs` (trimmed from
  shipit-architecture.md 2.5's full schema — no `users`/auth yet, no
  S3 columns, `findings` denormalized as JSONB instead of its own
  table; see the migration file's comment for why). `POST /v1/audits`
  and `POST /v1/fixpacks` persist when `DATABASE_URL` is set
  (`"persisted": true/false` in the response either way, same request
  still works unpersisted); `GET /v1/audits/{id}` and
  `GET /v1/fixpacks/{id}` read them back. **Confirmed end-to-end**: a
  real Supabase Postgres 17 project now backs this (schema applied via
  migration, verified with real INSERT/SELECT round trips including
  the `audits` -> `fixpack_jobs` foreign key). The actual `psycopg`
  driver code in `app/db.py` connecting to it is proven by
  `scripts/verify_db_locally.py` — run locally with your own
  `DATABASE_URL`, never sent anywhere else. **Driver note:** `asyncpg`
  was tried first but hangs indefinitely on the first parameterized
  query through Supabase's Supavisor pooler (confirmed by hand, both
  session and transaction pooler modes) — a known open Supabase-side
  bug ([supabase/supabase#39227](https://github.com/supabase/supabase/issues/39227)),
  not a ShipIt bug. Switched to `psycopg` (libpq-based, same library
  `psql` uses, which never hit this) with `prepare_threshold=None` to
  avoid the same class of pooler incompatibility. See `app/db.py`'s
  module docstring for the full diagnostic trail. **Resolved 2026-07-12:**
  `scripts/verify_db_locally.py` ran clean from the production VPS —
  connect, insert, read-back, FK, jsonb round trip, `mark_delivered`,
  no hangs. The earlier unpredictable hangs after the `psycopg` switch
  were the home network path (the "plausible read" below turned out to
  be the correct one), not the driver. Original note kept for the
  diagnostic record: re-running from the home network still hit an
  unpredictable hang partway through (2nd
  query one run, 3rd another, on both a pooled and a plain unpooled
  connection) from the same home network used for all the debugging
  above — inconsistent with a deterministic protocol bug, and a mobile
  hotspot test was inconclusive (carrier NAT silently drops port 5432
  outbound, a different failure mode). Best current read: an unreliable
  home network path to `eu-central-1`, not a `psycopg` regression — but
  this is a plausible read, not a confirmed one. Decided to defer
  further isolation (e.g. a throwaway VPS in the same region) until
  real deployment, rather than keep debugging against an unreliable
  local network. (That re-run happened — see "Resolved" above.)
  **Known gap:** Row Level
  Security is off on both tables in Supabase — fine for this app's own
  direct Postgres connection, but if the project's anon/publishable
  key is ever used elsewhere (a frontend, Supabase client libraries),
  these tables would be fully readable/writable through PostgREST. Not
  auto-fixed; enabling RLS needs real policies decided first, see
  Supabase's advisory.

## Production deployment

Runs on a Timeweb VPS (`45.10.40.169`) as of 2026-07-12. Layout:

- Code at `/opt/shipit`, venv at `/opt/shipit/.venv`, secrets in
  `/opt/shipit/.env` (chmod 600, never committed).
- `shipit.service` (systemd): uvicorn on `127.0.0.1:8000`,
  `EnvironmentFile=/opt/shipit/.env`, `Restart=on-failure`.
- Caddy terminates TLS for `45-10-40-169.sslip.io` (sslip.io wildcard
  DNS — no owned domain yet) and reverse-proxies to 8000. The public
  `{job_id}.preview.*` URL still needs a real domain; previews are
  reachable as `http://45.10.40.169:<port>` (ufw opens 20000–30000).
- `shipit-reap.timer` (systemd, hourly) replaces the GitHub Actions
  reaper cron on this deployment — the endpoint is the same
  `POST /internal/preview/reap` with the bearer token from `.env`.

Deployment gotchas found the hard way (all encoded in `.env.example`):

- systemd `EnvironmentFile` keeps inline comments as part of the value
  — a commented-out-looking `ANTHROPIC_API_KEY=  # direct fallback`
  becomes a garbage non-empty key, puts a dead provider in the LLM
  chain, and surfaces as a 401 mid-audit.
- The AITunnel provider needs `AITUNNEL_BASE_URL` *and*
  `AITUNNEL_API_KEY`; with only the key set, the LLM stage silently
  reports `prompts: 0`.
- `LLM_MODEL` must use the provider's model naming
  (`claude-sonnet-4.6` on AITunnel vs `claude-sonnet-4-6` on the
  direct Anthropic API) — the mismatch is a bare 400.
- After `systemctl restart shipit`, hit `/healthz` before sending real
  requests — a request racing the restart gets Caddy's 502.

## Known gaps (honest list, post-deploy)

- `POST /v1/audits` accepts a zip upload only — public-repo-URL intake
  is not implemented yet.
- `GET /v1/audits/{id}` returns `score_total` as a string (Postgres
  `numeric` serialization); `score_json.total` is a number. Pick one.
- `llm: {prompts: 0, ...}` is ambiguous for API consumers: it means
  "ran, no rubric-relevant files" — while "didn't run" is a separate
  string. Worth a `skipped_reason` field.
- The auth and security rubrics can report the same finding twice
  (seen in production: the same JWT issue at two severities). Needs
  cross-rubric dedup.
- LLM client surfaces only the HTTP status on provider errors; log the
  response body for 4xx to make the next 400 diagnosable without curl.
- Next.js Deploy Pack still deferred; RLS still off on the Supabase
  tables (see above).

## Dev

```bash
pip install -e ".[dev]"
pytest
uvicorn app.main:app --reload
```

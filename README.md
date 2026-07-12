# ShipIt

Autonomous rescue for vibe-coded apps: free production-readiness audit,
paid Fix Packs executed by agents and verified in a sandbox, delivered
as a pull request via GitHub sync.

Architecture: see `docs/shipit-architecture.md` (v0.2).

## Status: phase 1 (Audit Engine) done, phase 2 (Deploy Pack) mostly done

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
  the `audits` -> `fixpack_jobs` foreign key). The actual `asyncpg`
  driver code in `app/db.py` connecting to it is proven by
  `scripts/verify_db_locally.py` — run locally with your own
  `DATABASE_URL`, never sent anywhere else. **Known gap:** Row Level
  Security is off on both tables in Supabase — fine for this app's own
  direct Postgres connection, but if the project's anon/publishable
  key is ever used elsewhere (a frontend, Supabase client libraries),
  these tables would be fully readable/writable through PostgREST. Not
  auto-fixed; enabling RLS needs real policies decided first, see
  Supabase's advisory.

## Dev

```bash
pip install -e ".[dev]"
pytest
uvicorn app.main:app --reload
```

# Drydock

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
  configured). Accepts either a zip `archive` upload or a public
  `repo_url` (exactly one). `repo_url` is validated against a strict
  `https://github.com/<owner>/<repo>` pattern **before any network call**
  (the SSRF guard — host must be exactly github.com, no userinfo/port/
  subdomain tricks), then the repo's default-branch zipball is fetched
  from the hardcoded `api.github.com` and fed through the *same*
  `validate_zip`/`detect_stack`/scan pipeline as an upload — no second
  validation path. Public GitHub repos only (no auth; a private repo's
  unauthenticated 404 is treated as "not found or private"). See
  `app/ingest/github_fetch.py`. **Confirmed against live GitHub**: a real
  fetch of `tiangolo/fastapi` through the actual code path downloaded,
  validated, and detected as `fastapi` (the pytest suite itself stubs the
  outbound call and never hits the network).
- `app/deploypack/generate.py` — Deploy Pack, minimal scope: generates
  Dockerfile / docker-compose.yml / .env.example / CI workflow for
  `fastapi`, `vite-react`, and `nextjs`. Detects poetry vs pip, Postgres
  usage, and Vite build-time `VITE_*` env vars (wired as Docker build
  args, since Vite inlines them at build time, not runtime). Next.js
  requires `output: "standalone"` in next.config (js/mjs/cjs/ts) — that
  mode produces the self-contained `server.js` the image runs; without
  it there is nothing bootable to build, so we refuse with an actionable
  message rather than ship a Pack that builds green then fails to serve.
  Package manager is detected from the lockfile (npm/yarn/pnpm), and
  build-time `NEXT_PUBLIC_*` env vars are wired as Docker build args
  (same inlining reason as `VITE_*`).
- `app/deploypack/sandbox.py` — real `docker build` + `docker run` +
  `curl` verification, never trusts a generated Pack without booting
  it. **Confirmed end-to-end** on a real GitHub Actions runner (this
  dev sandbox has no `docker` binary itself) — see
  `.github/workflows/smoke-deploy-pack.yml` / `scripts/smoke_verify_deploy_pack.py`.
  `fastapi_sample`, `vite_sample`, and `next_sample` (standalone
  Next.js) all `verified=True` — confirmed 2026-07-15 via a real
  `workflow_dispatch` run of `smoke-deploy-pack.yml`
  ([run 29421963371](https://github.com/aiagent2046-coder/shipit/actions/runs/29421963371)):
  `next_sample` built and served real HTTP 200 on `/` from an actual
  booted container, not a mock.
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
- `POST /internal/preview/reap` — bearer-token-protected endpoint.
  **Confirmed end-to-end**: auth and wiring proven for real over HTTP
  against a live uvicorn process (`scripts/smoke_verify_reap_endpoint.py`).
  Scheduling is `shipit-reap.timer` on the production VPS (see
  "Production deployment" below) — there used to also be a
  `.github/workflows/preview-reaper.yml` calling this same endpoint
  hourly, but it never had `PREVIEW_BASE_URL` / `PREVIEW_REAP_TOKEN`
  repo secrets configured (every one of its 21 scheduled runs failed
  loudly with that exact message), and once the VPS timer existed it
  was a redundant second mechanism for one job anyway. Removed
  2026-07-14 rather than configured — one reaper, not two.
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
  not a Drydock bug. Switched to `psycopg` (libpq-based, same library
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
  **Resolved 2026-07-14:** Row Level Security is now enabled on both
  tables (`migrations/0002_enable_rls_default_deny.sql`), applied for
  real against the live Supabase project and confirmed via Supabase's
  own advisor that the ERROR-level "RLS Disabled in Public" notices
  are gone. No permissive policies were added — there's no user/auth
  model yet to write real per-row ownership policies against (Auth
  comes after Deploy in this project's own phase ordering), so this is
  a deliberate default-deny: PostgREST via the anon/publishable key
  now gets zero rows from either table, closing the exposure gap,
  while this app's own access is untouched (it connects as the
  `postgres` role via the pooler, which owns these tables and bypasses
  RLS regardless of policies).
- `app/accounts.py` + `migrations/0003_accounts_tiers_payments.sql` +
  `AccountRepository`/`PaymentRepository` in `app/db.py` — **paywall
  foundation, Stage 1 of 2** (the account/tier/entitlement layer a
  follow-up will bolt payment providers onto). This is the first identity
  concept in the codebase; everything stays anonymous by default. An
  account is identified by a server-generated opaque API key
  (`sk_live_<random>`), NOT email/password — there's no auth system, and
  onboarding is payment-driven (Stage 2's payment flow creates the account
  and returns the key). A request may optionally carry
  `Authorization: Bearer sk_live_...` to be recognized as a `pro` account;
  **no key, an unknown key, or an unconfigured database all fall back to
  anonymous `free` — never a 401** (same graceful-degradation tone as the
  `DatabaseNotConfigured` handling). Two tiers only (`free`/`pro`).
  `GET /v1/account` returns the caller's tier + entitlements for either
  case (never echoes the key back). Entitlements are deliberately short
  and matched to what exists today:
  - `daily_audit_limit` — **the one entitlement really enforced.**
    `POST /v1/audits` resolves the caller's tier and passes the per-tier
    limit into the *existing* `RateLimiter` (given an optional `limit`
    override; the leak-fixed limiter is reused, not replaced). Free =
    today's configured limit (`AUDIT_RATE_LIMIT_PER_DAY`, default 5), keyed
    by client IP exactly as before — **anonymous usage is byte-for-byte
    unchanged**; pro = 100, keyed by account id so the budget follows the
    account, not the IP.
  - `private_repos_allowed` (free=False, pro=True) — **a flag with no real
    effect yet.** The check point is documented in `create_audit`'s
    `repo_url` branch (where it would gate private-repo intake), but
    private repos aren't fetchable at all today (`github_fetch.py` is
    public-only), so there's nothing to gate. Not faked with an `if` that
    can never fire.
  - `priority_queue` (free=False, pro=True) — **a flag not wired to
    anything**, because there is no job queue in this codebase to
    prioritize (the scan runs inline in a threadpool). Exists so later
    scheduling work has a defined switch.
  No payment provider is implemented in this stage (explicitly out of
  scope): the `payments` table + `PaymentRepository` are schema-and-CRUD
  only, so Stage 2 has somewhere to write. There is **no** public
  create-account endpoint (that would be a free-unlimited-pro abuse hole);
  accounts are created only by Stage 2's payment flow or, in tests,
  directly via `AccountRepository`. **Applied to Supabase 2026-07-14:**
  `0003` was written in the sandbox that couldn't reach Supabase directly,
  then applied for real against the live `shipit` project via the Supabase
  migration tool — confirmed both tables exist with `rls_enabled: true`
  and no new ERROR-level advisories (same expected `rls_enabled_no_policy`
  INFO notice as `0001`/`0002`). All the repository/entitlement/rate-limit
  code is also unit-tested against the same `FakePool`/dependency-override
  patterns as the rest of `app/db.py`.
- `app/billing/` + `migrations/0004_payments_external_ref_unique.sql` —
  **paywall Stage 2 of 2: two payment providers.** Both take completely
  different paths to the *same* outcome — a completed `payments` row plus
  an `accounts` row with `tier='pro'`, and the account's API key handed
  back to whoever paid. That converging step ("a confirmed payment
  becomes a pro account with a key") is factored into one shared
  `grant_pro_tier()` in `app/billing/__init__.py`, idempotent on the
  provider's charge/transaction id, so neither provider reimplements it.
  New repo methods back it: `AccountRepository.get_by_id`,
  `PaymentRepository.{get_by_external_ref,list_pending,mark_completed}`.
  Migration `0004` adds a partial unique index on `(provider,
  external_ref)` (where `external_ref` is not null) — the DB-level
  backstop for the check-then-write idempotency race; pending USDT
  invoices carry a null `external_ref` so several may coexist.
  - **Telegram Stars** (`app/billing/telegram_stars.py`,
    `POST /v1/webhooks/telegram`). Stars is the simpler flow: invoice
    currency is the literal `"XTR"` and `provider_token` is an **empty
    string** (no third-party provider to register — confirmed at
    [core.telegram.org/bots/payments-stars](https://core.telegram.org/bots/payments-stars)).
    `sendInvoice` takes `prices=[{label, amount}]` where `amount` is the
    integer star count. The webhook handles two update types: a
    `pre_checkout_query` (approved within Telegram's 10s deadline via
    `answerPreCheckoutQuery`) and a `message.successful_payment` (grants
    pro, DMs the key via `sendMessage`). Idempotency key is
    `telegram_payment_charge_id` (Telegram retries the webhook until it
    gets 200, so the same charge can arrive twice — the retry re-delivers
    the *same* key, mints no second account). Authenticity is Telegram's
    own `secret_token`: `setWebhook` is called with a secret, echoed in
    the `X-Telegram-Bot-Api-Secret-Token` header, constant-time compared
    (`hmac.compare_digest`) exactly like the reap endpoint's bearer token.
    Env: `TELEGRAM_BOT_TOKEN`, `TELEGRAM_WEBHOOK_SECRET`,
    `TELEGRAM_PRO_STARS` (default 250). **Not exercised live** — this
    sandbox has no bot token and can't receive a real webhook; run
    `scripts/verify_telegram_stars_locally.py` with your own token to
    prove the real `sendInvoice` (it does `getMe` then sends a real
    Pay-with-Stars button). The webhook half only truly closes on a real
    payment.
  - **USDT/TRC20, self-hosted** (`app/billing/usdt_trc20.py`,
    `POST /v1/billing/usdt/invoice`, `GET /v1/billing/usdt/invoice/{id}`,
    `POST /internal/billing/poll-usdt`). No third-party gateway: ONE
    fixed receiving address (`USDT_TRC20_ADDRESS`, public, not a secret),
    invoices disambiguated by a **unique amount** (base price + a random
    sub-cent nonce — TRC20 USDT has 6 decimals, a million micro-slots per
    dollar) rather than per-invoice addresses. Matching is on **exact
    base units**, not a float tolerance: TronGrid returns the transfer
    `value` as an integer string of micro-USDT and we derive each
    invoice's expected micros from its stored amount, so `==` is both
    simpler and stricter (can't match a neighbouring invoice a cent
    away). Invoices expire after `INVOICE_TTL_SECONDS` (30 min); an
    expired unpaid invoice is never auto-matched even if its exact amount
    arrives later. The poll endpoint is bearer-protected (`USDT_POLL_TOKEN`,
    `hmac.compare_digest`, same as the reaper) and meant for a scheduled
    caller — **this repo ships no timer/cron unit**, same as the reaper
    (see "Production deployment"); wire a `shipit-poll-usdt.timer` to it.
    TronGrid REST: `GET /v1/accounts/{address}/transactions/trc20`; an API
    key is **optional** (only raises rate limits — sent as the
    `TRON-PRO-API-KEY` header when `TRONGRID_API_KEY` is set).
    **Reachability confirmed for real from this sandbox**: an
    unauthenticated `GET` to `api.trongrid.io` for the mainnet USDT
    contract address returned HTTP 200 with the documented shape
    (`data[].value` as an integer-string of base units,
    `token_info.decimals: 6`, `block_timestamp` in ms). That was a raw
    reachability probe, **not** the feature working end to end — no real
    invoice was paid on-chain. Run `scripts/verify_usdt_trc20_locally.py`
    to exercise the actual `fetch_transfers()` code against live TronGrid.
  Tests (`tests/test_billing_telegram.py`, `tests/test_billing_usdt.py`,
  17 new): all outbound HTTP is faked with `httpx.MockTransport` (no real
  network in the suite) — invoice payload shape, pre_checkout approval,
  successful_payment → account + idempotent retry, webhook secret
  rejection, USDT unique-amount pending invoice, poll matches a mocked
  transfer + completes + reveals key, poll bearer auth, expired invoice
  not matched. **Applied to Supabase 2026-07-14:** `migrations/0004`
  was applied for real against the live `shipit` project via the
  Supabase migration tool, right after `0003` — same session, same
  method.

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
- `shipit-fixpack.timer` (systemd) should call
  `POST /internal/fixpack/process-paid` (bearer token `FIXPACK_PROCESS_TOKEN`
  from `.env`) on a short interval (2–5 min) to drain paid Fix Pack jobs into
  fix PRs. Like the reaper/USDT poller, **this repo ships no unit file** —
  wire one up. The endpoint is safe to fire on a timer even while a previous
  run is still working: it takes a Postgres advisory lock (a second firing
  returns `{"skipped_locked": true}`) and claims each job atomically into a
  `running` lease, so overlapping runs never open a duplicate PR. A run also
  reaps `running` leases older than 15 min (a crashed worker) — re-queuing up
  to 3 attempts, then failing — so `systemctl restart shipit` mid-job never
  loses or wedges a job (see `PHASE3_QUEUE_PLAN.md`).

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
  requests — a request racing the restart gets Caddy's 502. `/healthz` stays
  a static `{"status":"ok"}` liveness probe for exactly this race; use
  `/health` (below) for the richer readiness signal.

### Observability (Phase 3)

Single VPS, single uvicorn process — so no Prometheus/Grafana/ELK/Sentry.
Everything rides Postgres and the Telegram bot that already exist (see
`PHASE3_OBSERVABILITY_PLAN.md`).

- **`GET /health`** (public, unauthenticated, leak-free) reports what
  actually fails here: `{"db": <bool>, "fixpack_backlog": <n|null>,
  "oldest_paid_seconds": <secs|null>}`. `db:false` means the database is
  unset or unreachable (a live process honestly reporting degraded — still
  `200`, so a dumb uptime pinger can read it). A growing `oldest_paid_seconds`
  past the `shipit-fixpack.timer` interval means the processor isn't draining.
  Returns only booleans/coarse counts — no ids, urls, or error text — so it's
  safe to expose without a token, unlike the side-effecting `/internal/*`
  endpoints.
- **Operator alerts** push a short Telegram message on high-signal failures:
  a Fix Pack job landing on `failed`, and any unhandled `5xx` (with a short
  `request_id` echoed in the response body and log line so a user report ties
  to a log line). Intentional `HTTPException`s (422/404/503/401) are normal
  control flow and never alert. Alerts are best-effort (never break a request
  or job), self-throttled *within the uvicorn process* (an in-memory per-key
  window, so a crash-loop hitting the same server-side path can't spam), and a
  silent no-op unless both `TELEGRAM_BOT_TOKEN` and `TELEGRAM_ADMIN_CHAT_ID`
  are set. The in-process throttle does **not** span the CLI path below (each
  invocation is a fresh process) — that path is rate-limited by systemd
  instead (see the restart-alert note).
- **Service crash/restart alert** — reuse the same code path from systemd
  without a new agent, endpoint, or token. Add an `OnFailure=` companion to
  `shipit.service`:

  ```ini
  # shipit.service
  [Unit]
  OnFailure=shipit-alert@%n.service
  ```

  ```ini
  # shipit-alert@.service (templated on the failed unit name %i)
  [Unit]
  Description=Push an operator alert when %i fails
  [Service]
  Type=oneshot
  EnvironmentFile=/opt/shipit/.env
  WorkingDirectory=/opt/shipit
  ExecStart=/opt/shipit/.venv/bin/python -m app.alerts "Drydock: systemd unit %i failed/restarted on the VPS"
  ```

  `python -m app.alerts "<msg>"` formats and sends the alert in Python (same
  bot, same `.env`, no direct `curl` to the Bot API), and exits `0` even if
  the send fails so it never turns a service failure into a failing
  `OnFailure` unit. Matching the reaper/USDT/fixpack convention, **no unit
  file is committed** — the snippets above are the recipe.

  **Throttling this path is systemd's job, not the code's.** Each
  `python -m app.alerts` run is a fresh process, so the in-process throttle
  (which only dedupes the long-lived server's own alerts) can't suppress
  repeats here — a fast crash-loop would otherwise fire one Telegram message
  per restart. Bound it on `shipit.service` with systemd's own start-rate
  limiter (these are not set by default — add them):

  ```ini
  # shipit.service, [Unit]
  StartLimitIntervalSec=300
  StartLimitBurst=5
  # shipit.service, [Service]
  RestartSec=3
  ```

  With `RestartSec=3` a flapping service can restart at most a handful of
  times before systemd gives up for the interval, which caps the `OnFailure=`
  alerts to that same handful rather than an unbounded stream.

### CORS (browser frontend on Vercel)

The API talks to a separately-deployed Next.js frontend, so browser
cross-origin calls are gated by env, configured in `app/main.py`'s
`configure_cors()` (Starlette `CORSMiddleware`). It is **deny-by-default**:
with nothing set, no cross-origin browser access is allowed — deliberately
NOT `"*"`, because this API now takes an `Authorization: Bearer` key and a
wildcard combined with credentials would let any site make credentialed
calls.

- `CORS_ALLOWED_ORIGINS` — comma-separated exact origins (scheme included,
  no trailing slash), e.g. `https://shipit-web.vercel.app,https://shipit.app`.
  Unset/empty allows no origins.
- `CORS_ALLOW_VERCEL_PREVIEWS` — set `true` to also allow Vercel preview
  deploys (per-deploy `https://<name>-<hash>-<team>.vercel.app` subdomains,
  matched by regex `^https://[a-z0-9-]+\.vercel\.app$`). Explicit opt-in,
  default off.

Credentials (`allow_credentials`) are enabled only when at least one
explicit origin is listed or previews are on — never alongside `"*"` (which
is never passed), so the disallowed wildcard+credentials combination can't
occur. Allowed methods are `GET, POST` (the only methods the API uses);
allowed request headers are `Authorization` and `Content-Type`.

## Known gaps (honest list, post-deploy)

- `POST /v1/audits` intake now accepts a public GitHub `repo_url` as an
  alternative to a zip upload (see above). Still NOT supported by design:
  private repos, non-GitHub hosts (GitLab/Bitbucket/self-hosted), and any
  auth/OAuth flow — public github.com repos only.
- Paywall Stage 2 (both payment providers) is now implemented in code
  (see the implemented entry above), but **neither provider has been
  exercised against a real payment**: Telegram Stars has no bot token and
  no real webhook here (only `sendInvoice` is provable, via the verify
  script), and USDT/TRC20 has no funded address or real on-chain transfer
  (only the TronGrid *read* is provable). The matching/granting logic is
  covered only by mocked tests. Closing this needs the operator to run
  the two `scripts/verify_*_locally.py` scripts and then take one real
  payment through each. `migrations/0003` and `0004` are both applied to
  the live Supabase project already (see the entries above) — what's
  still pending is exercising the two providers against a real bot token
  and a real on-chain transfer, not schema. The
  `private_repos_allowed` and `priority_queue` entitlements still aren't
  enforced anywhere real (no private-repo intake, no job queue); only
  `daily_audit_limit` is.
- Cross-rubric dedup collapses a finding reported by both the auth and
  security rubrics into one (most severe wins, the other rubric noted on
  the survivor). It matches on same file + line numbers within a small
  window (3 lines) + similar titles (difflib ratio ≥ 0.5), so the same
  issue anchored to *adjacent* lines of one multi-line statement by each
  rubric now merges instead of double-counting. Still a real limit: the
  same issue reported *far apart* in the same file (beyond the window),
  in genuinely different files, or with dissimilar titles won't merge —
  the similarity gate is deliberately conservative to avoid dropping
  distinct findings that happen to sit near each other.
- The secret scanner damps (never drops) findings in contexts where a
  credential-shaped string is far more likely fabricated than leaked, so one
  tutorial or test file can't zero out a real score: `docs/`/`blog/`/`.md` and
  example/fixture paths are capped at medium on path alone, and test-setup
  files (`jest.setup.ts`, `__tests__/`, `*.test.ts`/`*.spec.ts`, …) are capped
  the same way **only when the matched value itself carries a placeholder
  marker** (`placeholder`, `not-real`, `fake`, `dummy`, …). This is a
  deliberate recall tradeoff: a genuine secret in a test file with no such
  marker is still flagged critically, and a placeholder-looking value in a
  production path is still flagged — but a real leaked key pasted into a test
  file *and* renamed to look like a placeholder would be under-reported.
- LLM client surfaces only the HTTP status on provider errors; log the
  response body for 4xx to make the next 400 diagnosable without curl.

## Dev

```bash
pip install -e ".[dev]"
pytest
uvicorn app.main:app --reload
```

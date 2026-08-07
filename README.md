# Drydock

Autonomous rescue for vibe-coded apps: free production-readiness audit,
paid Fix Packs executed by agents and verified in a sandbox, delivered
as a pull request via GitHub sync.

Architecture: see `docs/shipit-architecture.md` (v0.2).

## Status: phase 1 (Audit Engine) done, phase 2 (Deploy Pack) mostly done, deployed to a production VPS

Live deployment: the backend host configured via `NEXT_PUBLIC_API_BASE_URL`
(frontend) / served by Caddy on the Timeweb VPS (systemd + Caddy; see
"Production deployment" below for the concrete host). Confirmed there for real on
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
  `GET /v1/fixpacks/{id}` read them back. Both read endpoints are
  ownership-gated by a per-row `access_token` (`?token=...`), delivered
  once in the create response and minted by a DB column default
  (`migrations/0010_audits_access_token.sql`,
  `migrations/0012_fixpack_jobs_access_token.sql`): a leaked id alone is
  not enough, and a missing/wrong token answers **404 (not 403)** so the
  endpoint never confirms an id exists to a caller who doesn't hold its
  token. **Confirmed end-to-end**: a
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
  - **Recurring subscriptions (Telegram Stars).** Stars is the *only*
    provider that can auto-charge (crypto has no allowance-free auto-debit,
    so USDT stays one-time). A subscription invoice **cannot** be sent with
    `sendInvoice` — Telegram rejects that with `SUBSCRIPTION_EXPORT_MISSING`
    ("subscription invoices may not be sent using `messages.sendMedia`, only
    exported to invoice deep links using `payments.exportInvoice`",
    https://core.telegram.org/api/subscriptions). It must instead be minted
    with `createInvoiceLink` (adding `subscription_period`, which **must**
    equal `SUBSCRIPTION_PERIOD_SECONDS = 2592000`, 30 days — the only value the
    Bot API accepts). `/subscribe` exports that link and DMs it to the user
    (with an inline URL button) to open the Pay flow. The webhook grows two
    behaviours:
    - `message.successful_payment` for a `sub:`-prefixed payload →
      `grant_subscription` upserts/renews the `subscriptions` row
      (migration 0015). `is_first_recurring` inserts the row; `is_recurring`
      renews it — pushing `expires_at` (from `subscription_expiration_date`)
      out and rotating `telegram_payment_charge_id` to the latest period.
      Unlike Pro, this mints **no account and no API key** (the current
      `test-monitoring` tier unlocks nothing yet; it exists only to prove the
      billing).
    - **`subscription`** — the new `BotSubscriptionUpdated` update type (this
      is the exact Update field key per the Bot API). It carries `user`,
      `invoice_payload`, and `state` (`canceled` / `active` / `failed`) but
      **no charge id**, so it is matched to a row on the
      `(telegram_user_id, invoice_payload)` natural key and updates only
      `status`. It is the sole signal for a **failed renewal** — without it,
      a failed charge is just silence at `expires_at`.

    **Access rule:** access is `expires_at`-based, *not* status-based. A
    `canceled` or `failed` subscription keeps the period it already paid for
    (matches Telegram: cancelling never revokes access immediately). `status`
    is the *renewal* state (will it charge again?); `expires_at` is the
    *access* boundary. A `failed` renewal therefore does **not** revoke
    access — the paid period is honoured to its end.

    Bot commands: `/subscribe` sends the recurring invoice; `/unsubscribe`
    calls `editUserStarSubscription(is_canceled=True)` with the stored charge
    id and flips the row to `canceled` (access continues to `expires_at`).
    Env: `SUBSCRIPTION_STARS` (default 1). **Not exercised live** here (same
    reason as one-shot Stars) — proven end to end only by a real Stars
    subscription: `/subscribe` → pay → confirm the row is `active`, then
    `/unsubscribe` → confirm it flips to `canceled`.
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
  - **PayPal Checkout** (`app/billing/paypal.py`, `POST /v1/paypal/orders`,
    `GET /v1/paypal/orders/{id}`, `POST /v1/paypal/subscriptions`,
    `POST /v1/webhooks/paypal`). An ALTERNATIVE offered beside Stars/USDT for
    all three products, entirely additive: with `PAYPAL_CLIENT_ID` /
    `PAYPAL_CLIENT_SECRET` unset every PayPal endpoint 503s and the other
    providers are byte-for-byte unchanged. One-time Pro and Fix Pack use the
    **Orders API** (create → the browser JS SDK approves + captures → a
    `PAYMENT.CAPTURE.COMPLETED` webhook grants); monitoring uses the
    **Subscriptions API** against a billing plan (`PAYPAL_MONITOR_PLAN_ID`),
    activated/renewed by `BILLING.SUBSCRIPTION.ACTIVATED` /
    `PAYMENT.SALE.COMPLETED` webhooks and cancelled by the
    `CANCELLED/SUSPENDED/EXPIRED` events. Routing context rides the order /
    subscription `custom_id` (`pro` / `fixpack:<audit_id>` /
    `monitor:<owner/repo>`), the PayPal equivalent of the Stars invoice
    payload, so a webhook routes with **no DB round trip**. Idempotency reuses
    the existing partial unique indexes — `(provider, external_ref)` keyed on
    the capture/sale id for `payments`, and `paypal_subscription_id`
    (migration 0018) for `subscriptions`. Unlike Stars/GitHub (local HMAC),
    PayPal authenticity is verified by an **outbound** call to
    `POST /v1/notifications/verify-webhook-signature` (needs the OAuth token +
    `PAYPAL_WEBHOOK_ID`); an unverified event never grants. Pure `httpx`, no
    PayPal SDK, with an injectable `transport=` seam so the whole surface is
    faked in tests. **Not exercised against real PayPal** — this sandbox has no
    credentials; run `scripts/verify_paypal_sandbox_locally.py` (with sandbox
    keys in the environment) to drive a real sandbox order/subscription once
    the founder wires them. Frontend: `web/src/components/PayPalButton.tsx`
    loads the JS SDK with `NEXT_PUBLIC_PAYPAL_CLIENT_ID` (blank → the cards
    show as unconfigured, exactly like the Stars button) and renders the
    buttons beside the existing Stars/USDT cards on `/pricing` and the audit
    results page.
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
  `/opt/shipit/.env` (`chmod 0640`, owner `root:shipit-ops`, never committed).
  Two identities read it: systemd itself, as root, for `EnvironmentFile=`, and
  the `ExecStartPre=` validator, which runs as the service user — hence group
  read rather than 0600.
- `shipit.service` (systemd): uvicorn on `127.0.0.1:8000`,
  `EnvironmentFile=/opt/shipit/.env`, `Restart=on-failure`. Runs as
  `shipit-ops`, not root, with `SupplementaryGroups=shipit-runner` for the
  sandbox socket — see `deploy/systemd/shipit.service.d/30-service-user.conf`.
- Caddy terminates TLS for `api.drydock.co` and, still, for
  `45-10-40-169.sslip.io`, and reverse-proxies both to 8000. The sslip name
  predates owning the domain and keeps answering: delivered audit reports
  carry absolute links to it. Certificates are per-name and automatic;
  api.drydock.co needs an A record to 45.10.40.169 before Caddy can complete
  the HTTP-01 challenge for it.
- The subdomain is not cosmetic. `drydock.co` and `api.drydock.co` are the
  same site, so a session cookie set by the API is first-party and
  `SameSite=Lax` applies; against an unrelated host it is a third-party
  cookie, which Safari and Firefox block by default. See PR #171.
- The public `{job_id}.preview.*` URL still needs its own name; previews are
  reachable as `http://45.10.40.169:<port>` (ufw opens 20000–30000).
- `shipit-reap.timer` (systemd, hourly) replaces the GitHub Actions
  reaper cron on this deployment — the endpoint is the same
  `POST /internal/preview/reap` with the bearer token from `.env`.
- `shipit-fixpack.timer` (systemd) should call
  `POST /internal/fixpack/process-paid` (bearer token `FIXPACK_PROCESS_TOKEN`
  from `.env`) on a short interval (2–5 min) to drain paid Fix Pack jobs into
  fix PRs. The unit files are `deploy/systemd/shipit-fixpack.{service,timer}`
  — install them, do not write your own (see "Installing the timers" below).
  The endpoint is safe to fire on a timer even while a previous
  run is still working: it takes a Postgres advisory lock (a second firing
  returns `{"skipped_locked": true}`) and claims each job atomically into a
  `running` lease, so overlapping runs never open a duplicate PR. A run also
  reaps `running` leases older than 15 min (a crashed worker) — re-queuing up
  to 3 attempts, then failing — so `systemctl restart shipit` mid-job never
  loses or wedges a job (see `PHASE3_QUEUE_PLAN.md`).
- `shipit-monitoring.timer` (systemd) should call
  `POST /internal/monitoring/process-pending` (bearer token
  `MONITORING_PROCESS_TOKEN` from `.env`) to drain the continuous-monitoring
  backlog: each pending run re-audits its repo, diffs the findings, and DMs
  subscribers. Same durable-queue shape as `shipit-fixpack.timer` (advisory
  lock → `{"skipped_locked": true}` on overlap, atomic per-run claim, 15 min /
  3-attempt stale-lease reaper). The unit files are
  `deploy/systemd/shipit-monitoring.{service,timer}` — install them, do not
  write your own (see "Installing the timers" below). A
  **longer interval than Fix Pack** is right (~5 min, `OnUnitActiveSec=5min`): a
  repo is re-audited at most once per 24h and a pending run only needs to drain
  within a few minutes of a push. The push webhook only enqueues the run and
  ACKs immediately, so nothing gets audited until this timer fires (see
  `MONITORING_ASYNC_PLAN.md`).
- `shipit-usdt-poller.timer` (systemd, 2 min) calls
  `POST /internal/billing/poll-usdt` (bearer token `USDT_POLL_TOKEN`) to match
  incoming TRC20 transfers against pending invoices. Unit files are
  `deploy/systemd/shipit-usdt-poller.{service,timer}`. This endpoint 503s when
  `USDT_TRC20_ADDRESS` is unparseable, which is a whole-feature outage that
  looks like silence: no payment is ever confirmed, and nobody complains,
  because a customer who paid just sees an invoice that stays `pending`.

### Release tags (CalVer)

Releases are tagged `v<YYYY.MM.DD>-<n>` in **UTC**, with `n` counting the
releases tagged on that same day: `v2026.08.07-1`, `v2026.08.07-2`. Tags are
annotated and never moved — a release tag is a permanent record of what was
shipped.

CalVer rather than semver because this is a continuously deployed service, not
a library anyone imports. Its public contract is already versioned in the URL
path (`/v1/...`), so semver major/minor/patch on the *deployment* would have to
be assigned by taste, and "how old is production" — the question actually asked
during an incident — would still need a lookup. A date answers it directly.

    # tag origin/main, then publish the tag
    deploy/scripts/tag-release.sh --push

    # then deploy the tag it printed
    deploy/scripts/deploy-production.sh --revision v2026.08.07-1

**Tag before you deploy, not after.** `release_manager.py build` records
`git describe` into `.shipit-release.json` at build time, and `GET /version`
reports it from there. A tag pushed *after* the build cannot reach the metadata
that was already written, so the running release keeps reporting a bare short
SHA until it is rebuilt. Tagging afterwards still marks history correctly, but
it buys nothing at runtime.

`tag-release.sh` refuses to tag a commit that is not an ancestor of
`origin/main` — the same gate `deploy-production.sh` applies — so a release tag
can never point at unreviewed work. It fetches tags first, so two people
tagging on the same day see each other's counter instead of racing to the same
number.

`deploy-production.sh` checks the control repository out at the revision being
deployed before it builds. The deploy tooling is versioned with the application
but runs from `/opt/shipit`, and `git fetch` updates refs without touching the
working tree — so without that step a new release is built by whatever builder
was last checked out. The first CalVer release hit exactly this: it deployed
cleanly and still reported `version: null`, because the previous builder wrote
the metadata and did not know about the `git_describe` field. Replacing the
script mid-run is safe, since `git checkout` renames a new file into place and
the running shell keeps reading the original inode.

### Host provisioning — one-time, not part of a deploy

These set up **host** state, so they survive every release swap and
`deploy-production.sh` does not run them. Both are needed once when a host is
built (or rebuilt from scratch), and both are idempotent:

```bash
# 1. The audit payload spool the API writes and the worker reads.
sudo deploy/scripts/provision-audit-spool.sh

# 2. Group-read on .env for the ExecStartPre validator.
sudo chown root:shipit-ops /opt/shipit/.env
sudo chmod 0640 /opt/shipit/.env
```

Step 2 must happen **before** `shipit.service` is first started with the
`30-service-user.conf` drop-in in place. `EnvironmentFile=` is read by systemd
as root and would not notice, but
`ExecStartPre=… validate-production-env.py --env-file /opt/shipit/.env` runs as
`shipit-ops` and opens the file itself — on a `0600 root:root` `.env` the unit
fails to start.

Given `--env-file`, the validator reads **only** that file and ignores its own
process environment: the validating process is not the service, so a variable
exported in an operator's shell is one the service will never see. Running the
command by hand therefore gives the same verdict systemd gets. If the file
defines no `ENVIRONMENT`, the production checks are skipped and the script says
so on stderr rather than silently reporting success. Without `--env-file` it
validates the ambient environment, which is what the `10-production-operations`
drop-in relies on — there `ExecStartPre` has already inherited
`EnvironmentFile=` from the unit.

`/opt/shipit/.env` is the host's own file and is never overwritten by a deploy,
so it can drift from `.env.example`. One such value is worth knowing about when
rebuilding a host: production already carries `LOG_FORMAT=json`, set by hand
after Stage 5 shipped the JSON formatter. `.env.example` now ships `json` too,
so a `.env` seeded from it matches the running host instead of silently
downgrading it to `text` (the code-level fallback for unset/unrecognized
values) and breaking the `jq` runbook below.

### Installing the timers

`deploy-production.sh` swaps the release and restarts `shipit.service` and
`shipit-audit-worker.service`. Two services, not one, because the worker is a
long-lived process out of the `current` symlink: swapping the symlink leaves
the running Python on the previous release, so an engine change would ship,
pass its health gates and never reach an audit. Restarting it is the deploy's
job; the timers are not, since a oneshot re-execs on its next firing and picks
up the new release by itself.

Installing the unit *files* is still host provisioning. The deploy restarts
units, it does not write them: done once per host, and again by hand whenever
a unit file in `deploy/systemd/` changes.

Copy from **`/srv/shipit/current`**, the symlink to the release that is
actually running. Not from `/opt/shipit`: that is the control checkout, no
deploy updates its working tree, and it can be many releases behind. An
earlier version of this section said `/opt/shipit`, and on 2026-08-02 that
silently installed stale units -- the copy succeeded, `daemon-reload`
succeeded, and the change simply was not there. Verify afterwards rather than
trusting the exit code; the last command below is that check.

```bash
sudo cp /srv/shipit/current/deploy/systemd/*.service \
        /srv/shipit/current/deploy/systemd/*.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now shipit-fixpack.timer shipit-monitoring.timer \
                          shipit-usdt-poller.timer shipit-reap.timer
systemctl list-timers --all | grep shipit

# Prove that what systemd LOADED is what the release ships. `systemctl cat`
# reads the loaded unit, so a stale copy shows up here and nowhere else; its
# first line is the path it read, hence the tail. No output means they match.
diff <(systemctl cat shipit-fixpack.service | tail -n +2) \
     /srv/shipit/current/deploy/systemd/shipit-fixpack.service
```

Run the `.service` once by hand before enabling its `.timer` — a oneshot unit
reports its exit code immediately, and a broken one is much easier to read in
`journalctl -u <unit>` than as a silent no-op every two minutes.

**Do not hand-write a unit that curls the endpoint directly.** On 2026-08-02
this host was found running three such units under names that no longer
matched anything in this repo, and they were worse in ways that are easy to
miss:

- one had the bearer token written into the unit file, so it sat in plaintext
  under `/etc/systemd/system` and was echoed by `systemctl cat`;
- another interpolated the token into a `bash -c` command line, putting it in
  `ps aux` for every local user each time it fired;
- both called the **public** HTTPS URL rather than `127.0.0.1:8000`, ran as
  root, and had no `OnFailure=`, so their failures alerted no one.

The shipped units avoid all of that: `call-internal-endpoint.sh` writes the
header into a `curl` config file with mode `0600` so it never reaches `ps`,
the token comes from `.env` in one place, and `OnFailure=shipit-alert@%n`
means a failed run is reported. The missing alert is not academic — the USDT
poller had been failing on every run since 2026-07-31 and nobody knew, because
the hand-written unit had nothing to tell.

### GitHub webhook — two jobs (`pr_merged` + continuous monitoring)

`POST /v1/webhooks/github` is one endpoint dispatching on `X-GitHub-Event`.
Authenticity (shared by both events) uses the standard GitHub scheme: the
delivery carries `X-Hub-Signature-256: sha256=<hex>`, where `<hex>` is
`HMAC-SHA256(GITHUB_APP_WEBHOOK_SECRET, <raw body>)`, verified constant-time over
the raw bytes. The endpoint 503s until `GITHUB_APP_WEBHOOK_SECRET` is set — an
unconfigured webhook is an operational gap, not a silent no-op (same posture as
the Telegram webhook). Any event other than the two below is a 200 no-op.

**`pull_request` — Fix Pack merge signal.** Records whether a delivered Fix Pack
PR was actually merged — the real-world signal for whether a fix was good enough
to ship — into `fix_outcomes.pr_merged` (migration 0014). This is **collection
only**: nothing scores or acts on the data yet (see
`PHASE_B_KNOWLEDGE_BASE_PLAN.md`). Each terminal Fix Pack outcome (delivered /
blocked / failed / no_fix_needed) is recorded when the processor finishes a job;
the webhook backfills `pr_merged` later, matched by the PR's `html_url`. Only
`action: "closed"` deliveries do work; everything else (and any PR not opened by
a Fix Pack) is a 200 no-op.

**`push` — continuous monitoring (Phase C).** A subscriber enables monitoring of
a public repo from its audit page (the `/monitor <auditId>` bot command → a
recurring Stars subscription whose payload binds the repo; see
`PHASE_C_MONITORING_PLAN.md`). On a push **to that repo's default branch**, the
webhook does only the fast half — it claims the repo and **enqueues** a durable
`monitoring_runs` row (migration 0017), then ACKs 200 immediately. The slow work
(re-audit + diff + notify) runs later on the `shipit-monitoring.timer` processor,
off the HTTP path. This is deliberate: the audit takes ~10 s–2 min, longer than
GitHub's webhook-response timeout, so doing it inline made GitHub's *Recent
Deliveries* mark successful deliveries "timed out" and left the work
un-restartable on a crash (see `MONITORING_ASYNC_PLAN.md`).

The processor re-audits the repo — reusing the same pipeline and content-hash
cache as the URL intake path, so a push that didn't change the audited content
costs no LLM call — and DMs every active subscriber the **new** critical/high
findings. "New" means a `(rule_id, file)` key absent from the previous audit of
the same repo (line numbers are excluded, so incidental line drift isn't a false
alarm; a medium→high re-score of the same key isn't flagged either — that's a
deliberate non-goal). Cost is capped at **one enqueue per repo per 24h**
(`subscriptions.last_monitored_at`, migration 0016), stamped at enqueue time even
when the later re-audit finds nothing or the repo can't be fetched, so a burst of
pushes can't bypass the cap. Pushes to non-default branches, and repos with no
active subscription, are 200 no-ops that enqueue nothing. Monitoring is
public-repo-only (the fetcher uses no auth); a repo that goes private simply
stops producing findings.

The push side and the stored `audits.repo_url` are matched through a single
normalization (`app/monitor.normalize_repo_full_name`) to a canonical lowercased
`owner/repo`, so casing, a trailing `.git`, or a trailing slash never cause a
silent mismatch that would bury the diff.

**Manual, one-time GitHub-UI setup (not code-configurable, done by the
operator):** in the GitHub App's settings, set the **Webhook URL** to
`https://<host>/v1/webhooks/github`, set the **Webhook secret** to the same value
as `GITHUB_APP_WEBHOOK_SECRET` in `.env`, and subscribe the App to **both** the
**Pull request** and **Push** events. Until the App is subscribed to an event, no
deliveries of that kind arrive — `pr_merged` stays `null` and monitoring never
fires — while the rest of each flow is unaffected.

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

### Dependencies & supply chain (Phase 3)

ShipIt's own dependencies are pinned and audited (this is *not* about the
client-repo deps a Fix Pack installs in Docker — that's the egress-allowlist
proxy, a separate concern). See `PHASE3_SBOM_PLAN.md` for the recon and
rationale.

- **Backend lock file.** `pyproject.toml` stays the source of truth for
  *direct* deps (still `>=` ranges); the exact resolved graph is pinned, with
  hashes, in the committed `requirements.txt` (runtime) and
  `requirements-dev.txt` (runtime + `[dev]`). Both are generated by
  `pip-compile` (pip-tools) — regenerate after editing `pyproject.toml`:

  ```sh
  pip-compile --generate-hashes --strip-extras -o requirements.txt pyproject.toml
  pip-compile --generate-hashes --strip-extras --extra dev -o requirements-dev.txt pyproject.toml
  ```

  Install the exact, hash-verified set instead of resolving fresh — on the VPS
  and in CI:

  ```sh
  pip install --require-hashes -r requirements-dev.txt   # exact, verified graph
  pip install -e . --no-deps                             # app code only
  ```

- **Frontend lock file.** `web/package.json` is exact-pinned and
  `web/package-lock.json` is committed; Vercel builds with `npm ci` (lockfile
  exact) by default — nothing to change.

- **`security-audit.yml`** (`.github/workflows/`) runs on pushes to `main`
  touching dep files, on dep-touching PRs, and weekly. Per ecosystem it
  generates a CycloneDX SBOM artifact ("what is actually deployed") and runs a
  free audit: both `pip-audit` and `npm audit --audit-level=high` now **block**.
  The frontend cleared its `next` high advisories in the 14→16 upgrade (see
  "Frontend framework" below), so a new high on either side is a regression to
  fail on. One **moderate** remains that the gate ignores by design: `next`
  pins `postcss@8.4.31` internally (GHSA-qx2v-qp2m-jg93), a build-time-only XSS
  in postcss's CSS stringifier that no attacker input reaches at runtime and
  that we can't move without overriding `next`'s own pinned dep.

- **Frontend framework.** `web/` runs **Next.js 16 on React 19** (upgraded from
  Next 14 / React 18 to clear the `next@14` advisory cluster incl. the RSC RCE
  CVE-2025-55182 / CVE-2025-66478). Future-upgrader notes: Next 16 needs
  **Node ≥ 20.9** (pinned via `web/package.json` `engines`; check the Vercel
  project's Node version on deploy), **Turbopack is now the default builder**
  for `next build` (no custom webpack config here, so no action; `--webpack` is
  the escape hatch), and `next lint` was removed (the vestigial `lint` script
  was dropped — use ESLint/Biome directly if a lint gate is wanted).

- **Dependabot** (`.github/dependabot.yml`) opens weekly PRs for `pip`, `npm`
  (`web/`), and `github-actions` — so patches land as reviewable PRs with no
  new infrastructure.

- **`db-postgres-smoke.yml`** (`.github/workflows/`) is the real-Postgres schema
  + SQL smoke test. The whole unit suite runs with `DATABASE_URL` unset
  (`tests/conftest.py` strips it in an autouse fixture), so every `app/db.py`
  repository write takes the not-configured `None` path and never touches a
  database; `tests/test_db.py` stands in a `FakePool` that records query
  text/params but never sends them to real Postgres. That is fast and catches
  wiring/param-order bugs, but it **cannot** catch a mismatch between a Python
  value's type and a real column type — which is exactly what took `/subscribe`
  down twice (a Telegram Unix-int `expires_at` bound straight into the
  `timestamptz` column → `psycopg.errors.DatatypeMismatch`), all while 517 tests
  stayed green. This job closes that gap: it spins up a **Postgres 17** service
  container (matching the real Supabase major version), applies **every**
  migration in order via `scripts/apply_migrations.sh`, then runs
  `tests/test_db_postgres_smoke.py`, which calls the **write path of every
  repository** in `app/db.py` once against the live schema and asserts the rows
  read back with the right types. A future migration that adds a column or
  changes a type without updating the matching write method makes one of those
  calls raise. It runs on PRs/pushes touching `migrations/**`, `app/db.py`, the
  smoke test, or the runner script (plus `workflow_dispatch`).

  Run it locally against a throwaway Postgres (the file self-skips when
  `DATABASE_URL` is unset, so a normal `pytest -q` is unaffected):

  ```sh
  export DATABASE_URL="postgresql://postgres@localhost:5432/shipit_smoke"
  bash scripts/apply_migrations.sh          # apply all migrations in order
  pytest -q tests/test_db_postgres_smoke.py # exercise every repo write path
  ```

  The test is proven load-bearing, not decorative: reverting the `expires_at`
  timestamptz conversion in `app/db.py` makes it fail with the exact prod
  `DatatypeMismatch` (verified via a temporary local revert on a real
  Postgres — see the job's PR for the captured red→green output).

### Observability (Phase 3)

Single VPS, single uvicorn process — so no Prometheus/Grafana/ELK/Sentry.
Everything rides Postgres and the Telegram bot that already exist (see
`PHASE3_OBSERVABILITY_PLAN.md`).

- **Log format** is configured in one place for every process
  (`app/logging_config.py`, called by both the API and the audit worker;
  the fixpack/monitoring/reap/usdt timers are `curl` calls into the API, not
  Python processes of their own). `LOG_FORMAT=json` emits one JSON object per
  line for `journalctl -o cat | jq` — see the runbook below — and is what
  `.env.example` now ships and what production runs; `LOG_FORMAT=text` is the
  plain line this emitted before Stage 5 and remains the fallback the *code*
  uses when the variable is unset or unrecognized. The JSON
  formatter serialises an explicit allowlist of fields, so a value that nobody
  reviewed cannot reach the log by being attached to a record. Secrets
  matching a known shape (GitHub tokens, PEM keys, JWTs, bot tokens, DSN
  passwords) are masked by a filter that runs in **both** formats.

- **`GET /health`** (public, unauthenticated, leak-free) reports what
  actually fails here: `{"db": <bool>, "fixpack_backlog": <n|null>,
  "oldest_paid_seconds": <secs|null>, "github_app": <bool|null>}`. `db:false`
  means the database is
  unset or unreachable (a live process honestly reporting degraded — still
  `200`, so a dumb uptime pinger can read it). A growing `oldest_paid_seconds`
  past the `shipit-fixpack.timer` interval means the processor isn't draining.
  `github_app:false` means GitHub no longer accepts this deployment's App
  credentials, so **no** Fix Pack can open a PR until `GITHUB_APP_ID` /
  `GITHUB_APP_PRIVATE_KEY_B64` are fixed — affected jobs stay queued rather
  than failing, and the 401 log line carries a non-secret public-key
  fingerprint to compare against the App's registered key. `null` means App
  auth isn't configured here at all (the PAT path), which is not a fault. The
  verdict is cached for five minutes, so the probe stays cheap.
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

### Debugging one `audit_id` / `job_id`

Given nothing but an id from a user report, these three queries say where the
work stopped, how many times it was tried, and what it cost. The first two work
today against the live database and need no code change — the tables have
carried these columns since migrations `0020_llm_usage.sql` and
`0022_audit_jobs.sql`, nothing was reading them.

**1. Where it stopped and how many attempts it took.** `state` plus
`error_code` (written by `classify_failure` in `app/worker/main.py`) give the
class of failure; `attempts` vs `max_attempts` says whether it was retried and
whether it gave up:

```sh
psql "$DATABASE_URL" -c "
  select id as job_id, state, attempts, max_attempts, error_code,
         created_at, claimed_at, completed_at,
         completed_at - claimed_at as duration
    from audit_jobs
   where audit_id = '<AUDIT_ID>' or id = '<AUDIT_ID>';"
```

Query by `id` when the audit never got far enough to exist — a job that failed
before persisting has `audit_id = null`, and the id the client was handed at
submission is the job's.

**2. What it cost.** `llm_usage.job_id` holds the *audit* id for scan jobs (see
`_record_llm_usage` in `app/main.py`):

```sh
psql "$DATABASE_URL" -c "
  select model, calls, input_tokens, output_tokens, cost_usd, created_at
    from llm_usage where job_id = '<AUDIT_ID>';"
```

Note the gap: a row is written only when the LLM stage actually spent tokens
*and* the audit persisted, so a failed audit's spend is not recorded anywhere
yet.

**3. Every log line for that work, across processes.** Only with
`LOG_FORMAT=json` set (see `.env.example`); in the default `text` mode use
`journalctl --grep` instead.

```sh
journalctl -u shipit -u shipit-audit-worker --since '-24h' -o cat \
  | jq -c 'select(.audit_id=="<AUDIT_ID>" or .job_id=="<JOB_ID>")
           | {ts, level, service, step, duration_ms, error_code, msg}'
```

`-o cat` prints the bare `MESSAGE` field with no syslog prefix, which is what
keeps the stream valid JSON for `jq`. Both units are listed because a
submission crosses processes — the API enqueues, the worker runs it — and the
handoff happens through the `audit_jobs` table, so querying one unit shows half
the story.

Correlation ids only appear on lines emitted underneath a set log context. All
four places that own a unit of work set one (`app/log_context.py` names them):
the HTTP middleware, the audit worker's claim loop, the Fix Pack processor and
the monitoring drain. A line logged outside any of them — module import, an
unhandled path — has no ids, so the filter above won't match it.

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

- **Every foreign key is `ON DELETE NO ACTION`, and that is deliberate.**
  Reviewed 2026-08-02 across all ten of them: `audit_jobs.{audit_id,
  account_id}`, `fixpack_jobs.audit_id`, `fix_outcomes.{audit_id,
  fixpack_job_id}`, `llm_usage.{account_id,audit_job_id}`,
  `payments.{account_id,audit_id}`, `subscriptions.account_id`.

  `NO ACTION` does not produce orphans — a foreign key makes orphans
  impossible by definition. It refuses a delete that would create one, which
  is the fail-safe direction. Nothing in the application deletes a parent row:
  there is no account-deletion endpoint, no retention job, no GDPR erasure
  path, and no `delete from` anywhere outside `scripts/verify_db_locally.py`
  (which removes its own fixtures, children first, in the order the
  constraints require).

  Adding `ON DELETE CASCADE` would therefore fix nothing that is broken and
  would introduce something that is not: four of these keys reach money
  (`payments.account_id`, `payments.audit_id`, `subscriptions.account_id`,
  `llm_usage.account_id`). Cascading them means deleting an account silently
  takes its payment history with it, where today the database would refuse and
  make a human stop and think. `SET NULL` is gentler but still changes what
  the data means: a payment with no owner is money received that no longer
  appears in any account's history.

  Decide the semantics when there is a requirement to decide them against — an
  erasure request, or a retention policy for old audits. Choosing now would be
  guessing, and the guess is recorded in the `payments` table.

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
- Billing has no transactions anywhere (`app/db.py` is 100% autocommit).
  `grant_fixpack`'s permanent-money-loss window is now closed without one: the
  two writes are reordered (`create_paid` before `mark_completed_fixpack`), and
  `create_paid` is made idempotent per audit via a partial unique index
  (`migrations/0025`, `ON CONFLICT ... RETURNING (xmax = 0) AS inserted`), so a
  crash between the two leaves the payment `pending` (retryable) instead of
  `completed` with no job. `mark_completed`/`mark_completed_fixpack` also picked
  up a compare-and-set gate (`WHERE status = 'pending' OR (status = 'completed'
  AND external_ref = %s)`), so a retried webhook or a transfer seen on two USDT
  polls is idempotent instead of silently overwriting `account_id`. Still open:
  the USDT branch of `grant_pro_tier` has one narrower window left — a crash
  between that CAS succeeding and the account being created leaves the payment
  `completed` with no account and no key, and closing it needs an actual
  transaction (there isn't one anywhere in this codebase yet). The PayPal SALE
  webhook replay (a redelivered charge extending a subscription for free) and
  the Telegram `grant_pro_tier` branch aren't touched by this either — next up.

## Dev

```bash
pip install -e ".[dev]"
pytest
uvicorn app.main:app --reload
```

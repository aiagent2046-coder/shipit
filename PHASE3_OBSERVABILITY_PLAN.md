# Phase 3 — Observability: reconnaissance + plan

**Status: Step 1 (recon + plan) only. No implementation code in this PR.**
Awaiting review/approval before Step 2.

---

## TL;DR — where the real gaps are

The external audit is right that there's no observability layer: today you
learn about a problem only by SSHing in and reading `journalctl`. But after
reading the code, the picture is more nuanced than "nothing is logged":

- The **Fix Pack `failed` path is already well-instrumented** — it was
  explicitly hardened after a prior silent-failure incident (`app/main.py:813`
  logs a full traceback via `logger.exception` **and** persists a short reason
  to the job's `detail` column).
- **GitHub App auth failures are already logged** with careful, secret-free
  structural diagnostics (`app/deploypack/github_app.py:119, 166, 230`).
- The genuinely dangerous gaps are narrower and specific:
  1. **An LLM provider failure mid-audit is swallowed and never logged**
     (`app/scan/pipeline.py:76`). This is the *known* incident the README
     itself documents ("a repo that scored 0.0 with the LLM stage present
     scored 9.2 without it… when the provider returned 402 mid-run"). It is
     the single most valuable find here.
  2. **No push alerting at all.** Nothing pages the operator on a `failed`
     job, an unhealthy service, or an unhandled 5xx — the data is (mostly) in
     the logs, but a human must go look.
  3. **`/healthz` is a static `{"status": "ok"}`** (`app/main.py:278`) that
     proves only "the process answers HTTP" — not that the DB is reachable or
     that the Fix Pack backlog is actually draining.
  4. **Logging is unconfigured plain text** with no correlation/request id.

The right response at this scale (single VPS, single uvicorn process) is
**not** Prometheus/Grafana/ELK/Sentry. It is: reuse the Telegram bot we
already have to push a handful of high-signal alerts, fix the one real
silent swallow, and make `/health` actually mean something. Details below.

---

## Step 1 — Reconnaissance (answers to the specific questions)

### 1. How logging is set up today

- **No logging configuration exists.** There is **no** `logging.basicConfig`,
  `dictConfig`, `StreamHandler`, or `Formatter` anywhere in `app/`. Modules
  just do `logger = logging.getLogger(__name__)` in four places:
  `app/main.py:71`, `app/fixpack/generate.py:42`,
  `app/deploypack/github_app.py:50`, `app/deploypack/preview.py:35`.
- **So log output is whatever the root/uvicorn logger emits.** In production
  the service is `uvicorn app.main:app` under systemd (`README.md` §Production
  deployment, `shipit.service`), so uvicorn's default handlers write **plain
  text to stdout/stderr → journald → `journalctl -u shipit`**. That matches
  the audit's "SSH/journalctl only" description exactly.
- **Format:** plain text. **No structured/JSON logs.** **No correlation id /
  request id** anywhere — an audit or Fix Pack job cannot be traced across log
  lines except by the ad-hoc `job_id` some Fix Pack messages happen to include.
- **Volume is tiny.** Only **12 `logger.*` calls in the entire backend**:
  7 × `warning`, 2 × `error`, 2 × `exception`, 1 × `info` (counted across
  `app/`). This is important for sizing the fix — see §6, we should not
  over-engineer logging for a codebase that logs a dozen lines.

### 2. What actually reaches the log on each failure path (verified in code)

| Failure | What happens today | Logged? |
|---|---|---|
| **Fix Pack job `failed`** (`_process_one_paid_job`, `app/main.py:742–822`) | `logger.exception(...)` with full traceback **and** a short reason persisted to `fixpack_jobs.detail` via `mark_status`. Explicitly hardened for the "silent-failure incident" (see the docstring at `app/main.py:757`). | **Yes — well.** |
| **GitHub App auth failure** (`app/deploypack/github_app.py`) | 401/JWT/PEM problems logged as `logger.warning` with secret-free diagnostics (app_id, jwt segment count, public-key fingerprint) at lines 119, 166, 230; raised as `GitHubAppError`. In the Fix Pack path the raise lands in the `failed` handler above (so it's double-covered). | **Yes.** |
| **`semantic_check` Docker failure** (`app/fixpack/semantic_check.py:369–384, 464–472`) | `docker` absent / timeout / OSError become an inconclusive `RunResult(error=...)`; the caller treats a symmetric infra error as "could not verify," never a regression. **Not logged** — the error string only flows into the job outcome. | **No** (by design, but invisible in logs). |
| **USDT polling** (`app/billing/usdt_trc20.py:383–451`) | A malformed transfer is silently `continue`d (`except (KeyError, ValueError, TypeError): continue`, line 419) — **not logged**. There is **no** top-level try around the run, so a real failure (TronGrid down, a `grant_*` raising) **propagates** and 500s the endpoint — visible to the scheduler as a non-200, but nothing is logged in-process. | **Partly** — hard failure surfaces as a 500; skipped transfers are silent. |
| **5xx in HTTP handlers** | There is **no** app-level exception handler or middleware. An unhandled exception uses FastAPI/Starlette's default 500, whose traceback is emitted by uvicorn's `uvicorn.error` logger to stderr→journald. **No app-level capture, no alert, no request id.** | **Yes** (uvicorn default) **but not alerted.** |
| **LLM provider failure during an audit scan** (`app/scan/pipeline.py:73–77`) | `except LLMError as exc: llm_summary = f"failed: {exc}"`. The failure is recorded in the audit's `llm` field (and persisted), but **`app/scan/pipeline.py` imports no logger — this is never logged.** | **No — silent.** ⚠️ |

### 3. Existing error-tracking (Sentry/etc.)?

- **None.** No `sentry`, `rollbar`, `bugsnag`, `honeybadger`, `opentelemetry`,
  `prometheus`, or `statsd` in `pyproject.toml` or anywhere in the code/env.
  Dependencies are lean: fastapi, uvicorn, python-multipart, httpx, pyjwt,
  psycopg.
- **Recommendation: do not add one.** Per the task's constraint and the
  Karpathy simplicity bar, a paid SaaS error-tracker is unjustified for a
  single-VPS product that emits ~12 log lines. The Telegram channel below
  covers the "tell me when something breaks" need for free.

### 4. Reusable Telegram client for operator alerts?

**Yes — cleanly, with zero new integration.** `app/billing/telegram_stars.py`
already has a small, tested Bot API wrapper:

- `send_message(chat_id, text, *, token, transport=None)` (`:218`) → posts to
  `sendMessage` via the shared `_call` helper (`:168`), which already raises
  `TelegramError` on a non-2xx / `ok:false`.
- `bot_token_from_env()` (`:78`) already reads `TELEGRAM_BOT_TOKEN`.

So an operator-alert path is: **new env var `TELEGRAM_ADMIN_CHAT_ID`** + a thin
`app/alerts.py` helper that calls the existing `send_message` with the admin
chat id and the existing bot token. **No new dependency, no new HTTP client, no
new provider.** If either the token or the admin chat id is unset, alerting is
a silent no-op (same graceful-degradation contract as the rest of the codebase)
— alerts are additive and must never break a request or a job.

**One caveat to respect:** alerting must be **best-effort and swallow its own
errors** (a Telegram outage or a bad chat id must never turn a handled failure
into a *new* unhandled one, and must never recurse into itself). This is the
one place a deliberate `except Exception: log-and-continue` is correct.

### 5. Health-check endpoint?

- **`GET /healthz` exists** (`app/main.py:278`) but returns a **static
  `{"status": "ok"}`** — no DB check, no freshness. The README already leans on
  it only as a liveness probe ("After `systemctl restart shipit`, hit
  `/healthz` before sending real requests"), which is all it can honestly do
  today.
- **A real `/health` is worth adding**, reporting two things that actually fail
  in this system:
  1. **DB reachable** — a trivial `SELECT 1` through the existing pool
     (`get_pool()` in `app/db.py`). Distinguishes "process up" from "process up
     but Supabase pooler unreachable," which is invisible today until a request
     fails.
  2. **Fix Pack backlog is draining** — the meaningful "is the processor/timer
     alive" signal. **Note:** `fixpack_jobs` has **no `delivered_at`/`updated_at`
     column** (only `created_at` from purchase and `started_at` from the lease —
     verified against migrations 0001/0007/0011), so "time since last successful
     run" is not directly stored. The honest, zero-schema-change signal is
     **age of the oldest `status='paid'` job**: if the oldest queued job is
     older than the timer interval by a healthy margin (e.g. > ~15 min), the
     processor timer is not draining and that is degraded. This needs one new
     read-only repo method (`oldest_paid_age()` / a small counts query); no new
     column, no new table.
- **Auth:** make `/health` **public and unauthenticated**, but **leak nothing**
  — booleans and coarse counts/ages only (`{"db": true, "fixpack_backlog": 2,
  "oldest_paid_seconds": 43}`), never ids, urls, or error text. Rationale: it
  must be callable by a dumb uptime pinger / the systemd timer / Caddy without
  distributing a token, and it reveals nothing an attacker can use. This is a
  different contract from the *operational* endpoints (reap / USDT / process),
  which take a bearer token because they *cause side effects*; `/health` only
  reads. Keep the existing static `/healthz` as-is for the
  race-after-restart liveness probe the README documents, and add the richer
  `/health` alongside it.

### Silently-swallowed errors — the prioritization find

Counting `except` blocks that discard the error **without logging** and where a
*real operational problem* could hide (excluding deliberate parse/format
tolerance and the DB "not configured" sentinel):

- **`app/scan/pipeline.py:76`** — `except LLMError` → stuffed into the response
  string, **never logged.** This is the **one that has already bitten prod**
  (the README's 402-mid-run → 0.0-score incident). **Top priority.**
- **`app/billing/usdt_trc20.py:419`** — malformed on-chain transfer silently
  `continue`d; a systematically bad TronGrid response would look like "nothing
  to match" forever. Low severity, worth a `logger.warning`.
- **`app/scan/secrets.py:217`** — broad `except Exception` when decoding a JWT
  claim, silently downgrades to a generic verdict. Defensive and low-risk;
  leave it, or add a `debug` log at most.

For calibration, the rest of the `except` blocks are **not** bugs and should be
left alone:
- **26 × `except DatabaseNotConfigured`** in `app/db.py` — this is the
  intentional "no `DATABASE_URL` → degrade to unpersisted" contract; real DB
  errors are **not** caught here and do propagate.
- Parse/format tolerance that correctly returns a default:
  `telegram_stars.py:95/105` (bad env int → default price),
  `stack_detect.py:49/72`, `semantic_check.py:111`, `scan/pipeline.py:46`
  (bad zip → raw hash), `scan/llm_scan.py:155/185`, `preview.py:65`,
  `fixpack/generate.py:269/275` (syntax/JSON validation gates),
  `github_app.py:197` (fingerprint → diagnostic string). None of these hide an
  operational failure.

**So the actionable silent-swallow count is effectively one that matters
(`scan/pipeline.py:76`) plus one nice-to-have (`usdt_trc20.py:419`).** That is
the single most useful output of this recon: the observability problem is far
more "no push alerting + one unlogged LLM failure + a hollow health check" than
"errors are swallowed everywhere."

### 6. Proposed MINIMAL plan (Karpathy: simplest thing that works)

No Prometheus/Grafana/StatsD/ELK/Sentry. Postgres + the existing Telegram bot +
stdlib `logging` only. Four surgical pieces, in priority order:

**A. Fix the one real silent swallow (highest value, smallest change).**
Add a module logger to `app/scan/pipeline.py` and `logger.warning(...)` (or
`exception`) the `LLMError` at line 76 before degrading the summary. This alone
makes the exact prod incident the README documents visible in `journalctl`
next time.

**B. Operator alerts via the existing Telegram bot (the core of the ask).**
New `app/alerts.py` with a best-effort `notify_operator(text)` that reuses
`telegram_stars.send_message` + `bot_token_from_env()` + a new
`TELEGRAM_ADMIN_CHAT_ID`. Wire it to a **small, high-signal** set of events —
alert on the things a human must act on, not routine chatter:
  - **Fix Pack job → `failed`** (in `_process_one_paid_job`'s failure handler,
    `app/main.py:818` — right where we already log the traceback). Include
    `job_id` + the short `detail`, no secrets.
  - **GitHub App auth failure** in the Fix Pack delivery path (the
    `GitHubAppError` case) — a paying customer's PR silently not opening is
    exactly the "learn about it manually" pain the audit named.
  - **Unhandled 5xx** — via a single Starlette exception handler / middleware
    in `app/main.py` that logs with a generated **request id** and fires one
    alert. This is also where the request-id correlation gap (Q1) gets its
    minimal fix: attach a short uuid to the request, include it in the 500 log
    line and the alert, and return it in the error body so a report can be
    tied to a log line. Keep it to *unhandled* 500s — the intentional
    `HTTPException`s (422/404/503/etc.) are normal control flow, not alerts.
  - Alerts must be **rate-limited / deduped** minimally (e.g. don't fire more
    than once per N seconds per key) so a crash-loop can't spam the operator
    or Telegram's rate limits. A tiny in-process throttle is enough at this
    scale; no external store.

**C. systemd-level alert for service restart/failure — no new agent.**
Ship (or at least document, matching the repo's "we describe units but don't
commit them" convention) an `OnFailure=` companion unit for `shipit.service`
that curls a tiny authenticated `POST /internal/alert/notify` (or invokes a
one-line `curl` to Telegram directly using values from the same `.env`). This
uses **only** systemd + curl — both already on the box — and satisfies the
task's "systemd-restart alert if technically feasible without a new agent"
note. Exact mechanism (an `OnFailure=` unit that hits an internal endpoint vs.
a direct `ExecStart=curl` to the Bot API) to be decided in Step 2; I lean
toward a bearer-protected internal endpoint so the alert text/formatting lives
in one place in Python. **No unit file is committed** unless you want one, same
as the reaper/USDT/fixpack timers.

**D. Meaningful `/health` (Q5).** Add `GET /health` (public, read-only,
leak-free) returning `{db, fixpack_backlog, oldest_paid_seconds}`; keep
`/healthz` static. One new read-only repo method for the oldest-paid age; no
schema change.

**Logging structure (Q1) — deliberately minimal.** Given ~12 log lines total,
full JSON structured logging is over-engineering right now. The high-value
piece is the **request-id correlation** introduced in (B) for 5xx, plus a
one-time `logging.basicConfig` (or a small `configure_logging()` called from
the lifespan) so log level/format is explicit and consistent instead of
inherited-by-accident. I would **not** convert every line to JSON at this
scale; if log volume grows later, revisit. (Open question 3 below.)

**Explicitly NOT doing:** no Prometheus/StatsD metrics, no Grafana, no ELK, no
Sentry/other SaaS, no new runtime dependency, no OpenTelemetry, no log
shipping, no per-request JSON logs. All alerting rides the Telegram bot that
already exists; all health/freshness data comes from Postgres we already query.

---

## Step 2 — Implementation plan (pending approval; NOT in this PR)

Surgical commits on a fresh branch:

1. **Silent-swallow fix + logging config**
   - `app/scan/pipeline.py`: add module logger; log the `LLMError` at line 76.
   - `app/billing/usdt_trc20.py`: `logger.warning` the skipped-transfer path
     (line 419).
   - `app/main.py` (or a new `app/logging_config.py`): a tiny
     `configure_logging()` invoked from the existing `lifespan`, setting an
     explicit level/format (env-overridable `LOG_LEVEL`), no JSON.

2. **Alerts helper + wiring**
   - New `app/alerts.py`: best-effort `notify_operator(text, *, dedupe_key)`
     reusing `telegram_stars.send_message` + `TELEGRAM_ADMIN_CHAT_ID`; swallows
     its own errors; minimal in-process throttle.
   - Wire into: the Fix Pack `failed` handler and the GitHub-App-auth failure
     in `app/main.py`; a Starlette 500 exception handler that adds a request id,
     logs it, and alerts once.
   - `.env.example`: document `TELEGRAM_ADMIN_CHAT_ID` and (optional)
     `LOG_LEVEL`, following the existing commented style.

3. **`/health`**
   - `app/main.py`: `GET /health` (public, leak-free) → `{db,
     fixpack_backlog, oldest_paid_seconds}`.
   - `app/db.py`: one read-only `fixpack_backlog_stats()` (count of `paid` +
     age of oldest `paid`); `DatabaseNotConfigured` → reports `db:false`
     gracefully.

4. **Docs / ops (no committed unit files, matching convention)**
   - `README.md`: document `/health`, the alert env vars, and the
     `OnFailure=`/curl systemd recipe for restart alerts next to the existing
     reaper/USDT/fixpack timer notes.

### Tests (required, mirroring the queue PR's approach)

- **Alerts:** `notify_operator` posts the expected `sendMessage` body via an
  injected `httpx.MockTransport` (same pattern as `tests/test_billing_*`);
  is a **no-op** when token/chat-id unset; **swallows** a `TelegramError`
  without propagating; throttle suppresses a duplicate within the window.
- **Fix Pack failure → alert:** extend `tests/test_fixpack_process_endpoint.py`
  (existing `FakeFixpackRepo`/`FakeAuditRepo`) to assert one alert fires on a
  `failed` outcome and none on `delivered`.
- **5xx handler:** a route that raises is caught, returns a 500 carrying a
  request id, logs it, and fires exactly one alert; an intentional
  `HTTPException` (422/404) fires **none**.
- **`/health`:** DB-up → `{db:true,...}`; DB-not-configured → `{db:false}` and
  still 200 (or a documented non-200 — see open question 4); backlog age
  reflects a stale `paid` job in the fake repo.

### Open questions for the reviewer (please confirm before Step 2)

1. **Alert scope** — is {`failed` Fix Pack job, GitHub-App auth failure,
   unhandled 5xx, systemd `OnFailure`} the right set, or do you also want
   `blocked` (semantic-check regression) and USDT/TronGrid poll failures?
   I propose keeping the first set (highest signal) and leaving `blocked` to
   the DB/logs.
2. **Restart alert mechanism** — `OnFailure=` unit hitting a bearer-protected
   internal endpoint (formatting in Python) vs. a direct `ExecStart=curl` to
   the Bot API in the unit? I lean toward the internal endpoint.
3. **Logging format** — confirm "explicit `configure_logging()` + request-id
   on 5xx, but **no** full JSON structured logging yet." Or do you want JSON
   now despite the tiny log volume?
4. **`/health` when DB unconfigured** — 200 with `{db:false}` (my preference,
   so the pinger sees a live process reporting degraded) vs. 503?
5. **New env vars** — OK to add `TELEGRAM_ADMIN_CHAT_ID` (required for alerts)
   and optional `LOG_LEVEL`, and nothing else?

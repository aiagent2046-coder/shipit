# Async Continuous Monitoring — move the push audit off the HTTP hot path

> **Later note (2026-08-28).** Every "24h" below is the number this plan was
> written with; the cap is now `MONITORING_INTERVAL_HOURS` in `app/monitor`,
> set to **72**. Nothing else about the claim changed — it is still one atomic
> conditional UPDATE doing both the cost cap and the enqueue dedup.

## Problem (from the live incident)

Phase C's GitHub `push` webhook (`/v1/webhooks/github`) currently does the whole
monitoring cycle **synchronously inside the HTTP handler**: `_handle_monitoring_push`
calls `run_repo_audit` (a real LLM scan, ~10 s–2 min per its docstring), diffs the
findings, and sends the Telegram alert — all before returning the HTTP response.

A live test today confirmed the work completes correctly (the alert arrived with the
right findings, and the atomic `claim_for_monitoring` prevented any duplication), but
GitHub's *Recent Deliveries* UI showed the delivery as **"timed out"**: GitHub's
webhook-response timeout is shorter than our processing. That is:

- a permanent "failure" in the GitHub UI even though the work succeeded, and
- genuinely fragile — if the process restarts or crashes mid-audit, GitHub may never
  see a success and a retry is not guaranteed.

## Goal

Make the `push` handler **fast (instant ACK)** and move the real work
(audit + diff + notify) into **background processing**, mirroring the already-shipped
Fix Pack queue: an atomic claim + a durable job row + a separate
`POST /internal/…/process-…` endpoint drained by a systemd timer.

---

## Step 1 recon — how the Fix Pack queue works today (verified in code)

The Fix Pack durable-processing model (`PHASE3_QUEUE_PLAN.md`, migration 0011):

1. **Job row + lease columns** — `fixpack_jobs` (migration 0001) plus `started_at` and
   `attempts` (0011). Status is plain text: `paid → running → {delivered | no_fix_needed
   | blocked | failed}`. No enum/CHECK (a new status value must never need a migration).
2. **Atomic claim** — `FixpackJobRepository.claim_one_paid` (`app/db.py:482`) does a single
   `UPDATE … WHERE id = (SELECT id … FOR UPDATE SKIP LOCKED LIMIT 1)` that flips one
   `paid` row to `running`, stamps `started_at = now()`, and `attempts = attempts + 1`.
   Two overlapping runs can never both grab the same job — the loser's `SELECT` skips the
   locked row. This is the "no duplicate PR per payment" guarantee.
3. **Stale-lease reaper** — `reap_stale_running(max_age_minutes, max_attempts)`
   (`app/db.py:527`) recovers a crashed worker's job: a `running` lease older than the
   threshold is either re-queued to `paid` (`attempts < max`) or moved to `failed`
   (`attempts >= max`, with a diagnosable `detail`). Called at the **start** of every
   processor pass, before claiming.
4. **Advisory lock** — `fixpack_processor_lock()` (`app/db.py:115`) takes a session-level
   `pg_try_advisory_lock` on a fixed key (`0x46495850` = "FIXP") for the whole run;
   raises `ProcessorLockBusy` if already held. Belt-and-suspenders so overlapping timer
   firings don't stampede.
5. **Processor endpoint** — `POST /internal/fixpack/process-paid`
   (`app/main.py:1273`): 503 if `FIXPACK_PROCESS_TOKEN` unset, 401 on bad bearer
   (`_require_bearer_token`, constant-time). Then: `async with fixpack_processor_lock()`
   → `reap_stale_running` → loop `claim_one_paid()` until `None`, processing each via
   `_process_one_paid_job` (`app/main.py:1161`), which catches every exception, marks the
   job `failed` with a `detail`, and logs a full traceback (the silent-failure hardening).
   Returns a summary dict, or `{"skipped_locked": true}` on `ProcessorLockBusy`. Tuning
   constants `STALE_LEASE_MINUTES = 15`, `MAX_JOB_ATTEMPTS = 3` (`app/main.py:355`).
6. **Scheduling** — the repo ships **no unit file** (README "Production deployment",
   lines 342–352): the operator wires `shipit-fixpack.timer` to hit the endpoint with the
   bearer token from `.env` on a 2–5 min interval. Same pattern as `shipit-reap.timer`
   (preview reaper) and the USDT poller.

## Step 1 recon — the current monitoring push path

`_handle_monitoring_push` (`app/main.py:706`), all synchronous in the request:

1. Ignore non-default-branch pushes and unparseable repos (fast, no DB).
2. `list_active_for_repo(repo_full_name)` — no active subscriber ⇒ 200 no-op.
3. `claim_for_monitoring(repo_full_name, now)` (`app/db.py:1281`) — a single conditional
   `UPDATE subscriptions SET last_monitored_at = now WHERE … (never monitored OR
   last_monitored_at < now - 24h) RETURNING id`. This is **both** the 24h-per-repo cost
   cap **and** the concurrency guard: exactly one of two racing pushes wins. Lost/throttled
   ⇒ 200 `within_interval`.
4. **[SLOW — to be moved]** `get_latest_by_repo_url` (diff baseline) → `run_repo_audit`
   (fetch + validate + stack-detect + content-hash cache + LLM `run_scan` + persist) →
   `new_high_severity_findings` diff → Telegram DM to each subscriber.

Steps 1–3 are already fast. Only step 4 blocks the response.

---

## Step 1 design decisions

### Decision A — a dedicated `monitoring_runs` table (not overloading `subscriptions`)

**Chosen: a new `monitoring_runs` table**, directly analogous to `fixpack_jobs`.

Why not reuse `subscriptions.last_monitored_at`? That column is the *claim* (24h
throttle + enqueue dedup) and stays. But splitting claim from processing means the
background worker needs to know **which repos have work waiting** — a durable
"pending audit" record with its own status/lease/attempts lifecycle. `subscriptions`
can't carry that: it's billing data, one repo can have *several* subscription rows, and a
monitoring run is a per-repo-per-push concept, not a per-subscription one. Overloading it
would be wrong normalization and would tangle the billing key with run state. A separate
queue table is exactly the Fix Pack shape and the minimal correct model.

**What the row must carry:** only the repo + lease machinery. It deliberately does **not**
store the diff baseline or the subscriber list — both are read *at process time*
(`get_latest_by_repo_url` and `list_active_for_repo`), which is fresher (new/expired subs
handled) and matches the current ordering (baseline read before the new audit is
persisted).

`migrations/0017_monitoring_runs.sql`:

```sql
create table if not exists monitoring_runs (
    id uuid primary key default gen_random_uuid(),
    repo_full_name text not null,
    status text not null default 'pending',   -- pending | running | done | failed
    attempts integer not null default 0,
    started_at timestamptz,
    error text,
    created_at timestamptz not null default now(),
    completed_at timestamptz
);

-- The processor claims the oldest 'pending' row; index that scan.
create index if not exists monitoring_runs_status_created_idx
    on monitoring_runs (status, created_at);

-- Default-deny RLS, same posture/rationale as 0002/0014/0015.
alter table monitoring_runs enable row level security;
```

Status is plain text (no enum/CHECK), matching 0011/0015. `started_at` = current lease
(NULL when not running); `attempts` bounds crash-requeues; `error` is the diagnosable
failure reason (mirrors `fixpack_jobs.detail`); `completed_at` stamps terminal states.

### Decision B — the new flow

**`push` webhook (`_handle_monitoring_push`), now fast:**
1. signature check → parse (already in `github_webhook`)
2. default-branch / unparseable-repo guards (unchanged)
3. `list_active_for_repo` — no subscriber ⇒ 200 `no_active_subscription` (unchanged)
4. `claim_for_monitoring(repo, now)` — **unchanged**; lost/throttled ⇒ 200 `within_interval`
5. **if claim won:** `monitoring_repo.enqueue(repo)` — a fast `INSERT … 'pending'` — then
   **return 200 immediately** (`{"queued": true, "run_id": …}`). No audit, no diff, no DM.

Keeping `claim_for_monitoring` exactly as-is preserves the 24h cap + race dedup at
*enqueue* time (a push burst still enqueues at most one run per repo per 24h), which is
precisely the flow the task describes. (Minor, accepted edge: a crash in the narrow window
*between* the claim `UPDATE` and the `enqueue` `INSERT` would stamp `last_monitored_at`
without a queued run, costing one missed cycle that self-heals at the next push after 24h.
Following the task's prescribed two-step flow; noted for transparency.)

**New `POST /internal/monitoring/process-pending`** (mirrors `process-paid` exactly):
- 503 if `MONITORING_PROCESS_TOKEN` unset; 401 on bad bearer (`_require_bearer_token`).
- `async with monitoring_processor_lock()` → `reap_stale_running(…)` → loop
  `claim_one_pending()` until `None`, processing each via a new
  `_process_one_monitoring_run(...)`.
- Returns a summary `{processed, notified, no_new, unfetchable, unauditable, failed,
  requeued}`, or `{"skipped_locked": true}` on `ProcessorLockBusy`.

`_process_one_monitoring_run(run, *, subscription_repo, audit_repo, llm_client,
repo_fetcher, transport)` — the body lifted verbatim from today's `_handle_monitoring_push`
step 4, wrapped in the Fix Pack try/except discipline:
- `subs = list_active_for_repo(repo)` — none now (all expired since enqueue) ⇒ `mark_done`,
  return `no_subscription` (benign).
- `previous = get_latest_by_repo_url(repo)` (baseline **before** the new audit).
- `run_repo_audit(...)`; `RepoFetchError` ⇒ `mark_done`, `unfetchable`; `None` ⇒ `mark_done`,
  `unauditable`.
- `new_high_severity_findings(previous, result["findings"])`; DM each subscriber
  (`_monitoring_alert_text`, one bad DM never aborts the rest — unchanged).
- `mark_done` on success; any unexpected `Exception` ⇒ log traceback + `mark_failed(error)`
  (terminal, diagnosable — matches `_process_one_paid_job`). The reaper handles only true
  crashes (row stuck `running`), not caught failures.

### Decision C — fault tolerance (identical Fix Pack pattern, not a new one)

- **Advisory lock:** refactor the existing lock into a private
  `_advisory_processor_lock(key)` async-generator; `fixpack_processor_lock` keeps its key
  (`0x46495850`), add `monitoring_processor_lock` with a new fixed key `0x4D4F4E49`
  ("MONI"). Both public names preserved; no behavior change for Fix Pack.
- **Atomic claim:** `MonitoringRunRepository.claim_one_pending()` — the same
  `UPDATE … WHERE id = (SELECT … FOR UPDATE SKIP LOCKED LIMIT 1)` flipping `pending →
  running`, stamping `started_at = now()`, `attempts = attempts + 1`.
- **Stale-lease reaper:** `MonitoringRunRepository.reap_stale_running(max_age_minutes,
  max_attempts)` — `running` older than threshold → `pending` (`attempts < max`, clear
  `started_at`) or `failed` (`attempts >= max`, with `error`). Reused constants
  `STALE_LEASE_MINUTES = 15`, `MAX_JOB_ATTEMPTS = 3`.

### `MonitoringRunRepository` (`app/db.py`) — mirrors `FixpackJobRepository`
- `enqueue(repo_full_name)` → `INSERT … 'pending' RETURNING …`; None when DB unconfigured.
- `claim_one_pending()` → atomic claim (above); None when nothing pending / DB unconfigured.
- `mark_done(run_id)` → `status='done', completed_at=now()`.
- `mark_failed(run_id, error)` → `status='failed', error=…, completed_at=now()`.
- `reap_stale_running(...)` → `{"requeued": n, "failed": m}`.

All follow the `DatabaseNotConfigured` → no-op contract used throughout `app/db.py`.

### Wiring (`app/main.py`)
- `_monitoring_process_token()` → `MONITORING_PROCESS_TOKEN` (mirror
  `_fixpack_process_token`).
- Module singleton `_monitoring_repo = MonitoringRunRepository()` +
  `get_monitoring_repo()` dependency (mirror `get_fixpack_repo`).
- `github_webhook` gains `monitoring_repo = Depends(get_monitoring_repo)`, passed to
  `_handle_monitoring_push`. The push handler no longer needs `audit_repo/llm_client/
  repo_fetcher/transport` (those move to the processor); the endpoint keeps them for the
  `pull_request` branch as needed.

---

## Files changed

| File | Change |
|---|---|
| `migrations/0017_monitoring_runs.sql` | **new** — `monitoring_runs` table + index + RLS |
| `app/db.py` | **new** `MonitoringRunRepository`; refactor advisory lock into `_advisory_processor_lock(key)` + add `monitoring_processor_lock` |
| `app/main.py` | slim `_handle_monitoring_push` to claim+enqueue+ACK; new `_process_one_monitoring_run`; new `POST /internal/monitoring/process-pending`; token helper; DI singleton/dependency; wire webhook |
| `tests/test_monitoring.py` | webhook tests now assert fast ACK + enqueue (no `run_repo_audit`); move audit/diff/notify assertions to the processor |
| `tests/test_monitoring_process_endpoint.py` | **new** — processor happy path, notify, unfetchable/unauditable, atomic claim, stale-lease reaper, poison-pill, auth guards, lock-busy (mirrors `test_fixpack_process_endpoint.py`) |
| `README.md` | document `shipit-monitoring.timer` recipe + `MONITORING_PROCESS_TOKEN`; update the `push` section to describe the async flow |
| `.env.example` | add `MONITORING_PROCESS_TOKEN=` with the same comment pattern |

## Tests (task point 6)

- **(a) webhook is fast & does no audit:** monkeypatch `main_mod.run_repo_audit` to a stub
  that fails the test if called; assert an eligible push returns `{"queued": true}` and the
  fake monitoring repo recorded exactly one `pending` enqueue. Scenarios a/b (no sub, within
  24h) and non-default-branch stay on the webhook and assert **no** enqueue.
- **(b) processor runs audit+diff+notify:** a `pending` run through
  `/internal/monitoring/process-pending` re-audits (fake scan), diffs against the fake
  baseline, DMs subscribers, and marks the run `done` (moves scenarios c/d here).
- **(c) atomic claim:** `claim_one_pending()` hands a run back once, then `None` (mirrors
  `test_claim_hands_back_each_job_once`).
- **(d) stale-lease reaper:** a `running` run with an old lease is requeued then delivered
  once; a run at `MAX_JOB_ATTEMPTS` is failed, not re-queued (mirrors the Fix Pack lease
  tests). Plus auth guards (503/401) and `skipped_locked`.

Full suite run before the PR (`pytest -q`).

## systemd timer (README recipe; operator wires it on the VPS)

New `MONITORING_PROCESS_TOKEN` in `.env`. `shipit-monitoring.timer` hits
`POST /internal/monitoring/process-pending` with that bearer. A **longer interval than Fix
Pack** is appropriate — a repo is re-audited at most once per 24h, and a pending run only
needs to drain within a few minutes of a push — so ~5 min (`OnUnitActiveSec=5min`). Safe to
fire while a previous run works: advisory lock (`{"skipped_locked": true}`) + atomic
per-run claim; a run reaps `running` leases older than 15 min (crashed worker), re-queuing
up to 3 attempts then failing. No unit file shipped (same convention as reaper/USDT/Fix
Pack).

## Out of scope
- No change to the diff logic, `claim_for_monitoring`, or the 24h cap.
- No `/health` backlog stat for monitoring (Fix Pack has one; not required here — can be a
  follow-up).
- No change to the `pull_request` webhook branch.

# Phase 3 — Fix Pack job durability / queue: reconnaissance + plan

**Status: Step 1 (recon + plan) only. No implementation code in this PR.**
Awaiting review/approval before Step 2.

---

## TL;DR — the audit's premise is only half right

The external audit flagged: *"no real queue / state machine; a job's state is
lost or stuck forever if `shipit` restarts mid-job, so a paying client may
never get a PR or a clear status."*

After reading the code, the reality is narrower and different:

- **Jobs are already durably persisted in Postgres** (`fixpack_jobs`, status
  `paid`) and are **NOT lost on restart.**
- Generation is **not** synchronous in the HTTP request and **not** an
  `asyncio.create_task`. It runs in a **separate batch endpoint**
  (`POST /internal/fixpack/process-paid`) meant to be driven by a scheduled
  systemd timer (which, per the README, is *not yet shipped* — same as the
  reaper and USDT poller).
- On a mid-job crash/restart the job **stays `paid`** and is simply
  **re-picked by the next processor run.** There is no `processing` status to
  get stuck in, so there is **no zombie-forever bug today.**

So the "state machine + persistence" that the audit asks for is **largely
already present.** The genuine, smaller gaps are:

1. **No concurrency guard → risk of a duplicate PR + duplicate work.** Because
   a job remains `paid` for the entire (minutes-long, Docker + LLM) generation,
   two overlapping processor runs both see it as `paid` and both process it →
   **two fix PRs for one payment.** There is no lease, no advisory lock, no
   `FOR UPDATE SKIP LOCKED` — `list_paid()` is a plain `SELECT`.
2. **No "in-flight" visibility.** `paid` conflates "queued, waiting" with
   "currently generating". Operationally you cannot tell a stuck job from a
   fresh one.
3. **A latent trap:** the moment we *do* add an in-flight state (a lease), we
   reintroduce exactly the zombie the audit feared **unless** we also add
   stale-lease reaping. So reaping is a required part of the fix, not optional.

The net scope is **smaller than "build a queue"** and **surgical**: no Redis /
Celery / RabbitMQ — Postgres already gives us everything (row locks, advisory
locks, timestamps).

---

## Step 1 — Reconnaissance (answers to the specific questions)

### 1. How is a Fix Pack job processed today? (concrete names)

- **Purchase → enqueue:** `app/billing/__init__.py:163`
  `fixpack_repo.create_paid(audit_id=..., stack=...)` inserts a `fixpack_jobs`
  row with `status='paid'` (`app/db.py:313` `create_paid`). Called from the
  USDT-confirmed and Telegram-Stars-confirmed payment paths.
- **Generation → delivery:** `app/main.py:730` `_process_one_paid_job(job, ...)`
  does the whole pipeline for one job:
  re-fetch repo (`fetch_repo_zip`), `build_fixpack_plan`
  (`app/fixpack/generate.py`), `run_semantic_check` in Docker
  (`app/fixpack/semantic_check.py`), resolve a GitHub App installation token,
  `open_pull_request` (`app/deploypack/delivery.py`), then advance status.
- **Trigger:** `app/main.py:813` `POST /internal/fixpack/process-paid`
  (bearer-token protected via `FIXPACK_PROCESS_TOKEN`). It calls
  `fixpack_repo.list_paid()` (`app/db.py:352`, plain `SELECT ... WHERE
  status='paid' ORDER BY created_at ASC`) and loops over the jobs
  **sequentially** in one request.

So: **not** synchronous in a user HTTP request, **not** `asyncio.create_task` /
FastAPI `BackgroundTasks`, **not** a separate process. It is an **operational
batch endpoint** designed for a systemd timer. Per `README.md` (§"USDT/TRC20"
and §"Production deployment"), **the repo ships no timer unit** for it yet —
the same known gap called out for the reaper and USDT poller.

### 2. What happens to job state on a mid-job restart, right now?

- The row is in Postgres as `status='paid'` from purchase time.
- `_process_one_paid_job` writes **only terminal** statuses
  (`app/main.py`): `delivered` (via `mark_fixpack_delivered`, `app/db.py:377`),
  `no_fix_needed`, `blocked`, or `failed` (via `mark_status`, `app/db.py:399`).
  It **never** writes an intermediate `running`/`processing`.
- Therefore a crash/`systemctl restart shipit` mid-job leaves the row `paid`.
  **The next processor run re-picks it** — accidentally durable.
- **There is no zombie `processing` state to get stuck in.** The audit's
  "stuck in processing forever" scenario **cannot happen in the current code**
  because that state does not exist.

Statuses actually written in code (do not invent new ones beyond need):
`generated` (Deploy Pack default, migration 0007), `paid` (purchase),
`delivered`, `no_fix_needed`, `blocked`, `failed`. Frontend
(`web/src/lib/types.ts` `FixpackJobStatus`, `FixpackPurchase.tsx`) knows:
`paid`, `delivered`, `no_fix_needed`, `blocked`, `failed`.

### 3. Existing retry logic anywhere?

- **Job level: none.** A `failed` job stays `failed` for a human to notice; it
  is not auto-retried. A `paid` job that crashed mid-run is *effectively*
  retried only because it never left `paid`.
- **LLM client: yes, local.** `app/llm/client.py:63` retries transient errors
  against the same provider with backoff. Unrelated to job orchestration.
- **GitHub delivery / semantic check: no retry.**

### 4. Proposed minimal design (Karpathy: simplest thing that works; Postgres only)

Add a real, minimal state machine **around the existing pipeline** — do not
rewrite the pipeline itself.

**New status:** `running` (in-flight lease). Full progression becomes:

```
paid ──(atomic claim)──> running ──> delivered | no_fix_needed | blocked | failed
  ^                          │
  └────(stale-lease reap)────┘   (crashed mid-run: running older than N min → back to paid, bounded retries)
```

Concrete changes (surgical):

1. **Migration `0011_fixpack_jobs_lease.sql`:** add
   - `started_at timestamptz` (when the current lease was taken; NULL when not
     running),
   - `attempts integer not null default 0` (retry bound).
   No new table, no enum/check constraint (matches the plain-text-status
   convention in migrations 0003/0007). Backward compatible.

2. **Atomic claim in `FixpackJobRepository` (`app/db.py`).** Replace the
   "`list_paid()` then loop" with a **claim-one-at-a-time** primitive:
   ```sql
   UPDATE fixpack_jobs
      SET status='running', started_at=now(), attempts=attempts+1
    WHERE id = (
      SELECT id FROM fixpack_jobs
       WHERE status='paid'
       ORDER BY created_at ASC
       FOR UPDATE SKIP LOCKED
       LIMIT 1)
   RETURNING ...;
   ```
   `FOR UPDATE SKIP LOCKED` + the single-row `UPDATE ... RETURNING` guarantees
   **only one worker can move a given job `paid → running`**, even with
   overlapping processor runs or (future) multiple instances. This alone closes
   the duplicate-PR bug. The processor loops "claim → process → claim next"
   until `claim` returns nothing.

3. **Session advisory lock around a processor run** (belt-and-suspenders,
   cheap): `pg_try_advisory_lock(<const>)` at the top of
   `process_paid_fixpacks`; if not acquired, return early (`{"skipped_locked":
   true}`) so two timer firings never run concurrently. Optional given (2)
   already makes it safe per-job; I lean **include it** — it's ~5 lines and
   makes the "one run at a time" invariant explicit and observable.

4. **Stale-lease reaper (the required counterpart to adding `running`).** At the
   start of each processor run, before claiming: find jobs `status='running'
   AND started_at < now() - interval 'N minutes'` (N configurable, default e.g.
   15 min — comfortably above a real Docker+LLM job's worst case). For each:
   - if `attempts < MAX_ATTEMPTS` (e.g. 3) → reset to `paid` (re-queue),
   - else → `failed` with a clear `detail` ("exceeded max attempts / stuck
     lease reaped").
   This is what makes a real mid-job crash recover automatically **and** bounds
   infinite ret/crash loops.

5. **Frontend:** teach the UI that `running` is "in progress" (identical UX to
   `paid` — spinner + "Generating your fix…"). Update
   `web/src/lib/types.ts` `FixpackJobStatus` to include `running`, and add a
   `running` branch (or fold it into the existing `paid` branch) in
   `FixpackPurchase.tsx`. Note: the current UI already *degrades safely* on an
   unknown non-terminal status (keeps polling, shows an empty box), so this is
   a polish/correctness update, not a crash fix — but worth doing minimally as
   the task requires.

**Explicitly NOT doing:** no Redis/Celery/RabbitMQ, no separate worker process,
no new `jobs` table, no rewrite of the generation pipeline, no change to the
purchase or payment flow, no change to the reaper/USDT endpoints.

### 5. Concurrency / scale — do we even need a separate worker?

- **Scale is tiny / early-stage.** Single VPS, single `uvicorn` process
  (`shipit.service`, `Restart=on-failure`), self-hosted USDT + Telegram Stars,
  manual/absent timers. The processor already handles jobs **sequentially**
  (one `for` loop in one request); there is no parallelism and no configured
  parallelism limit — concurrency within a run is effectively 1.
- **A separate worker process is NOT warranted.** The pickup-on-start behaviour
  the audit wants is already the natural consequence of jobs staying `paid`; we
  just need the **atomic claim + advisory lock + stale-lease reaping** so that
  (a) overlapping runs can't double-deliver and (b) a crashed lease recovers.
  This all lives inside the same process, driven by the same
  `POST /internal/fixpack/process-paid` endpoint + a systemd timer.
- **What still needs wiring outside this repo (ops, documented not shipped):** a
  `shipit-fixpack.timer` systemd unit calling the endpoint on an interval
  (e.g. every 2–5 min). This PR will document it in the README next to the
  reaper/USDT-poller notes but, consistent with existing convention, will not
  ship a unit file.

---

## Step 2 — Implementation plan (pending approval; NOT in this PR)

Commits (surgical, on this branch):

1. **DB + state machine**
   - `migrations/0011_fixpack_jobs_lease.sql` (`started_at`, `attempts`).
   - `app/db.py`: `claim_one_paid()` (atomic claim via `FOR UPDATE SKIP
     LOCKED`), `reap_stale_running(max_age, max_attempts)` (re-queue or fail),
     and advisory-lock helpers (`try_processor_lock` / release).
   - `app/main.py`: rework `process_paid_fixpacks` to
     advisory-lock → reap stale → claim-loop; `_process_one_paid_job` unchanged
     internally except it now operates on an already-claimed (`running`) job.
2. **Frontend**
   - `web/src/lib/types.ts`: add `running` to `FixpackJobStatus`.
   - `web/src/components/FixpackPurchase.tsx`: render `running` as in-progress.
   - README: note the intended `shipit-fixpack.timer`.

### Tests (required by the task)

- **(a) Happy-path state transitions:** `paid → running → delivered` (and
  `→ no_fix_needed` / `→ blocked` / `→ failed`) using the existing
  `FakeFixpackRepo` pattern in `tests/test_fixpack_process_endpoint.py`,
  extended with claim/lease bookkeeping.
- **(b) Restart / stuck-job pickup, no double-run:**
  - a job left in `running` with an old `started_at` (simulated crash) is
    reaped → re-queued → processed to completion (not stuck forever);
  - **no double-delivery:** two overlapping processor runs (or a claim race)
    result in the PR opener being called **exactly once** for a job — asserted
    against the atomic-claim primitive (and, for the real repo path, an
    integration-style test of `claim_one_paid` returning the row to only one
    caller if a live Postgres is available; otherwise a focused unit test of
    the claim SQL / fake with lock semantics).
  - bounded retries: a job that keeps failing to lease-complete lands in
    `failed` after `MAX_ATTEMPTS`, not an infinite requeue loop.

### Open questions for the reviewer (please confirm before Step 2)

1. **Reap thresholds:** default stale-lease age (proposing 15 min) and
   `MAX_ATTEMPTS` (proposing 3) — OK, or different?
2. **On stale-lease reap, prefer re-queue (`running → paid`) or straight to
   `failed`?** Proposing re-queue up to `MAX_ATTEMPTS` then `failed`.
3. **Include the session advisory lock** (item 3) or rely solely on the atomic
   per-job claim? Proposing include it.
4. Confirm you're OK adding exactly one new status (`running`) and two columns
   (`started_at`, `attempts`), nothing more.

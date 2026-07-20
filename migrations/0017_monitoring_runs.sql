-- Phase C async continuous monitoring: move the push audit off the HTTP hot
-- path (see MONITORING_ASYNC_PLAN.md). The GitHub push webhook used to run the
-- LLM re-audit + diff + Telegram notify synchronously inside the request, which
-- GitHub's Recent Deliveries marked "timed out" (its webhook-response timeout is
-- shorter than a ~10s-2min audit) even though the work succeeded -- and left the
-- work un-restartable if the process crashed mid-audit.
--
-- This is the durable job queue that fixes it, directly analogous to
-- fixpack_jobs' lease model (migrations 0001/0011): the webhook wins the atomic
-- claim_for_monitoring (subscriptions.last_monitored_at -- the 24h cost cap AND
-- enqueue dedup, unchanged), then INSERTs one 'pending' row here and ACKs 200
-- immediately. POST /internal/monitoring/process-pending drains the queue on a
-- systemd timer: claim 'pending' -> 'running' atomically (FOR UPDATE SKIP
-- LOCKED), run audit+diff+notify, mark 'done'/'failed'.
--
-- Deliberately NOT a column on subscriptions: subscriptions is billing data with
-- possibly several rows per repo, while a run is a per-repo-per-push object with
-- its own lifecycle/lease/attempts. Overloading it would tangle the billing
-- natural key with run state.
create table if not exists monitoring_runs (
    id uuid primary key default gen_random_uuid(),
    -- The canonical lowercased 'owner/repo' this run must re-audit (see
    -- app/monitor.normalize_repo_full_name). The diff baseline and the
    -- subscriber list are NOT stored here: both are read at process time
    -- (get_latest_by_repo_url, list_active_for_repo), which is fresher and
    -- matches the ordering the synchronous path already used.
    repo_full_name text not null,
    -- Plain text (no enum/CHECK), same rationale as 0011/0015: a new status
    -- value must never require a migration. pending -> running -> (done |
    -- failed).
    status text not null default 'pending',
    -- How many times this run has been claimed into 'running'. Bumped at claim
    -- time; bounds crash-requeues so a poison-pill run lands in 'failed' after
    -- MAX_JOB_ATTEMPTS rather than re-queuing forever. Mirrors
    -- fixpack_jobs.attempts.
    attempts integer not null default 0,
    -- When the current 'running' lease was taken; NULL whenever not running.
    -- The stale-lease reaper compares it against now() to recover a crashed
    -- worker's run. Mirrors fixpack_jobs.started_at.
    started_at timestamptz,
    -- Diagnosable failure reason on a 'failed' run (mirrors fixpack_jobs.detail)
    -- -- a 'failed' row with a null error is the silent failure this guards
    -- against.
    error text,
    created_at timestamptz not null default now(),
    -- Stamped when the run reaches a terminal state (done | failed).
    completed_at timestamptz
);

-- The processor claims the oldest 'pending' row every pass (and the reaper scans
-- 'running'); index the (status, created_at) lookup.
create index if not exists monitoring_runs_status_created_idx
    on monitoring_runs (status, created_at);

-- Default-deny RLS with no policies, same posture and rationale as migrations
-- 0002/0014/0015: no user/auth model to write a per-row policy against, and the
-- app connects as the table-owning role (RLS never applies to the owner without
-- FORCE ROW LEVEL SECURITY, which this deliberately does not set), so this only
-- closes the "RLS Disabled in Public" advisory for a role reaching the table via
-- PostgREST.
alter table monitoring_runs enable row level security;

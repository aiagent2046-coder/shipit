-- Fix Pack job lease + retry bound, for the durable-processing state
-- machine (see PHASE3_QUEUE_PLAN.md). Two additions to fixpack_jobs plus
-- one new status value ('running'), all backward-compatible.
--
-- The processor used to select status='paid' rows and process them in
-- place, never writing an intermediate state. That was accidentally
-- restart-safe (a crashed job stayed 'paid' and got re-picked) but had NO
-- guard against two overlapping processor runs both picking the same
-- 'paid' job -> two fix PRs for one payment. The fix claims a job
-- atomically into a 'running' lease; these columns back that lease.
--
-- started_at: when the current 'running' lease was taken. NULL whenever
-- the job is not running (never claimed, re-queued after a stale-lease
-- reap, or terminal). The stale-lease reaper compares it against now() to
-- find jobs whose worker crashed mid-run.
alter table fixpack_jobs add column if not exists started_at timestamptz;

-- attempts: how many times this job has been claimed into 'running'.
-- Incremented atomically at claim time; bounds retries so a job that
-- crashes the worker every time (poison pill) lands in 'failed' after
-- MAX_ATTEMPTS rather than re-queuing forever. Default 0, so every
-- existing row reads as "never attempted".
alter table fixpack_jobs add column if not exists attempts integer not null default 0;

-- No new status enum/check constraint: status stays plain text, same
-- rationale as migrations 0003/0007. 'running' is simply a new value the
-- claim path writes; 'paid' -> 'running' -> terminal
-- (delivered | no_fix_needed | blocked | failed).

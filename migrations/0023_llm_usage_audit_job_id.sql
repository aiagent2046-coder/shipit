-- Stage 5 (observability): make the cost journal answer "what did this QUEUE
-- job cost, across all of its attempts".
--
-- llm_usage.job_id (0020) holds an audits.id, and a row is written only when an
-- audit was successfully persisted. That leaves two questions unanswerable:
--
--   1. What did a job cost when it never produced an audits row? A provider
--      failing on the second rubric, a database blip on audit_repo.create, or a
--      job exhausting its attempts into dead_letter all spend real money at the
--      provider and, until now, recorded none of it.
--   2. What did a job cost in total? audit_jobs allows max_attempts tries and
--      every attempt re-runs the scan, so the spend is the SUM over attempts.
--      audits.id identifies at most the one attempt that succeeded.
--
-- A NEW nullable column rather than re-pointing job_id: job_id's existing rows
-- and its (job_type, job_id) index mean audits.id to every operator query
-- written against this table since 0020, and silently changing what a populated
-- column refers to is the kind of migration that is discovered months later in
-- a billing dispute. The two columns answer different questions and are
-- populated independently -- a row can have both (a successful attempt), only
-- audit_job_id (an attempt that spent money and then failed), or neither (a
-- monitoring re-audit, which has no queue row, on a deployment where the audit
-- did not persist).
alter table llm_usage
    add column if not exists audit_job_id uuid references audit_jobs(id);

-- The whole point of the column: sum(cost_usd) ... where audit_job_id = ?
create index if not exists llm_usage_audit_job_idx
    on llm_usage (audit_job_id);

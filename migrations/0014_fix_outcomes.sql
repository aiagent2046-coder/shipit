-- Fix outcome knowledge base (Phase B, instrumentation only). One row per
-- terminal Fix Pack job outcome: what was fixed, on what stack, how the job
-- ended, whether our semantic gate flagged a regression, and -- later, via the
-- pull_request.closed webhook -- whether the customer actually merged the PR.
--
-- This is collection only: no scoring, heuristics, UI, or prompt adaptation is
-- built on it yet (real volume is only a few jobs/week). The goal is to have the
-- durable history when there is enough of it to learn from. See
-- PHASE_B_KNOWLEDGE_BASE_PLAN.md.
--
-- Denormalized on purpose: `stack` and `audit_id` are copied from the
-- fixpack_jobs row we already hold at write time, so a later analytics query
-- needs no join back through fixpack_jobs. Same "denormalize what's cheap to
-- copy" reasoning as fixpack_jobs.stack itself (migration 0001).
--
-- No enum/CHECK on `outcome`: plain text with the app writing one of
-- delivered | blocked | failed | no_fix_needed, same rationale as the
-- status/product/provider columns in migrations 0003/0007/0011 (a new outcome
-- value must not require its own migration).
--
-- rule_ids: JSONB array of the rule_id strings this job actually fixed (one Fix
-- Pack fixes N findings across secret_fixes + config_fixes). Empty array for
-- no_fix_needed and for early failures where no plan was built. JSONB, matching
-- audits.findings_json.
--
-- pr_url: the delivered PR's html_url, set only for the 'delivered' outcome (the
-- other outcomes never open a PR). It is the join key the webhook matches on.
--
-- pr_merged: nullable tri-state -- NULL until the pull_request.closed webhook
-- fires for this PR, then true (merged) or false (closed without merging). Only
-- ever set for rows that have a pr_url.
create table if not exists fix_outcomes (
    id uuid primary key default gen_random_uuid(),
    fixpack_job_id uuid references fixpack_jobs(id),
    audit_id uuid references audits(id),
    rule_ids jsonb not null default '[]'::jsonb,
    stack text not null,
    outcome text not null,
    is_regression boolean not null default false,
    pr_url text,
    pr_merged boolean,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create index if not exists fix_outcomes_fixpack_job_id_idx
    on fix_outcomes (fixpack_job_id);

-- Partial index on pr_url: the webhook looks a delivered PR up by its html_url,
-- and only 'delivered' rows have a non-null pr_url.
create index if not exists fix_outcomes_pr_url_idx
    on fix_outcomes (pr_url) where pr_url is not null;

create index if not exists fix_outcomes_created_at_idx
    on fix_outcomes (created_at desc);

-- Default-deny RLS with no policies, same posture and rationale as migration
-- 0002 (audits, fixpack_jobs): there is no user/auth model to write a per-row
-- policy against, and the app connects as the table-owning `postgres` role
-- (RLS never applies to the owner without FORCE ROW LEVEL SECURITY, which this
-- deliberately does not set), so this only closes the "RLS Disabled in Public"
-- advisory for a role that reaches the table via PostgREST.
alter table fix_outcomes enable row level security;

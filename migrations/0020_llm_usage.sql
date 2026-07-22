-- Stage 4 (cost management), step 1 of 2: OBSERVABILITY ONLY. This table is the
-- single journal of what every LLM-backed job actually cost. Until now the token
-- usage the providers return (usage.input_tokens/output_tokens on Anthropic,
-- usage.prompt_tokens/completion_tokens on the OpenAI-compatible AITunnel path)
-- was read off the response and thrown away in app/llm/client.py -- so there was
-- no way to answer "what did today's audits cost". One row is written per job
-- that actually called the LLM (see app/main.py); it records the summed tokens
-- across every .complete() call in that job and the cost computed from the
-- code-side price table (app/llm/pricing.py).
--
-- Deliberately ONE table, not columns bolted onto audits/monitoring_runs: both
-- LLM-spending flows (a POST /v1/audits scan, a monitoring re-audit) write the
-- same shape here, and the daily spend a follow-up step will cap is a single
--   select sum(cost_usd) from llm_usage where account_id = ? and created_at >= <utc midnight>
-- with no joins and no per-flow special-casing. fixpack_jobs are NOT represented
-- here: Fix Pack generation is deterministic (app/fixpack/generate.py) and its
-- semantic check is Docker-only (app/fixpack/semantic_check.py) -- neither calls
-- the LLM, so neither has usage to record.
--
-- This step is accounting only. Nothing reads this table to block or throttle a
-- request yet; the cost cap, per-account daily limit, concurrency semaphore and
-- emergency stop are a separate follow-up PR.
create table if not exists llm_usage (
    id uuid primary key default gen_random_uuid(),
    -- Which flow spent the tokens: 'audit' (POST /v1/audits) or 'monitoring' (an
    -- async re-audit). Plain text (no enum/CHECK), same rationale as
    -- 0011/0015/0017: a new flow must never require a migration.
    job_type text not null,
    -- The audits.id this usage produced. Nullable because a scan on a
    -- DATABASE_URL-less deployment has no persisted row to point at, and because
    -- we never want a missing id to block writing the cost fact itself.
    job_id uuid,
    -- The paying account this is billable to, or NULL for anonymous/free and for
    -- system re-audits (a monitoring run's cost is incurred once regardless of
    -- how many subscribers watch the repo, so it is not attributed to any one of
    -- them). Mirrors accounts(id); ON DELETE not set -- usage history outlives a
    -- closed account and must not silently vanish.
    account_id uuid references accounts(id),
    -- The model the provider reports it actually served (data["model"] in the
    -- response), which may differ from what we requested if AITunnel proxies to a
    -- different upstream. Stored so cost can be reconciled against the right price
    -- row later even when the request model and the served model diverge.
    model text not null,
    -- How many .complete() calls this job made (a free audit = 2, one per rubric;
    -- a paid Fix Pack scan would be 4). Lets a per-call average be derived without
    -- a second table.
    calls integer not null default 0,
    input_tokens bigint not null default 0,
    output_tokens bigint not null default 0,
    -- Computed cost in USD from app/llm/pricing.py at write time (tokens are
    -- ground truth from the provider; price is a hand-maintained table). numeric,
    -- never float -- money must not carry binary-fp rounding error.
    cost_usd numeric(12, 6) not null default 0,
    created_at timestamptz not null default now()
);

-- The daily-spend aggregate a follow-up step will run:
--   where account_id = ? and created_at >= <utc midnight>
create index if not exists llm_usage_account_created_idx
    on llm_usage (account_id, created_at desc);

-- Per-job lookup ("what did this audit cost").
create index if not exists llm_usage_job_idx on llm_usage (job_type, job_id);

-- Default-deny RLS with no policies, same posture and rationale as migrations
-- 0002/0015/0017: no user/auth model to write a per-row policy against, and the
-- app connects as the table-owning role (RLS never applies to the owner without
-- FORCE ROW LEVEL SECURITY, which this deliberately does not set), so this only
-- closes the "RLS Disabled in Public" advisory for a role reaching the table via
-- PostgREST.
alter table llm_usage enable row level security;

-- Stage 2, PR 1 of 3: the durable queue that moves an audit out of the API
-- process. Schema + claim layer only -- nothing calls this table yet, so this
-- migration is safe to deploy ahead of the worker (see PR2).
--
-- Why this exists: POST /v1/audits (app/main.py create_audit) is declared 202
-- but runs the whole scan inline and INSERTs the audits row only AFTER it
-- finishes. An in-flight audit therefore has no row at all -- an API restart
-- discards LLM work already paid for at the provider and leaves zero trace, not
-- even in llm_usage. A queue row written at intake is what makes the work
-- survivable and re-claimable.
--
-- Deliberately NOT columns on audits: audits is simultaneously the result row,
-- the content_hash result cache (get_by_content_hash, 0008/0013) and the
-- token-gated read model (access_token, 0010). Putting 'queued'/'running' rows
-- in it would force every cache lookup and every report endpoint to start
-- excluding non-terminal rows -- a change to working, security-relevant code --
-- and would need a backfill of every existing row. Same separation, same
-- rationale as monitoring_runs (0017): a job is an execution attempt with its
-- own lease/attempts lifecycle, the audit is the result it eventually produces.
create table if not exists audit_jobs (
    id uuid primary key default gen_random_uuid(),
    -- Per-row ownership secret for polling the job's state, minted by the
    -- column default exactly like audits.access_token (0010) and
    -- fixpack_jobs.access_token (0012). The creator receives it once from
    -- RETURNING; get_authorized() matches it in SQL and never selects it back.
    access_token text not null default encode(gen_random_bytes(16), 'hex'),
    -- Plain text (no enum/CHECK), same rationale as 0011/0015/0017: a new state
    -- must never require a migration.
    --   created -> queued -> claimed -> running
    --           -> succeeded | failed | timed_out | cancelled | dead_letter
    -- PR1 enqueues straight into 'queued'; 'created' becomes load-bearing in
    -- PR2, where the row is inserted first and flipped to 'queued' only after
    -- the uploaded archive is staged, so a crash between the two can never
    -- leave a claimable job pointing at a payload that was never written.
    state text not null default 'created',
    -- 'zip' | 'repo_url'. Kept as a discriminator (rather than assuming a URL)
    -- so the payload handoff can later move from staged local blob to object
    -- storage without a schema change.
    source_kind text not null,
    -- The repo URL for 'repo_url' intake, or the staged archive path for 'zip'.
    -- Null until PR2 introduces staging; a 'zip' job has nowhere to point yet.
    source_ref  text,
    -- content_digest(raw) and AUDIT_ENGINE_VERSION, carried so the worker
    -- re-checks the result cache under the same key the API used at intake.
    content_hash text not null,
    engine_version text not null,
    -- Filled once detect_stack has run; null while unknown.
    stack text,
    account_id uuid references accounts(id),   -- NULL = anonymous
    -- The rate-limit key this submission was charged against at intake, kept so
    -- a later refund/diagnosis can find it without re-deriving it.
    quota_key text,
    -- Collapses concurrent duplicate submissions onto ONE in-flight job.
    -- Enforced by audit_jobs_idempotency_live_idx below -- a PARTIAL unique
    -- index, not a plain UNIQUE, because once a job reaches a terminal state
    -- the same content must be runnable again (an engine_version bump, or a
    -- retry after the cause of a dead_letter is fixed).
    idempotency_key text not null,
    -- Lease. claimed_by identifies the leaseholder ("<host>/<pid>/<slot>"); every
    -- state transition after the claim is gated on it, so a worker that lost its
    -- lease to the reaper can never overwrite the row a second worker is now
    -- legitimately working -- the zombie-writer guard the flat started_at leases
    -- in 0011/0017 do not have.
    claimed_by text,
    claimed_at timestamptz,
    -- Renewable, unlike fixpack_jobs.started_at + a flat max_age: an audit is
    -- normally ~2 min but a large repo plus provider retries can legitimately
    -- run longer, and a heartbeat is safer than one large constant.
    lease_expires_at timestamptz,
    -- Bumped at claim time; bounds crash-requeues so a poison pill lands in
    -- dead_letter instead of re-queuing forever. Mirrors fixpack_jobs.attempts.
    attempts integer not null default 0,
    max_attempts integer not null default 3,
    -- Backoff gate: a transient failure pushes this into the future, and the
    -- claim skips rows whose available_at has not arrived.
    available_at timestamptz not null default now(),
    -- The result this job produced, set exactly once on 'succeeded'.
    audit_id uuid references audits(id),
    -- Machine-readable classification (transient vs permanent lives in Python;
    -- this records which class fired) plus the human-readable reason. A terminal
    -- failure with a null error_message is the silent failure this guards
    -- against, same hardening as fixpack_jobs.detail / monitoring_runs.error.
    error_code text,
    error_message text,
    created_at   timestamptz not null default now(),
    updated_at   timestamptz not null default now(),
    completed_at timestamptz
);

-- The claim hot path: oldest claimable row first. Partial, because the
-- claimable set is tiny next to the history the table accumulates.
create index if not exists audit_jobs_claimable_idx
    on audit_jobs (available_at, created_at) where state = 'queued';

-- The reaper's scan for leases that outlived their holder.
create index if not exists audit_jobs_lease_idx
    on audit_jobs (lease_expires_at) where state in ('claimed', 'running');

-- At most ONE live job per logical submission; terminal rows are excluded so
-- the same content can be resubmitted later. See idempotency_key above.
create unique index if not exists audit_jobs_idempotency_live_idx
    on audit_jobs (idempotency_key)
    where state in ('created', 'queued', 'claimed', 'running');

create unique index if not exists audit_jobs_access_token_key
    on audit_jobs (access_token);

-- "My recent jobs" for an authenticated account.
create index if not exists audit_jobs_account_created_idx
    on audit_jobs (account_id, created_at desc);

-- Default-deny RLS with no policies, same posture and rationale as migrations
-- 0002/0014/0015/0017: there is no user/auth model to write a per-row policy
-- against, and the app connects as the table-owning role (RLS never applies to
-- the owner without FORCE ROW LEVEL SECURITY, which this deliberately does not
-- set), so this only closes the "RLS Disabled in Public" advisory for a role
-- reaching the table via PostgREST.
alter table audit_jobs enable row level security;

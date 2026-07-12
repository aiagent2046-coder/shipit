-- Persistence layer, minimal scope. Trimmed from shipit-architecture.md
-- 2.5's full schema: no `users` table (no auth yet, see architecture's
-- own "Deploy -> Hardening -> Auth -> Payments" ordering -- Auth comes
-- after this), no `s3_key`/`artifact_s3_key` (no S3 wired up yet, the
-- app never stores archive bytes or generated files anywhere durable
-- -- only audit/job metadata). `findings` is a JSONB column on
-- `audits`, not architecture's separate `findings` table with a
-- per-finding `verified` flag -- that split is real value (querying
-- individual findings, tracking anti-hallucination verification per
-- row) but not needed for what unblocks right now: giving audits and
-- fixpack jobs a durable id you can look up later. Split it out when
-- something actually needs to query individual findings.

create table if not exists audits (
    id uuid primary key default gen_random_uuid(),
    stack text not null,
    status text not null default 'completed',
    file_count integer,
    score_total numeric,
    score_json jsonb,
    findings_json jsonb,
    created_at timestamptz not null default now()
);

create index if not exists audits_created_at_idx on audits (created_at desc);

create table if not exists fixpack_jobs (
    id uuid primary key default gen_random_uuid(),
    audit_id uuid references audits(id),
    pack text not null,
    stack text not null,
    verified boolean,
    detail text,
    preview_local_url text,
    preview_expires_at timestamptz,
    pr_url text,
    pr_delivered boolean not null default false,
    created_at timestamptz not null default now()
);

create index if not exists fixpack_jobs_audit_id_idx on fixpack_jobs (audit_id);
create index if not exists fixpack_jobs_created_at_idx on fixpack_jobs (created_at desc);

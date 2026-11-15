-- rollback-safe: no
-- Awaiting repository authorization is still funded live work. Older workers
-- do not understand this state and must not run alongside the new release.
create table if not exists fixpack_delivery_grants (
    payment_id uuid primary key references payments(id) on delete cascade,
    encrypted_grant text not null,
    updated_at timestamptz not null default now()
);

-- Credentials have no public read policy, including deployments exposing
-- public-schema tables through PostgREST. Only the trusted database role reads.
alter table fixpack_delivery_grants enable row level security;

drop index if exists fixpack_jobs_audit_live_idx;
create unique index fixpack_jobs_audit_live_idx on fixpack_jobs (audit_id)
    where status in ('paid', 'running', 'awaiting_authorization');

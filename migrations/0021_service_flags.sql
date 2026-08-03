-- Stage 4 (cost management), step 2 of 2: ENFORCEMENT. This table backs the
-- emergency stop -- a single operator-controlled kill switch for all
-- LLM-spending work (POST /v1/audits scans and async monitoring re-audits).
--
-- One row per flag, keyed by a stable string. The only flag used today is
-- key='llm_paid_ops': when enabled=false, app/main.py returns 503
-- {"reason":"service_paused"} for direct API calls and soft-degrades the
-- monitoring drain to a no-op (a background process has no user to 503). The
-- flag is read on the request path behind a short TTL cache so a paused
-- service doesn't hammer the DB, and toggled via a small authed internal
-- endpoint (POST /internal/service-flags/llm_paid_ops).
--
-- enabled DEFAULTS TO true: creating the table (or inserting a fresh row)
-- changes nothing -- paid ops stay on until an operator explicitly turns them
-- off. There is intentionally no CHECK/enum on key: a future kill switch is a
-- new row, never a migration.
create table if not exists service_flags (
    key text primary key,
    enabled boolean not null default true,
    note text,
    updated_at timestamptz not null default now()
);

-- Default-deny RLS with no policies, same posture and rationale as migrations
-- 0002/0015/0017/0020: the app connects as the table-owning role (RLS does not
-- apply to the owner absent FORCE ROW LEVEL SECURITY, which this does not set),
-- so this only closes the "RLS Disabled in Public" advisory for a role reaching
-- the table via PostgREST.
alter table service_flags enable row level security;

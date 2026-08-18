-- rollback-safe: yes
--
-- The consent ledger for the live RLS check.
--
-- Every other stage of an audit reads a copy of the customer's code. This one
-- sends a request to a database that belongs to somebody, and that is the only
-- thing this product does which reaches outside our own infrastructure and
-- touches a third party's system. If it is ever questioned — by the customer,
-- by their counterparty, by us — the answer has to be a row, not a log line
-- that rotated out.
--
-- One row per check ATTEMPT, written before the requests go out, so a refusal
-- and a crash are both visible rather than only the successes. `outcome` and
-- `result_json` are filled in afterwards and stay NULL if the process dies
-- mid-check, which is itself the record that something was started.
--
-- WHAT IS DELIBERATELY NOT HERE: the anon key. It is derived from the
-- repository at check time, used, and dropped (app/proof/rls_live_check.py),
-- and a credential belonging to a customer must not acquire a second home in
-- our database. `project_ref` identifies the project without being able to
-- open it.
--
-- `consent_phrase` stores what the caller actually typed rather than a
-- boolean. A boolean records our interpretation; the phrase records their
-- act, and the two differ exactly when it matters.
--
-- rollback-safe: a new table nothing older reads or writes.

create table if not exists rls_live_checks (
    id              uuid primary key default gen_random_uuid(),
    audit_id        uuid references audits (id) on delete set null,
    client_key      text        not null,
    project_ref     text,
    consent_phrase  text        not null,
    tables_asked    jsonb,
    outcome         text,
    result_json     jsonb,
    created_at      timestamptz not null default now(),
    completed_at    timestamptz
);

create index if not exists rls_live_checks_audit_idx
    on rls_live_checks (audit_id);

create index if not exists rls_live_checks_created_idx
    on rls_live_checks (created_at desc);

-- Same posture as 0029: the table is reached only through the service role,
-- and RLS on with no policy is the default-deny that says so.
alter table rls_live_checks enable row level security;

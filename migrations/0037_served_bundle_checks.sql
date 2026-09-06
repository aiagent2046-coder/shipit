-- rollback-safe: yes
--
-- Purely additive: one new table nothing else references. The previous
-- release's code neither reads nor writes served_bundle_checks, so it runs
-- unchanged with this applied, and a rollback past it strands only rows this
-- release wrote.
--
-- The consent ledger for the served-bundle check (SUPABASE_SERVICE_ROLE_BUNDLE_PLAN.md,
-- Part C). Second of its kind: 0031 recorded the live RLS check, which until
-- now was the ONLY thing this product does that reaches outside our
-- infrastructure and touches a third party's system. This one fetches a
-- customer's deployed JavaScript from a URL they supply, so it needs the same
-- accounting, and 0031's docstring claim to be the only such path is corrected
-- alongside this migration rather than left to rot.
--
-- A SEPARATE TABLE, NOT A `kind` COLUMN ON rls_live_checks. The two checks ask
-- different questions and carry different evidence: one records a project ref
-- and the tables it asked about, this one records a deployment URL and the
-- assets it read. Overloading one table would mean half its columns are NULL
-- for half its rows, and every future query would start by working out which
-- kind of row it is looking at.
--
-- WHAT IS NOT HERE, deliberately: no fetched bytes, no raw token. The result
-- json carries the registry's redacted mask, the credential class, and the
-- asset URLs -- see app/proof/secret_registry.Finding.evidence(). A leaked
-- service_role key is abused within minutes of exposure, so storing one to
-- prove we found it would be the same defect we are reporting.
create table if not exists served_bundle_checks (
    id              uuid primary key default gen_random_uuid(),
    -- The audit this was offered from. ON DELETE SET NULL, same as 0031: the
    -- ledger outlives the audit, because the question "did you fetch this
    -- deployment, and did somebody consent" must stay answerable after a
    -- report is gone.
    audit_id        uuid references audits (id) on delete set null,
    client_key      text        not null,
    -- The URL as validated, not as typed: what we actually fetched.
    deployment_url  text,
    -- The phrase the caller typed, stored verbatim. A boolean would record our
    -- interpretation of their act; the phrase records the act. Same reasoning
    -- as 0031.
    consent_phrase  text        not null,
    -- Which same-origin assets were read, so the scope of the fetch is a fact
    -- rather than a reconstruction.
    assets_read     jsonb,
    outcome         text,
    result_json     jsonb,
    created_at      timestamptz not null default now(),
    completed_at    timestamptz
);

-- "What did we fetch for this audit" -- the lookup a support question starts
-- from.
create index if not exists served_bundle_checks_audit_idx
    on served_bundle_checks (audit_id);

-- "What did we fetch today", for the same review a spend or abuse question
-- would open.
create index if not exists served_bundle_checks_created_idx
    on served_bundle_checks (created_at desc);

-- Default-deny RLS with no policies, same posture and rationale as 0031: no
-- user/auth model to write a per-row policy against, and the app connects as
-- the table-owning role, so this only closes the "RLS Disabled in Public"
-- advisory for a role reaching the table via PostgREST.
alter table served_bundle_checks enable row level security;

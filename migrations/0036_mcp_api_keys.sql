-- rollback-safe: yes
--
-- Two new tables and no change to an existing one. A release rolled back to
-- the previous code ignores both, and every existing row stays valid.
--
-- The credential an editor uses to reach Drydock over MCP, and the record of
-- which audits each key may read.
--
-- WHY NOT accounts. The obvious move is to hang MCP off the identity model
-- that already exists, and docs/MCP.md records why that is wrong here: an
-- audit is anonymous, a Fix Pack purchase mints no account by design, and Pro
-- is no longer sold -- so "reuse accounts" would have meant "MCP is for the
-- one existing Pro customer". An MCP key is its own thing: free,
-- self-service, rate-limited as anonymous traffic, and deliberately carrying
-- no tier. Adding account_id here would reintroduce that coupling, and the
-- first person to buy Pro again would silently change what their MCP key can
-- do.
--
-- SAME KEY POSTURE AS accounts AFTER MIGRATION 0019, and for the same reason:
-- key_hash is HMAC-SHA256(pepper, key) with the pepper in the environment and
-- never in the database, so a database leak alone cannot replay a key.
-- key_prefix is the safe-to-display head, enough to identify a key in a list
-- and useless on its own. The plaintext exists once, in memory, at mint time.
-- A lost key is rotated, not recovered.
create table if not exists mcp_api_keys (
    id uuid primary key default gen_random_uuid(),
    key_hash text not null,
    key_prefix text not null,
    -- What the holder called it, for their own list. Never trusted, never
    -- interpolated anywhere but their own screen.
    label text,
    created_at timestamptz not null default now(),
    -- Recorded from the first day so an expiry policy can later be chosen
    -- from data instead of guessed now (docs/MCP.md leaves it open).
    last_used_at timestamptz,
    -- Revocation without deleting the row: the audits a revoked key created
    -- still trace back to it, which is the whole point of keeping a record.
    revoked_at timestamptz
);

-- The lookup every authenticated MCP request performs, on every request.
create unique index if not exists mcp_api_keys_key_hash_key
    on mcp_api_keys (key_hash);

-- WHICH AUDITS A KEY MAY READ, AND WHY THIS IS A TABLE RATHER THAN A COLUMN.
--
-- The first draft put mcp_key_id on audits, one owner per audit. That is
-- wrong, and the reason is the content-hash cache: get_by_content_hash
-- returns a PREVIOUSLY CREATED audit row whenever byte-identical content was
-- audited before, by anyone (app/main.py). Two keys auditing the same
-- repository therefore land on one row.
--
-- With a single owner column, the second key either cannot read the audit it
-- just asked for, or takes the row from the first. Both are wrong, and the
-- second is worse -- it removes access somebody already had.
--
-- A join row says the true thing: this key asked for this audit and may read
-- it. A cache hit inserts a second row and takes nothing from anyone.
--
-- This is the table that enforces docs/MCP.md §2: a key reads only its own
-- audits. audits.access_token stays exactly as it is -- a per-row capability
-- for the web report -- and neither mechanism weakens the other.
create table if not exists mcp_key_audits (
    mcp_key_id uuid not null references mcp_api_keys(id),
    audit_id uuid not null references audits(id),
    created_at timestamptz not null default now(),
    primary key (mcp_key_id, audit_id)
);

-- "Which audits does this key have?" is the list endpoint; the primary key
-- above already serves it. This one answers the reverse -- "who reached this
-- audit?" -- which is what a support question or an abuse report starts from.
create index if not exists mcp_key_audits_audit_id_idx
    on mcp_key_audits (audit_id);

-- Default-deny, same posture and reasoning as migrations 0002 and 0003: no
-- permissive policies, so anon/authenticated through PostgREST get zero rows.
-- It matters here for the same reason it mattered for accounts -- key_hash is
-- a credential, and mcp_key_audits is a map of who audited what. This app's
-- own access is unaffected: app/db.py connects as the table owner, and RLS
-- never applies to the owner unless FORCE ROW LEVEL SECURITY is set, which
-- this does not set.
alter table mcp_api_keys enable row level security;
alter table mcp_key_audits enable row level security;

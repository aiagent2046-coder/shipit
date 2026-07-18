-- Ownership for audit reports: a per-row capability token.
--
-- Before this, GET /v1/audits/{id} and /v1/audits/{id}/report authorized by
-- knowledge of the audit's UUID alone -- no ownership check. UUIDs are hard to
-- guess but they leak (browser history, referrer headers, server logs, support
-- tickets, screenshots), and a report can expose filenames, architecture, and
-- masked vulnerability fragments. This adds a secret the id alone doesn't
-- reveal, so a leaked id is not enough to read the report.
--
-- Unlike the accounts pepper (a server-wide shared secret, deliberately kept
-- out of git/migrations -- see migration 0009 and scripts/backfill_api_key_
-- hashes.py), access_token is a PER-ROW random value with no cross-row secret.
-- It is safe to generate and backfill entirely inside this migration: leaking
-- one row's token compromises only that one audit.
--
-- gen_random_bytes is from pgcrypto (gen_random_uuid used elsewhere is a PG13+
-- builtin, but gen_random_bytes is not); enable it if it isn't already.
create extension if not exists pgcrypto;

-- The column default mints a token for every INSERT that doesn't supply one, so
-- application code doesn't have to. 16 random bytes = 128 bits, hex-encoded to a
-- 32-char string.
alter table audits
    add column if not exists access_token text
    default encode(gen_random_bytes(16), 'hex');

-- Backfill pre-existing rows. A column-level default with a VOLATILE function
-- (gen_random_bytes) is evaluated per-row on ADD COLUMN, so existing rows should
-- already be populated with distinct tokens -- but do it explicitly so the
-- NOT NULL below is safe regardless of the server's fast-default behavior.
-- Each row gets its own distinct token (gen_random_bytes is volatile).
update audits
set access_token = encode(gen_random_bytes(16), 'hex')
where access_token is null;

-- Every audit now has a token; make it required so no future row is readable by
-- id alone.
alter table audits alter column access_token set not null;

-- Looked up together with the id (where id = %s and access_token = %s); unique
-- because a token is a capability -- two audits must never share one.
create unique index if not exists audits_access_token_key
    on audits (access_token);

-- NOTE (deliberate, one-time breaking change): existing audits get a freshly
-- generated token that no prior link carries, so old links of the form
-- /audit/{id} (no ?token=) stop resolving after this migration. That is
-- acceptable -- those are test/early rows and the alternative (readable by id
-- alone) is the vulnerability being closed.

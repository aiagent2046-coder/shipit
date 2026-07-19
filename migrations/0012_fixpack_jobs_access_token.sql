-- Ownership for Fix Pack jobs: a per-row capability token.
--
-- Before this, GET /v1/fixpacks/{job_id} authorized by knowledge of the job's
-- UUID alone -- no ownership check, exactly the gap migration 0010 closed for
-- audits. UUIDs are hard to guess but they leak (browser history, referrer
-- headers, server logs, support tickets, screenshots), and a fixpack job row
-- can expose repo detail: the build/verify `detail`, `pr_url`, the linked
-- `audit_id`, and the stack. This adds a secret the id alone doesn't reveal, so
-- a leaked id is not enough to read the job.
--
-- This mirrors migration 0010 (audits.access_token) exactly. Like there, and
-- unlike the accounts pepper (a server-wide shared secret kept out of git --
-- see migration 0009), access_token is a PER-ROW random value with no cross-row
-- secret. It is safe to generate and backfill entirely inside this migration:
-- leaking one row's token compromises only that one job.
--
-- gen_random_bytes is from pgcrypto (gen_random_uuid used elsewhere is a PG13+
-- builtin, but gen_random_bytes is not); enable it if it isn't already.
create extension if not exists pgcrypto;

-- The column default mints a token for every INSERT that doesn't supply one, so
-- application code doesn't have to. 16 random bytes = 128 bits, hex-encoded to a
-- 32-char string.
alter table fixpack_jobs
    add column if not exists access_token text
    default encode(gen_random_bytes(16), 'hex');

-- Backfill pre-existing rows. A column-level default with a VOLATILE function
-- (gen_random_bytes) is evaluated per-row on ADD COLUMN, so existing rows should
-- already be populated with distinct tokens -- but do it explicitly so the
-- NOT NULL below is safe regardless of the server's fast-default behavior.
-- Each row gets its own distinct token (gen_random_bytes is volatile).
update fixpack_jobs
set access_token = encode(gen_random_bytes(16), 'hex')
where access_token is null;

-- Every job now has a token; make it required so no future row is readable by
-- id alone.
alter table fixpack_jobs alter column access_token set not null;

-- Looked up together with the id (where id = %s and access_token = %s); unique
-- because a token is a capability -- two jobs must never share one.
create unique index if not exists fixpack_jobs_access_token_key
    on fixpack_jobs (access_token);

-- NOTE (deliberate, one-time breaking change): existing fixpack jobs get a
-- freshly generated token that no prior link carries, so old links of the form
-- /v1/fixpacks/{id} (no ?token=) stop resolving after this migration. That is
-- acceptable -- only a few rows exist in prod, and the alternative (readable by
-- id alone) is the vulnerability being closed. Same rationale as migration 0010.

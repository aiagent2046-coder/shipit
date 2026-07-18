-- Harden API-key storage: stop keeping account keys as recoverable
-- plaintext. Today `accounts.api_key` holds the full `sk_live_<random>`
-- secret in the clear, and lookup matches on it directly -- so a DB leak
-- hands an attacker every live key, ready to use. We move to a split
-- representation:
--   * key_prefix -- the first ~12 chars (e.g. `sk_live_ab12`), safe to
--     show in logs / a dashboard to identify a key without revealing it.
--   * key_hash   -- HMAC-SHA256(server_pepper, full_key), hex. Lookup
--     hashes the presented bearer token and matches on this column, so
--     the plaintext is never needed at rest. The pepper is a server-side
--     secret held ONLY in the environment (API_KEY_PEPPER), never in the
--     DB, so a DB-only leak can't even offline-brute the hashes.
--
-- This migration is DDL ONLY -- it adds the columns and the uniqueness
-- guarantee. It writes no data: hashing the already-issued real keys is
-- done out-of-band by scripts/backfill_api_key_hashes.py, which reads the
-- pepper from the environment at run time (the pepper must never enter a
-- migration file or git history).
--
-- `api_key` is intentionally KEPT for now, but is DEPRECATED: it stays so
-- (a) the few keys already handed to real Pro users keep working via the
-- transitional plaintext fallback in app/accounts.resolve_account, and
-- (b) the backfill can read the existing plaintext to compute each hash.
-- A LATER migration will drop the plaintext fallback and this column once
-- the backfill is confirmed complete and the deprecation window closes.

alter table accounts add column if not exists key_prefix text;
alter table accounts add column if not exists key_hash text;

-- New accounts store only prefix+hash, never plaintext, so api_key can no
-- longer be NOT NULL. (Old rows keep their plaintext until the backfill
-- populates key_hash and the follow-up migration drops this column.)
alter table accounts alter column api_key drop not null;

-- One account per key. NULLs are distinct in a Postgres unique index, so
-- the not-yet-backfilled rows (key_hash IS NULL) don't collide with each
-- other; once backfilled each row carries a distinct hash.
create unique index if not exists accounts_key_hash_key on accounts (key_hash);

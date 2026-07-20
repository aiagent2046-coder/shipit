-- Phase C (Continuous Monitoring): bind a subscription to a repository and
-- track the last monitoring run, so a push to the repo's default branch can
-- re-audit at most once per 24h and notify the subscriber on new critical/high
-- findings. Extends `subscriptions` (0015) rather than adding a table: billing
-- (upsert/renew/status, the natural key, the charge id) already lives there and
-- monitoring is a property of the subscription, not a new billing object.
--
-- repo_full_name is the canonical 'owner/repo' (lowercased) the subscription
-- monitors -- see app/monitor.normalize_repo_full_name. NULL for the legacy
-- 'test-monitoring' tier (0015), which monitors nothing. The monitoring tier's
-- invoice payload is 'sub:monitor:<owner/repo>', so the natural key
-- (telegram_user_id, invoice_payload) is naturally distinct per repo per user:
-- one user can monitor several repos, each its own row, no schema change.
alter table subscriptions add column if not exists repo_full_name text;

-- The 24h-per-repo throttle. NULL means "never monitored" -> the first eligible
-- push runs. Stamped on every monitoring run (all active rows for the repo).
alter table subscriptions add column if not exists last_monitored_at timestamptz;

-- The push handler looks up active monitoring subs by repo on every eligible
-- default-branch push; index the lookup. Partial: only monitoring rows carry a
-- repo_full_name, so legacy/no-repo rows stay out of the index.
create index if not exists subscriptions_repo_full_name_idx
    on subscriptions (repo_full_name) where repo_full_name is not null;

-- "Previous audit for this repo" is read on every eligible push (the diff
-- baseline). repo_url is stored as typed at intake (0006); the lookup
-- normalizes it (lower + strip .git/trailing slash) to match a canonical
-- owner/repo, so this index covers the (repo_url, created_at desc) scan.
create index if not exists audits_repo_url_created_at_idx
    on audits (repo_url, created_at desc) where repo_url is not null;

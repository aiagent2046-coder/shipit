-- rollback-safe: yes
-- An older release ignores the nullable column and simply never refreshes; the
-- index is partial and unused by it. Nothing to backfill: a row without an
-- inventory was never asked, which is exactly what NULL means here.
-- Store the resolved dependency inventory beside the audit that reported on it.
--
-- Why a column and not the existing score_json: score_json is the served
-- document. app/main.py hands `cached["score_json"]` straight to a response
-- body, so anything stored there is published. The inventory is machine input
-- for a REFRESH -- it exists so a stale dependency answer can be re-queried
-- without the archive bytes, which this deployment deliberately does not keep
-- (see 0001: "the app never stores archive bytes or generated files anywhere
-- durable").
--
-- Why it can be refreshed at all: the dependency answer is the only part of an
-- audit that expires. advisory data changes while the repository does not, so a
-- cached row's "no known vulnerabilities" quietly stops being true. Without a
-- stored inventory there is nothing to re-ask with, which is why this is the
-- prerequisite for the refresh rather than a convenience.
--
-- Nullable and never required: an audit that was never asked (a free tier run,
-- an opted-out account, an archive with no lockfile) stores nothing, and every
-- existing row keeps working. Absent means "not stored", never "no
-- dependencies".
alter table audits add column if not exists dependency_inventory jsonb;

-- The refresh sweep's access path: the oldest paid audits that have an
-- inventory. Partial, because most rows have none and a full index on a
-- nullable jsonb column would be paid for by every write.
create index if not exists audits_dependency_inventory_age_idx
    on audits (created_at)
    where dependency_inventory is not null;

-- Version the audit result cache so an engine change invalidates stale rows.
--
-- The content-hash cache (migration 0008) reuses a prior audit for
-- byte-identical content, which pins "same commit -> same score" (the LLM
-- scan is non-deterministic even at temperature=0). But content_hash alone
-- says nothing about WHICH engine produced the score: if the LLM prompt,
-- the model, the scoring formula, or the static rules change, an unchanged
-- content_hash keeps serving the OLD result forever -- even after the engine
-- improved or a bug in it was fixed. engine_version closes that: the cache
-- lookup (app/db.py get_by_content_hash) now filters on both, so a bump of
-- AUDIT_ENGINE_VERSION (app/scan/pipeline.py) turns the next audit of
-- identical content into a cache miss and a recompute.
--
-- Nullable, matching content_hash in 0008: the app always supplies it on
-- insert, so no column default is added.
alter table audits add column if not exists engine_version text;

-- Backfill existing rows with the CURRENT version. This is a literal copy of
-- AUDIT_ENGINE_VERSION as of this migration -- keep the two in sync when the
-- constant is bumped in code (migrations are point-in-time). Stamping prior
-- rows "current engine" means this deploy does NOT invalidate the existing
-- cache; invalidation happens later, the first time the constant is bumped.
update audits set engine_version = '2026-07-19-1' where engine_version is null;

-- The lookup filters on (content_hash, engine_version); index the pair. A
-- composite index also serves the content_hash-prefix queries the old
-- single-column index (0008) covered, so that one is now redundant -- drop it.
create index if not exists audits_content_hash_engine_version_idx
    on audits (content_hash, engine_version);
drop index if exists audits_content_hash_idx;

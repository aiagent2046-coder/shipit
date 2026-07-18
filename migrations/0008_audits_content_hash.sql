-- Reproducibility: reuse a prior audit for byte-identical content.
--
-- Three audits of the same repo at the same commit (identical file_count)
-- produced different score_total (8.9, 9.9, 9.9) within an hour. The score
-- math (app/scan/scoring.py) is fully deterministic; the variance came from
-- the LLM scan stage, which returns a different findings set run to run even
-- at temperature=0 (documented in app/scan/llm_scan.py). Different findings
-- feed the deterministic formula -> different score.
--
-- content_hash is a canonical SHA-256 of the scanned archive's contents
-- (see app/scan/pipeline.py content_digest): independent of zip packaging,
-- so the same code always hashes the same. On a re-audit of identical
-- content we return the stored row instead of re-running the
-- non-deterministic scan, guaranteeing "same commit -> same score".
--
-- Nullable: audits created before this column existed have no hash (same
-- reasoning as repo_url in 0006). Indexed because it is looked up on its
-- own, unlike repo_url.
alter table audits add column if not exists content_hash text;
create index if not exists audits_content_hash_idx on audits (content_hash);

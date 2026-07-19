# Plan: version the audit cache key so an engine change invalidates stale results

## Problem

The audit result cache — built in PR #31 to make an identical re-audit reproducible —
keys **only** on `content_hash`. `AuditRepository.get_by_content_hash` (`app/db.py:239`)
does:

```sql
where content_hash = %s and status = 'completed'
order by created_at desc limit 1
```

`content_hash` is a canonical SHA-256 of the scanned archive's *contents*
(`content_digest` in `app/scan/pipeline.py:29`), so the same code always hashes the same,
and `app/main.py:1141` reuses the stored row instead of re-running the (non-deterministic)
LLM scan. That was the whole point of PR #31: **same commit → same score.**

But the cache key omits *what produced* the score. If the audit engine changes — the LLM
model, the prompt, the scoring formula, the static rules — a repo with an unchanged
`content_hash` keeps getting served the **old** frozen result forever, even after the
engine improved (or after a bug in it was fixed). Reproducibility for a fixed engine (PR
#31) and *not freezing a result across an engine change* are two distinct, complementary
requirements; this closes the second gap.

## Reconnaissance findings

### The cache, end to end (PR #31)

- **Migration `0008_audits_content_hash.sql`**: `alter table audits add column ...
  content_hash text` (nullable — pre-existing rows have none, same reasoning as `repo_url`
  in 0006) + `create index audits_content_hash_idx on audits (content_hash)`.
- **`app/db.py`**:
  - `create(..., content_hash=None)` inserts it (`app/db.py:204`).
  - `get_by_content_hash(content_hash)` is the lookup above (`app/db.py:239`).
- **`app/main.py:1140`**: `digest = content_digest(raw)` → `get_by_content_hash(digest)` →
  on hit, returns the stored row with `"reused": True` and the row's own `access_token`;
  on miss, runs `run_scan` and `create(..., content_hash=digest)`.
- The cache is **all-or-nothing per row**: one row stores the *final* `score_json` +
  `findings_json`. There is no separate cache of the intermediate LLM output; a miss
  re-runs the entire `run_scan` pipeline. (This matters for the cost analysis below.)

### What can actually change in the engine (the versionable surface)

Nothing in the pipeline is versioned today. The real moving parts:

| Component | Where | Versioned now? |
|---|---|---|
| LLM model | `DEFAULT_MODEL = "claude-sonnet-4-6"` in `app/llm/client.py:17`, overridable via `LLM_MODEL` env | No — and it's a **runtime** value, not a code constant |
| LLM prompt | `SYSTEM_PROMPT` + `RUBRICS[*]["instructions"]` in `app/scan/llm_scan.py:27` | No |
| Static scanner rules | `app/scan/secrets.py`, `app/scan/checks.py` | No |
| Scoring formula | `SEVERITY_WEIGHT` / `CATEGORY_WEIGHT` in `app/scan/scoring.py:20` | No |
| Collapse / cross-rubric dedup | `app/scan/collapse.py`, `app/scan/cross_rubric_dedup.py` | No |

## Recommendation: a single `AUDIT_ENGINE_VERSION` constant

Introduce one manually-bumped constant and fold it into the cache key. Bump it whenever any
of the components above changes in a way that should invalidate prior results.

### Single vs. composite — the honest trade-off

The composite option (separate `prompt_version` / `model_id` / `scoring_version` /
`scanner_version`) is *more granular*: a scoring-only change wouldn't invalidate rows whose
expensive LLM findings are unchanged. The theoretical win is **not re-paying for the LLM
stage** when only cheap deterministic scoring changed.

**That win does not exist under the current cache design.** The cache stores one final row
(score + findings); a miss re-runs *all* of `run_scan`, LLM included. To actually skip the
LLM re-run on a scoring-only change you'd need to *separately* cache the LLM findings (keyed
by content + prompt + model) and recompute scoring on read — a much larger change (new
table/column, a re-score path, more code to keep correct). At this product's scale that is
premature; the composite key would add four constants and key-assembly logic **for a cost
saving the architecture can't yet realize.**

So: **single `AUDIT_ENGINE_VERSION`.** Karpathy-simple, one thing to bump, and no false
promise of granularity. If/when LLM cost makes partial re-use worth it, that's a separate,
larger project — noted here as future work, not built now.

### The one subtlety: the model is a runtime env var

`LLM_MODEL` can change the effective model without any code edit, and `AUDIT_ENGINE_VERSION`
is a code constant. An operator who changes `LLM_MODEL` **must also bump
`AUDIT_ENGINE_VERSION`** or the cache will serve pre-change results across the model switch.
I'll document this next to the constant. (Deriving the version partly from the runtime model
would automate it but couples the DB layer to LLM config and complicates the key — rejected
as over-engineering for now; the bump discipline is one line in a deploy.)

## Implementation plan (Step 2)

Surgical, mirrors the PR #31 shape.

### 1. The constant — `app/scan/pipeline.py`

`pipeline.py` is the audit-engine entry point (`run_scan`) and already owns the other half
of the cache key (`content_digest`), so the version lives beside it:

```python
# Bump when any part of the audit engine changes in a way that should
# invalidate cached results: LLM model (incl. the LLM_MODEL env override),
# the LLM prompt (app/scan/llm_scan.py), scoring (app/scan/scoring.py), or
# the static rules (app/scan/secrets.py, app/scan/checks.py). Folded into
# the audit cache key (app/db.py get_by_content_hash), so a bump makes the
# next audit of unchanged content recompute instead of reusing a stale row.
AUDIT_ENGINE_VERSION = "2026-07-19-1"
```

### 2. Migration — `migrations/0013_audits_engine_version.sql`

```sql
alter table audits add column if not exists engine_version text;
-- Backfill existing rows with the CURRENT version (literal, matching the
-- AUDIT_ENGINE_VERSION value at the time this migration is written). This
-- does NOT invalidate the existing cache at deploy — it stamps prior rows
-- as "current engine" so they keep serving. Invalidation happens later,
-- when AUDIT_ENGINE_VERSION is next bumped in code.
update audits set engine_version = '2026-07-19-1' where engine_version is null;
-- The lookup filters on (content_hash, engine_version); index the pair.
-- This supersedes the content_hash-only index from 0008 (a composite index
-- serves content_hash-prefix queries too), so drop the redundant one.
create index if not exists audits_content_hash_engine_version_idx
    on audits (content_hash, engine_version);
drop index if exists audits_content_hash_idx;
```

Kept **nullable** (matching `content_hash`'s style in 0008); new inserts always pass it
explicitly from the app, so no column default is added.

### 3. `app/db.py`

- `AuditRepository.create(..., engine_version: str | None = None)`: add `engine_version` to
  the INSERT column list, values, params, and to `RETURNING` (returned for symmetry).
- `AuditRepository.get_by_content_hash(self, content_hash, engine_version)`: add the filter:

  ```sql
  where content_hash = %s and engine_version = %s and status = 'completed'
  ```

  A version mismatch now falls through to `row is None` → a cache **miss** → the audit
  re-runs, exactly as if `content_hash` hadn't matched.

### 4. `app/main.py`

- Import `AUDIT_ENGINE_VERSION` from `app.scan.pipeline` (referenced as a module attribute
  so it's monkeypatchable in tests).
- `get_by_content_hash(digest, AUDIT_ENGINE_VERSION)` (`app/main.py:1141`).
- `create(..., content_hash=digest, engine_version=AUDIT_ENGINE_VERSION)`
  (`app/main.py:1164`).

### 5. Tests

- **`tests/test_db.py`** (real-repo SQL/param shape, `FakePool`):
  - `create` passes `engine_version` in the correct param position and includes it in the
    SQL.
  - `get_by_content_hash` puts `engine_version` in the WHERE clause and passes both params.
- **`tests/test_audit_determinism.py`** (endpoint behavior, in-memory `FakeAuditRepo`):
  - Update `FakeAuditRepo.create`/`get_by_content_hash` signatures to carry
    `engine_version`, keyed by `(content_hash, engine_version)`.
  - **(a)** same content + same version → cache **hit** (the existing reuse test still
    passes — regression guard).
  - **(b)** same content + **different** version → cache **miss**: post identical content,
    then monkeypatch `app.main.AUDIT_ENGINE_VERSION` to a new value, post again, assert
    `reused` is not `True` and a second row was created.
  - **(c)** different content still not served from cache (existing test unchanged).
- Also update the `get_by_content_hash` fake in `tests/test_persistence_wiring.py:75` to the
  new signature so the suite stays green.

### 6. README

The README does **not** currently document the cache mechanism (confirmed: no reference to
`content_hash`/reproducibility/caching in `README.md`). I'll re-check in Step 2 and add a
one-line note only if there's an existing audit/reproducibility section it belongs in —
otherwise no README change (avoid inventing docs).

## Out of scope

- Per-stage / composite versioning and separate caching of LLM output for scoring-only
  re-use — a larger project justified only once LLM re-run cost demands it (see trade-off
  above).
- Auto-deriving the version from the runtime model.
- Any change to `content_digest` or the reproducibility guarantee itself (PR #31 stands).

# Plan: per-row access token for Fix Pack jobs (`GET /v1/fixpacks/{job_id}`)

## Status: **IMPLEMENTED** (migration `0012_fixpack_jobs_access_token.sql`, `FixpackJobRepository.get_authorized`, `GET /v1/fixpacks/{job_id}?token=`, tests in `tests/test_persistence_wiring.py`).

Public read requires the per-row token. `GET /v1/audits/{id}/fixpack-status` remains a limited poll (status + pr_url only) by design.

## Problem

`GET /v1/audits/{audit_id}` and `/v1/audits/{audit_id}/report` are ownership-gated by a
per-row `access_token` (`?token=...`). A leaked audit UUID alone is not enough to read the report.

`GET /v1/fixpacks/{job_id}` historically authorized on knowledge of the bare `job_id` UUID alone.
A Fix Pack job row exposes potentially sensitive repo details — `detail`, `pr_url`, linked `audit_id`, stack — and UUIDs leak (browser history, referrer headers, logs, support tickets).

## Solution (shipped)

Mirror audits exactly:

- Migration `0012_fixpack_jobs_access_token.sql` — per-row random token, unique index.
- `FixpackJobRepository.get_authorized(job_id, access_token)` — SQL match, token not in SELECT.
- `GET /v1/fixpacks/{job_id}?token=` — 404 on missing/wrong token (does not confirm id existence).
- Token returned once at create (`POST /v1/fixpacks` / paid create paths).

Out of scope by design: `GET /v1/audits/{id}/fixpack-status` (status + pr_url only, no sensitive detail).

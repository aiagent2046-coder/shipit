# Plan: per-row access token for Fix Pack jobs (`GET /v1/fixpacks/{job_id}`)

## Problem

`GET /v1/audits/{audit_id}` and `/v1/audits/{audit_id}/report` are ownership-gated by a
per-row `access_token` (`?token=...`), added in PR #43 / migration
`0010_audits_access_token.sql`. A leaked audit UUID alone is not enough to read the report.

`GET /v1/fixpacks/{job_id}` (`get_fixpack` in `app/main.py:1189`) has **no such gate**: it
authorizes on knowledge of the bare `job_id` UUID alone via `FixpackJobRepository.get()`.
A Fix Pack job row exposes potentially sensitive repo details — `detail` (build/verify
output), `pr_url`, `preview_local_url`, linked `audit_id`, stack — and UUIDs leak (browser
history, referrer headers, logs, support tickets, screenshots). This closes that gap by
mirroring the audits model **exactly**, for consistency.

## Reconnaissance findings

### How audits does it (the pattern to mirror — PR #43)

- **Migration `0010_audits_access_token.sql`**: `create extension if not exists pgcrypto`;
  `alter table audits add column ... access_token text default encode(gen_random_bytes(16),'hex')`
  (16 bytes = 128 bits, hex → 32-char string); explicit backfill `update ... where access_token is null`;
  `alter column ... set not null`; `create unique index audits_access_token_key on audits (access_token)`.
  The token is **per-row random** (no cross-row secret), so it is safe to generate and backfill
  entirely inside the migration — leaking one row's token compromises only that row. Deliberate
  one-time breaking change: existing rows get fresh tokens, so old tokenless links stop resolving.
- **`app/db.py` `AuditRepository`**:
  - `create()` does **not** insert `access_token` (the column default mints it); it adds
    `access_token` to the `RETURNING` clause so the API can deliver it to the creator exactly once.
  - `get_authorized(audit_id, access_token)`: returns the row only if the token matches. Matched
    **in SQL** (`where id = %s and access_token = %s`) and **not** in the selected columns, so the
    token never rides back out in the body. Returns `None` for: missing/empty token (no DB round-trip
    at all), malformed id (no round-trip), wrong token (SQL yields no row), unconfigured DB.
  - `get()` remains the trusted server-side lookup with **no** token gate and does not select the token.
- **`app/main.py`**:
  - `get_audit` (line 407) and `get_audit_report` (line 428) take `token: str | None = None`, call
    `audit_repo.get_authorized(...)`, and return **404** (not 403) on `None` — never confirms an id exists.
  - `POST /v1/audits` returns `"access_token": persisted.get("access_token")` (line 1177) for one-time delivery.
- **Frontend**: `getAudit(id, token)` / `reportUrl(id, token)` append `?token=...`
  (`web/src/lib/api.ts`); `AuditForm.tsx` redirects to `/audit/{id}?token=...` after create;
  `audit/[id]/page.tsx` reads `token` from the query string.
- **Confirmed**: wrong/missing token → **404**, verified in `tests/test_persistence_wiring.py`
  (`test_get_audit_without_token_is_404`) and `tests/test_db.py` (`get_authorized` suite).

### fixpack_jobs today

- Table defined in `migrations/0001_audits_and_fixpack_jobs.sql`; extended by
  `0011_fixpack_jobs_lease.sql` (`started_at`, `attempts`, `running` status). **No `access_token`
  column exists** — it must be added from scratch via a new migration.
- Highest existing migration is `0011`, so the new one is `0012_fixpack_jobs_access_token.sql`.

### Where fixpack jobs are created (token must be minted at each)

1. `POST /v1/fixpacks` → `create_fixpack` (`app/main.py:1205`) → `fixpack_repo.create(...)`
   (`app/db.py:328`). Deploy Pack flow. Response returns `fixpack_id` (line 1359) but **no token today**.
2. Fix Pack purchase flow: `app/billing/__init__.py:163` → `fixpack_repo.create_paid(...)`
   (`app/db.py:360`), reached from the Telegram Stars and USDT payment paths.

Both currently rely on the DB default for id; both will get their token minted by the same
column default. Both `create()` and `create_paid()` `RETURNING` clauses need `access_token`
added so `_row_to_fixpack_job` carries it out for one-time delivery.

### Who reads a fixpack job by id

- `fixpack_repo.get(job_id)` is called from **exactly one place**: the `get_fixpack` endpoint
  (`app/main.py:1194`). (Unlike audits, whose `get()` is also used server-side by the billing
  flow.) The other read paths — `get_by_audit`, `claim_one_paid`, `reap_stale_running` — do not
  select `access_token` and are untouched.

### Frontend impact: none

The frontend **never calls `GET /v1/fixpacks/{job_id}`** and never calls `POST /v1/fixpacks`.
Fix Pack purchase status is polled via `GET /v1/audits/{audit_id}/fixpack-status`
(`getFixpackStatus` in `web/src/lib/api.ts`), keyed by `audit_id`, returning only
`status` + `pr_url` (not the sensitive fields). That endpoint is a separate surface and is
**out of scope** for this task. So **no frontend changes are required** — this is the one place
the fixpacks story legitimately diverges from audits (audits has a public results page that
consumes the token; the deploy-pack `GET /v1/fixpacks/{id}` endpoint has no frontend consumer).

### README

The README does **not** contain a dedicated "audits access-token model" section to mirror —
it only lists the endpoints (`GET /v1/audits/{id}` / `GET /v1/fixpacks/{id}` "read them back",
lines ~110-111) without describing the token gate. Since the audits pattern isn't written up in
the README, there is no matching prose to extend. I will add a short, symmetric note to that
endpoint bullet stating both endpoints now require the per-row `?token=` (404 on missing/wrong),
so the README doesn't imply bare-UUID reads.

## Implementation plan (Step 2 — after approval)

### 1. Migration — `migrations/0012_fixpack_jobs_access_token.sql`

Mirror `0010` line-for-line, retargeted to `fixpack_jobs`:
- `create extension if not exists pgcrypto;`
- `alter table fixpack_jobs add column if not exists access_token text default encode(gen_random_bytes(16), 'hex');`
- Explicit backfill: `update fixpack_jobs set access_token = encode(gen_random_bytes(16),'hex') where access_token is null;`
  (only a few prod rows, confirmed via Supabase).
- `alter table fixpack_jobs alter column access_token set not null;`
- `create unique index if not exists fixpack_jobs_access_token_key on fixpack_jobs (access_token);`
- Comment block mirroring 0010's rationale (per-row capability, safe to backfill in-migration,
  same deliberate one-time breaking change for existing tokenless links — negligible, few rows).

### 2. `app/db.py` — `FixpackJobRepository`

- `create()`: add `access_token` to the `RETURNING` clause (not an INSERT param — default mints it).
- `create_paid()`: same — add `access_token` to `RETURNING`.
- Add `get_authorized(self, job_id, access_token)` mirroring `AuditRepository.get_authorized`
  exactly: early-return `None` on falsy token (no DB round-trip); `None` on malformed UUID (no
  round-trip); `select <existing columns> from fixpack_jobs where id = %s and access_token = %s`
  — **`access_token` stays out of the select list** so it never leaks; `None` on unconfigured DB.
  Docstring notes `get()` remains the trusted server-side lookup, distinct from this gated fetch.
- `get()` unchanged (already does not select `access_token`; kept as the trusted lookup and it
  still has coverage in `tests/test_db.py`).
- `_row_to_fixpack_job` needs no change (token passes through `dict(row)` only when a query
  selects it — i.e. only `create`/`create_paid`, for one-time delivery — same as `_row_to_audit`).

### 3. `app/main.py`

- `get_fixpack` (line 1189): add param `token: str | None = None`; replace `fixpack_repo.get(job_id)`
  with `fixpack_repo.get_authorized(job_id, token)`; keep the **404** on `None` with the same
  "no fixpack job with this id and token, or persistence isn't configured" wording as audits.
- `create_fixpack` response (line 1358): add
  `"access_token": persisted_job.get("access_token") if persisted_job else None`.

### 4. Tests

- **`tests/test_db.py`** (`TestFixpackJobRepositoryWithFakePool`): mirror the audit suite —
  `create`/`create_paid` return `access_token` and it appears in `RETURNING` but not in INSERT
  params; `get_authorized` matches id+token in SQL and doesn't select the token; no token → no
  query; malformed id → no query; wrong token → `None`.
- **`tests/test_persistence_wiring.py`**: extend `FakeFixpackRepo` to mint a per-row token in
  `create()` and add `get_authorized()` (dropping the token from the returned dict), mirroring
  `FakeAuditRepo`. Update `test_get_fixpack_after_create_round_trips` to pass `?token=`. Add
  `test_get_fixpack_without_token_is_404` (no token and wrong token → 404). Add a create-returns-token
  assertion.
- Run the full `pytest` suite; fix any fallout.

### 5. README

Add a short symmetric note to the `GET /v1/audits/{id}` / `GET /v1/fixpacks/{id}` bullet:
both require the per-row `?token=` delivered once at creation; a missing/wrong token → 404
(never confirms the id exists).

## Out of scope / deliberate divergences

- `GET /v1/audits/{audit_id}/fixpack-status` (poll by audit_id) — separate surface, returns only
  `status` + `pr_url`, not the sensitive fields; unchanged.
- No frontend changes — nothing in `web/src` calls `GET /v1/fixpacks/{job_id}`.
- `get()` is kept (not removed) to preserve the trusted-lookup split, exactly as audits keeps its `get()`.

---
🤖 *Generated by Computer*

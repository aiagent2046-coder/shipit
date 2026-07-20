# Real-Postgres CI smoke test — reconnaissance + plan

**Status: Step 1 (recon + plan) only. No implementation code in this PR.**
Awaiting review/approval before Step 2.

Goal: a CI job that stands up a **real** Postgres, applies **every** migration
in `migrations/` in order, and executes the **write path of every repository**
in `app/db.py` against it — so the exact class of bug that hit prod twice
(`psycopg.errors.DatatypeMismatch: column "expires_at" is of type timestamp
with time zone but expression is of type integer`) is caught in CI forever,
for any future migration/column, instead of sailing through 517 green tests
that never touch a real database.

---

## TL;DR — why the whole suite is blind to this bug class

`tests/conftest.py` has an **autouse** fixture, `_no_ambient_database_url`
(lines 39–44), that runs for **every test in the suite**:

```python
@pytest.fixture(autouse=True)
def _no_ambient_database_url(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    db_mod._pool = None
    yield
    db_mod._pool = None
```

So `DATABASE_URL` is unset for 100% of tests. Every repository method in
`app/db.py` starts with `try: pool = await get_pool() except
DatabaseNotConfigured: return None` — meaning under the test suite each write
method **returns `None` without ever building a SQL string or touching a
database**. The repository tests (`tests/test_db.py`) then substitute a
`FakePool` that records the query *text* and *params* but never sends them to
Postgres. That fake can (and does — see `TestSubscriptionRepositoryExpiresAtType`)
assert "the param is a `datetime`, not an `int`", but it can **never** assert
"this SQL actually executes against the real schema without a type/column
error", because there is no real schema and no real type coercion in a Python
dict.

That is exactly the gap: the `expires_at` bug was a mismatch between a Python
value's type and a real Postgres column type. Only real Postgres can catch it.
This plan adds that missing layer **alongside** the fast fake-based tests (it
does not replace them): the fakes prove wiring/param-order cheaply on every
run; the new job proves the SQL is real against a live schema.

The autouse fixture is **correct and stays** — the recon below confirms the new
job must work *with* it, not remove it (removing it would reintroduce the
event-loop/pool-leak cascade its docstring describes for the fast suite).

---

## 1. `tests/conftest.py` — full read, and the interaction that matters

Three autouse fixtures, all applying to every test under `tests/`:

1. `_generous_rate_limit_by_default` — overrides the rate limiter dependency.
   Harmless to the new job (the smoke test calls repositories directly, not the
   HTTP API).
2. `_no_ambient_database_url` — **the load-bearing one** (see TL;DR). Deletes
   `DATABASE_URL` and nulls `db_mod._pool` before *and* after every test.
3. `_no_ambient_llm_providers` — deletes `AITUNNEL_*` / `ANTHROPIC_*` /
   `LLM_MODEL`. Does **not** touch `DATABASE_URL` or `API_KEY_PEPPER`.

**The critical interaction.** The task suggests guarding the new file with
`pytest.mark.skipif(not os.environ.get("DATABASE_URL"), ...)`. That works for
*selection* — `skipif` is evaluated at **collection time**, before any fixture
runs, so when CI exports `DATABASE_URL` the file is collected and not skipped;
when a dev runs `pytest` locally with no `DATABASE_URL`, the whole file is
skipped and they see no failures. Good.

But there is a trap: at **runtime**, `_no_ambient_database_url` (autouse) will
delete `DATABASE_URL` and null the pool *right before the test body runs* —
even in CI. So a naive smoke test would find `DATABASE_URL` gone by the time it
calls a repository and get the not-configured `None` path — a **false green**
(the worst outcome: a test that looks like it ran but exercised nothing).

**The fix (no conftest change needed):** capture the URL at **module import
time** (collection, before fixtures run) and have the smoke file's own fixture
re-establish it after the autouse fixture has run:

```python
import os
import app.db as db_mod

# Captured at import (collection) time, before the autouse
# _no_ambient_database_url deletes it.
_SMOKE_DB_URL = os.environ.get("DATABASE_URL")

pytestmark = pytest.mark.skipif(
    not _SMOKE_DB_URL,
    reason="real-Postgres smoke test: set DATABASE_URL (CI does; local runs skip)",
)

@pytest.fixture
def real_db(monkeypatch):
    # Runs AFTER the autouse _no_ambient_database_url (test-requested
    # fixtures finalize setup last), so this is the value get_pool() sees.
    monkeypatch.setenv("DATABASE_URL", _SMOKE_DB_URL)
    monkeypatch.setenv("API_KEY_PEPPER", "ci-smoke-pepper-not-a-real-secret")
    db_mod._pool = None
    yield
    asyncio.get_event_loop().run_until_complete(db_mod.close_pool())
    db_mod._pool = None
```

(Exact teardown mechanics finalized in Step 2 — likely an `async` fixture that
`await db_mod.close_pool()`, given `asyncio_mode = "auto"`.) The point proven
here: relying on ambient `DATABASE_URL` at runtime is **not** safe under this
conftest; the value must be captured pre-fixture and re-injected. This is the
single most important recon finding and the thing most likely to silently break
the job if missed.

`API_KEY_PEPPER` is required because `AccountRepository.create` calls
`hash_api_key`, which raises `RuntimeError` if the pepper is unset (a made-up CI
value is fine — nothing verifies a real key here).

---

## 2. Every repository and the write path each needs one smoke call

Six repository classes in `app/db.py`. The job is a *smoke* — one real call per
write path, asserting "no exception + row reads back with sane types", **not**
re-testing behavior already covered by the fakes. Ordered so FK dependencies are
satisfied (audit → fixpack_job → fix_outcome; account → payment).

| Repository | Write method | What it exercises against real Postgres |
|---|---|---|
| **AuditRepository** | `create` | INSERT `audits`, `%s::jsonb` casts for score/findings, `RETURNING access_token` (column default from migration 0010) |
| **FixpackJobRepository** | `create` | INSERT `fixpack_jobs`, `preview_expires_at` float→`datetime` boundary conversion, FK to `audits` |
| | `create_paid` | INSERT with `status='paid'` |
| | `mark_delivered` | UPDATE `pr_url`/`pr_delivered` |
| | `mark_fixpack_delivered` | UPDATE → `status='delivered'` |
| | `mark_status` | UPDATE status (both branches: `detail=None` and `detail=...`) |
| | `claim_one_paid` | `UPDATE ... WHERE id = (SELECT ... FOR UPDATE SKIP LOCKED)` — real subquery/lock syntax |
| | `reap_stale_running` | two UPDATEs using `make_interval(mins => %s)` — real interval function |
| **FixOutcomeRepository** | `record` | INSERT `fix_outcomes`, `%s::jsonb` for `rule_ids`, FKs to fixpack_job + audit |
| | `set_pr_merged_by_pr_url` | UPDATE by `pr_url`, returns `rowcount` |
| **AccountRepository** | `create` | INSERT `accounts` (prefix+hash, needs `API_KEY_PEPPER`) |
| **PaymentRepository** | `create` | INSERT `payments` (9 columns incl. `product`, `audit_id` FK) |
| | `mark_completed` | UPDATE → completed, links account_id |
| | `mark_completed_fixpack` | UPDATE → completed (no account) |
| | `link_telegram_chat_id` | UPDATE with the null-guard anti-hijack WHERE |
| **SubscriptionRepository** | `upsert_first` | **the prod bug's path** — INSERT ... ON CONFLICT, `expires_at` timestamptz |
| | `renew` | **also `expires_at` timestamptz** — UPDATE |
| | `set_status` | UPDATE status only |

Plus one non-repository write path worth one call: `fixpack_processor_lock`
(the `pg_try_advisory_lock` / `pg_advisory_unlock` context manager) — it
executes real SQL and is cheap to smoke.

Read-only methods (`get`, `get_by_*`, `get_authorized`, `backlog_stats`,
`list_pending`, `get_active_by_user`) are **not** the target of this job, but
the smoke will naturally call a few (`get`, `get_by_external_ref`) to read back
inserted rows and assert types round-trip — a bonus, not the focus.

Coverage rule for Step 2: **every write method above is called at least once.**
A future migration that adds a column or changes a type, without updating the
corresponding write method, will make one of these calls raise — which is the
whole point.

---

## 3. `migrations/` — count, order, and the runner (must be written)

15 files, `0001_*.sql` … `0015_*.sql`. They apply in **plain filename order**
(zero-padded, so lexical == numeric). Key properties confirmed by reading all
15:

- **Idempotent / additive**: `create table if not exists`, `add column if not
  exists`, `create index if not exists`, `create extension if not exists
  pgcrypto` (migrations 0010, 0012). A clean apply on an empty DB just builds
  the schema top to bottom.
- **`pgcrypto`** is created inside the migrations themselves (0010/0012) for
  `gen_random_bytes`; `gen_random_uuid` is a PG13+ builtin. No pre-seeding of
  extensions needed beyond running the migrations.
- **RLS is default-deny** (0002, 0003, 0014, 0015: `enable row level security`
  with no policies). This does **not** block the smoke test: the migration
  comments state, and it is true, that RLS never applies to the **table owner**
  unless `FORCE ROW LEVEL SECURITY` is set (it is not). The smoke job connects
  as the `postgres` superuser/owner of the service container, so every
  INSERT/UPDATE bypasses RLS exactly as the real app does (it connects as the
  `postgres` role via Supavisor). No policy work required.

**There is no existing "apply all migrations" mechanism.** The user applies them
by hand via Supabase's `apply_migration` tool, one at a time. `app/db.py` never
runs migrations; there is no `alembic`, no `migrate` script. So Step 2 adds a
tiny runner — **`scripts/apply_migrations.sh`**:

```sh
#!/usr/bin/env bash
set -euo pipefail
: "${DATABASE_URL:?set DATABASE_URL}"
for f in migrations/[0-9]*.sql; do
  echo "applying $f"
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f "$f"
done
```

`ON_ERROR_STOP=1` so a broken migration fails the job loudly. Committing it as a
script (vs. inlining in YAML) means a dev can also run it against their own
throwaway Postgres locally, mirroring `scripts/verify_db_locally.py`'s "prove it
for real" ethos. `psql` is preinstalled on GitHub's `ubuntu-latest` runners.

---

## 4. CI job design — a **new** workflow, `db-postgres-smoke.yml`

Neither existing workflow fits, and extending one would muddy its trigger:

- `security-audit.yml` is dependency/SBOM scanning, triggered only on dep-file
  changes. A DB-schema smoke has nothing to do with dep files and would never
  fire on a `migrations/` or `app/db.py` change.
- `smoke-deploy-pack.yml` is `workflow_dispatch`-only (manual) and about Docker.
  We want the DB smoke to run automatically on every relevant PR, not manually.

So a new, single-purpose workflow is the right call (not a duplicate — a
distinct concern with its own triggers and a `services: postgres`).

**Postgres version: `postgres:17`.** The `app/db.py` module docstring states the
schema/SQL "were verified for real against a real Supabase **Postgres 17**
project." Matching the prod major version is the point of a smoke test, so use
17, not "latest LTS."

```yaml
name: db-postgres-smoke

# Runs the real-Postgres schema+SQL smoke: apply every migration to a fresh
# Postgres 17, then exercise the write path of every app/db.py repository.
# Catches type/column/SQL mismatches (e.g. the expires_at timestamptz bug)
# that the fake-based suite structurally cannot — see
# POSTGRES_CI_SMOKE_TEST_PLAN.md and tests/conftest.py's DATABASE_URL fixture.
on:
  push:
    branches: [main]
    paths:
      - "migrations/**"
      - "app/db.py"
      - "tests/test_db_postgres_smoke.py"
      - "scripts/apply_migrations.sh"
      - ".github/workflows/db-postgres-smoke.yml"
  pull_request:
    paths:
      - "migrations/**"
      - "app/db.py"
      - "tests/test_db_postgres_smoke.py"
      - "scripts/apply_migrations.sh"
      - ".github/workflows/db-postgres-smoke.yml"
  workflow_dispatch: {}

permissions:
  contents: read

jobs:
  smoke:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:17
        env:
          POSTGRES_PASSWORD: postgres
          POSTGRES_DB: shipit_smoke
        ports:
          - 5432:5432
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    env:
      DATABASE_URL: postgresql://postgres:postgres@localhost:5432/shipit_smoke
      API_KEY_PEPPER: ci-smoke-pepper-not-a-real-secret
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install shipit (locked, hash-verified deps)
        run: |
          pip install --require-hashes -r requirements-dev.txt
          pip install -e . --no-deps
      - name: Apply all migrations in order
        run: bash scripts/apply_migrations.sh
      - name: Real-Postgres repository write-path smoke
        run: pytest -q tests/test_db_postgres_smoke.py
```

Notes:
- `DATABASE_URL` is set at the **job** level so both `psql` (the migration step)
  and `pytest` (which captures it at import) see it. Its runtime deletion by
  conftest is defeated by the module-capture-and-reinject pattern in §1.
- No `prepare_threshold` concern: that app-side setting (disabling server-side
  prepares to dodge a Supavisor+psycopg bug) is harmless against a direct
  Postgres connection, so the real `get_pool()` runs unmodified — the job tests
  the *actual* pool code, not a variant.
- Deps installed the same hash-verified way as `smoke-deploy-pack.yml`, for
  consistency.

---

## 5. **Proving the test actually catches today's bug** (mandatory gate)

A test that merely *exists* proves nothing. Before Step 2 is considered done, we
prove the new smoke test would have caught the `expires_at` bug had it existed
yesterday morning. Method (done locally in Step 2 against a throwaway Postgres
17 container — **not** committed to the final PR):

1. Bring up Postgres 17 and apply all migrations via
   `scripts/apply_migrations.sh`.
2. Confirm the new smoke test is **green** with the fix in place
   (`_expires_at_to_timestamptz` present in `app/db.py`).
3. **Temporarily revert the fix** — make `upsert_first`/`renew` pass the raw
   `expires_at` int straight to the timestamptz column (i.e. delete the
   `expires_dt = _expires_at_to_timestamptz(expires_at)` conversion and bind the
   int). Re-run the smoke test.
4. **Assert it now fails with the exact prod error**:
   `psycopg.errors.DatatypeMismatch: column "expires_at" is of type timestamp
   with time zone but expression is of type integer`.
5. Restore the fix; confirm green again.

Only after observing that red→green transition do we know the test is load
bearing rather than decorative. The PR description for Step 2 will paste the
actual failing output from step 4 and the passing output from steps 2/5, so the
proof is reviewable, not just claimed.

(If, and only if, a smoke call for some *other* repository can't be made to fail
by a deliberately-broken column, that indicates the smoke isn't really
exercising that path — it will be fixed until a deliberate break in each write
path is observably caught.)

---

## 6. Files Step 2 will add/touch (surgical)

- **`scripts/apply_migrations.sh`** (new) — the psql migration runner (§3).
- **`tests/test_db_postgres_smoke.py`** (new) — the module-captured-`DATABASE_URL`
  guard + one write call per repository write path (§1, §2). Skipped locally
  when `DATABASE_URL` is unset, so the normal `pytest -q` run is unchanged.
- **`.github/workflows/db-postgres-smoke.yml`** (new) — the CI job (§4).
- **`README.md`** — document the new job under the Phase 3 CI section (near the
  `security-audit.yml` / `smoke-deploy-pack.yml` write-ups), including the
  "proves the type-mismatch bug class" rationale and how to run the smoke
  locally against a throwaway Postgres.
- **No change** to `tests/conftest.py`, `app/db.py`, or existing tests. The
  autouse `DATABASE_URL` fixture stays; the new test works around it by design.

---

## What I need from you

Approve this plan (or adjust: Postgres major version, new-workflow vs. extend,
whether the migration runner should be a committed script vs. inlined YAML) and
I'll implement Step 2 exactly as above — including pasting the real red→green
proof from §5 into the PR.

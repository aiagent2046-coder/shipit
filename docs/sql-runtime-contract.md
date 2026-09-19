# Synthetic PostgreSQL value-binding contract

The [agent integration](agent-synthetic-runtime.md) selects and executes this
contract from completed source evidence and records its result in the report.

`scripts/verify_sql_runtime_contract.py` exercises the proposed
`sql-value-parameterization-python-psycopg3` recipe against PostgreSQL. It accepts
no project archive, project path, SQL text or supplied expectations. Its table,
queries and data are trusted fixtures maintained with the harness.

The first contract covers a **text value** in one fixed `SELECT`. It executes
nine cases in three stages: vulnerable string interpolation, Psycopg `%s` value
binding, and a mutation restoring interpolation. It checks actual rows, order,
column names, PostgreSQL type OIDs and Python value types against a separate
Python oracle. Two executions producing the same wrong answer cannot pass.

| Case | Required behavior |
| --- | --- |
| Ordinary name with duplicates | Preserve both matching rows and their order |
| Missing value, empty string, Unicode, backslash | Match the exact fixture rows |
| Apostrophe in a name | Record the baseline syntax failure; the corrected query returns the literal name |
| SQL-shaped input stored as a literal fixture value | Baseline returns all 9 rows; binding returns only row 9; restored mutation again returns all 9 |
| `NULL` with equality | Return no rows in every stage |
| `NULL` with `IS NOT DISTINCT FROM` | Return the NULL row in every stage; retain the explicitly chosen operator |

The final verdict requires all nine cases, a demonstrated baseline defect, a
passing corrected attack case and a detected mutation of the same control.
An empty corpus, missing attack control, surviving mutation, SQL timeout or
connection failure cannot produce a verified recipe. The expected apostrophe
syntax error is a baseline behavior control, never exploit evidence.

## Isolation and execution

The dedicated PostgreSQL 17 CI service starts with database
`drydock_sql_contract`. No application migrations or production data are used.
The harness creates a temporary table inside an outer rollback-only transaction;
every case has a rollback-only savepoint. Session settings use `SET LOCAL`.
A pre-existing table with the fixture name is left intact and returns
`unavailable`. Success additionally requires an idle connection and an
independent check that rollback removed the fixture table.

Each statement has a 1.5-second timeout, locks a 0.5-second timeout, and results
are capped at 32 rows. Only an explicitly configured loopback TCP connection to
`drydock_sql_contract` is accepted. The runner pins both host and numeric
hostaddr, refuses URL query/service overrides and ambient `PG*` settings, and
never falls back to the application's `DATABASE_URL`.

With the repository's locked development dependencies and a disposable local
PostgreSQL server configured, run:

```bash
export SQL_CONTRACT_DATABASE_URL='postgresql://postgres:synthetic-contract-password@127.0.0.1:5432/drydock_sql_contract' # scan-allow: disposable local example
python -m pytest -q tests/test_sql_runtime_target.py tests/test_sql_runtime_contract.py
python scripts/verify_sql_runtime_contract.py --output /tmp/sql-runtime-contract.json
```

The output path must be new. Exit codes are 0 for a passed synthetic contract,
1 for a failed contract and 2 for unavailable execution. Without the dedicated
DSN, unit tests still run and the three real-database tests explicitly skip;
the CLI returns unavailable. CI supplies the DSN and must execute all tests.

## Evidence boundary

The JSON artifact records `scope: synthetic_recipe`, the contract ID, Psycopg
and PostgreSQL versions, schema/fixture/query/result hashes, per-case outcomes,
row IDs, type information and cleanup results. It contains no connection
string, credentials, raw exception message or customer project data.

`synthetic_recipe_verified: true` means this fixed recipe passed this contract.
`runtime_verified`, `customer_project_verified` and `automatic_patch` remain
false. The scanner's authorization, deployed reachability, intended type and
runtime prerequisites remain unresolved for uploaded applications. This harness
does not alter Fix Pack delivery or enable automatic repair.

The `sql-runtime-contract` workflow retains the JSON evidence artifact. A future
application-specific proof must bind its own source snapshot, driver/schema,
input semantics and authorization to an independently approved runtime contract.

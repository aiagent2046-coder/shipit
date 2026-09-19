# Agent-selected synthetic PostgreSQL evidence

The deterministic agent can now select and execute the registered text-value
Psycopg contract after collecting matching source evidence. It consumes the
result, records a source-bound journal and plans the next missing proof.

The selection requires a validated Psycopg 3 `execute` chain, completed source
acquisition, exactly one SQL value slot and only string constraints for that
slot. Unknown drivers, missing facts, integer slots, multiple substitutions and
`executemany` do not select this contract. The fixed synthetic SELECT proves a
recipe on its own schema; selection does not establish equivalence with the
customer query, schema or deployed route.

An investigation executes the contract at most once. Multiple matching
candidates reuse that result with separate archive/file/candidate, engine and
catalog bindings. Failure, timeout or malformed output never triggers a retry
and never deletes successful source findings. A failed or unavailable selected
experiment makes the investigation partial. An investigation with no eligible
candidate does not start a process or connect to a database.

## Run an investigation

Use the repository's locked application/development dependencies and the
dedicated disposable database described in [sql-runtime-contract.md](sql-runtime-contract.md).
The DSN is supplied only in `SQL_CONTRACT_DATABASE_URL`, never in command-line
arguments, uploaded configuration or `DATABASE_URL`.

```bash
python scripts/investigate_sql_runtime.py project.zip --output /tmp/agent-investigation.json
```

This entry point calls the same `run_scan` and evidence coordinator used by the
application, with no LLM providers and an explicit `SyntheticSqlExecutor`
capability. Exit 0 means a completed selected synthetic investigation, 1 a failed
recipe experiment, and 2 unavailable/incomplete execution or no eligible
contract. It never means the project is safe. Output files must be new.

Trusted Python callers may pass `synthetic_sql_executor=SyntheticSqlExecutor()`
to `run_scan`. The core scanner never discovers executors from environment
variables or uploaded source. The executor's optional
`executor_from_environment()` factory is for explicit callers only; setting
`SHIPIT_SQL_CONTRACT_AGENT_ENABLED=1` alone does **not** enable it in cached web
audits. Automatic web-worker rollout requires a separate cache-aware policy so
enabling a capability cannot silently reuse an older source-only report or
re-run paid LLM work.

The existing browser and standalone offline installers retain their source-only
execution. They acquire no Psycopg dependency, database access or subprocess
capability. Saved reports can display the new scoped evidence.

## Execution boundary

The executor invokes one fixed bundled worker with Python isolated mode (`-I`),
a trusted working directory and a minimal environment. It receives no archive,
project SQL, project code or supplied expectations. The existing target validator
pins a loopback connection to `drydock_sql_contract` and rejects libpq overrides.
The parent enforces a 60-second wall limit and 256 KiB output acceptance limit,
kills and reaps an over-budget child, and discards stderr and exception messages.
The worker retains SQL timeouts, row limits and rollback-only fixture handling.

Before accepting success, the native adapter checks the full nine-case matrix
for all three stages, exact query/result/fixture/schema hashes, column OIDs,
NULL behavior, control rows and cleanup. It returns a compact summary; the
coordinator validates it again and binds it to the investigation.

## Report meaning

An accepted result changes the candidate to `synthetic_recipe_verified` with
`next_action: review_project_runtime_contract`. The four project requirements
remain missing: caller authorization, deployed reachability, intended value
types and the application runtime behavior contract. `runtime_verified`,
`customer_project_verified`, `automatic_patch` and recipe `automatic_apply`
remain false; finding severity, score and verification status are not upgraded.

JSON/SARIF, HTML, web and browser views validate the optional `synthetic_contract`
section. Inconsistent saved records are dropped or displayed as unavailable,
never promoted. Hashes and schema validation establish consistency, not the
authenticity of an externally edited JSON report. Saved records never instruct
the executor or authorize an automatic patch.

The PostgreSQL CI workflow now tests and invokes the agent entry point as well
as the direct harness, and retains both JSON artifacts.

# Source evidence task chain

The SQL reviewer now delegates work through a bounded in-process queue. This is
an execution path, not a journal reconstructed after a monolithic review. Each
worker receives a copy of the accepted predecessor output; the coordinator
validates and commits the hand-off before scheduling the next task.

| Worker | Responsibility | Completion criterion |
| --- | --- | --- |
| Detector | Validate the existing static SQL observation and classify its pattern | Scanner-owned source/driver trace matches the candidate |
| Researcher | Collect missing request origin, local flow, SQL value positions and value constraints | Source acquisition validates against the original snapshot |
| Experimenter | Select the registered synthetic contract when source prerequisites match | One trusted executor result obtained, or an explicit blocked reason |
| Verifier | Validate the experiment, its source binding and scope; plan the next missing proof | Accepted synthetic result with remaining project gaps, or explicit missing evidence |

The chain covers the existing Python/Psycopg SQL pattern and the bounded
[FastAPI Body-to-pickle input trace](deserialization-source-evidence.md).
Deserialization receipts use `scope: source_evidence`; the researcher establishes
only HTTP origin and local flow. Its experimenter has no registered recipe and
remains blocked, and the verifier retains the missing trust/runtime evidence.
Other weakness cards retain their previous review behavior. This does not add
cross-process distribution, automatic repair, or customer-project execution.

## Task and evidence contract

Each observation carries `agent_chain` version 1. Its four task receipts contain:

- a deterministic task ID and named worker/goal;
- archive, source-file, observation, engine and catalog identities;
- predecessor task IDs and input/output SHA-256 references;
- one allowed attempt, actual attempts, outcome and bounded reason code.

Task order is detector → researcher → experimenter → verifier. The experimenter
chooses its action from newly acquired evidence: an unknown driver, incomplete
source facts, unsupported slot or absent explicit executor blocks execution.
The verifier then records that evidence is still missing. Queue completion is
not proof that the application is safe.

There are at most four tasks per candidate and 128 candidates per review.
Source acquisition retains the shared 512-action/640,000-work-unit budgets.
Native execution retains the 60-second process limit and 256 KiB output limit.
The coordinator performs no automatic retries. The registered synthetic recipe
runs once per investigation; subsequent eligible candidates receive separately
source-bound copies of the same result, including a failed/unavailable result.

Worker exceptions discard that worker's proposed changes, preserve accepted
facts and detector findings, block downstream acquisition/execution, and leave
verification to report the gap. An executor failure is instead a sanitized
unavailable evidence result and is consumed by the verifier. No exception text,
project code, project SQL or credentials enter task receipts.

Receipts are checked on Python report normalization. Edited, incomplete,
cross-source or hash-inconsistent chains are removed and the review is marked
partial. Receipts never authorize execution when loading a report. Their hashes
prove internal consistency, not the authenticity of externally edited JSON.
Legacy reports without receipts remain readable. Existing HTML/web/browser
summaries still show findings and scoped evidence; detailed task receipts are
available in JSON/SARIF rather than a new task dashboard.

## Run the full chain

Use the dedicated disposable PostgreSQL setup in
[sql-runtime-contract.md](sql-runtime-contract.md), then run:

```bash
python scripts/investigate_sql_runtime.py project.zip --output /tmp/agent-chain.json
```

`score.scan_manifest.security_agent.observations[*].agent_chain` contains the
queue receipts. Ordinary browser/local scans run the source-only stages and
record a blocked experimenter without gaining a database/process capability.
No LLM calls are needed. The synthetic executor still receives zero project
inputs and must be supplied explicitly by a trusted native caller.

A successful synthetic experiment verifies only the repair recipe. Caller
authorization, deployed route reachability, intended value semantics and actual
application runtime behavior remain missing. `runtime_verified`,
`customer_project_verified`, `automatic_patch` and `automatic_apply` remain false.

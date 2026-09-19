# Deterministic security agent: first pilot

The shared scanner now includes a bounded coordinator that reviews static
observations against a machine-readable catalog. It makes no model calls,
executes no project code, and installs no project dependencies. It selects a
pattern, checks its evidence requirements, records the next permitted action,
and stops. Source findings and their existing scores remain the detector's
responsibility.

## Two catalogs with separate purposes

The existing CVE/GHSA catalog matches resolved dependency versions to published
advisories. The new **pattern catalog** describes candidate weakness classes,
source evidence, repair prerequisites and verification contracts. Its cards do
not create CVE records or claim that every occurrence of a pattern is exploitable.

| Pattern | Candidate class | Current decision |
| --- | --- | --- |
| Python SQL string assembly | CWE-89 | Static flow evidence; manual Psycopg 3 recipe with unmet prerequisites |
| Python unsafe deserialization | CWE-502 | Static observation; trust-boundary and loader contract required |
| Python outbound request input | CWE-918 | Static observation; destination and input-control evidence required |

`app/scan/pattern_catalog.py` is the versioned source of truth. Each card contains
detector/rule references, applicability, evidence descriptions, recipe state,
verification fixture references and primary sources. Detection scope and budgets
remain in the existing capability registry. The catalog checksum covers its
canonical contents. Card changes require a catalog version/revision update and
an engine version bump because scan caches also use the engine identity.

```bash
python -m app.local_cli patterns
python -m app.local_cli patterns --json
drydock-local scan /absolute/path/to/project --json
```

`patterns` reads only the bundled catalog; it does not require a project,
database, network connection or credentials. The standalone package exposes the
same commands through `drydock-local`.

## SQL evidence and limits

The existing Python AST/local-flow detector attaches structured evidence to a
SQL finding: file hash, assembly line and kind, execution-sink line and method,
and `flow_status: possible_local_flow`. The bounded analysis can follow selected
assignments and branches. The report includes locations and a source hash, not
copied SQL expressions or values.

The SQL card only selects Python findings. A shared JavaScript rule ID cannot
select the Psycopg recipe. Neither an `execute` method name nor an `import psycopg`
establishes the cursor's driver. A bounded same-file import → connect() → cursor()
chain can establish static Psycopg 3 provenance and remove that single prerequisite.
Unknown chains retain it. Attacker control, value position, intended value type
and a runtime behavior contract remain missing even when a plan completes.
See the [SQL pilot](sql-pattern-pilot.md) for the proposed value-binding recipe.

## Bounded execution and reporting

Every report includes `security_agent`: schema version, source archive hash,
engine and catalog identities, per-card coverage, observation decisions, budget,
stop reason and limitations. Decisions use a stable identifier derived from the
same source snapshot, card revision and finding location. The coordinator sorts
candidates and reviews at most 128 in one pass. It does not retry missing proof.

- `completed`: the bounded review plan finished; candidates can still need evidence.
- `partial`: a selected check has a coverage gap or the candidate budget was exhausted.
- `unavailable`: the required checks or the coordinator could not run.

Candidate decisions currently end in `state: needs_evidence` and
`next_action: manual_review`. `runtime_verified` and `automatic_patch` remain
false. Parsing, decoding, size and analysis failures never become clean results;
independent findings survive failures. Browser continuation recomputes the plan
after the next bounded detector batch and preserves unresolved gaps.

The same record reaches browser JSON/SARIF, local JSON/history and the online
scan manifest/HTML/SARIF. Local CLI returns exit code 2 for incomplete/unavailable
pattern review. SARIF records incomplete review as a warning; coordinator
unavailability also marks execution unsuccessful. Legacy reports remain readable.
The online service can separately request its existing model preview; this
coordinator belongs to the static stage and does not depend on that preview.

## Verification and next development boundary

Tests cover positive and parameterized SQL, missing driver proof, other card
prerequisites, malformed evidence, parse/size gaps, candidate limits, continuation,
coordinator failure, legacy reports and export parity. Offline integration tests
block network/process calls and include a source-execution canary. Installed-wheel
acceptance and the browser CPython/WASM/Chromium corpus exercise the same record.

This release provides classification, static evidence and bounded decisions.
Broader driver resolution, cross-function input flow, automatic repairs and
database execution tests remain future work. Promoting the SQL recipe requires
an independent synthetic runtime contract and a mutation that restores the
vulnerable construction and is detected by that contract.

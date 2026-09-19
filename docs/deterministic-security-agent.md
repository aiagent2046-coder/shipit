# Deterministic security agent: first pilot

The shared scanner now includes a bounded coordinator that reviews static
observations against a machine-readable catalog. It makes no model calls,
executes no project code, and installs no project dependencies. It selects a
pattern, selects a missing source fact, runs a collector, validates its result
and selects the next action from the facts now available. Source findings and their existing scores remain the detector's
responsibility.

## Two catalogs with separate purposes

The existing CVE/GHSA catalog matches resolved dependency versions to published
advisories. The new **pattern catalog** describes candidate weakness classes,
source evidence, repair prerequisites and verification contracts. Its cards do
not create CVE records or claim that every occurrence of a pattern is exploitable.

| Pattern | Candidate class | Current decision |
| --- | --- | --- |
| Python SQL string assembly | CWE-89 | Adaptive source investigation for FastAPI/Psycopg; manual recipe with remaining runtime prerequisites |
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
Unknown chains retain it. A supported FastAPI route decorator permits the same
driver analysis inside a synchronous handler; arbitrary decorators remain unknown.

For SQL schema-2 observations, the coordinator reads the original archive bytes
and requires matching archive/file hashes and one unambiguous AST sink. It then:

1. Traces query/path parameters or `Request.query_params` through straight-line
   local assignments to the query's dynamic slots.
2. When the Psycopg driver and symbolic query are known, checks SQL slot roles
   with the bundled PostgreSQL parser. The first grammar supports one `SELECT`
   from a fixed relation and fixed-column/value comparisons in `WHERE`.
3. When HTTP input flow is established, records declared primitive types,
   direct request-string access and supported `int()` conversions.

Each collector runs at most once per sink. An unknown driver skips the SQL role
check; an unknown HTTP source skips value constraints. The journal records
actions, results, produced facts, reasons and spent work. It contains no SQL text,
input values or exception messages. Simple aliases, f-strings and string
concatenation are supported; branches, wrappers, dependency injection,
asynchronous routes, dynamic identifiers and ambiguous SQL remain unknown.
Nonempty router prefixes remain unsupported because they can introduce path
parameters absent from the decorator. Parameter names support Unicode Python
identifiers up to 128 characters; longer names remain explicitly unsupported.
Repository-local `fastapi` or `starlette` modules/packages prevent framework
identity claims, including the decorated driver's source proof.

HTTP origin does not prove caller authorization or deployed route reachability.
A declared type is not intended business semantics. SQL value position is not
runtime exploitability. Those missing requirements remain visible after a
source investigation completes.
See the [SQL pilot](sql-pattern-pilot.md) for the proposed value-binding recipe.

## Bounded execution and reporting

Every report includes `security_agent`: schema version, source archive hash,
engine and catalog identities, per-card coverage, observation decisions, budget,
stop reason and limitations. Decisions use a stable identifier derived from the
same source snapshot, card revision and finding location. The coordinator sorts
candidates and reviews at most 128 in one pass. Source collection has a shared
640,000-unit work budget, 512-action cap and four actions per candidate. Source
files are limited to 400,000 bytes and 80,000 AST nodes; parsed source bytes are
capped at 2,000,000 per snapshot. Results are reused only within that snapshot.

- `completed`: the bounded review plan finished; candidates can still need evidence.
- `partial`: a selected check has a coverage gap, a budget was exhausted or source collection failed.
- `unavailable`: the required checks or the coordinator could not run.

An SQL candidate whose four source facts are established ends in
`state: source_evidence_collected` and `next_action: review_runtime_contract`.
Other candidates retain `needs_evidence` / `manual_review`. An unsupported
source form is an explicit unknown; exhausted resources make the review partial.
`runtime_verified` and `automatic_patch` remain
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

This release provides classification, adaptive source collection and bounded decisions.
Broader driver resolution, cross-function input flow, automatic repairs and
application-specific database execution tests remain future work. The separate
[synthetic PostgreSQL contract](sql-runtime-contract.md) checks a fixed text-value
recipe before/after binding and detects a restored vulnerable mutation. Its
success does not close any uploaded application's runtime prerequisites.

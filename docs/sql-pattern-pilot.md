# SQL pattern pilot: Python and Psycopg 3

Pattern ID: `python-sql-string-assembly`, revision 3.
Recipe ID: `sql-value-parameterization-python-psycopg3`, revision 1.
Status: executable static-evidence pilot selected by the
[deterministic coordinator](deterministic-security-agent.md). The recipe remains
manual guidance; it does not enable automatic patch application.

## Applicability and evidence

Class: [CWE-89](https://cwe.mitre.org/data/definitions/89.html).
Pilot stack: Python 3.12 and Psycopg 3; the repository pins Psycopg 3.3.5.
The transformation concerns a **value** in a SQL statement passed to an actual
Psycopg cursor. Establish the cursor's driver and the intended value type before
applying it. A method named `execute` alone does not establish this contract.

Existing detector: `app.scan.sql_injection.scan_sql_injection`.
Finding ID: `sql-injection-string-built-query`.
Coverage key: `sql_injection`.

The detector records a source observation: SQL text supplied to a recognized
execution sink is assembled from non-literal values. Its limited local flow
analysis can follow assignments and selected branches. The finding does not
establish an attacker-controlled source, a complete interprocedural path, or
runtime exploitability. Cross-file builders, dynamic drivers and application
authorization require separate evidence.

Record the source snapshot, engine version, catalog identity if used, file and
line, observed assembly, execution sink and per-rule coverage. A parse, decoding,
size, file-count, finding-count or analysis limit leaves the affected scope
incomplete. Existing findings remain observations even when another file fails.

## Bounded driver provenance

SQL observation schema 2 adds `driver_status: source_resolved | unknown`.
A resolved observation contains `driver_provenance` with the import, connection
and cursor source lines, under the observation's existing file and source hash.
Schema 1 reports remain readable as historical `not_checked` evidence.

The optional AST pass traces synchronous `import psycopg` / `from psycopg import
connect`, import and object aliases, `connect()` → `cursor()` → `execute()` or
`executemany()`, and their `with` forms. Function-local chains may inherit a
single stable import binding; connections and cursors never cross deferred
function scopes. Only a no-argument `cursor()` and a connection without a custom
cursor factory or argument unpacking qualify. Psycopg's
[connection API](https://www.psycopg.org/psycopg3/docs/api/connections.html)
permits replacing cursor factories, so a familiar method name is insufficient.

Branches, loops, exception handling, classes, nested functions, asynchronous
chains, wrappers, named/custom cursors, object escapes and resource exhaustion
remain unknown. Visible dynamic namespace access, attribute writes, wildcard
imports or driver-module escapes conservatively disable provenance for the
whole file. A repository-local `psycopg.py` or `psycopg/` disables it for the
archive. These conservative boundaries may leave valid chains unknown.

Unknown attribute access, function defaults and container stores revoke source
identity for the affected object and its aliases. A later target in a chained
assignment cannot restore it. Executable annotation expressions are analyzed
conservatively, including rebinding and opaque calls; match captures are treated
as local bindings throughout their function. A driver-module escape also
invalidates evidence recorded in a deferred function before that escape.

The optional pass has an 80,000-node cap and a separate 640,000-unit work budget
covering traversal and binding work. Exhaustion yields unknown driver provenance
while retaining the independently detected SQL finding. Calls do not copy the
entire alias table, and files without SQL observations skip this evidence pass.

This establishes a chain in the uploaded source under ordinary Python import
semantics. It does not inspect the installed package, import hooks, external
monkeypatching, connection success or execution. DSNs and source values are not
copied to the evidence. SQL findings and their severity remain unchanged.

The driver pass removes only `psycopg3_cursor_provenance` from missing recipe
prerequisites. The adaptive source collectors can separately establish HTTP
origin, local input flow, SQL value positions and declared/conversion constraints
for supported FastAPI handlers. See the [source investigation contract](deterministic-security-agent.md#sql-evidence-and-limits).
Caller authorization, deployed reachability, intended type and runtime behavior
still require evidence. The implementation
and positive/unknown regressions live in `app/scan/psycopg_provenance.py` and
`tests/test_psycopg_provenance.py`, `tests/test_psycopg_provenance_review.py` and
`tests/test_psycopg_provenance_budget.py`; browser parity includes these result shapes.

## One constrained transformation

Input candidate:

```python
cur.execute("SELECT id, email FROM users WHERE id = " + user_id)
```

Proposed value binding, after verifying driver and expected parameter type:

```python
cur.execute("SELECT id, email FROM users WHERE id = %s", (user_id,))
```

Psycopg accepts values separately from SQL through the second argument; the
single-value tuple needs its comma and the placeholder must not be quoted.
This template does not parameterize table names, column names, keywords or sort
directions. Those require a separate composition contract. Source:
[Psycopg parameter binding](https://www.psycopg.org/psycopg3/docs/basic/params.html).

Only apply the transformation after checking existing parameters, value types,
NULL behavior, result shape and transaction semantics. Preserve fixed SQL
fragments and intentional identifier composition; do not treat a function named
`sanitize` as sufficient evidence of protection.

## Existing executable checks

| Case | Repository evidence | Expected result |
|---|---|---|
| Non-literal concatenation reaches the sink | `tests/detectors/sql-injection-string-built-query/positive/concatenated-query/` | Static SQL observation |
| A parameterized value with a fixed column fragment | `tests/detectors/sql-injection-string-built-query/negative/parameterised-query/` | No SQL observation for the supported path |
| Assignment and branch behavior | `tests/test_sql_injection_flow.py` | Preserve established local-flow semantics |
| Broken, oversized or unread source | `tests/test_sql_injection_coverage.py` | Explicit incomplete coverage; other findings remain |
| Visitor interruption inside a literal expression | `tests/test_sql_injection_coverage.py::test_exhausted_expression_never_fabricates_finding_for_literal_query` | A resource limit never manufactures a SQL finding |
| CLI/report boundaries | `tests/test_sql_coverage_contracts.py` | Partial status and retained findings survive JSON, CLI, HTML and SARIF |
| False completion mutation | `scripts/check_security_mutations.py` | Treating a parse failure as analyzed makes the contract test fail |

These fixtures are parsed as source; their application dependencies and source
are not executed by the scanner. Passing a negative example means the supported
rule did not produce a finding, not that the application is safe.

## Acceptance before promoting this to a repair recipe

1. Maintain independent positive, negative and unknown cases for the selected driver.
2. Confirm the original behavior in a separate, authorized synthetic database
   harness, including ordinary values, quotes, NULL and expected result shape.
3. Confirm the corrected value binding removes the demonstrated defect without
   changing the intended query or surrounding API behavior.
4. Restore the vulnerable construction as a controlled mutation: the regression
   check must detect it.
5. Measure false positives, misses, unknown outcomes, time and memory against
   the same input and versions. Fewer findings alone is not an improvement.

The [synthetic PostgreSQL contract](sql-runtime-contract.md) now exercises steps
2–4 for a fixed text-value fixture and two explicit NULL operators. Its evidence
is scoped to the recipe, not an uploaded application. The current pilot delivers bounded static evidence, explicit gaps
and a reviewable recipe. The deterministic coordinator classifies the source
observation, gathers supported missing source facts and records which recipe
prerequisites remain. When all four source facts are collected, the next action
is `review_runtime_contract`; other candidates retain `manual_review`. It cannot establish the installed driver's
runtime identity or promote the proposed transformation to an automatic repair.

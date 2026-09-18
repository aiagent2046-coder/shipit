# SQL pattern pilot: Python and Psycopg 3

Card ID: `sql-value-parameterization-python-psycopg3`, revision 1.
Status: design pilot tied to existing static evidence and tests; no automatic
patch application or new agent coordinator is enabled by this card.

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

1. Add independent positive, negative and unknown cases for the selected driver.
2. Confirm the original behavior in a separate, authorized synthetic database
   harness, including ordinary values, quotes, NULL and expected result shape.
3. Confirm the corrected value binding removes the demonstrated defect without
   changing the intended query or surrounding API behavior.
4. Restore the vulnerable construction as a controlled mutation: the regression
   check must detect it.
5. Measure false positives, misses, unknown outcomes, time and memory against
   the same input and versions. Fewer findings alone is not an improvement.

The runtime repair checks in steps 2–4 are proposed work, not capabilities added
by this PR. The current pilot delivers bounded static evidence, explicit gaps
and a reviewable recipe. A future deterministic coordinator can select this card
only when its applicability evidence is present; otherwise it should return the
specific missing evidence and stop within its budget.

# Security properties: first batch

These tests verify Drydock itself. They do not run new tests against uploaded
customer applications, change Fix Pack delivery policy, or certify arbitrary
fixes. Hypothesis is a development dependency and is absent from the standalone
scanner's runtime bundle.

| Suite | Property and independent oracle | Limits |
| --- | --- | --- |
| `tests/test_authorization_properties.py` | Two generated job/audit pairs keep their capabilities separate. Unauthorized RLS requests produce the same 404 as a missing resource, perform no fetch/write, and preserve the legitimate request's budget. A successful request and a subsequent 429 are positive controls. | Real ASGI routes; repository doubles and external fetch doubles. Does not verify SQL authorization. |
| `tests/test_billing_properties_postgres.py` | Every prefix of generated replay histories preserves one account per charge, returns a plaintext key only on first grant, and keeps invoice/charge bindings. A small first-association model predicts conflicts independently of SQL. Rejected conflicts leave the ledger unchanged. | Real PostgreSQL; sequential Pro grants, one provider and one amount. Existing concurrency tests remain responsible for races and rollback. Does not exercise provider webhooks or Fix Pack funding. |
| `tests/test_cve_properties.py` | Numeric intervals independently predict CVE/OSV boundary results; prerelease ordering, status changes and source reordering preserve their specified meaning. Unsupported inputs and source disagreement keep explicit uncertainty. | Bounded npm/PyPI version subset; not full SemVer/PEP 440 conformance and not runtime reachability. |
| `tests/test_dependency_occurrence_properties.py` | A model of per-manifest source facts predicts scope precedence, directness, groups and canonical scalar fields. File/entry reordering and adding/removing a manifest preserve all selected origins while package/version assessments remain unique. Findings and unknown assessments retain the same recorded origins; different versions remain independent. | Tiny synthetic npm locks within the manifest budget, one requirements-line regression and a legacy fallback control. One occurrence represents a selected manifest, not every installation path or importer within it. `occurrences_recorded` denotes retained origins, not complete archive coverage. |
| `tests/test_manifest_fuzz_properties.py` | Guaranteed malformed/ambiguous JSON, YAML, TOML and requirements create explicit gaps; arbitrary bytes retain an independent positive without assuming every byte string is invalid. Valid formatting changes and archive entry order preserve pins, findings and locations. | 24 derandomized examples per property/format; five supported lockfile formats, arbitrary byte inputs at most 48 bytes. This is bounded structure-aware fuzzing, not a coverage-guided native-code campaign. |
| `tests/test_sql_coverage_contracts.py` | Real CLI scans retain an independent SQL finding alongside a syntax gap and return exit code 2. Browser-engine JSON, SARIF and HTML retain decode, size, finding and analysis gaps. Continuation respects separate Python and JS/TS budgets even though their findings share one rule ID. | Deterministic synthetic source; static string-assembly evidence, not reachable exploitation. Exercises the browser's Python entry point, not a graphical browser or Pyodide. Local history retains finding changes, not a complete coverage snapshot. |

`tests/test_manifest_parser_limits.py` covers byte-size acceptance/refusal,
YAML node/depth boundaries, aliases/duplicate keys and file selection. Native
JSON/TOML recursion refusals run in subprocesses with a 15-second timeout and
payloads at most 21 KB. `tests/test_manifest_fuzz_integration.py` checks the real
CLI: malformed/oversized metadata retains independent CVE findings and returns
exit code 2. Damaged ZIP members (CRC, encryption and DEFLATE failures) retain
assessments from readable locks. A skipped manifest is never converted to a
clean result.

`tests/test_sql_injection_coverage.py` checks the detector boundaries: file,
finding, byte-size, decoding, parsing and analysis budgets, retained positives,
exclusions and continuation accounting. The product contracts additionally use
the real 400-file batch boundary and check that a completed batch cannot hide
an earlier syntax gap. Repairing the unread file changes coverage without
erasing the independent SQL observation or declaring a verified fix. The
analysis-budget export contract lowers the visitor budget to 64 visits to
exercise real exhaustion with a small source fixture; detector tests cover the
remaining traversal behavior.

Lockfiles must decode as UTF-8; decoding no longer replaces damaged bytes.
Ambiguous duplicate JSON keys and non-finite JSON constants are rejected.
Poetry names/pins use the same registry identity grammar as uv. A damaged or
oversized adjacent `package.json` remains an explicit gap while its valid
lockfile's pinned versions can still be assessed. Invalid dependency-field
types are gaps; direct names from other valid fields are preserved. These behaviors also apply
to the shared online reader; no package manager or repository code is run.

All generated examples create their own mutable state. In particular, a pytest
function-scoped fixture is not mistaken for per-example database isolation.
Counterexamples are shrunk by Hypothesis. CVE and occurrence generation are derandomized for the
pinned Hypothesis version; auth/payment tests also use Hypothesis's normal
example database, ignored by Git. CI mutation controls use an explicit seed.

## Run the properties

Install the hash-locked development dependencies in a Python 3.12+ environment:

```bash
python -m pip install --require-hashes -r requirements-dev.txt
python -m pytest -q tests/test_authorization_properties.py tests/test_cve_properties.py tests/test_dependency_occurrence_properties.py tests/test_manifest_fuzz_properties.py tests/test_manifest_parser_limits.py tests/test_manifest_fuzz_integration.py
python -m pytest -q tests/test_sql_injection_coverage.py tests/test_sql_coverage_contracts.py
```

The payment suite requires an already migrated, disposable PostgreSQL database
on localhost or a Unix socket. It truncates `accounts` and `payments` with
cascades before and after every generated history. Use the existing
`db-postgres-smoke` workflow for a fresh PostgreSQL 17 service and all migrations.
With that disposable database configured in `DATABASE_URL`, run:

```bash
python -m pytest -q tests/test_billing_properties_postgres.py --hypothesis-seed=20260917
```

Without `DATABASE_URL`, payment tests are explicitly skipped, not verified.
To replay a failure, retain its minimized example, seed, commit, locked package
versions and test node ID. A new regression can be pinned with Hypothesis's
`@example` in addition to the generated cases.

## Check sensitivity to deliberate defects

The bounded runner first requires every selected property to pass on an
unchanged copy. It then applies one source mutation at a time in temporary
copies of `app/` and `tests/`, restoring that source between probes:

- include a CVE range's exclusive upper bound;
- convert cross-source uncertainty into `unaffected`;
- drop a second dependency origin while leaving package/version lookup counts unchanged;
- hide a malformed selected manifest's gap while retaining the independent positive finding;
- report unparseable Python SQL source as completely analyzed while retaining an independent SQL finding;
- bypass ownership before an RLS check;
- refuse a valid completed-payment replay (with PostgreSQL).

```bash
python scripts/check_security_mutations.py --output-dir /tmp/drydock-mutation-evidence
```

Use a new output directory for each run. Add `--with-postgres` to include payment
properties; this requires the same migrated disposable database. The CI database
job runs this mode, so payment coverage cannot silently be skipped there.

An assertion failure detects a mutation. A passing mutated suite means it
survived. A missing report, skipped check, fixture/import error, non-assertion
exception or 180-second timeout invalidates the probe and fails the command.
These seven checks are not an exhaustive mutation campaign or a mutation score.

`summary.json`, pytest logs and JUnit XML record the seed, selected tests, exit
codes and original/mutated source hashes. The database workflow retains these
files as the `security-mutation-evidence` artifact for 14 days. A static matcher
test, an HTTP route test and a real SQL test establish different scopes; reports
must preserve that distinction.

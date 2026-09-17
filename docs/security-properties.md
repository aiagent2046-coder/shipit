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

All generated examples create their own mutable state. In particular, a pytest
function-scoped fixture is not mistaken for per-example database isolation.
Counterexamples are shrunk by Hypothesis. CVE and occurrence generation are derandomized for the
pinned Hypothesis version; auth/payment tests also use Hypothesis's normal
example database, ignored by Git. CI mutation controls use an explicit seed.

## Run the properties

Install the hash-locked development dependencies in a Python 3.12+ environment:

```bash
python -m pip install --require-hashes -r requirements-dev.txt
python -m pytest -q tests/test_authorization_properties.py tests/test_cve_properties.py tests/test_dependency_occurrence_properties.py
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
These five checks are not an exhaustive mutation campaign or a mutation score.

`summary.json`, pytest logs and JUnit XML record the seed, selected tests, exit
codes and original/mutated source hashes. The database workflow retains these
files as the `security-mutation-evidence` artifact for 14 days. A static matcher
test, an HTTP route test and a real SQL test establish different scopes; reports
must preserve that distinction.

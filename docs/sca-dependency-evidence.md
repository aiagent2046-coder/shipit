# Dependency evidence and SARIF

The integrated audit engine is `2026-09-10-5`. It combines the paid dependency
stage with the released harness-fixture classification and independent
environment keys for secret rewrites. The engine change invalidates older
content-cache entries; it does not reinterpret existing reports in place.

## Deployment

Apply migration `0039_audit_dependency_inventory.sql` before starting the new
API and audit workers. The release migration gate must report 39 migrations.
The migration adds a nullable inventory column and a partial index, with no
backfill; it is marked rollback-safe for older application releases.

For account-backed full audits, the service enables dependency lookups by
default. `SCA_ENABLED=0` disables service lookups, including refreshes. Free
audits and repository monitoring runs without account context do not initiate
dependency lookups. There is no persisted per-account opt-out setting.

The CLI requires an explicit `--sca` option. This per-run choice overrides
`SCA_ENABLED`; omitting the option sends no dependency query from the CLI.
Queries send resolved package ecosystems, names and versions to OSV. They do
not send the source archive. Current inventory inputs are `package-lock.json`,
exactly pinned entries in `requirements.txt`, and `poetry.lock`; unsupported or
incomplete inputs cannot establish a clean dependency inventory.

## Report contract

A dependency finding establishes that the queried version matches a known
advisory. It does not establish that an exploitable application path is
reachable. Findings are grouped by package, with explicit lookup dates,
coverage limits and skipped/unavailable states. Static scanning remains
offline; the SCA stage adds no model request.

Dependency answers become stale after seven days. The worker can query a
stored complete inventory again and create a new audit row; the original
report remains unchanged. An incomplete refresh or unavailable advisory
details preserve the earlier findings and their date. Paid cache reuse can
complete a missing dependency stage without repeating the model analysis.

## CLI export

```sh
python -m app.audit_cli archive.zip report.html --sarif report.sarif
python -m app.audit_cli archive.zip report.html --sca --sarif report.sarif
```

`--sarif` exports the same findings as SARIF 2.1.0. `--sarif-root` can remove an
explicit archive wrapper from reported paths; recognized GitHub commit-export
wrappers are handled automatically. Generated HTML and SARIF files receive
owner-only permissions, including when replacing an existing artifact.

The SARIF schema gate runs in `tests/test_sarif_export.py`. It checks structure
and the schema's `date-time`, `uri`, and `uri-reference` formats with
`jsonschema.FormatChecker`. Install the dev lock with
`pip install --require-hashes -r requirements-dev.txt`; the
`jsonschema[format-nongpl]` dev dependency supplies the optional format checkers.
A separate check fails when any format declared by the schema lacks a checker,
because `FormatChecker` otherwise silently accepts unsupported formats.

Control cases reject impossible calendar dates, missing time zones, and invalid
URIs, while accepting valid leap days and invocations without timestamps.
`startTimeUtc` and `endTimeUtc` are optional and the current exporter emits
neither. This is a test gate; the CLI does not validate exports against the
schema at runtime. Schema validation does not establish timestamp ordering or
guarantee acceptance by every consumer. Separate tests compare exported findings
with the audit results.

## Integration verification

The scanner version pin records `2026-09-10-5`. The integration checks cover
SCA parsing, incomplete OSV answers, refresh and paid-cache behavior, SARIF
schema validation, and the released harness-fixture and secret-allocation
regressions. Tests use fake OSV responses and do not make live advisory or
model requests. PostgreSQL migration and repository-write checks remain part
of the required `db-postgres-smoke` workflow.

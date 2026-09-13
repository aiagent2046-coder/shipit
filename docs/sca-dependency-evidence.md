# Dependency evidence and SARIF

The integrated audit engine is `2026-09-13-14`. It adds official CVE Program
record evidence to OSV package-version matches. The engine change invalidates older
content-cache entries; it does not reinterpret existing reports in place.

## Deployment

Apply migration `0039_audit_dependency_inventory.sql` before starting the new
API and audit workers. The release migration gate must report 39 migrations.
The migration adds a nullable inventory column and a partial index, with no
backfill; it is marked rollback-safe for older application releases. CVE
enrichment requires no additional migration or credential.

For account-backed full audits, the service enables dependency lookups by
default. `SCA_ENABLED=0` disables service lookups, including refreshes. Free
audits and repository monitoring runs without account context do not initiate
dependency lookups. There is no persisted per-account opt-out setting.

The CLI requires an explicit `--sca` option. This per-run choice overrides
`SCA_ENABLED`; omitting the option sends no dependency query from the CLI.
Queries send resolved package ecosystems, names and versions to OSV. They do
not send the source archive. Official CVE lookups send only CVE IDs from the
OSV answer. `CVE_ENABLED=0` disables this enrichment independently, including
CLI `--sca`, while preserving OSV checks. Current inventory inputs are `package-lock.json`,
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

## Official CVE records

The client uses the public [CVE Services GET /cve/{id} API](https://cveawg.mitre.org/api-docs/)
at `https://cveawg.mitre.org/api/cve/`. The [official catalogue](https://github.com/CVEProject/cvelistV5)
and [CVE Record Format](https://github.com/CVEProject/cve-schema/blob/main/schema/CVE_Record_Format.json)
document the source and schema. Records remain subject to the
[CVE Terms of Use](https://www.cve.org/Legal/TermsOfUse).

OSV identifies affected ecosystem/package/version tuples. CVE supplies the
official `PUBLISHED` or `REJECTED` state, CNA description (or rejection reason),
CWE IDs, publication/update dates and canonical CVE link. Only CNA fields are
consumed; ADP enrichment and CVSS scoring are outside this integration. A
rejected CVE still referenced by OSV is shown as a source disagreement; it
does not silently remove the package finding or lower its rating. A CVE record
does not prove runtime reachability, and no fuzzy product-name matching is used.

Each SCA invocation requests at most 20 unique validated CVE IDs, with a
3-second per-operation timeout, a 10-second cooperative lookup budget and a
1,000,000-byte response limit. The remaining budget limits each request timeout;
the budget is checked before requests and between body chunks. A blocking
network operation may finish after the deadline. HTTP 429 stops further
lookups. There are no retries, redirects, environment proxies or fallback
hosts. Record-format families 5.0, 5.1 and 5.2 (including patch versions) are
supported; unknown schemas are reported as unavailable. No complete database
download, authentication key, extra Python dependency or model call is needed.

`scan_manifest.sca_cve` records source, lookup time, coverage counts, normalized
records and fixed error reasons. HTML, web and SARIF retain this evidence.
Partial answers and rejection conflicts are visible separately from OSV
coverage. No CVE IDs in the available OSV answer means no CVE request, not a
search of the entire catalogue. A failed refresh that would lose previously
fetched CVE records preserves the older audit and its date. A paid cache hit can
retry missing CVE evidence without repeating the model review. Complete answers
follow the existing seven-day dependency refresh policy.

Free, static-only and browser scans do not instantiate the network client.
The browser bundle contains only the standard-library evidence normalizer.

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
`python -m venv .venv` followed by
`.venv/bin/python -m pip install --require-hashes -r requirements-dev.txt`; the
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

The scanner version pin records `2026-09-13-14`. The integration checks cover
SCA parsing, incomplete OSV answers, refresh and paid-cache behavior, SARIF
schema validation, and the released harness-fixture and secret-allocation
regressions, CVE API failure/size/time limits, rejected records, exports and
refresh/cache preservation. Tests use fake OSV and CVE responses and do not make live advisory or
model requests. PostgreSQL migration and repository-write checks remain part
of the required `db-postgres-smoke` workflow.

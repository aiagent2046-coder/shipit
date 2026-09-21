# Advisory-backed remediation cards

Drydock turns confirmed dependency/advisory matches into reusable upgrade review
plans without calling an LLM. The first catalog provides two recipes:

| Recipe | Scope | Suggested work |
| --- | --- | --- |
| `npm-dependency-upgrade`, revision 1 | Resolved npm packages | Review compatibility, update the dependency or its parent, regenerate the lockfile with the existing package manager. |
| `pypi-dependency-upgrade`, revision 1 | Resolved PyPI packages | Review Python/API compatibility, update the requirement or its parent, regenerate resolved requirements or the lockfile. |

Both recipes require another advisory scan and application build/regression
checks. They describe work to perform; the scanner does not perform that work.

## How a card is selected

1. The existing offline matcher resolves package identity and installed version,
   then emits a finding only when its advisory assessment is `affected`.
2. The planner collects newer versions from explicit OSV `fixed` events in
   reviewed GHSA records for that exact package. Supported range types are
   `ECOSYSTEM` for PyPI and `ECOSYSTEM` or `SEMVER` for npm.
3. Each candidate is checked against **every recorded advisory entry for the
   package**, including CVE records and advisories that do not affect the
   currently installed version. Every assessment must be `unaffected`, with
   zero unresolved ranges. Unknown applicability and conflicting sources block
   the candidate.
4. The finding receives a saved card with `candidates_available` or
   `manual_review`, its recipe, candidate versions, and reason codes. JSON,
   terminal output, and report evidence expose this plan.

CVE records participate in candidate rejection but do not supply candidate
releases in this version. Neither CVE `lessThan` nor OSV `last_affected` or
`limit` establishes an available fixed release. No next version is guessed,
and advisory titles are not interpreted as repair instructions.

A candidate clears the recorded package advisories in that snapshot. It is
not a claim that the package or application is safe: the snapshot can omit
advisories, and compatibility, feature reachability, and runtime behavior have
not been assessed. The card always records `automatic_apply: false`,
`runtime_verified: false`, and `compatibility: not_assessed`.

## Evidence and limits

Cards bind to ecosystem, package, installed version, pinned source metadata,
and SHA-256 digests of the source metadata and package records. The recipe and
catalog versions are saved with the finding. Rendering validates that binding
against the finding's source metadata; it does not recompute an old plan using
the latest catalog. The digests identify the evidence; they are not signatures.

When a refreshed scan retains an older finding without reconfirming it, its
previous candidate advice is not presented as a current upgrade recommendation.
Malformed cards cannot prevent the original finding from rendering.

| Bound | Limit |
| --- | --- |
| Advisory entries considered per package | 256 |
| Distinct candidate release strings per card | 16 |
| Range/event discovery items per card | 4,096 |
| Candidate/advisory evaluations shared by an archive scan | 4,096 |

Exceeding a bound produces a manual-review outcome for the affected card.
Exhausting the evaluation budget clears a partially computed candidate list;
it does not erase the scanner's dependency findings. Missing fixed-release
evidence and unsupported versions also remain explicit manual-review outcomes.

## Examples from the bundled snapshot

These examples are tied to the snapshot generated on 2026-09-17 and are covered
by regression tests. They are not recommendations for the latest package release.

| Package and installed version | Candidate | Why |
| --- | --- | --- |
| npm `@apollo/server` 4.7.2 | 5.5.0 | 4.7.4 fixes the nonce advisory, but does not clear the other recorded advisories. Of the recorded fixed boundaries, only 5.5.0 clears all five package entries. |
| PyPI `adyen` 7.0.0 | 7.1.0 | The reviewed timing-attack advisory explicitly records 7.1.0 as fixed; it clears the package's recorded advisory. |

In particular, the Apollo candidate crosses a major version. Application
compatibility and migration work remain to be reviewed by the developer.

## Inspect cards

Use the existing CLI documented in [Local Drydock](local-drydock.md):

```bash
drydock-local scan /absolute/path/to/project --json
```

Inspect the two shared recipes without scanning a project:

```bash
drydock-local recipes --json
```

For a source checkout, the equivalent command is:

```bash
python -m app.local_cli scan /absolute/path/to/project --json
```

Dependency findings store their card at
`findings[].claim_evidence.remediation`. A project without an affected dependency
finding does not receive an upgrade card. When redirecting JSON, save it outside
the scanned project. `drydock-local patterns` remains the separate source-code
pattern catalog; it does not list these dependency plans.

## Verification and next scope

```bash
pytest -q tests/test_remediation_catalog.py tests/test_remediation_reporting.py
```

The tests cover overlapping and reintroduced vulnerabilities, CVE/GHSA
disagreement, unknown ranges, missing fixed boundaries, exhausted budgets,
source bindings, retained reports, and the bundled examples above.

Automatic source-code recipe extraction from CWE classifications, patch
references, or before/after code is **not implemented**. The existing Python
SQL/Psycopg pilot remains in its separate pattern catalog and evidence workflow;
dependency cards do not authorize its repairs. Future reviewed source-code
recipes will need their own applicability evidence and reproducible checks.

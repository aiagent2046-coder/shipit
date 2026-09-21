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

### Real package-manager contracts

Two repository-owned consumer fixtures now exercise the installation part of
the recipes. Run them explicitly on Linux with Python 3.12, Node 24 and npm 11,
from an environment containing the locked scanner dependencies:

```bash
python -m pip install --require-hashes -r requirements.txt
python scripts/verify_dependency_remediation.py --case npm --output-dir /tmp/drydock-npm-contract
python scripts/verify_dependency_remediation.py --case pypi --output-dir /tmp/drydock-pypi-contract
```

Each output directory must be new. The commands download public registry
packages into disposable environments and preserve JSON evidence, resolved
manifests and command logs. They do not take a customer project, arbitrary
package, command, or version as input. Exit codes are `0` passed, `1` failed,
and `2` unavailable; unavailable is not a successful or skipped check.

| Fixture | Before → candidate → restored | Independent consumer |
| --- | --- | --- |
| npm picomatch | 2.3.0 → 2.3.2 → 2.3.0 | Nine Rollup pluginutils filter assertions |
| PyPI sqlparse | 0.5.5 → 0.6.0 → 0.5.5 | Four Django/SQL assertions and a Python-snippet escaping regression |

The current planner must offer the selected candidate. npm regenerates its
lockfile and installs it with lifecycle scripts disabled. pip installs exact,
hashed wheels into a fresh environment for every stage, checks dependencies,
and generates resolved requirements from that actual installation. Each probe
reports the package loaded by the real consumer. The runner compares installed
and resolved versions, requires a complete target assessment, rejects any
unknown or unresolved target advisory, and requires every recorded target entry
to be unaffected after the update. The original manifests, findings and inventory
must return in the last stage; other package versions cannot silently change.

The `dependency-remediation-contract` workflow runs both fixtures on pull
requests, main pushes and manual dispatch, and uploads evidence even on failure.
The normal offline pytest suite checks false-success boundaries without registry
access. Branch-protection settings are not changed by this workflow.

`fixture_verified` is limited to these fixtures. `runtime_verified`,
`customer_project_verified` and `automatic_patch` remain false; ordinary cards
are not promoted to runtime evidence. The npm probe does not reproduce ReDoS.
The PyPI probe verifies one escaping fix without executing generated code; it
does not establish that the Django application can reach the advisory's code
execution scenario. These smaller fixtures do not repeat the earlier full
Svelte build or Django HTTP/ORM experiment. See the
[fixture provenance and exact scope](../tests/fixtures/dependency-remediation/README.md).

Automatic source-code recipe extraction from CWE classifications, patch
references, or before/after code is **not implemented**. The existing Python
SQL/Psycopg pilot remains in its separate pattern catalog and evidence workflow;
dependency cards do not authorize its repairs. Future reviewed source-code
recipes will need their own applicability evidence and reproducible checks.

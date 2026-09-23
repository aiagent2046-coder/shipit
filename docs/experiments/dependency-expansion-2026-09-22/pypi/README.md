# PyPI remediation expansion: VTEX / Requests

The bounded dependency experiment passed. This is not a clean-project verdict or a verified exploit against the VTEX service.

- Project: https://github.com/lmeilibr/vtex
- Reviewed and executed source: `c957049c51b7e070e6c91f6212ade5216f7343cb`.
- Original dependency file: `requirements.txt`, with `pytest==7.4.0` and `requests==2.31.0`.
- Drydock scanner: `0b5c981412ad0a9ab62ad4a7a6da1b90a0acd67b`.
- Catalog SHA-256: `e8cc8c6a60e29331c42f0c50bbdb57484766b947d377afc966c723ec7b3347af`.
- Tracked source digest (SHA-256 of sorted file-to-SHA-256 JSON): `3d6e44383cb24b4e32ff8cb566675ffabb6c155fdbdedb69b0338eb4c70d1570`.
- Environment: CPython 3.12.14, uv 0.12.15, Linux.

| Stage | Installed Requests | Target findings | Upstream smoke tests | Added consumer checks | Synthetic netrc credential misbinding |
| --- | --- | --- | --- | --- | --- |
| Before | 2.31.0 | 3 | 2 passed | 7 passed | Reproduced |
| After | 2.33.0 | 0 | 2 passed | 7 passed | Blocked |
| Restore | 2.31.0 | 3 | 2 passed | 7 passed | Reproduced |

The three findings correspond to CVE-2024-47081 / GHSA-9hjg-9r4m-mvj7, CVE-2024-35195 / GHSA-9wx4-h78v-vm56, and CVE-2026-25645 / GHSA-gc5v-m9x4-r6x2. The card's actual candidate list contains `2.33.0`. The after scan evaluates all eight Requests advisory entries as `unaffected`, with zero unresolved target ranges. The lower individual advisory fix version is not substituted for the all-advisories candidate.

The original and restored requirements files and installed inventories match. The source is restored to the pinned commit. The only installed dependency change is Requests. The nine-package inventory is recorded for every stage; the other eight packages remain identical. `uv pip check` passes on all three environments, and imported Requests resolves inside its stage environment.

## What was exercised

The repository's own unit suite consists of two import tests. These are smoke evidence, not sufficient compatibility evidence on their own. The additional offline probe instantiates the actual `Vtex` client and a real `requests.Session`, with a custom in-memory `BaseAdapter`. Requests constructs actual `PreparedRequest` objects. Seven checks cover product GET URL, authentication/content headers, configured timeout forwarding, success JSON and pagination-token decoding, pagination query parameters, 404 mapping, and timeout propagation.

A separate dependency-level regression prepares a request with an adversarial userinfo/hostname combination and synthetic `.netrc` credentials. Requests 2.31.0 incorrectly attaches the trusted host's credentials; 2.33.0 does not. The normal-host control still attaches the intended credentials. No request is sent and no real credential is accessed. Both `socket.socket` and `socket.create_connection` are blocked in the probe. This confirms the library behavior associated with CVE-2024-47081; application exploitability was not established.

Primary upstream references:

- https://github.com/psf/requests/security/advisories/GHSA-9hjg-9r4m-mvj7
- https://github.com/psf/requests/pull/6965
- https://github.com/lmeilibr/vtex/blob/c957049c51b7e070e6c91f6212ade5216f7343cb/tests/unit_tests/test_imports.py
- https://github.com/lmeilibr/vtex/blob/c957049c51b7e070e6c91f6212ade5216f7343cb/requirements.txt

## Limits retained in the evidence

- Live VTEX integration tests require a real account and were not run. No live store is contacted.
- The manifest scan remains `partial`: pytest has an unresolved advisory assessment (CVE-2025-71176 / GHSA-6w46-j5rx-g56g) from incomplete advisory-source agreement. This is not reclassified as safe and is not fixed by this experiment.
- The project did not supply a full transitive lock. The exact nine-package environment used here is experiment-specific and saved in `environment-before.txt`. No unrelated package upgrades are attributed to the Requests fix.
- The dependency scan covers the source requirements file. It does not claim whole-repository, transitive vulnerability, or source-code coverage.
- Only the netrc advisory is dynamically exercised. The other two target vulnerabilities are checked by catalog/version assessment.
- The candidate was applied by the experiment runner in a disposable checkout. This is not an automatic patch feature in Drydock; scanner cards remain `automatic_apply=false` and `runtime_verified=false`.

## Reproduce

Use a scanner checkout at the exact scanner commit above, with its Python dependencies installed. Clone the public project into a separate directory, then select the pinned project commit:

```bash
git clone https://github.com/lmeilibr/vtex.git /tmp/vtex-card-example
git -C /tmp/vtex-card-example checkout --detach c957049c51b7e070e6c91f6212ade5216f7343cb
/path/to/scanner/.venv/bin/python run_experiment.py \
  --scanner /path/to/scanner \
  --project /tmp/vtex-card-example \
  --output /tmp/vtex-card-evidence-new
```

Keep `probe.py`, `source_guards.py` and `environment-before.txt` next to `run_experiment.py`. Output must not exist. Installation uses registry wheels only, no project build hook or setup script. Before importing scanner or project code, the runner verifies both checkout commits and rejects modified tracked scanner files under `app/` or `scripts/`. It then exports committed Git blobs into new `output/project` and `output/scanner` directories. Untracked or ignored files (including `conftest.py`, shadow modules and bytecode) cannot enter these snapshots; project working-tree changes are excluded and the supplied checkout is never modified. Symlinks and submodules are rejected. The runner verifies the catalog digest, the installed version and import origin, card candidate membership, complete target assessments, unchanged unrelated dependency inventory, and restoration. Each stage has a 180-second subprocess timeout.

Before execution, the pinned project's setup file, unit tests, Vtex/BaseApi code, imported API modules and relevant integration fixtures were inspected. Source is imported directly; `setup.py`, project install hooks and live integration scripts are not executed. Installation receives a filtered environment with an isolated home; automatic pytest plugin discovery is disabled.

The initial three-stage run is retained. The subsequent source-vs-Git, package-origin and `uv pip check` checks were read-only checks against those completed environments; the experiment was not rerun merely to regenerate logs. The checked-in runner also enforces those checks on future executions.

Evidence includes full scan JSON, stage inventories, source hashes, consumer probe JSON, upstream pytest JUnit XML and logs, and installation/check logs. Venv directories and the upstream clone are not report artifacts.

Offline guard regressions cover untracked pytest hooks, ignored/import-shadowing inputs, modified staged and unstaged scanner code, revision mismatch and symlink rejection. They require no registry installs.

The final runner and probe received guard and formatting refinements after that initial execution; they are not presented as byte-for-byte copies of the initially executed scripts. Ruff passes using the scanner repository configuration.

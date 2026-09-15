# Local Drydock — first release

Scan a selected project directory with the shipped static engine and local
CVE/GHSA snapshot. Scan, watch and history do not send network requests, use an
LLM, load server credentials, install project dependencies, or run project code.
Only the explicit `update` command downloads a public catalog.

This release supports Linux/macOS with Python 3.12+ (Windows: WSL). The
standalone distribution is named `drydock-local`; it contains four runtime
dependencies (PyYAML, tree-sitter, tree-sitter-typescript and pglast), the shared
detectors and the CVE/GHSA snapshot. It does not install Shipit's server stack.

## Install a reviewed build

The `local-package` GitHub Actions workflow produces an install bundle for each
tested OS/architecture/Python combination. Open a successful run on the reviewed
commit, download its `drydock-local-...` artifact and extract it. These are CI
artifacts with retention limits, not a published PyPI package or permanent release
channel. Do not install an unrelated package from PyPI by guessing the name.

Choose the bundle matching your OS, CPU architecture and Python minor version.
The first CI matrix covers Linux x86_64 and macOS arm64 with Python 3.12.
Windows users can use the Linux bundle inside matching WSL. Python must already
be installed with `venv` support (on distributions that separate it, install the
matching Python venv package first).

From the extracted bundle, run:

```bash
bash install.sh
"$HOME/.local/share/drydock/venv/bin/drydock-local" scan /absolute/path/to/project
```

`install.sh` creates a private application virtual environment and installs
only the included wheels, using `--no-index --require-hashes`. Internet is needed
to obtain the bundle, but neither installation from a complete matching bundle
nor scanning needs it. No compiler, API keys, Postgres, Redis or Ollama is needed.
Use `PYTHON=/path/to/python3.12 bash install.sh /new/venv/path` to choose Python
or the installation directory. The installer refuses an existing destination;
for an upgrade, install in a new directory and switch the command you use after
checking it. Scan history stays in the independent state directory.

The wheel itself is platform-independent Python code; its bundled native
parser dependencies are specific to the target platform. Other Python versions
need their own wheel bundle and validation. The package uses `drydock_local`
internally and does not install a generic `app` namespace. Use a separate venv
from Shipit, since both distributions offer the `drydock-local` command.

To type the short command in the examples below, activate the installed venv:

```bash
. "$HOME/.local/share/drydock/venv/bin/activate"
drydock-local --help
```

## Build from source (maintainers)

From a reviewed Shipit checkout, create a build environment and stage the source:

```bash
python3.12 -m venv /tmp/drydock-build-env
. /tmp/drydock-build-env/bin/activate
python scripts/build_local_package.py --out /tmp/drydock-bootstrap --stage-only
python -m pip install --require-hashes -r /tmp/drydock-bootstrap/build-requirements.txt
python scripts/build_local_package.py --out dist/local-bundle --wheelhouse
```

Each output directory must be new. Build-only setuptools and the four runtime
pins/hashes come from the reviewed `requirements.txt`. `--wheelhouse` downloads
binary dependencies for the current platform; without it, only the Drydock wheel
is built and the directory is not a complete offline installer.

The build stages only the offline import closure from `app`, rewrites internal
import sites into `drydock_local`, and builds through standard setuptools.
Evidence strings and the pinned update URL are preserved. New server imports or
external dependencies fail the build instead of silently expanding this package.
`build-info.json` records the source revision, dirty-checkout flag, original
module hashes, engine version, catalog digest and runtime pins. A separate source
archive can be rebuilt without the original Git checkout. Package version and
engine version are separate: packaging changes do not claim new detector logic.

The same build identity is installed at
`drydock_local/build-info.json`. Source hashes and wheel hashes are provenance
and integrity records, not digital signatures. Public release publication and
signed automatic updates are separate steps.

The original developer checkout also continues to support
`python -m app.local_cli`; the standalone wheel supports
`python -m drydock_local.local_cli`. Both use the same engine and state format.

## Scan, watch, history

```bash
drydock-local scan /absolute/path/to/project --json
drydock-local scan /absolute/path/to/project --fail-on high
drydock-local watch /absolute/path/to/project --interval 10
drydock-local history /absolute/path/to/project
```

`--json` prints the full structured report; watch emits one JSON object per scan
with `--json`. Redirect reports outside the project to avoid observing the output
as a new source change. Reports can contain project paths and finding evidence;
protect exported files appropriately. Default text output shows the first 20
findings, dependency coverage, folder exclusions, catalog age and limitations.

The watcher reads and hashes included file contents once per interval and skips
the expensive scan when unchanged. A changed directory snapshot, catalog digest,
engine version, or UTC day triggers a full scan of the selected scope. It does
not yet scan only changed files: cross-file rules need project context. A failed
poll prints an error and retries without accepting a new baseline. Ctrl-C stops
the foreground watcher. No background service is installed automatically.

Each result lists new and no-longer-reported finding identities. First scan is a
baseline. Disappearance is not proof of a fix: deleting files, losing coverage,
or changing the catalog can remove a finding. The result explicitly indicates
whether engine/catalog versions are comparable. Identities include rule, file,
line and advisory/package identity; moving a finding to another line can count
as a new finding in this first version.

State defaults to `$XDG_STATE_HOME/drydock`, or `~/.local/state/drydock`. Override
it before the subcommand:

```bash
drydock-local --state-dir /private/path/drydock-state scan /path/to/project
```

The directory must be private (0700); new directories are created accordingly.
The SQLite file is 0600. History keeps the latest 100 summaries per project,
including timestamps, engine/catalog versions and finding hashes, without
storing source bodies or complete finding text. Projects are isolated by
resolved absolute path. A state directory inside a project is excluded from its
snapshot; a project inside the state directory is rejected.

## Explicit catalog updates

```bash
drydock-local update --revision FULL_40_CHARACTER_SHIPIT_COMMIT_SHA
```

Choose the full SHA of a reviewed release containing the desired catalog.
The command downloads only `app/data/cve-catalog.json` and its SHA-256 sidecar
from that exact revision in `aiagent2046-coder/shipit`, over HTTPS. It checks
size, checksum, schema and source provenance before atomically activating the
new snapshot. Invalid/interrupted downloads retain the active database. A
corrupt active snapshot fails explicitly; scan does not silently fall back to
an older bundled catalog. To return to an earlier snapshot, explicitly update
from that earlier reviewed commit.

The checksum detects corruption; it is **not a digital signature**. Trust comes
from the operator-selected commit and HTTPS to the official repository. This
version has no automatic latest-revision selection or background downloader.
Signed update metadata and automatic scheduling are later milestones.

Catalog freshness uses the upstream source timestamps, not download time. The
report flags a source older than seven days and includes each source commit.
Downloading the same old snapshot does not make it fresh. The bundled snapshot
contains both CVE and GitHub-reviewed GHSA records; exact coverage depends on the
installed revision and is included in each report.

## Scope and exit codes

The snapshot excludes `.git`, `node_modules`, `.venv`, `venv`, `__pycache__` and
`.drydock` directories, the selected state directory, symlinks and special files.
Exclusions are counted. `.gitignore` is not applied: ignored configuration and
`.env` files remain relevant. The shared scanner's further production-path,
file-type, size, syntax and analysis exclusions remain in `rule_coverage` and
`coverage`. No source file is rewritten or deleted.

The folder snapshot is bounded to 20,000 regular files / 40 MB of input and
50,000 observed entries. Unreadable files, read failures and budget overflow
fail explicitly. File reads check for concurrent modification, but a folder
snapshot is not a filesystem transaction. Large repositories can be scanned by
selected subproject; doing so establishes only that subproject's coverage.

Supported resumable rules continue through the shared `ScanSession` API, with
a bound of 128 continuation batches. Remaining skips and unavailable checks
are reported, including missing native parsers. No numeric safety score is
shown. Dependency matches establish affected package versions, **not runtime
reachability**. Unlisted packages, unsupported version forms and incomplete
lockfiles remain unknown/partial. No findings never establishes global safety.

| Exit | Meaning for `scan` |
| --- | --- |
| 0 | Execution completed within reported scope; no selected severity gate triggered. Not a safety certificate. |
| 1 | A finding meets `--fail-on` (default `none`). |
| 2 | Input/catalog failure, unavailable check, rule analysis skip, dependency inventory failure or truncation. |
| 130 | Interrupted by the user. |

Runtime tests, model explanations, automatic fixes, GUI, service installation,
signatures and native Windows packaging are outside this first PR. These can
build on the local report/history contract after reviewing the offline core.

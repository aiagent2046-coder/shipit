# Local Drydock — first release

Scan a selected project directory with the shipped static engine and local
CVE/GHSA snapshot. Scan, watch and history do not send network requests, use an
LLM, load server credentials, install project dependencies, or run project code.
Only the explicit `update` command downloads a public catalog.

This first release supports Linux/macOS with Python 3.12+ (Windows: WSL).
Install from a reviewed Shipit checkout; this is not a published PyPI package:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements.txt
python -m pip install --no-deps -e .
drydock-local scan /absolute/path/to/project
```

Installation needs network access to fetch Python packages. Subsequent checks
use the included catalog and need no API keys, Postgres, Redis or Ollama service.
The package currently includes server dependencies; a smaller standalone
distribution is a later packaging step. `python -m app.local_cli` is equivalent
to `drydock-local` from the checkout.

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

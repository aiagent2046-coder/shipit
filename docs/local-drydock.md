# Local Drydock — first release

Scan a selected project directory with the shipped static engine and local
CVE/GHSA snapshot. Scan, watch and history do not send network requests, use an
LLM, load server credentials, install project dependencies, or run project code.
Only the explicit `update` command downloads a public catalog.

The [deterministic pattern review](deterministic-security-agent.md) classifies
selected Python observations using bundled, versioned CWE cards. Inspect them
with `drydock-local patterns` or `drydock-local patterns --json`. Scan reports
include the card catalog identity, source evidence, missing prerequisites and
the next review step. Supported FastAPI/Psycopg SQL investigations collect
missing source facts and record their actions and stop reason. This stage makes
no model calls and applies no patches.

This release supports Linux/macOS with Python 3.12+ (Windows: WSL). The
standalone distribution is named `drydock-local`; it contains four runtime
dependencies (PyYAML, tree-sitter, tree-sitter-typescript and pglast), the shared
detectors and the CVE/GHSA snapshot. It does not install Shipit's server stack.

## Install a reviewed build

Permanent installation archives are published in
[GitHub Releases](https://github.com/aiagent2046-coder/shipit/releases) after the
`release-local` workflow verifies both platforms. Use a release that actually
lists the installation assets; creating a Git tag alone does not publish them.
A typical name is `drydock-local-v2026.09.16-1-linux-x86_64-py3.12.tar.gz`, with
a matching `.tar.gz.sha256` file. Download both files for the selected platform.
There is no published PyPI package: do not guess the package name on PyPI.

In the download directory, verify before extracting (substitute the selected
release tag):

```bash
bundle=drydock-local-v2026.09.16-1-linux-x86_64-py3.12
sha256sum -c "$bundle.tar.gz.sha256"
tar -xzf "$bundle.tar.gz"
cd "$bundle"
```

On macOS use the `macos-arm64` bundle and `shasum -a 256 -c` instead of
`sha256sum -c`. Checksums detect corruption, not publisher identity; obtain both
files from the official release. A failed checksum means do not extract/install.

Successful `local-package` Actions runs also keep the unpacked install bundles
for 30 days for review/pilots. Those temporary artifacts have names such as
`drydock-local-Linux-X64-py3.12`; extract the downloaded ZIP before running
`install.sh`. Permanent release archives additionally get tested *after*
checksumming and extraction, using their own included installer and wheels.

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

`local/pyproject.toml.in` is a build template, not a standalone Python project.
Staging writes it as `source/pyproject.toml` alongside the package sources,
`dependencies.txt` and a hash-locked `requirements.txt`. The four runtime pins
come from the root lockfile, which also covers them when scanning this repository.

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
and integrity records, not digital signatures. Signed automatic catalog updates
are a separate milestone.

The original developer checkout also continues to support
`python -m app.local_cli`; the standalone wheel supports
`python -m drydock_local.local_cli`. Both use the same engine and state format.

## Publish installation archives (maintainers)

After this workflow is merged to `main`, an existing reviewed production tag can
be packaged without a new server deployment:

```bash
gh workflow run release-local.yml --repo aiagent2046-coder/shipit \
  --ref main -f tag=v2026.09.16-1
```

The manual workflow only runs from `main`. It resolves the existing tag, requires
its commit to be on `main`, and builds that exact SHA using the same Linux/macOS
acceptance workflow as pull requests. The release archiver comes from the
workflow revision, so tags created before publication tooling existed can still
be packaged. The engine and bundled catalog come from the selected tag.

Both archives must pass fresh offline installation, source parity, scan/watch/
history and source-archive rebuild checks. Only the final publish job gets
`contents: write`. It rechecks tag identity, verifies both archive checksums,
creates a draft with all four assets, then publishes it. No deployment is
triggered. Existing releases/assets are not overwritten. If upload fails, inspect
the remaining draft before retrying; this workflow intentionally does not delete
or replace it automatically. A build failure creates no release.

GitHub CLI publication behavior:
[release create](https://cli.github.com/manual/gh_release_create) and
[release edit](https://cli.github.com/manual/gh_release_edit).

## Ubuntu pilot using the deployed build

The first pilot uses the verified Linux x86_64 / Python 3.12 artifact from
[run 34969279185](https://github.com/aiagent2046-coder/shipit/actions/runs/34969279185),
source `338adce5e1ab2f8233807a252014d2a7eca69a69` (`v2026.09.16-1`).
Until the permanent release is published, download it with an authenticated `gh`:

```bash
pilot_dir="$(mktemp -d "$HOME/drydock-pilot.XXXXXX")"
printf 'Pilot directory: %s\n' "$pilot_dir"
gh run download 34969279185 --repo aiagent2046-coder/shipit \
  --name drydock-local-Linux-X64-py3.12 --dir "$pilot_dir"
PYTHON=python3.12 bash "$pilot_dir/install.sh" "$pilot_dir/venv"
"$pilot_dir/venv/bin/drydock-local" --help
"$pilot_dir/venv/bin/drydock-local" scan "$HOME/shipit"
"$pilot_dir/venv/bin/drydock-local" history "$HOME/shipit"
```

Run these on the workstation where the project lives. Use an existing project
path if it differs from `~/shipit`. Python 3.12 and its venv support must already
be installed; Ubuntu 24.04 x86_64 is the Linux CI baseline. Keep the printed
`pilot_dir` path to run the same installation again. A scan exit 2 means an
execution or inventory gap (for example, a missing lockfile), or a processing
problem. Partial advisory coverage alone can still exit 0; see the exit-code
table below. Inspect the report rather than treating it as an installation
failure or a clean project.

For the pilot record elapsed scan time, finding usefulness, skipped checks and
whether the report is understandable. Disconnect the network and repeat scan
and history; compare engine/catalog identities. Start `watch` in the foreground,
make an ordinary source edit and confirm that one new scan appears; stop with
Ctrl-C. Reports and source stay on the workstation. Share a redacted summary,
not source files or secrets. Do not run `update` during the offline check.

## Scan, watch, history

```bash
drydock-local scan /absolute/path/to/project --json
drydock-local scan /absolute/path/to/project --fail-on high
drydock-local scan /absolute/path/to/project --show-contextual
drydock-local watch /absolute/path/to/project --interval 10
drydock-local history /absolute/path/to/project
```

`--json` prints the full structured report; watch emits one JSON object per scan
with `--json`. Redirect reports outside the project to avoid observing the output
as a new source change. Reports can contain project paths and finding evidence;
protect exported files appropriately. Default text output shows up to 20
priority review tasks in descending severity, with a short explanation and next
action. Missing context is labeled `unknown`, not assumed to be production use.
High/critical findings remain visible in this section even in tests and examples:
a real credential there still matters. Lower-severity findings with known
test/example/comment context and optional Dockerfile hygiene are grouped into
a secondary summary by context and severity. `--show-contextual` expands up to
20 of these findings; omitted counts point to the complete `--json` report.
The option works for both scan and watch.

Dependency findings with the same ecosystem, package, installed version and
manifest are presented as one review task; distinct packages, versions and
manifests remain separate. The task shows advisory IDs, linked advisories and
their matched version ranges, along with known development/runtime scope,
directness and dependency groups. Unknown scope stays explicit. Development
dependencies can affect builds and CI; the label does not suppress their
severity. Range boundaries, including OSV `fixed` events, belong to individual
advisories and do not establish a universally safe upgrade. Long text, advisory
lists and ranges are bounded with truncation notices; `--json` contains all
finding evidence.

These are presentation changes only: findings, severities, identities, history
and `--fail-on` are unchanged by grouping or `--show-contextual`. Counts by
severity describe all findings, not grouped tasks. `--json` retains all findings
in their original order, including contextual findings and every advisory ID.

Dependency coverage includes unknown-reason counts and a few examples, with
per-source assessments in `--json`. `affected`, `unaffected` and `unknown` count
assessment outcomes (normally an advisory group per dependency entry), not
distinct packages; `not_in_catalog` counts dependency entries absent from the
snapshot. Unknown means the supported comparison could not establish a verdict.
It must not be treated as an affected package or as proof of safety.
`incomplete_advisory_sources` means at least one source could not be evaluated;
it does not claim that sources disagree about affected versus unaffected.
Raw reason codes and the individual source assessments remain in JSON.

The shared matcher supports numeric PyPI releases and canonical `aN`, `bN`,
`rcN` prereleases, such as the `5.1b7` boundary in the PyYAML advisory. Epochs,
post/dev/local versions and other spellings remain unsupported. CVE range lower
bound `"0"` denotes the earliest version, including prereleases before `0.0.0`;
other incomplete npm versions such as `13.0` remain unknown. These comparisons
preserve the source ranges and do not override disagreement between CVE and GHSA.

Missing lockfiles remain coverage gaps. For example, a `pyproject.toml` that
declares dynamic dependencies without a neighboring supported lockfile reports
`dynamic_dependencies_without_lock`. The scanner does not execute the build to
guess the dependencies. Other reasons identify unsupported formats, malformed
metadata and inventory limits.

Dependency manifests under an exact `.next` directory component are generated
Next.js output, so they are excluded from dependency inventory and listed as
`generated_next_build`. This includes `.next/package.json` without a lockfile.
Ordinary `build` and `dist` directories and similarly named source directories
are not excluded by this rule. Source/secret scanners keep their existing
policies (the secret scanner already excludes `.next`); this inventory rule does
not apply `.gitignore` or remove source files from the local snapshot. Exclusion
details and coverage examples are bounded and report omitted counts.

Text output also includes folder exclusions, catalog age and coverage limitations.
Static Supabase RLS checks apply to SQL in explicit Supabase project paths. A
generic SQL file, SQLite tutorial or ordinary PostgreSQL schema is not evidence
that Supabase publicly exposes its tables. These source checks do not verify a
live database's grants or applied policies.

The watcher reads and hashes included file contents once per interval and skips
the expensive scan when unchanged. A changed directory snapshot, catalog digest,
engine version, or UTC day triggers a full scan of the selected scope. It does
not yet scan only changed files: cross-file rules need project context. A failed
poll prints an error and retries without accepting a new baseline. Ctrl-C stops
the foreground watcher. No background service is installed automatically.

Each result lists new and no-longer-reported finding identities. First scan is a
baseline (shown as `baseline recorded`, rather than new regressions).
Disappearance is not proof of a fix: deleting files, losing coverage,
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
| 2 | Input/catalog failure, unavailable check, rule analysis skip, incomplete dependency manifest/lockfile, or inventory/findings/evaluation truncation. |
| 130 | Interrupted by the user. |

`dependency_cve.status = partial` is broader than exit 2. Unknown assessments,
packages absent from the catalog and advisory-source uncertainty alone do not
trigger exit 2. With the default `--fail-on none`, even confirmed version matches
can exit 0 when execution and dependency inventory completed. A missing
supported lockfile (including for a project with dynamic dependencies) does trigger exit 2,
which takes precedence over the selected severity gate.

Runtime tests, model explanations, automatic fixes, GUI, service installation,
signatures and native Windows packaging are outside this first PR. These can
build on the local report/history contract after reviewing the offline core.

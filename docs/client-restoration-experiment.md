# Controlled client restoration experiment

Run from a source checkout with Python 3.12+, Linux, Docker Engine and Compose
v2/BuildKit. This command is explicitly opt-in and executes the supported client
application in disposable Docker services. Ordinary browser, CLI and server
scans never invoke it.

```bash
python scripts/run_client_experiment.py "$HOME/Загрузки/cumora-main.zip" \
  --output "$HOME/cumora-cycle-$(date -u +%Y%m%dT%H%M%SZ)"
```

Only archive SHA-256
`dce64bacef7ffcc5f801d50447f035bd67ec14829a97a79401bb0d0a397e226d`
is supported. No client source archive is shipped in this repository.
The original archive is never modified. An existing output directory is refused.

The coordinator invokes separate detector, researcher, experimenter and verifier
processes with file handoffs. No stage requests an LLM:

1. Detector checks the pinned archive and Express/PostgreSQL route signatures.
2. Researcher rechecks detection, extracts filtered source copies, changes exactly
   one GET /projects tenant predicate, then restores it in a copy of the mutant.
   The complete restored source tree must equal the baseline tree.
3. Experimenter builds and runs baseline, mutant and restored separately, each
   with a fresh PostgreSQL/Redis environment and run UUID. Before building, it
   rechecks the complete prepared source manifest against the plan. Inside the
   running container it checks every prepared source file again; generated build
   output and installed dependencies are outside that source manifest. It runs
   the same scenario without an expected-outcome argument. Before each scenario
   it clears demo projects in that disposable database only.
4. Verifier recomputes expected API/database observations, checks receipt and
   source bindings, and rejects incomplete cleanup or infrastructure errors.
   Baseline and restored use the same bounded validator as the evidence importer.

A passing cycle requires 12 passing baseline checks, the specific cross-tenant
project disclosure at mutant check 7, and 12 passing restored checks. A random
failure, timeout or merely a nonzero process exit does not prove detection.
Each experimenter exits 0 when it has collected usable observations, including
the expected failing mutant scenario. The final verdict is `experiment.json`;
`cycle_status: passed` and `exit-code.txt: 0` identify a successful cycle.
The coordinator prints each stage's log path and timeout. During a long build,
the variant's `build.log` and `<variant>-experimenter.log` show progress; image
downloads and the first npm installation can take several minutes.

## Preparation without execution

```bash
python scripts/run_client_experiment.py "$HOME/Загрузки/cumora-main.zip" \
  --prepare-only --output "$HOME/cumora-cycle-prepared"
```

This checks source selection and restoration without Docker or client execution.
Prepared trees remain in the output directory. Preparation does not assert
runtime success and cannot replace the full cycle.

## Boundaries and recovery

Downloads of Docker images and npm packages require network access. npm install
uses `--ignore-scripts`; the project build runs without network. Runtime uses an
internal Docker network, no published ports, no host bind mounts, disposable
credentials and a non-root, read-only application container. Dotenv files,
Git metadata and node_modules are excluded from extraction. Model functions are
not used by the scenario; runtime provider access is unavailable.

Docker image tags and registry availability remain external dependencies.
The command records application image IDs, observed router hashes and the
verified prepared-source manifest hash; it does
not claim byte-identical image builds across machines or dates. Use a dedicated
Docker host for this explicit application execution experiment.

Interruptions stop subsequent variants and trigger targeted cleanup. Failed
cleanup preserves the working Compose files and reports an unavailable result;
inspect the printed directory and cleanup logs before rerunning. Forced host
termination, SIGKILL or a Docker daemon failure may still require manual cleanup.

The result is host-side evidence consistency, not signed execution attestation.
The known inverse mutation is controlled restoration, not autonomous repair of
unknown vulnerabilities. Whole-project verification, vulnerability remediation
and automatic patch flags remain false.

To attach successful baseline evidence to a regular report, explicitly use
[the runtime importer](client-runtime-evidence.md) with that variant's
scenario.json and run-id.txt. A failing mutant is never imported as success.
This command is source-checkout tooling; the local installation bundles do not
install the scripts directory.

## Validation

The preceding standalone harness completed the three-variant Docker cycle on
the operator's machine. The integrated command has separate regression checks
for receipt rejection, source preparation, timeout and cancellation behavior.
Local tests with constructed receipts are not a new Docker execution result.
The integrated preparation command has also been checked against the pinned
archive: the restored tree equals the baseline tree, and no client code is run.

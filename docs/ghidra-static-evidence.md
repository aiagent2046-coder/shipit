# Ghidra evidence in project checks

This standalone operator command imports one ELF64 little-endian x86-64 executable/shared object
into a fresh Ghidra project and exports discovered functions and external symbols. It does not
run the target, decompile to proposed patches, classify vulnerabilities, change finding severity,
or join the existing source-pattern security agent. The shared project audit imports its saved
report in local, browser and hosted scans. Running Ghidra itself remains an explicit local
operator action. There is no LLM dependency.

```bash
python scripts/inspect_binary_ghidra.py sample.elf \
  --ghidra-archive /tools/ghidra_12.2_PUBLIC_20261016.zip \
  --java-home /tools/jdk-25 \
  --output /tmp/static-evidence.json
```

The output path must be new. Exit 0 means only `static_export_completed`; exit 2 means
partial/unavailable evidence. Neither means the program is safe. Wrong format/architecture,
missing tools, mismatched distribution hash, timeout, excessive output and invalid records
never become a completed result. `runtime_verified` and `automatic_patch` always remain false.
Use optional `--diagnostic-log /tmp/ghidra.log` to retain a bounded native diagnostic log in a
new file. Without this option the temporary log is removed.

## Toolchain and contract

- Ghidra 12.2, release tag `Ghidra_12.2_build`, archive `ghidra_12.2_PUBLIC_20261016.zip`.
- Archive SHA-256 `2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67`.
- JDK 25 with `java` and `javac`. The archive is verified, then unpacked into a private temporary
  directory for each invocation; ambient installed extensions/preferences are not reused.
- Output schema version 1, scope `binary_static`, profile `elf-x86-64-static-v1`.
- Binding: exact copied binary SHA-256/length, Ghidra distribution version/hash, exporter SHA-256,
  actual JDK version, language `x86:LE:64:default`, compiler spec `gcc`. The imported program SHA must match the parent.
- Function entries are Ghidra virtual addresses. `external_location` is an address in Ghidra's
  EXTERNAL database space, not the imported function's runtime address or a file offset.
- Import names are observations. For example, an imported `system` symbol alone does not prove
  attacker control or exploitability. Function discovery is not proven exhaustive.

The Java postscript extends `HeadlessScript` and uses `analysisTimeoutOccurred()`. The 60-second
analysis timeout does not cover post-scripts; the parent therefore enforces a separate 120-second
wall limit for the entire process group, including launch and script compilation. Library loading
and existing-project linking are disabled. Reports omit timestamps and temporary paths; rows are
sorted with explicit identifiers. Duplicate keys/rows, unknown fields and inconsistent bindings
are rejected. Hash validation checks consistency, not authenticity of an edited saved report.

## Limits

Input 10 MiB, 1000 function records and 1000 import records, names 256 characters, accepted JSON
1 MiB, combined native log 2 MiB. Analysis timeout or record truncation yields `partial`. Zero
recovered functions yields `partial` (`no_functions_recovered`): Ghidra exits 0 on an ELF whose
valid header precedes unloadable content, and an empty export is not evidence.
The child receives a clean environment, one analysis CPU and a 1 GiB **Java heap** limit. This is
not a total process-memory limit or a security sandbox for the native parser. A service rollout
would require a separate isolated worker with network and total-memory controls; this pilot is
an explicit local operator tool. Ghidra reads the binary but never launches it.

## Validation

`tests/test_ghidra_evidence.py` checks format and size boundaries, strict result normalization,
changed hashes/tool versions, duplicate/nonfinite records, missing tools, parent wall/output
limits and failed process exit. It does not pretend to run Ghidra.

The dedicated `Optional Ghidra static evidence` CI job downloads the verified archive, installs
JDK 25, compiles a harmless tiny C fixture without executing it, runs two fresh projects and
requires byte-identical JSON plus known function/import facts. A header-plus-garbage ELF must
end as `partial`/`unavailable`, never `completed`. The native run is a distinct gate; it cannot
be replaced by mocked/unit-only success. JSON and bounded logs are retained as artifacts.

## Connect evidence to a project audit

Generate the report for the exact binary included in the project, then attach it explicitly:

```bash
drydock-local scan ./project --binary-evidence bin/app=/tmp/static-evidence.json --json
```

Repeat `--binary-evidence PROJECT_PATH=REPORT_JSON` for up to eight reports. The same option
works with `watch`; edits to either a report or its binary invalidate the cached result.
Keep report files outside the project. The CLI does not launch Ghidra or the target binary.
A changed or missing binary, unsupported tool version, or malformed report is not accepted
as completed evidence. Binary checks that are incomplete/unavailable/not run produce exit 2.

For a browser upload or hosted ZIP audit, prepare a new ZIP from the repository checkout:

```bash
python scripts/attach_binary_evidence.py project.zip \
  --binary-evidence bin/app=/tmp/static-evidence.json \
  --output project-with-evidence.zip
```

`ZIP_PATH` is the exact path inside the ZIP (including a repository wrapper, if present).
The command refuses to overwrite an existing output or existing evidence manifest. Exit 2
can mean the output contains incomplete evidence; inspect the printed status and audit report.
The generated ZIP can then be uploaded through the existing project-audit input.

The reserved `.drydock-evidence/ghidra.json` envelope is:

```json
{"version":1,"artifacts":[{"path":"bin/app","report":{"version":1,"scope":"binary_static","...":"original complete producer JSON"}}]}
```

This example abbreviates the report; use the complete original producer JSON. A manually
packaged manifest may also live under a single repository wrapper; its paths are relative to
that wrapper. Ambiguous manifests are rejected. The envelope is audit metadata and excluded
from source/secret/LLM scanning. Other files in the directory remain ordinary scan inputs.

`scan_manifest.project_checks` joins source coverage, vulnerability-database coverage and
binary evidence under one archive SHA-256; the browser/local JSON exposes `project_checks`
as well. HTML, web/browser reports and SARIF display a bounded projection. Binary facts do
not enter vulnerability findings, severity, readiness scores or automatic patch selection.
CVE/GHSA matches still require the existing package/version evidence. Offline catalog
provenance stays distinct from live OSV checks; a database outage is not a clean result.

No binaries means `not_applicable`; supported binaries without reports mean `not_run`.
Unsupported formats mean `unavailable`; mixed complete/incomplete artifacts mean `partial`.
At most 32 binary artifacts and eight supplied reports are represented (2 MiB total manifest).
Omitted artifacts are counted and prevent a completed result. Hashes establish consistency
with the archive, not authenticity of operator-supplied reports or proof of native execution.
The dedicated native CI also imports its actual Ghidra export into the shared project contract.

# Optional Ghidra static evidence pilot

This standalone operator command imports one ELF64 little-endian x86-64 executable/shared object
into a fresh Ghidra project and exports discovered functions and external symbols. It does not
run the target, decompile to proposed patches, classify vulnerabilities, change finding severity,
or join the existing source-pattern security agent. Nothing enables it in web/browser/local scan
entry points. There is no LLM dependency.

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
1 MiB, combined native log 2 MiB. Analysis timeout or record truncation yields `partial`.
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
requires byte-identical JSON plus known function/import facts. The native run is a distinct gate;
it cannot be replaced by mocked/unit-only success. JSON and bounded logs are retained as artifacts.

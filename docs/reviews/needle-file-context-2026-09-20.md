# Needle file-input control — 2026-09-20

## Reproduction scope

The same user-supplied `needle-main.zip` was scanned with `scan_archive` and the
same bundled advisory catalog before and after this change. The baseline is
main commit `405cc1f6dc47cecc2c2671ced9aad10ede644500`, engine `2026-09-19-6`;
the changed engine is `2026-09-20-1`.

- ZIP SHA-256: `68fab22198cdd1b83b881dcd6c553e64aa90baa5ecefcf147af4824b536ad277`.
- CVE catalog SHA-256: `2c869a983b0379d5087e502270a50bb0463231bfab980aceffc2b50d0b8066fa`.
- Checkpoint source SHA-256: `eafd1dad65f7aac3830ca2d249e6bd563c854b1c44c1856f13302ee16a7efe6a`.
- No customer code, checkpoint, model or application was executed.

## Observed change

| Measure | Before | After |
| --- | --- | --- |
| Findings | 3 | 3 |
| Pickle locations | 77 and 128 | 77 and 128 |
| Severity / verification | High / unverified | High / unverified |
| Source acquisition actions | 0 | 4 |
| Acquired facts | 0 | 4: file source + local binding for each sink |
| Research state | `needs_evidence` | `source_evidence_collected` |
| Display | Two separate loader cards | One group, both full cards retained |
| Checks unavailable | 0 | 0 |
| Dependencies evaluated | 0, partial coverage | 0, partial coverage |
| Model calls / runtime verification / automatic patch | 0 / false / false | 0 / false / false |

The two traces identify `read_checkpoint(path)` and `read_adapter(path)`, their
binary `open` calls at lines 76 and 127, and the exact `pickle.load` calls. Task
receipts are internally consistent. Findings are identical except for the new
structural source trace; coverage, advice, severity and dependency results are
unchanged. The optional Dockerfile finding remains as before.

Source collection does not establish where callers obtain a file, whether its
producer is trusted, what an earlier format predicate does, or whether the
deployed application reaches the loader. The remaining internal prerequisites
are `request_input_source`, `input_trust_boundary`, `loader_runtime_contract`;
for a file trace the UI labels the first as calling code/file origin. The four
agent tasks retain statuses completed/completed/blocked/blocked. This result
does not claim exploit reproduction or a verified fix.

## Validation

- Complete Needle JSON report and SARIF match between native Python and Pyodide
  314.0.6 in Node, using the same ZIP and catalog.
- Native/WASM corpus: 491/491 cases, all 23 checks available; parser probes and
  scan continuation pass.
- Web suite: 674 tests passed; TypeScript and production Next.js build pass.
- Local full Python suite: 11,117 passed, 156 skipped, 1 xfailed, 11 failed.
  All 11 failures reproduce on unchanged baseline main: ten mocked Docker-stage
  tests hit unsupported `os.lchown`, and one HTTP client test encounters the
  environment SOCKS proxy without optional `socksio`. No changes to those
  components are included here. GitHub CI remains the full-suite gate.
- Focused adversarial checks cover input rebinding, dynamic namespace mutation,
  unsupported file operations, source/receipt swaps, exhausted budgets, and
  removal of trust/runtime gaps. No-network/no-model/no-execution tests exercise
  the browser, CLI and free-preview entry points.
- A Chromium test covers disclosure, both locations, source evidence, mobile
  layout and unchanged JSON/SARIF exports. Local Chromium download was
  unavailable (CDN timeout); its execution is delegated to `browser-scan` CI.

Project-specific caller tracing and format-aware repair advice are follow-up
work. They must be supported by additional source evidence rather than inferred
from function names or a neighboring alternative loader.

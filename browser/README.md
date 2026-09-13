# Drydock browser scanner — partial preview

Select a local ZIP, run deterministic source checks in a Web Worker, and export
JSON or SARIF. No account, audit API, model provider, or customer-code execution.
The initial application/runtime download needs a connection. This first build
does not claim installable-PWA or guaranteed offline-reload support.

## Measured scope

Pinned runtime: Pyodide 314.0.6 / Python 3.14.2 / PyYAML 6.0.3.
The same reviewed Python detectors run here, with genuinely unavailable native
packages; no empty-result parser stubs or regular-expression replacements.

| Scope | First preview |
| --- | --- |
| Completed top-level checks | 13 of 17 |
| Unavailable checks | `sql_injection_js`, `tls_verification`, `session_cookie`, `http_success` |
| Findings matching the full native stage | 209 of 251 corpus cases |
| Cases with missing findings | 42 of 251; gaps remain explicit |
| Match to the same partial profile in CPython | Required for all 251 reports, including SARIF and coverage |
| Runtime assets before HTTP compression | 13,637,815 bytes |
| Python engine bundle | Approximately 1.35 MB before HTTP compression |

This is reviewed example coverage, **not recall on arbitrary repositories**.
Negative fixtures do not turn unavailable checks into tested capabilities.
Some unavailable aggregate checks include Python rules too: this preview does
not claim Python TLS/cookie support just because Python itself runs.
Recommendation hints are withheld when their prerequisite parser cannot load.
The report explains this; SARIF cannot silently restore dictionary advice.

The preview does not run repository tests, query dependency advisories, check a
live database, or prove runtime exploitability. It exposes no readiness score.
ZIP validation and per-rule budgets are shared with the server (50 MiB compressed,
500 MiB declared total expansion, 100 MiB per entry, 50,000 entries). A two-minute
UI deadline terminates the worker; users can cancel earlier. These limits do not
guarantee a fixed memory footprint. Runtime and input objects die with the worker.

## Build and serve

From the repository root, Node 22 or later and `curl` are needed:

```bash
npm --prefix browser ci --ignore-scripts
npm --prefix browser run build
python3 -m http.server 8080 --directory browser/dist
```

Open `http://localhost:8080/`. Deploy `browser/dist` to a static host, or build
the existing Next.js site: its prebuild generates `web/public/scanner` and the
preview is available at `/scanner/index.html`. Do not publish `test-dist`:
it contains synthetic corpus sources and test harnesses, not product assets.

All runtime assets are copied into the build. PyYAML is downloaded **at build
time** from the runtime's pinned catalog and SHA-256 verified. The browser makes
only same-origin asset GETs; no source values enter request bodies or URLs.
After initialization the production worker disables fetch/XHR/WebSocket before
handing customer bytes to Python. The UI has no telemetry or localStorage.
Next.js applies CSP to scanner pages and workers; standalone hosts should apply
the same headers from `browser/scripts/serve.py`. The HTML also supplies a CSP.

This inherits the repository's AGPL-3.0-or-later license. Distributors must retain
the repository license and applicable runtime/dependency license notices.

## Reproduce the evidence

In a development environment with `pip install -e '.[dev]'`:

```bash
python browser/scripts/corpus.py browser/test-dist/cases.json
node browser/scripts/prepare-harness.mjs
npm --prefix browser run test:wasm
```

`browser-scan` CI also runs real Chromium against the production CSP: all corpus
cases, valid and invalid ZIPs, cancellation, exports, mobile overflow, and a
network trace. Artifacts include per-case parity, screenshots and exported SARIF
validated with the canonical schema and `FormatChecker`.

## Next portability gate

The pinned Python packages `tree-sitter==0.26.0`, its JS/TS grammars and
`pglast==7.7` have no published Pyodide wheels as checked on 2026-09-13. Prefer
cross-building their source distributions against one pinned Pyodide ABI.
Pglast's nested `libpg_query` make must use the Emscripten compiler and archive
tools, not a host-native static library.

Alternatively, published npm TS/TSX/JS grammars work with `web-tree-sitter`, and
`@libpg-query/parser` has WASM parse/scan APIs. An adapter needs real node/AST
compatibility and offset tests: web Tree-sitter indices are UTF-16, while our
Python scanners slice UTF-8 bytes. Non-ASCII, astral characters, comments,
multistatement SQL and error locations must match before enabling these checks.
The next gate is restoring all four checks with full findings/coverage parity;
adding new rule classes comes after that measurement.

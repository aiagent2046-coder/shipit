# Drydock browser scanner — local static preview

Select a local ZIP, run deterministic source checks in a Web Worker, and export
JSON or SARIF. No account, audit API, model provider, or customer-code execution.
The initial application/runtime download needs a connection. This first build
does not claim installable-PWA or guaranteed offline-reload support.

## Coverage verification

Pinned runtime: Pyodide 314.0.6 / Python 3.14.2 / PyYAML 6.0.3.
The same reviewed Python detectors run here with real native parser extensions
cross-compiled to WASM. No empty-result stubs or substitute JS adapters.

| Scope | Native parser preview |
| --- | --- |
| Completed top-level checks | Every check in the shared capability registry when all assets load |
| Full CPython report and SARIF parity | Every case in the current detector corpus |
| Golden finding expectations | Every positive and negative corpus expectation |
| Parser probes | TS, TSX, JS and PostgreSQL AST, Unicode offsets and parse errors |
| Runtime assets before HTTP compression | 14,674,647 bytes |
| Python engine bundle | Size and SHA-256 recorded by each build |

The CI artifacts record actual case counts, completed checks and per-case differences
for each commit. The browser gate compares check identities, not a fixed historical
count; missing or duplicate checks still fail. This is reviewed example coverage,
**not recall on arbitrary repositories**.
The parser packages add 1,042,834 bytes of compressed wheels. All four previously
unavailable checks are restored: `sql_injection_js`, `tls_verification`,
`session_cookie` and `http_success`. Recommendation guard logic also runs.
If a native asset fails to load, available checks still run and the report lists
the gaps; incomplete SARIF reports use `executionSuccessful: false`. The CI
suite blocks native wheel downloads to exercise that failure mode in Chromium.

The preview does not run repository tests, query dependency advisories, check a
live database, or prove runtime exploitability. It exposes no readiness score.
ZIP validation and per-rule budgets are shared with the server (50 MiB compressed,
500 MiB declared total expansion, 100 MiB per entry, 50,000 entries). A two-minute
UI deadline terminates the worker; users can cancel earlier. These limits do not
guarantee a fixed memory footprint. Runtime and input objects die with the worker.

## Reading findings

The initial review section prioritizes signals without a recognized test or
example context. Tests, examples, comments, configuration templates and deployment
inventory appear in a collapsible group; high/critical severity or detector
confidence of at least 0.8 keeps a signal in initial review (except deployment
inventory). These are presentation groups, not vulnerability verdicts. All
findings remain in JSON and SARIF, including possible real secrets in tests.

Credential explanations and conditional next steps come from the shared static
rule dictionary, without a model request. Advice is withheld when prerequisite
checks cannot run. Stored `.sql.fixture` inputs use the SQL comparison exclusions;
inert `.env.fixture` files and entirely wrapped test dependency trees do not
produce instructions to remove working configuration or installed dependencies.
Their contents remain subject to the existing secret scanner and its exclusions.

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

All runtime assets are copied into the build. The four vendored native wheels
are verified against `native/manifest.json`, including runtime ABI. PyYAML is downloaded **at build
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

## Native wheel provenance and rebuilding

See [native/README.md](native/README.md) for the exact compiler/runtime, source
archive hashes, TypeScript header supplement and rebuild command. The static
web build uses the reviewed wheels; it does not install a C compiler or run
customer build scripts. `native-manifest.json` and `licenses/` ship alongside
the application. Parser versions match the server pins:
`tree-sitter==0.26.0`, `tree-sitter-typescript==0.23.2`,
`tree-sitter-javascript==0.25.0`, `pglast==7.7`.

`parser_probes.py` runs unchanged in CPython and WASM. Comparisons cover UTF-8
byte spans, TS/TSX/JS child fields, SQL AST node types and values, SQL scanner
character offsets and malformed SQL. The corpus gate compares entire reports,
including advice, coverage and SARIF, against the native profile. Chromium also
runs those probes under the production worker CSP with no network during scans.

The next coverage expansion should add rule classes and their positive/negative
fixtures to the shared engine, keeping this full parity gate. Restoring existing
checks does not itself add new defect classes or repository-test execution.

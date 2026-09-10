# Python route scanner hardening — 2026-09-10

The v6 comparison exposed five missed positive controls and additional work in
Python route scanners. This change closes those controls and avoids parsing and
walking source scopes that cannot contain a supported route. It does not execute
uploaded code or promote a source observation to a verified vulnerability.

## Measured revisions and inputs

- v5: `c8b10b03ceeac16cd182a7ba8471ede184f9149b`, engine `2026-09-10-5`.
- v6 baseline: `c58afedc74d65cc96beef8fc6a349d3eead0eaae`, engine `2026-09-10-9`.
- Candidate code: `75d13841c40ee0ccad04999f0c7282ca94d1a282`, engine `2026-09-10-10`.
- Frozen input manifest SHA-256: `8926ae258634aec7bbe241c5771ba8ed9764351b3dc9aff2437ed0a8e4f06a92`.
- 193 identical source ZIPs: 46 independent controls, 139 original golden cases,
  and eight snapshots of six public projects. Three Shipit revisions are separate
  inputs, not separate projects. Expectations were fixed before the first scan.

The full `app.scan.pipeline.run_scan` static-only path ran three times per input,
with explicit LLM skip and no SCA client. Every final result was deterministic;
there were no processing errors, LLM calls, OSV requests, or recorded external
operation attempts. No database or production action was performed.

## Coverage results

| Frozen set | v6 baseline | Candidate |
|---|---:|---:|
| Independent auth controls with expectations | 16/18 | 18/18 |
| Independent outbound controls with expectations | 19/22 | 22/22 |
| Independent controls combined | 35/40 | 40/40 |
| Original golden cases | 139/139 | 139/139 |

The six original boundary examples are outside the 40 scored controls. All 16
negative controls remain silent for their forbidden target rules. An additional
independently written adversarial set passed 19/19 strict cases (7 positive,
12 negative); three predeclared boundaries are reported separately. These are
sample-level checks, not estimates of population precision or recall.

The repository now contains 149 golden cases: ten new positive/negative examples
cover the changed behavior. The exact original five misses were dependency alias
recognition, dependency-guarded sibling reads, two model-field URL flows, and
query-string `.strip()`. The original shadowed-alias positive also remains
passing after distinguishing a narrowly proven `return None` helper from an
unknown dependency wrapper.

On all eight public snapshots, the stored finding sets and total scores are
unchanged. This comparison demonstrates improved controlled coverage; it does
not claim newly discovered vulnerabilities in those real repositories.

## Performance

Profiling v6 on the frozen Shipit v6 source found 4,462 calls to `_scope_routes`;
under cProfile these consumed about 2.04 seconds. The outbound tree-bound check
consumed about 0.93 seconds and declaration scanning about 0.86 seconds. These
instrumented numbers identify work, not production latency.

All supported routes require a decorator token. Files without `@` can therefore
be skipped before parsing. Remaining scopes are checked for the necessary route
syntax before expensive binding analysis; auth scope contexts are resolved
lazily. Outbound eligibility counters and existing resource limits still apply.
The syntactic filters never establish router, client, or dependency provenance.

Across the eight-snapshot full run, the sum of three-repeat medians changed from
38.38 to 33.33 seconds (-13.2%). To avoid comparing different
warmup/order histories, an additional matched two-input batch was run for v6,
v5, and the final candidate, in that order, with three repetitions each:

| Identical source input | v5 seconds | v6 seconds | Candidate seconds | vs v6 | vs v5 |
|---|---:|---:|---:|---:|---:|
| real-fastapi-users-fastapi-users | 0.350 | 0.371 | 0.342 | -7.9% | -2.3% |
| shipit-source-new | 9.085 | 10.923 | 9.385 | -14.1% | +3.3% |

The main v6 overhead is reduced. The final Shipit measurement is still about
3.3% above v5, while FastAPI Users is slightly below v5; this is not a claim that
every input becomes faster or that all overhead of the expanded analysis is
zero. Small controls can cost slightly more as the new provenance analysis runs.
These are local timings, not a production SLA.

Both versions use the same CPython 3.12.14 environment and pinned runtime
versions. Because the package CDN timed out during setup, the three tree-sitter
parsers were built from their official exact release sources: core 0.26.0,
JavaScript 0.25.0, TypeScript 0.23.2. Input reads, imports, warmup, hash checks and
JSON serialization are outside measured calls. The trusted worker used a Python
audit hook to reject external operations; that hook is not an OS sandbox.

## Boundaries retained

- Dependency aliases require visible import provenance. Unknown wrappers and
  rebindings cannot establish an identity witness. The only known non-dependency
  helper exception is a direct, undecorated synchronous function consisting of
  `return None`, with no later/conditional rebinding and a use after its definition.
- Dependency-guarded read witnesses require a visible read, the same router and
  the same stable repository binding or explicit storage provider. An unrelated
  guard or repository does not establish a policy for another operation.
- Model fields require a directly declared local Pydantic model and supported
  string annotations, bounded to 256 fields per handler. Cross-file models,
  inheritance chains, custom types and unknown transformations remain outside
  the trace. Field checks and field assignments track separate value origins;
  previously copied immutable strings retain their own checks.
- Only argument-free `.strip()` on a known string is transferred. It is not URL
  validation. `.strip(chars)` and general order-sensitive alias rebindings remain
  explicit coverage boundaries.
- Middleware, public reachability, DNS/redirect policy, validation correctness
  and actual storage/network effects remain unverified. No Fix Pack proof gate
  or paid delivery test is implied by this offline result.

## Validation and reproduction

Focused auth, outbound, golden and corpus-contract checks passed, as did Ruff,
whitespace checks and the added-line strong-secret scan. The initial local full
suite returned 6,524 passed, 147 skipped, one xfailed and 11 failures. The same
11 tests failed on untouched v6: ten attempts to chown temporary directories to
an unmapped UID, and one HTTP client constructor encountering the environment's
SOCKS proxy without the optional socksio package. No production code or safety
setting was changed to conceal these environment failures. Final PR CI runs the
complete suite on its normal runner; its status is the authoritative merge gate.

The code changes are covered by committed source-only fixtures and unit tests:

```bash
python -m pytest -q tests/test_auth_read.py tests/test_auth_write.py tests/test_outbound_url.py tests/detectors tests/test_engine_version_pins_the_scanners.py
ruff check .
```

Exact frozen inputs, sanitized baseline/candidate results, timing samples,
module hashes and the independent adversarial controls are retained in the
comparison evidence bundle. Public source ZIPs and benchmark output are kept
out of Git. Reproduction should use the unchanged manifest and the same worker
parameters; timing values are expected to vary with the host.

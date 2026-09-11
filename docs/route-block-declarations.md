# Route declarations inside block statements — measured impact

Four route rules now read a route declared inside a module-level `if:`/`try:`/
`with:`/`for:` (`python-route-read-auth-consistency`, `python-route-write-auth-
consistency`, `python-outbound-request-unvalidated-url`, `path-traversal-file-
sink`). The change is a correctness fix: a block statement opens no scope in
Python, so those routes always belonged to the scope's router.

Two claims follow from it, and neither is left to argument.

## Claim 1: unchanged repositories will see new findings

Measured by scanning the SAME bytes with two engine revisions and diffing the
findings — the shipped `run_static_scan`, not a copy of it:

| | |
|---|---|
| Baseline | `origin/main` `8f760f9`, engine `2026-09-10-16` |
| Candidate | this change, engine `2026-09-11-1` |
| Inputs | 12 public FastAPI projects, pinned by commit, 6.4 MB |
| Manifest SHA-256 | `356cdc7c190787e43ea5038058db916704dc07973dbdc1275ff670d93a08b579` |
| Result | **added 0, removed 0** |

The reason is visible in the same run: of 569 parsed Python files, 40 declare a
route, and **none declares one inside a block**. The shape the fix reads does not
occur in this sample, so the bump changes no report on it. The corpus cases show
the shape IS reported when present; the sample shows it is rare in template code.

**Claim 1 therefore becomes: no measured change on realistic template code, and a
new finding wherever a repository registers routes conditionally.** A customer
whose routes sit inside `if settings.X:` gains a finding that was previously
silent — that is the point of the fix, not a side effect to apologise for.

## Claim 2: a conditional import still establishes no provenance

The same inputs, counting where provenance-bearing imports (`fastapi`, `httpx`,
`requests`, `aiohttp`, `APIRouter`, `FastAPI`, `Depends`, `Security`) are
written: **3 files**, all three inside a block.

- `seapagan/fastapi-template: app/admin/admin.py` — `if TYPE_CHECKING: from fastapi import FastAPI`
- `seapagan/fastapi-template: app/admin/auth.py` — `if TYPE_CHECKING: from fastapi import Request`
- `JiayuXu0/FastAPI-Template: docs/gen_pages.py` — `try: from fastapi import FastAPI`

Two of three are typing-only imports that bind nothing at run time. Reading them
as runtime bindings would invent provenance and accuse a caller-filled value on
it. The third is a docs generator's `try:` fallback: the one shape where widening
would be defensible, and nothing measured depends on it. The conservatism stays,
now with this evidence beside it in `auth_read._scope_bindings` and a pinned test
for both shapes.

## Sampling, stated because it is not random

Twelve public FastAPI projects from GitHub's star ranking for "fastapi template",
pinned by commit in the script. Templates are not the population of customer
repositories, and they over-represent application factories and startup-time
registration — the shapes under measurement. The zero above is therefore an upper
bound on how common the block shape is in application code, and a single
occurrence elsewhere would still be a real finding for that repository.

## Reproduction

```sh
python scripts/measure_route_block_impact.py fetch
python scripts/measure_route_block_impact.py shapes --root <tree>
python scripts/measure_route_block_impact.py scan --root <baseline-tree> --out /tmp/base.json
python scripts/measure_route_block_impact.py scan --root <candidate-tree> --out /tmp/cand.json
python scripts/measure_route_block_impact.py diff /tmp/base.json /tmp/cand.json
```

No live contact: the only network calls fetch public repository zipballs, and no
uploaded code is executed — every scanner parses source.

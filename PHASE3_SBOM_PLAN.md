# Phase 3 — SBOM & dependency pinning: reconnaissance + plan

**Status: Step 1 (recon + plan) only. No implementation code in this PR.**
Awaiting review/approval before Step 2.

Scope note: this is about the dependencies of **ShipIt itself** — the
backend (`pyproject.toml`) and the frontend (`web/package.json`). It is **not**
about the client-repo dependencies that a Fix Pack installs inside Docker to
run tests; that supply-chain surface is a separate, already-handled concern
(egress-allowlist proxy).

---

## TL;DR — the audit is right about the backend, half-wrong about the frontend

The external audit flags "no SBOM, no pinning." Reading the actual files, the
two halves of ShipIt are in very different shape:

- **Frontend is already in good shape.** `web/package.json` pins every dep to
  an **exact** version (no `^`/`~`), and `web/package-lock.json`
  (lockfileVersion 3) **is committed**. Vercel runs `npm ci` off that lockfile
  by default, so frontend installs are already deterministic. The one real
  frontend problem is **stale, not unpinned**: the pinned `next@14.2.35` has a
  pile of known advisories (see §5).
- **Backend is the actual pinning gap.** `pyproject.toml` uses only
  lower-bound `>=` ranges with **no upper bounds and no lock file** anywhere
  (no `uv.lock`, `poetry.lock`, or `requirements*.txt`). Deploy is plain
  `pip install -e ".[dev]"` (confirmed in `.github/workflows/smoke-deploy-pack.yml`
  and the VPS `.venv` in the README). So the versions actually running in
  production are "whatever pip resolved on deploy day" — undocumented and
  non-reproducible. That is the real supply-chain risk here.
- **No dependency scanning exists at all.** The only workflow is a manual
  docker smoke; there is **no** `.github/dependabot.yml` and no audit/SBOM step.

The right response at this scale (single VPS, single Vercel app) is **not** a
paid scanner (no Snyk). It is: (1) add a backend lock file using the tool the
project's own `pyproject.toml` already supports, (2) keep leaning on the
frontend lockfile that already exists, (3) one free GitHub Actions job that
generates a CycloneDX SBOM and runs `pip-audit` / `npm audit`, and (4) turn on
Dependabot for both ecosystems. Details and a real audit run below.

---

## Step 1 — Reconnaissance (answers to the specific questions)

### 1. Backend `pyproject.toml` — pinning & lock file

- **Pinning:** ranges only, all lower-bound `>=`, no upper bound, no `==`:

  ```toml
  dependencies = [
    "fastapi>=0.115", "uvicorn[standard]>=0.30", "python-multipart>=0.0.9",
    "httpx>=0.27", "pyjwt[crypto]>=2.8", "psycopg[binary,pool]>=3.1",
  ]
  [project.optional-dependencies]
  dev = ["pytest>=8.0", "pyyaml>=6.0", "pytest-asyncio>=0.23"]
  ```

- **Lock file:** **none.** `git ls-files` shows no `uv.lock`, `poetry.lock`,
  `requirements.lock`, or `requirements.txt`.
- **Package manager at deploy:** plain **pip**, no lock. CI does
  `pip install -e ".[dev]"`; the VPS uses a `.venv` populated the same way
  (README "Production deployment": code at `/opt/shipit`, venv at
  `/opt/shipit/.venv`). Nothing records the resolved version set, so a
  re-deploy months later can silently pull newer transitive deps.

### 2. Frontend `web/package.json` — lock file & install mode

- `web/package-lock.json` **is committed** (lockfileVersion 3), and the direct
  deps are already exact-pinned (`next` `14.2.35`, `react`/`react-dom`
  `18.3.1`, `typescript` `5.5.3`, `postcss` `8.5.10`, etc.).
- **Install mode:** the frontend deploys to **Vercel** (README "browser
  frontend on Vercel"). Vercel's build step auto-detects the committed
  `package-lock.json` and installs with **`npm ci`** (clean, lockfile-exact)
  rather than `npm install`. So frontend determinism is already in place; there
  is no ShipIt-controlled deploy script to change here.

### 3. Existing dependency checking in CI / Dependabot

- Workflows present: **only** `.github/workflows/smoke-deploy-pack.yml`
  (`workflow_dispatch` manual docker smoke). No audit, no SBOM, no scan step.
- **No `.github/dependabot.yml`.**
- No SBOM artifact is produced anywhere.

### 4. Proposed MINIMAL plan (Karpathy: simplest thing that works, no paid SaaS)

Four small, independent pieces. Nothing migrates package managers; nothing adds
a paid service.

**(a) Backend lock file — via `pip-compile` (pip-tools), no manager migration.**
The `pyproject.toml` is already standard PEP 621, which `pip-compile` reads
directly. Generate a fully-pinned, hashed lock and commit it:

```bash
pip-compile --generate-hashes -o requirements.txt pyproject.toml
pip-compile --generate-hashes --extra dev -o requirements-dev.txt pyproject.toml
```

Deploy/CI then becomes deterministic without abandoning pip:

```bash
pip install --require-hashes -r requirements-dev.txt   # exact, verified set
pip install -e . --no-deps                             # install app code only
```

`pyproject.toml` stays the source of truth for *direct* deps; the committed
`requirements*.txt` records the *exact* resolved graph. (`uv pip compile`
produces the same file format if we'd rather use `uv` for speed — equally
valid, still no manager migration. Recommending pip-tools as the more
conventional default; happy to switch — see open questions.)

**(b) Frontend — keep the lockfile, prove it stays honest.** No change to how
Vercel builds. Add a cheap CI step that runs `npm ci` against the committed
lockfile so a drifted/uncommitted `package-lock.json` fails a PR instead of
only surfacing at Vercel build time.

**(c) SBOM + vulnerability check — one free workflow.** Add
`.github/workflows/security-audit.yml` (on `push` to `main`, on PRs touching
deps, and a weekly `schedule`) that does two cheap things per ecosystem:

- **SBOM artifact (CycloneDX, the standard, free):**
  - Python: `cyclonedx-py requirements requirements.txt` → `sbom-python.json`.
  - Node: `npm sbom --sbom-format cyclonedx` (built into npm 10.8.2, already
    on the runner — no extra dep) → `sbom-web.json`.
  - Upload both via `actions/upload-artifact` so every main build has a
    machine-readable "what's actually deployed" record.
- **Vulnerability check:** `pip-audit -r requirements-dev.txt` and
  `npm audit --audit-level=high` (run in `web/`).

  On whether the vuln check **blocks** or only **reports**: the honest answer
  depends on §5. `pip-audit` is clean today, so gating the backend is free and
  catches regressions immediately. `npm audit` currently fails at `high`
  because of `next@14.2.35` (§5), and the only fix is a **breaking** major
  bump. Recommendation: **block on `pip-audit`; run `npm audit` report-only
  (non-blocking) at first**, and let Dependabot (below) drive the `next`
  upgrade via its own PR. Once `next` is past the advisories, flip the npm
  step to blocking. (Alternative: block npm now and do the `next` upgrade as
  explicit separate work — flagged as an open question, not assumed.)

**(d) Dependabot — free, native, zero new infra.** Add `.github/dependabot.yml`
for both ecosystems (weekly, grouped minor/patch to cut PR noise):

```yaml
version: 2
updates:
  - package-ecosystem: pip
    directory: "/"
    schedule: { interval: weekly }
  - package-ecosystem: npm
    directory: "/web"
    schedule: { interval: weekly }
  - package-ecosystem: github-actions
    directory: "/"
    schedule: { interval: weekly }
```

This is what actually turns "we have an SBOM" into "patches land as reviewable
PRs" — including the `next` upgrade from §5 — with no service to run.

**Deliberately NOT proposed:** Snyk or any paid scanner; migrating off pip to
Poetry/PDM; adding upper-bound caps to every range in `pyproject.toml` (the
lock file makes that unnecessary and the caps just create future friction).

### 5. Known CVEs today — REAL audit runs, not guesses

Both audits were run during recon against the actual dependency files (network
access to pypi.org / npm registry confirmed available).

**Backend — `pip-audit` against the resolved ranges: CLEAN.**

```
$ pip-audit -r <pyproject deps, latest satisfying the >= ranges>
No known vulnerabilities found
```

Caveat: this audits the *latest* versions satisfying the ranges. With **no
lock file**, that is not necessarily what is deployed on the VPS — which is
exactly the visibility gap this task closes. Adding the lock (item a) makes the
audit assert something about the *actually-deployed* set.

**Frontend — `npm audit` against the committed `web/package-lock.json`:
2 vulnerabilities (1 high, 1 moderate).**

```
$ npm audit --audit-level=low
next  9.3.4-canary.0 - 16.3.0-canary.5   Severity: high
  (14 advisories: DoS via Image Optimizer, HTTP request smuggling/deserialization,
   SSRF via WebSocket upgrades, cache poisoning, XSS in App Router CSP-nonce /
   beforeInteractive, unbounded image-cache disk growth, i18n middleware bypass)
  Depends on vulnerable versions of postcss

postcss  <8.5.10   Severity: moderate
  PostCSS XSS via unescaped </style> in stringify output (transitive, under next)

2 vulnerabilities (1 moderate, 1 high)
Fix: `npm audit fix --force` → next@16.2.10 (BREAKING major change)
```

So the frontend's problem is **outdated pinned versions**, not missing pinning.
The fix (`next` 14 → 16) is a breaking major and is the main reason item (c)'s
npm gate should start report-only and item (d)'s Dependabot should exist to
open that upgrade as a reviewable PR rather than block CI on day one.

---

## Step 2 — Implementation plan (pending approval; NOT in this PR)

Surgical, matching prior Phase-3 PRs. Files touched:

1. **`requirements.txt` + `requirements-dev.txt`** (new, committed) — generated
   by `pip-compile --generate-hashes` from `pyproject.toml`. `pyproject.toml`
   itself is left as-is (still the source of truth for direct deps).
2. **`.github/workflows/security-audit.yml`** (new) — SBOM generation
   (CycloneDX for both ecosystems) + `pip-audit` (blocking) + `npm audit`
   (report-only initially) + `npm ci` lockfile-sync check; runs on push to
   `main`, dep-touching PRs, and weekly `schedule`; uploads SBOM artifacts.
3. **`.github/dependabot.yml`** (new) — pip (`/`), npm (`/web`),
   github-actions (`/`), weekly, grouped.
4. **`.github/workflows/smoke-deploy-pack.yml`** (edit, minimal) — switch the
   `Install shipit` step to `pip install --require-hashes -r requirements-dev.txt`
   then `pip install -e . --no-deps`, so CI installs the locked set.
5. **`README.md`** (edit) — under "Production deployment", document the new
   lock file + `pip install --require-hashes -r ...` deploy step, the
   SBOM/audit workflow, and Dependabot, mirroring how the queue/observability
   PRs documented their new mechanisms.

No `app/` runtime code changes — this is packaging/CI only.

### Tests

Consistent with the prior PRs' "tests where applicable" bar: SBOM/CI config has
no unit surface, so no `tests/` additions are planned. Verification is instead:

- `pip-audit -r requirements-dev.txt` runs clean locally and in CI.
- `pip install --require-hashes -r requirements-dev.txt && pip install -e . --no-deps`
  followed by the existing `pytest` suite passes (proves the locked set still
  runs the app).
- `cd web && npm ci` succeeds against the committed lockfile.
- Both `cyclonedx-py` / `npm sbom` produce valid CycloneDX JSON artifacts.

If Step 2 grows any actual Python helper code, it will be unit-tested.

### Open questions for the reviewer (please confirm before Step 2)

1. **Backend lock tool:** `pip-compile` (pip-tools, conventional, recommended)
   vs `uv pip compile` (faster, same output format). Either keeps plain-pip
   deploy. Preference?
2. **npm audit gating:** start **report-only** and let Dependabot drive the
   breaking `next` 14→16 upgrade (recommended), **or** block npm now and treat
   the `next` upgrade as explicit in-scope work for this PR? The `next` bump is
   a breaking major, which is why I'm not folding it into a "surgical" packaging
   PR by default.
3. **SBOM destination:** CI build artifacts (recommended, zero infra) are the
   plan. Do you also want them attached to GitHub Releases / committed to the
   repo, or are per-build artifacts enough?

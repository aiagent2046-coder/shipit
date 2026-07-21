# Hermes Audit Fixes (MEDIUM) — Implementation Plan

External security audit (agent **Hermes**) flagged 3 MEDIUM findings on commit
`67e80c8`. The 3 HIGH findings from the same audit are already fixed and
deployed (PR #75). This document covers the remaining 3 MEDIUM findings. It is
**plan-only** — no code changes yet. Each finding below re-verifies the issue
against the current code, states an explicit decision with argumentation, lists
the exact files to touch, and gives a test plan.

> **Access limitation up front:** I am a coding agent. I **cannot** read or
> change the Vercel project settings, the VPS `.env`, or the Caddy config —
> those live outside this repository. Wherever a fix depends on one of those,
> it is called out explicitly in the **"Manual steps for the founder"** section
> at the end. Read that section before approving: Finding 4 in particular has a
> **prod-breaking precondition** I cannot verify myself.

---

## Finding 4 — hardcoded production URL as a silent fallback

**Where:** `web/src/lib/api.ts:15-17`

```ts
export const API_BASE_URL = (
  process.env.NEXT_PUBLIC_API_BASE_URL || "https://45-10-40-169.sslip.io"
).replace(/\/+$/, "");
```

Also `README.md:11` documents the same IP as the live deployment.

**Re-verified problem:**
- (a) A hardcoded IP (`45-10-40-169.sslip.io` is `45.10.40.169` via sslip.io
  wildcard DNS — see `README.md:329`). It goes stale the moment the VPS
  migrates.
- (b) The fallback silently points local development at **production**. A
  developer who forgets to set `NEXT_PUBLIC_API_BASE_URL` hits the live backend
  without noticing — the exact risk Hermes flagged.

### Reconnaissance: how is `NEXT_PUBLIC_API_BASE_URL` set for prod today?

- `NEXT_PUBLIC_*` vars in Next.js are **inlined at build time** (not read at
  runtime), so whatever value exists when Vercel runs `next build` is baked into
  the client bundle.
- I searched the repo: there is **no `.env`, `.env.production`, or
  `.env.example` under `web/`**, and nothing in `web/next.config.mjs` sets this
  var. So within the repository the variable is **never defined** — the
  production bundle has been relying on the hardcoded `|| "https://45-10-40-169.sslip.io"`
  default this whole time, **unless** it is set as a Vercel Project Environment
  Variable (Vercel dashboard → Project → Settings → Environment Variables),
  which I **cannot inspect**.

> **This is the load-bearing uncertainty.** If the var is **not** set in Vercel,
> then removing/changing the hardcoded default **will break production** on the
> next deploy, regardless of which variant below we pick — because the bundle
> would no longer contain the prod URL. This must be confirmed by the founder
> before merging (see Manual steps).

### Decision: **Variant B — fall back to `http://localhost:8000`**

Recon confirms `localhost:8000` is the correct dev backend address: the README
dev instructions run `uvicorn app.main:app --reload` (`README.md:676`), uvicorn's
default is `:8000`, and the production service itself runs uvicorn on
`127.0.0.1:8000` (`README.md:333`). So `8000` is unambiguously "the backend
port" in this project.

**Why Variant B over Variant A (fail-fast build/start error):**

| Aspect | Variant A (throw if unset) | Variant B (localhost:8000) — **chosen** |
|---|---|---|
| Fixes the security finding (no silent prod fallback) | Yes | **Yes** — a forgotten var yields a visible "connection refused to localhost:8000", never a silent prod hit |
| Removes hardcoded prod IP | Yes | **Yes** |
| Local dev / CI / contributor `next build` with no env | **Breaks** (hard failure) | **Works out of the box** |
| Prod behaviour if Vercel var is unset | Build fails loudly | Silent breakage (calls localhost) |

Both variants regress prod **if and only if** the Vercel var is unset — that
risk is identical and is handled by the mandatory manual step below. Given that,
Variant B wins on developer ergonomics (no forced env for every local build)
while still fully closing the finding: the dangerous behaviour was *silently
hitting prod from dev*, and `localhost:8000` makes a forgotten var fail in an
obvious, local, harmless way instead.

Variant A's one advantage — a *loud* prod failure if the Vercel var is missing —
is neutralized by making the Vercel var a hard, pre-merge checklist item (below),
which I'd require for either variant anyway.

### Files to change
- `web/src/lib/api.ts:15-17` — replace the hardcoded prod IP fallback:
  ```ts
  export const API_BASE_URL = (
    process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000"
  ).replace(/\/+$/, "");
  ```
- `README.md:11` — replace the concrete IP with a neutral pointer to the env
  var, e.g. drop the literal `https://45-10-40-169.sslip.io` and describe the
  live URL as "the backend host configured via `NEXT_PUBLIC_API_BASE_URL`
  (frontend) / served by Caddy on the VPS (backend)". The specific IP already
  appears again at `README.md:329` in the "Production deployment" section as
  genuine infra documentation; I will leave **that** occurrence (it documents
  the actual server) but can also parameterize it if you prefer — flag in
  review. The `:11` occurrence is the redundant "live deployment" banner the
  finding targets.

### Test plan
- No unit test exists for `web/` (`api.ts` is a thin client). Verification is:
  1. `NEXT_PUBLIC_API_BASE_URL` set → `API_BASE_URL` equals it (trailing slash
     stripped). Confirm by grep/inspection; add no test framework for one line.
  2. Unset → `API_BASE_URL === "http://localhost:8000"`.
- Run `cd web && npm run build` (or `npx tsc --noEmit`) to confirm the change
  type-checks and the bundle builds.

---

## Finding 5 — no security headers

**Re-verified:** `app/main.py` registers only `CORSMiddleware`
(`configure_cors`, `:128-164`). No `X-Content-Type-Options`, `X-Frame-Options`,
`Strict-Transport-Security`, or `Content-Security-Policy` are set anywhere in
the backend. The frontend sets only `Referrer-Policy: no-referrer` for
`/audit/:path*` in `web/next.config.mjs:4-15`.

### Embed / iframe reconnaissance (decides `X-Frame-Options`)

I searched the whole repo for `iframe`, `WebApp`, `web_app`, `frame-ancestors`:
- The only backend HTML is the audit report at
  `GET /v1/audits/{id}/report` (`app/main.py:529-559`, rendered by
  `app/report/html.py` — self-contained HTML, inline `<style>`, **no scripts,
  no images, no external assets**).
- The frontend links to that report with `target="_blank"
  rel="noopener noreferrer"` (`web/src/app/audit/[id]/page.tsx:177-181`) — it is
  **opened as a new page, never embedded in an iframe**.
- There is **no Telegram WebApp / `web_app` button** anywhere; the bot uses
  Stars payment links and DMs, not an embedded backend page.

**Conclusion: no embed scenario exists → `X-Frame-Options: DENY` is safe
globally** on both backend and frontend. No per-route exception is needed.

### CSP reconnaissance (decides CSP scope)

- `FastAPI(...)` is constructed with **no `docs_url`/`redoc_url` override**
  (`app/main.py:119`), so Swagger UI (`/docs`) and ReDoc (`/redoc`) are
  **enabled**. Both are HTML pages that load their JS/CSS from a CDN and use
  inline scripts. A **global** strict CSP (e.g. `default-src 'none'`) would
  **break `/docs` and `/redoc`**. So CSP must **not** be applied globally as
  `default-src 'none'`.
- The audit **report** HTML uses inline CSS only (no JS, no external anything),
  so it can carry a very tight CSP of its own.

### Decision

**Backend — global middleware** (applies to every response, JSON and HTML):
Add a small Starlette middleware in `app/main.py` (a `BaseHTTPMiddleware`
subclass or an `@app.middleware("http")` function) setting on every response:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY` (safe globally — no embed scenario, see above)
- `Strict-Transport-Security: max-age=63072000; includeSubDomains`
  — HSTS is a response header FastAPI can emit directly; it does not require
  Caddy. (No `preload` — that is a domain-wide commitment the founder should opt
  into deliberately; `sslip.io` is a shared suffix so `preload` would be
  inappropriate anyway.)
- `Referrer-Policy: no-referrer` (backend equivalent of the frontend rule; the
  report URL carries the `?token=` and should not leak it in a Referer).

**Backend — per-route CSP on the HTML report only:** In `get_audit_report`
(`app/main.py:529-559`), set on the returned `HTMLResponse` a tight CSP matched
to that page's real needs:
```
Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
```
(`style-src 'unsafe-inline'` is required because the report inlines `<style>`;
everything else is denied since the page loads nothing external.) This is scoped
to the report response so it never touches `/docs`, `/redoc`, or JSON responses.

> I deliberately do **not** put a global CSP on JSON responses. It would be
> harmless for JSON but would also hit `/docs`/`/redoc` (which the global
> middleware runs for), so scoping CSP to the report is both safe and simpler.

**Frontend — `web/next.config.mjs`:** I *can* add headers here (same mechanism
as the existing `Referrer-Policy` rule), and this does **not** require Caddy.
Add a global block for `source: "/:path*"` with:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY` (frontend is not embedded either)
- `Strict-Transport-Security: max-age=63072000; includeSubDomains`
- keep the existing `Referrer-Policy: no-referrer` for `/audit/:path*`.

I will **not** add a frontend `Content-Security-Policy` in this PR: a correct
CSP for Next.js pages needs a nonce-based script policy (Next injects inline
runtime scripts) and is easy to silently break the app with. That is called out
as a founder follow-up (see Manual steps), not attempted blind here.

### Files to change
- `app/main.py` — add the security-headers middleware (near `configure_cors`,
  registered on `app`); set the per-route CSP header inside `get_audit_report`.
- `web/next.config.mjs` — add the global headers block.

### Test plan
- New `tests/test_security_headers.py`:
  - `GET /healthz` (JSON) carries `X-Content-Type-Options: nosniff`,
    `X-Frame-Options: DENY`, `Strict-Transport-Security`, `Referrer-Policy`.
  - The audit report response additionally carries the tight
    `Content-Security-Policy` with `style-src 'unsafe-inline'` and
    `frame-ancestors 'none'`. (Build the report path via an
    `app.dependency_overrides[get_audit_repo]` fake returning a row with a valid
    `score_json`, matching the DI pattern already used across the suite.)
  - A JSON endpoint does **not** carry the report's `Content-Security-Policy`
    (proves CSP is scoped, `/docs` stays functional).
- Run the full `pytest` suite to confirm the middleware doesn't disturb existing
  header/CORS assertions (`tests/test_cors.py`, `tests/test_report.py`).

---

## Finding 6 — flaky `test_200_and_reaps_with_correct_token`

**Where:** `tests/test_preview_reap_endpoint.py:45-64` (assert at `:63`).

**Re-verified root cause:** the test hardcodes
`body["reconciled"] == {"docker": False, "checked": 0, "removed": []}`. That
value comes from `reconcile_previews()` (`app/deploypack/preview.py:212-279`),
whose very first line is `if not docker_available(): return {"docker": False,
"checked": 0, "removed": []}`. `docker_available()` is literally
`shutil.which("docker") is not None` (`app/deploypack/sandbox.py:59-60`). So the
test's expected value is only correct on a machine **without** a `docker` binary
on `PATH`; on a machine **with** Docker installed, `reconcile_previews` proceeds
to actually shell out (`docker ps`) and returns a different dict — the test then
fails. This is exactly the "passes without Docker, fails with Docker" split.

**Why the existing override doesn't cover it:** the endpoint injects the preview
*registry* via `Depends(get_preview_registry)` (overridden in the test), but it
calls `reconcile_previews` as a **plain module-level function**
(`app/main.py:500`), which is **not** a dependency and therefore cannot be
swapped via `app.dependency_overrides`. The test leaves that call bound to the
real Docker-probing implementation.

### Decision: inject `reconcile_previews` through the existing DI pattern

Add a FastAPI dependency indirection for the reconciler — identical in spirit to
`get_preview_registry`, `get_repo_fetcher`, etc.:

```python
def get_preview_reconciler():
    """FastAPI dependency indirection — overridable in tests so the reap
    endpoint never shells out to a real `docker ps`."""
    return reconcile_previews
```

Then `reap_previews` takes
`reconciler=Depends(get_preview_reconciler)` and calls
`await run_in_threadpool(reconciler)` instead of `reconcile_previews` directly.
The test overrides it with a fake, making the outcome independent of whether
Docker exists in the runtime.

This is preferred over `monkeypatch`-ing `app.main.reconcile_previews` because
the founder's stated pattern is `app.dependency_overrides`, and this codebase
already uses per-collaborator dependency indirections everywhere for exactly
this reason.

### Files to change
- `app/main.py` — add `get_preview_reconciler`; add the `reconciler` param to
  `reap_previews` (`:468-505`) and call the injected callable.
- `tests/test_preview_reap_endpoint.py` — in
  `test_200_and_reaps_with_correct_token`, override
  `get_preview_reconciler` with a fake returning a **distinctive** dict (e.g.
  `{"docker": True, "checked": 2, "removed": [{"container": "abc", ...}]}`) and
  assert the endpoint passes that value through verbatim into
  `body["reconciled"]`. This both removes the Docker dependence and proves the
  endpoint actually forwards the reconciler's result. Remove the stale
  "Docker isn't available in this test sandbox" comment.

### Test plan
- Run `pytest tests/test_preview_reap_endpoint.py` — all four tests pass.
- The determinism is proven by construction: the fake reconciler is called
  regardless of `shutil.which("docker")`, so the result no longer depends on the
  execution environment. (Optionally note: it now passes identically whether or
  not a `docker` binary is present.)
- Run the full suite to confirm the added dependency doesn't break other
  callers.

---

## Manual steps for the founder (outside my access)

1. **Finding 4 — VERIFY BEFORE MERGING (prod-breaking if skipped).** Confirm
   `NEXT_PUBLIC_API_BASE_URL` is set to the real backend URL (e.g.
   `https://45-10-40-169.sslip.io`, or the new host) in the **Vercel project's
   Environment Variables** for the **Production** (and Preview) environments. I
   cannot read Vercel. Removing the hardcoded default means the production
   bundle stops containing the prod URL — **if the Vercel var is not set, the
   production frontend will break** (it would fall back to `localhost:8000`).
   Set it, then redeploy so the value is baked into the next build.

2. **Finding 5 — backend HSTS at the edge (optional reinforcement).** The FastAPI
   HSTS header covers responses that reach the client through Caddy. If you want
   HSTS emitted even on responses Caddy generates itself (e.g. its own error
   pages), add `Strict-Transport-Security` to the Caddy site block on the VPS.
   Not required for the finding — the app-level header is the substantive fix.

3. **Finding 5 — frontend CSP (deferred follow-up).** A `Content-Security-Policy`
   for the Next.js pages needs a nonce-based policy (Next injects inline
   scripts) and risks breaking the app if done blind. I did not attempt it in
   this PR. If you want it, it's a dedicated task (nonce middleware +
   `next.config`/middleware CSP), best verified against a running frontend.

---

## Summary of files to change (when implementing, after approval)

| Finding | Files |
|---|---|
| 4 | `web/src/lib/api.ts`, `README.md` |
| 5 | `app/main.py`, `web/next.config.mjs`, `tests/test_security_headers.py` (new) |
| 6 | `app/main.py`, `tests/test_preview_reap_endpoint.py` |

**Plan-only — awaiting founder approval before implementation (Step 2).**

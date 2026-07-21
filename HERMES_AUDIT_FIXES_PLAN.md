# Hermes Audit Fixes — Implementation Plan

External security audit (agent **Hermes**) flagged 3 HIGH findings on commit
`67e80c8` (current `main`). All three were re-verified against the code before
writing this plan. This document is **plan-only** — no code changes yet. Each
finding below states an explicit decision, the trade-offs weighed, the exact
files to touch, and a test plan.

> **Decisive architectural fact (affects Finding 1 heavily):** the web app is a
> **thin client with no backend of its own**. Every call from the browser goes
> **cross-origin** to the FastAPI backend
> (`web/src/lib/api.ts:1-2,15-17` — default `https://45-10-40-169.sslip.io`),
> while the frontend is served from Vercel (`*.vercel.app`, per the CORS regex
> in `app/main.py:140-152`). These are **cross-site** (different registrable
> domains: `vercel.app` vs `sslip.io`), not merely cross-origin. This single
> fact reshapes the cookie option in Finding 1.

---

## Finding 1 — API key in `localStorage` (XSS-readable)

**Where:** `web/src/components/providers.tsx:70` (`KEY_STORAGE = "shipit-api-key"`),
read at `:105`, written at `:117`, removed at `:125`. The raw `sk_live_...` key
is persisted in `window.localStorage`.

**Verified risk:** any XSS (including a supply-chain compromise via an npm
dependency) can read the raw key and use it against the Pro tier.

**Verified mitigations (already in place):** the key is stored **hashed** in the
DB (HMAC-SHA256 + pepper — `app/accounts.py:180-184`), a leak does **not**
compromise the pepper, and the key is **rotatable**. So a leak is bounded and
recoverable, not catastrophic.

**How auth works today (important for the CSRF analysis):** the key travels as
`Authorization: Bearer <key>` (`web/src/lib/api.ts:35-37`,
`app/accounts.py:160-166`). Browsers do **not** attach this header
automatically, and cross-site JS cannot set it without the backend's CORS
approval — so **the current header-based scheme is inherently CSRF-immune**.
Only **two** endpoints read the key: `GET /v1/account` (safe, read-only) and
`POST /v1/audits` (state-changing — resolves tier & consumes quota,
`app/main.py:1528-1530`). The billing/invoice endpoints do **not** read the key
at all (`web/src/lib/api.ts:126-150` send no auth header), so they are outside
the CSRF surface regardless.

### Why the httpOnly-cookie option is heavier here than it looks

The task asks to assess a cookie approach and its CSRF implications. The
cross-site fact is decisive:

- An httpOnly cookie set by the backend must be **`SameSite=None; Secure`** to
  be sent on cross-site requests from the Vercel app. `SameSite=Strict` or
  `Lax` cookies are **not sent on cross-site requests at all** — so a
  Strict/Lax cookie would simply **never reach the backend** and the app would
  break. The question here is therefore **not** "is Lax enough against CSRF" —
  Lax is functionally impossible.
- `SameSite=None` provides **zero** CSRF protection. Moving auth from a header
  (CSRF-immune) to an ambient `SameSite=None` cookie **reopens a CSRF vector**
  on `POST /v1/audits` (an attacker page could make a victim's browser silently
  run audits under the victim's Pro account / burn their quota).
- Mitigating that requires an explicit **double-submit CSRF token** (backend
  sets a second, JS-readable token cookie; frontend echoes it in a custom
  request header; backend constant-time compares). SameSite cannot substitute
  here because it cannot be enabled without breaking cross-site delivery.
- Net cost: a new backend `Set-Cookie` endpoint (set on key save, clear on
  logout), `credentials: "include"` on every fetch, `allow_credentials` CORS
  (already conditionally on — `app/main.py:158`), **and** the whole
  double-submit token machinery — a substantial new stateful surface on a
  product whose explicit stance is "no backend of our own"
  (`web/src/lib/api.ts:1-2`).
- Benefit is real but **bounded**: httpOnly stops XSS from **exfiltrating** the
  raw key. It does **not** stop an XSS running while the tab is open from
  **using** the ambient credential to issue requests. Given the key is already
  hashed at rest and rotatable, the marginal gain is "prevent offline
  theft/replay of the raw key value," not "prevent all abuse."

### Options and trade-offs

| Option | Security gain | UX | Scope / risk added |
|---|---|---|---|
| **A. httpOnly cookie + double-submit CSRF token** | Highest — raw key becomes un-exfiltratable by XSS. Preserves cross-visit persistence. | Unchanged (key entered once, remembered). | **High.** New backend endpoints, CSRF token system, cross-site `SameSite=None`. **Reintroduces** CSRF that must be mitigated by the token. |
| **B. `sessionStorage` (recommended for this cycle)** | Shrinks exposure to the active tab session; a dormant key no longer sits across browser restarts for a *later* XSS to harvest. Does **not** stop an XSS running while the tab is open. | **Regress:** key re-entered on each new tab / browser restart (single field; `ApiKeyWidget` already exists). | **Minimal** — one storage swap in `providers.tsx`. No new CSRF surface (header auth retained). |
| **C. Keep `localStorage`, document accepted risk** | None. | Best. | None — but **rejected**: Hermes rated HIGH, and doing nothing is indefensible for a security product even with the mitigations. |

### Decision: **Option B (`sessionStorage`) now; Option A documented as future hardening**

Rationale — the balance of *security vs UX vs scope*:

- The residual risk after Option B is **proportional** to the (already
  mitigated) threat: the key is hashed at rest and rotatable, so the realistic
  loss is bounded and recoverable.
- Option A's cost is **disproportionate** in this architecture: cross-site
  forces `SameSite=None`, which reopens CSRF and forces a double-submit token
  system — a lot of new attack surface and stateful backend code for a thin
  client, to gain protection only against *raw-key exfiltration* (XSS can still
  drive the credential live).
- Option B ships now, keeps the CSRF-immune header auth, and closes the
  "dormant key persists across sessions" window that Hermes cares about most.
  Hermes itself names `sessionStorage` an acceptable minimum.
- **UX cost is explicitly acknowledged, not chosen silently:** users re-enter
  the key per browser session. If the founder judges cross-visit persistence
  non-negotiable, escalate to **Option A** — the full Option-A file list is
  included below so that path is not blocked.

### Files to change (Option B — recommended)

- `web/src/components/providers.tsx`
  - Switch `KEY_STORAGE` reads/writes/removes (`:105`, `:117`, `:125`) from
    `window.localStorage` to `window.sessionStorage`. **Leave `THEME_KEY` on
    `localStorage`** (theme persistence is fine and desirable).
  - Update the comment at `:102-103` to state the new rationale (session-scoped
    to limit XSS exposure of the key).

### Files to change (Option A — only if founder escalates)

- `app/main.py` — new `POST /v1/session` (set httpOnly `SameSite=None; Secure`
  key cookie + issue a readable CSRF token cookie) and `DELETE /v1/session`
  (clear both); read the key from the cookie in `resolve_account`; enforce
  double-submit token on `POST /v1/audits`.
- `app/accounts.py` — `api_key_from_request` also reads the cookie.
- `web/src/lib/api.ts` — `credentials: "include"` on all requests; attach the
  CSRF token header on state-changing calls; drop `Authorization` header for the
  key.
- `web/src/components/providers.tsx` — call `/v1/session` on `setKey`/`clearKey`
  instead of touching storage.

---

## Finding 2 — audit `access_token` in the URL query string

**Where:** written to the URL at `web/src/components/AuditForm.tsx:52-59`; read
at `web/src/app/audit/[id]/page.tsx:49-50` and forwarded to the backend at
`web/src/lib/api.ts:110-123`. `?token=...` lands in access logs, browser
history, the `Referer` header on outbound navigation, and any copied link.

### Investigation: is link-sharing a real use case, or just self-return?

Both — and this rules out Hermes' `sessionStorage`-only suggestion:

- The token-in-URL backs the **user's own return/reload** path. `page.tsx`
  prefers a `sessionStorage` stash of the just-produced result
  (`:58-68`), but on **reload or later return** it falls back to
  `getAudit(id, token)` (`:72-116`) which is **404 without the token**
  (`app/main.py:1680-1699`, `app/db.py:384-413`). The GitHub-App install
  round-trip even stores the full token-bearing URL to come back to
  (`FixpackPurchase.tsx:172-178`, `INSTALL_RETURN_KEY`).
- Link-sharing is asserted by code comments (`AuditForm.tsx:52-53`,
  `api.ts:107-109`) but is **not** a documented/marketed feature (no mention in
  `README.md`). So sharing is plausibly light, **but the self-return/reload path
  alone already requires the token to survive in the URL.**

Therefore moving the token to `sessionStorage` (Hermes' idea) would **break
reload, the install round-trip return, and shared links** — it regresses the
core persisted-audit retrieval path. Not acceptable.

### What already protects the token, and the one concrete gap

- The audit page's outbound anchors to external origins **already** carry
  `rel="noopener noreferrer"`: the HTML-report link
  (`page.tsx:178-181`), the Telegram link and the PR link
  (`FixpackPurchase.tsx:232-234`, `:316-318`). Those do **not** leak the token
  via `Referer`.
- **Concrete leak found:** the "Install GitHub App" anchor
  (`FixpackPurchase.tsx:194-201`) navigates full-page to `status.install_url`
  (github.com) **without** `rel="noreferrer"`. That navigation sends the
  current audit URL — **including `?token=...`** — to GitHub in the `Referer`
  header.

### Scope of the token (bounds the residual risk)

The token authorizes **read of exactly one audit row**, not an account
(`app/db.py:384-413` — `where id = %s and access_token = %s`). A leaked token
exposes one audit's findings, not the account, other audits, or any billing
capability. That makes the access-log / browser-history residue a
**narrowly-scoped, acceptable** residual.

### Decision: keep the token in the URL; add explicit `Referer` protection + accept the narrow residual

This preserves the feature (reload, self-return, sharing all keep working) while
closing the live leak vector Hermes worried about:

1. **Route-scoped `Referrer-Policy: no-referrer` for `/audit/:path*`** via
   `next.config.mjs` `headers()`. Defense-in-depth: it strips `Referer` from
   **all** outbound navigations/subresources from the audit page regardless of
   any per-element `rel` being missing or a future link being added.
2. **Add `rel="noreferrer"`** to the GitHub-install anchor
   (`FixpackPurchase.tsx:194-201`) so the token isn't leaked to github.com even
   if the global header is misconfigured/stripped by a proxy.
3. **Document the accepted residual** (access.log / browser history): the token
   is a per-audit read capability, not an account credential, and the audit
   contains only the user's own repo findings.

**Rejected alternative:** token → `sessionStorage` only (Hermes) — breaks
reload / install-return / shared links, and regresses the `page.tsx` fetch
fallback. **Future option (out of scope, noted):** add a server-side TTL/expiry
to audit tokens so any leaked token ages out.

### Files to change

- `web/next.config.mjs` — add an async `headers()` returning
  `{ source: "/audit/:path*", headers: [{ key: "Referrer-Policy", value: "no-referrer" }] }`.
- `web/src/components/FixpackPurchase.tsx` — add `rel="noreferrer"` to the
  install anchor at `:194-201`.

No backend change required.

---

## Finding 3 — in-memory rate limiter resets on restart

**Where:** `app/ratelimit.py` — fixed-window counter in a process-local `dict`
(`:51`), lost on every `systemctl restart` / deploy.

**Verified facts:**

- The docstring claim "`REDIS_URL` is already reserved in `.env`"
  (`app/ratelimit.py:6-8`) is **false**: `.env.example` contains **no**
  `REDIS_URL` and there is **no** Redis infrastructure. It must be provisioned
  from scratch. The docstring will be corrected.
- The DI pattern the task describes is confirmed. `get_rate_limiter`
  (`app/main.py:169-171`) returns a module-level `_limiter` and is overridable
  via `app.dependency_overrides` — **identical** to `get_llm_client`
  (`:174-176`) and `get_billing_transport` (`:214-219`), and already exercised
  by `tests/test_ratelimit.py:101,130`. A Redis-backed limiter drops in cleanly.
- Only **one** uvicorn worker runs today, so the "N×5 limit across workers"
  scenario is **not** currently live. The real present-day impact is **reset on
  restart/deploy** — quotas silently zero out on each deploy.

### Decision (per founder's guidance): Redis-backed limiter with graceful in-memory fallback

- Add a `RedisRateLimiter` implementing the **same interface** as `RateLimiter`
  — `check(key, limit: int | None = None)` raising
  `RateLimitExceeded(retry_after)` — so it is a drop-in behind
  `get_rate_limiter` and works with the existing tier-aware
  `limit=entitlements.daily_audit_limit` call (`app/main.py:1609`).
- Atomicity: a single **Lua script** via `EVAL` performs `INCR` and, on first
  increment, `PEXPIRE window_ms`, returning `(count, pttl_ms)` in one atomic
  round-trip. `retry_after` is derived from the real TTL. (Equivalent
  `MULTI/EXEC` pipeline is acceptable; Lua is preferred for exactness.) Keys are
  namespaced, e.g. `ratelimit:{key}`. Redis TTL replaces the in-memory eviction
  sweep (no unbounded-dict concern).
- `limiter_from_env()` (`app/ratelimit.py:87-89`) returns a `RedisRateLimiter`
  **iff** `REDIS_URL` is set, otherwise the existing in-memory `RateLimiter`.
  This is **graceful degradation** — absence of infra is not a breaking change;
  behavior is byte-identical to today when `REDIS_URL` is unset.
- `.env.example` gains a documented (commented) `REDIS_URL` entry.
- **The founder provisions Upstash and supplies `REDIS_URL` later** — this does
  **not** block writing the code or the tests.

### Files to change

- `app/ratelimit.py` — add `RedisRateLimiter`; branch `limiter_from_env()` on
  `REDIS_URL`; correct the false docstring at `:6-8`.
- `pyproject.toml` — add `redis[hiredis]>=5` to `dependencies`.
- `requirements.txt` — **regenerate** with the repo's locked process
  (`pip-compile --generate-hashes --output-file=requirements.txt --strip-extras
  pyproject.toml`, per the header at `requirements.txt:1-6`, matching PR #48) so
  `redis`/`hiredis` land hash-pinned.
- `.env.example` — add commented `REDIS_URL=` with a one-line explanation.
- `tests/test_ratelimit_redis.py` (new) — Redis-path unit + wiring tests (see
  below). Existing `tests/test_ratelimit.py` stays green unchanged (proves the
  fallback path).

### Note on the test Redis dependency

To avoid adding a new **locked** runtime/dev dependency just for tests, the plan
uses a **small in-process fake** implementing only the Redis methods the limiter
calls (`eval`/`evalsha` or `incr`+`pexpire`+`pttl`), injected via the same
`dependency_overrides` seam. If the founder prefers a realistic fake, `fakeredis`
can be added to `requirements-dev.txt` (also hash-locked) instead — flagged here
as a choice, defaulting to the zero-new-dependency in-process fake.

---

## Consolidated test plan

**Automated backend tests (Finding 3):** run with `pytest` (`pyproject.toml`
configures `testpaths=["tests"]`, `asyncio_mode=auto`).

1. **Graceful fallback (no `REDIS_URL`):** with `REDIS_URL` unset,
   `limiter_from_env()` returns an in-memory `RateLimiter`; the existing
   `tests/test_ratelimit.py` suite passes unchanged. Explicit assertion on the
   returned type.
2. **Env selection:** with `REDIS_URL` set (monkeypatched) and the redis client
   patched to the in-process fake, `limiter_from_env()` returns a
   `RedisRateLimiter`.
3. **`RedisRateLimiter` unit behavior** (against the fake): allows up to the
   limit; blocks the (limit+1)th with `RateLimitExceeded` and `retry_after > 0`;
   independent keys don't interfere; window expiry via TTL resets the counter;
   per-call `limit=` override (tier-aware path) is honored; `retry_after` is
   derived from the fake's reported TTL.
4. **Endpoint integration:** inject a `RedisRateLimiter` (fake-backed, low limit)
   via `app.dependency_overrides[get_rate_limiter]` and assert
   `POST /v1/audits` returns `202` up to the limit then `429` with `Retry-After`,
   mirroring `test_ratelimit.py:99-121`.

**Frontend (Findings 1 & 2):** the web app has **no JS test framework**
(`web/package.json` scripts are only `dev`/`build`/`start`; no jest/vitest).
So these changes are verified by:

5. `next build` (type-checks the route + config) and lint pass.
6. **Manual browser check (Finding 1, Option B):** set a key → it appears in
   `sessionStorage`, **not** `localStorage`; survives in-tab reload; is gone in a
   fresh tab / after browser restart (documented UX trade-off); theme still
   persists via `localStorage`.
7. **Manual browser check (Finding 2):** on `/audit/[id]?token=...`, confirm the
   response carries `Referrer-Policy: no-referrer`; clicking "Install GitHub
   App" sends **no** `Referer` to github.com (DevTools → Network); reload and
   shared-link open still resolve the audit (token still read from URL).

**CSRF test — only if Option A is chosen for Finding 1:** assert that
`POST /v1/audits` with the auth cookie present but the double-submit token
header **missing/mismatched** is rejected (403), and **succeeds** when the header
matches the token cookie (constant-time compare). Not needed for the recommended
Option B, which keeps CSRF-immune header auth.

---

## Delivery

- Branch `hermes-audit-fixes-plan`; this plan committed; **draft PR with the
  plan only (no code)**.
- **Await founder approval of this plan before implementation (Step 2).**
- On approval, implement in three independent commits (one per finding). Only
  Finding 3 requires the founder's `REDIS_URL` afterward — code and tests do not
  block on it.

---
🤖 *Generated by Computer*

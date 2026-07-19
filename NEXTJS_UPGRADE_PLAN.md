# Next.js 14 → 16 security upgrade: reconnaissance + plan

**Status: Step 2 (implementation) done — this doc is the original Step-1 plan.**

> **Step-2 correction (post-implementation):** one prediction below was
> half-wrong. Upgrading to `next@16.2.10` cleared **all high** advisories (0
> high/critical, verified), but **not** the moderate `postcss` one — `next@16`
> still pins `postcss@8.4.31` as its own internal dependency, so
> GHSA-qx2v-qp2m-jg93 persists regardless of our top-level `postcss@8.5.10`.
> It's build-time-only (postcss stringifies our own CSS during build; no
> attacker input reaches it at runtime) and can't be moved without overriding
> `next`'s pinned dep, so we accept + document it. The CI gate is
> `--audit-level=high`, which stays green. Final pins: `next@16.2.10`,
> `react`/`react-dom@19.2.7` (≥ the CVE-2025-55182 fix `19.2.1` and the
> requested `19.2.4` floor), `@types/react@19.2.17`, `@types/react-dom@19.2.3`.

Scope: `web/` — the production Next.js (App Router) frontend deployed on Vercel
(alias `drydock.co`). Goal is to clear the known `next@14.2.35` advisories, whose
only fix is a breaking major bump. Revenue-critical surface (Fix Pack purchase,
GitHub App install-gate, audit results) — so this plan errs toward *more* QA than
a normal surgical change, precisely because the upgrade is breaking.

---

## TL;DR — the upgrade is real, but the code surface it touches is tiny

The audit is correct: `next@14.2.35` carries **1 high + 1 moderate** and the only
fix is a breaking major. Verified this session with `npm audit --audit-level=high`
(full output in §1). The high is the Next.js advisory *cluster* (~14 GHSAs:
Image-Optimizer DoS, request smuggling/deserialization DoS, WebSocket-upgrade
SSRF, cache poisoning, App-Router CSP-nonce XSS, `beforeInteractive` XSS,
unbounded image-cache disk growth, i18n middleware bypass, …). The moderate is a
**transitive** `postcss` XSS bundled inside `next` (note: our *top-level*
`postcss` devDep is already the fixed `8.5.10` — the vuln is `next`'s own bundled
copy). `npm audit fix --force` resolves **both** by installing `next@16.2.10`.

The important finding from reading the actual code: **almost none of the Next
15/16 breaking changes apply here.** All four App Router pages are effectively
client components; there are no server `params`/`searchParams` props, no
middleware, no `next/image`, no route handlers, no server `fetch()` caching, no
PPR, no AMP, no runtime config. The real work is:

1. Bump `next` 14→16 **and React 18→19** (Next 16 App Router runs on React 19.2).
2. **Two** concrete code touches: drop the removed `next lint` script, and add
   `data-scroll-behavior="smooth"` to `<html>` to preserve snappy navigation.
3. CI: flip the npm-audit step from report-only to blocking; update README.
4. Heavy QA (build + Playwright desktop/mobile on every route + payment/install
   happy-paths) because the *dependency* jump is large even though the *code*
   diff is small.

Recommended target: **`next@16.2.10`** (the exact version `audit fix` installs and
the current stable per Next docs), **`react@19` / `react-dom@19`**, matching
`@types/*`. Rationale and full detail below.

---

## Step 1 — Reconnaissance (answers to the specific questions)

### 1. Verified current vulnerability state (`npm audit --audit-level=high`)

```
next  9.3.4-canary.0 - 16.3.0-canary.5   Severity: high
  (~14 advisories: GHSA-9g9p-9gw9-jx7f Image-Optimizer DoS,
   GHSA-h25m-26qc-wcjf RSC deserialization DoS, GHSA-ggv3-7p47-pfv8 request
   smuggling in rewrites, GHSA-3x4c-7xq6-9pq8 unbounded next/image disk cache,
   GHSA-q4gf-8mx6-v5v3 / GHSA-8h8q-6873-q5fj Server-Component DoS,
   GHSA-3g8h-86w9-wvmq middleware/proxy cache poisoning,
   GHSA-ffhc-5mcf-pf4q App-Router CSP-nonce XSS,
   GHSA-vfv6-92ff-j949 / GHSA-wfc6-r584-vfw7 RSC cache poisoning,
   GHSA-gx5p-jg67-6x7h beforeInteractive XSS,
   GHSA-h64f-5h5j-jqjh Image-Optimization API DoS,
   GHSA-c4j6-fc7j-m34r WebSocket-upgrade SSRF,
   GHSA-36qx-fr4f-26g5 Pages-Router i18n middleware bypass)
  Depends on vulnerable versions of postcss
  fix available via `npm audit fix --force` → Will install next@16.2.10

postcss  <8.5.10   Severity: moderate  (GHSA-qx2v-qp2m-jg93 XSS)
  path: node_modules/next/node_modules/postcss   ← bundled by next, not our devDep

2 vulnerabilities (1 moderate, 1 high)
```

Most of these advisories describe surfaces this app does not expose (no
`next/image`, no middleware, no i18n, no self-hosted Image Optimizer — it's a
static-ish client app on Vercel). But `npm audit` matches on *version*, not
reachability, and the CI/Dependabot goal is a **clean** high-level audit, so the
version bump is the correct and only remedy.

### 2. Current dependency & config baseline

`web/package.json`:
```json
"next": "14.2.35", "react": "18.3.1", "react-dom": "18.3.1"
devDeps: @types/node 20.14.10, @types/react 18.3.3, @types/react-dom 18.3.0,
         autoprefixer 10.4.19, postcss 8.5.10, tailwindcss 3.4.6, typescript 5.5.3
scripts: dev/build/start = next …, lint = "next lint"
```
`web/next.config.mjs`: only `{ reactStrictMode: true }` — **no** webpack config,
no experimental flags, no image config, no i18n. (Matters: Turbopack-by-default
in 16 conflicts only with a *custom* webpack config; we have none.)

`web/tsconfig.json`: `moduleResolution: "bundler"`, `target ES2021`, strict.
`web/postcss.config.mjs`: tailwind + autoprefixer (unchanged by the upgrade).

### 3. App Router page-by-page audit (the async-params question)

The single most-cited Next 15 breaking change — `params`/`searchParams` becoming
`Promise`s — **does not apply**, because no page reads them as server props:

| Route | Kind | How it reads route data | Affected? |
|---|---|---|---|
| `/` (`app/page.tsx`) | Server component, **no** data/params | — | No |
| `/audit/[id]` | `"use client"` | `useParams()` + `useSearchParams()` from `next/navigation` (client hooks, API unchanged), inside a `<Suspense>` | No |
| `/pricing` | `"use client"` | none | No |
| `/github/installed` | `"use client"` | `useSearchParams()` inside `<Suspense>` | No |

`app/layout.tsx` is a server component but reads no request APIs (static
`metadata`, `next/font/google`, an inline theme `<script>`). All backend data is
fetched **client-side** via `src/lib/api.ts` → `fetch()` to the separate FastAPI
origin, so the Next 15 "fetch/GET-route-handler/client-nav no longer cached by
default" change has **no effect** (we never relied on Next's server fetch cache).

### 4. `next/image`, `middleware`, route handlers, deprecated APIs — none present

Grepped the whole `web/src` tree:
- **No** `next/image` import anywhere → every `next/image` breaking change in 16
  (localPatterns.search, minimumCacheTTL 60s→4h, imageSizes/qualities defaults,
  local-IP block, maxRedirects, `images.domains` deprecation) is **N/A**.
- **No** `middleware.ts`/`middleware.js` → the 16 `middleware`→`proxy` rename is **N/A**.
- **No** route handlers (`route.ts`), no parallel routes (`@slot`/`default.js`),
  no `generateSitemaps`/`opengraph-image`/`icon` generators → their async-`id`/
  async-`params` changes are **N/A**.
- **No** `revalidateTag`/`cacheTag`/`cacheLife`/`unstable_*`, no PPR
  (`experimental_ppr`), no `dynamicIO`/`useCache`, no AMP, no
  `serverRuntimeConfig`/`publicRuntimeConfig`, no `next lint` ESLint config
  committed → all their 16 removals are **N/A**.
- **Uses** `next/font/google` (Inter, JetBrains_Mono) in `layout.tsx` — supported
  in 16, no API change; Turbopack handles it. Verified in build QA (§ testing).

### 5. Breaking changes that DO land on this codebase

Sourced from the official upgrade guides (Next
`/docs/app/guides/upgrading/version-15` and `/version-16`), filtered to what's
actually reachable here:

1. **React 19 is required.** Next 16's App Router runs on React 19.2. Must bump
   `react`/`react-dom` `18.3.1 → 19.x` and `@types/react`/`@types/react-dom` to
   19.x. This is the largest real change. Low third-party risk: the only
   React-consuming deps are `next`/`react`/`react-dom` themselves — no external
   component libraries that might lag React 19.
2. **Node.js ≥ 20.9.0** (Node 18 dropped) and **TypeScript ≥ 5.1**. We're on TS
   5.5.3 (fine). CI uses `node-version: "20"` (resolves to latest 20.x ≥ 20.9 —
   fine). The live risk is **Vercel's** Node setting (see §Risks).
3. **`next lint` removed.** `package.json` still has `"lint": "next lint"`; that
   script breaks under 16 and `next build` no longer lints. There is **no**
   committed ESLint config and CI never runs lint, so the script is vestigial.
   Plan: **remove the `lint` script** (minimal, correct). Alternative if a lint
   gate is wanted later: `@next/codemod next-lint-to-eslint-cli` → ESLint flat
   config — out of scope for a security bump.
4. **`scroll-behavior` override dropped.** `globals.css` sets
   `html { scroll-behavior: smooth; }`. Next ≤15 forced instant scroll-to-top on
   SPA navigation; Next 16 no longer does, so route changes would animate a slow
   smooth-scroll. Plan: add `data-scroll-behavior="smooth"` to `<html>` in
   `layout.tsx` to restore the previous snappy behavior.
5. **Turbopack is the default builder** for `next dev`/`next build`. No custom
   webpack config here, so no conflict expected; build QA confirms. If a
   Turbopack-specific issue appears (e.g. with `next/font` or postcss/tailwind),
   the escape hatch is `next build --webpack` — noted as a fallback, not the plan.
6. Cosmetic-only: `next build` drops the `size`/`First Load JS` columns; dev
   output moves to `.next/dev` (already git-ignored via `/.next`). No action.

---

## Step 2 plan (for after approval)

### Target versions (exact-pinned, matching repo convention)

| Package | From | To | Why |
|---|---|---|---|
| `next` | `14.2.35` | **`16.2.10`** | exact version `audit fix --force` installs; current stable in Next docs; clears all high advisories + transitive postcss moderate. At implementation time, verify `npm view next version` and take the **latest 16.2.x patch** if one exists (patch-only, no further minor/major, to keep regression surface minimal). |
| `react` | `18.3.1` | **`19.2.x`** | required by Next 16 App Router |
| `react-dom` | `18.3.1` | **`19.2.x`** | matches react |
| `@types/react` | `18.3.3` | **`19.x`** | React 19 types |
| `@types/react-dom` | `18.3.0` | **`19.x`** | React 19 types |

Not a stepwise 14→15→16: the code surface is small and fully client-side, so a
direct jump (via `@next/codemod upgrade` to seed versions, then manual review) is
lower-effort and equally safe. `@types/node`, `tailwindcss`, `postcss`,
`autoprefixer`, `typescript` stay put (already current/fixed).

### Concrete file changes

1. `web/package.json` — bump the 5 packages above; **remove** `"lint": "next lint"`;
   add `"engines": { "node": ">=20.9.0" }` so Vercel/CI can't silently build on
   Node 18.
2. `web/package-lock.json` — regenerate with `npm install` (committed; Vercel uses
   `npm ci`).
3. `web/src/app/layout.tsx` — add `data-scroll-behavior="smooth"` to `<html>`.
4. `.github/workflows/security-audit.yml` — change
   `npm audit --audit-level=high || true` → `npm audit --audit-level=high`
   (blocking); update the top-of-file comment (drop the "report-only because the
   only fix is a breaking major" note now that it's fixed).
5. `README.md` — update the security-audit paragraph (report-only → **blocking**),
   the Dependabot note (`next` 14→16 is done, not pending), and add a short
   deploy/breaking-changes note: **Node ≥ 20.9 required, React 19, Turbopack is
   now the default builder** — the things a future upgrader must know.

`next.config.mjs` stays as-is (`reactStrictMode` only) — no turbopack/webpack
block needed.

### Testing (mandatory before the PR is marked ready)

- **Build:** `npm install` (regenerate lock) → **`npm run build` succeeds** (now
  Turbopack). Inspect for new warnings/errors, esp. around `next/font` and the
  theme `<script>`.
- **Types:** `npx tsc --noEmit` clean under React 19 types.
- **Playwright QA — every route, desktop 1280px + mobile 375px, before & after,
  screenshots kept:**
  - `/` — hero, `AuditForm`, `DemoReport`, theme toggle, "I have a key" widget.
  - `/audit/[id]` — seed a result into `sessionStorage` (or drive a real audit)
    so the score ring / findings / `FixpackPurchase` render; exercise the
    **install-gate happy path** (repo-URL parse → "Install GitHub App" vs pay
    cards) and click through to the **Telegram Stars / USDT invoice screen**
    (up to, not through, real payment).
  - `/pricing` — tier table, both payment cards, Pro-key state.
  - `/github/installed?state=owner/repo` — confirmation + "continue to audit"
    return path (seed the `drydock:github-install-return` sessionStorage key).
  - Fix any visual regression found (Tailwind/postcss under Turbopack, font
    swap, dark/light theme flash) before shipping.
- **Backend suite:** `pytest` — should be untouched (frontend-only change) but run
  to confirm nothing shared regressed.
- **Audit gate:** `npm audit --audit-level=high` → **0 high/critical**. If any
  residual finding remains, it will be reported explicitly in the PR, not hidden.

### Risks & explicit post-deploy checks (live, not just "build succeeded")

- **Vercel Node version.** Next 16 needs ≥ 20.9. If the Vercel project is pinned
  to Node 18 in dashboard settings, the deploy **fails**. Mitigation: `engines`
  field above; **post-deploy: confirm the Vercel build ran on Node 20/22.**
- **React 19 runtime behavior.** Stricter effects/ref/hydration semantics can
  surface as hydration warnings or subtle client bugs not caught by `tsc`.
  Mitigation: runtime Playwright QA + watch the browser console on every route.
- **Turbopack build differences** vs webpack (font inlining, CSS ordering).
  Mitigation: visual diff in QA; `next build --webpack` fallback if needed.
- **Navigation scroll** regression if the `data-scroll-behavior` attribute is
  omitted. Verified by clicking between routes in QA.
- **Post-deploy on `drydock.co` (required before sign-off):** load `/`,
  `/pricing`, a real `/audit/<id>`, `/github/installed` — desktop + mobile;
  no console errors; run one **real audit** end-to-end; walk the Fix Pack
  install-gate and reach a payment/invoice screen (no real charge); confirm
  theme toggle + font rendering; sanity-check Core Web Vitals (LCP/CLS) via
  Lighthouse or Vercel Analytics.

### Out of scope (deliberately not touched)

No async-params migration, no middleware/proxy, no `next/image` config, no
caching-API changes, no ESLint flat-config setup — none are present in this
codebase (see §3–4). Keeping the diff to exactly what the security bump requires.

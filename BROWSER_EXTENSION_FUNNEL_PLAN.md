# A free browser extension as the funnel into paid drydock.co

`BROWSER_EXTENSION_FUNNEL_PLAN.md`

The product proves a class of vulnerability by reading what a deployment serves
to a browser — `app/proof/served_bundle.py` fetches the served JS, extracts a
credential, and shows a live before/after. **The browser is where that surface
already is.** A free extension does not open a new attack surface; it puts a
detector we already ship into the one place the served bundle is already
loaded, and uses the finding as the top of a funnel whose paid floor is the
full audit, the Fix Pack, and rotation monitoring on drydock.co.

This document scopes that extension. It is a plan, not an approval — nothing is
built before the boundary below is settled, because this is the first artifact
we would ship that runs inside a stranger's page.

## The hard constraint, stated first because it shapes everything

**The extension inspects a site the user owns or has consented to, passively,
and is never a scanner of the open web.** Three rules, drawn verbatim from
`OFFENSIVE_TECHNIQUE_CATALOG.md`'s two-axis frame, translated to a browser:

1. **Passive on the current tab.** The extension reads only what the tab has
   **already loaded** as an ordinary visitor — the bytes are already in the
   user's own browser. It issues no active probe of its own: no extra `fetch`
   to the site's API, no OpenAPI introspection, no storage-bucket list. An
   active dozapros from inside the page is the same unauthorized touch the
   served-bundle guard (`_default_fetch_text`) is built to police, moved
   client-side. Reading loaded bytes is authorized; reaching past them is not.
2. **No exfiltration about third-party domains.** A finding about a site the
   user does not own never leaves the browser and never reaches our backend.
   We do not build, keep, or sell a list of leaking sites. The free tier's
   entire server contact is *zero* (see the local-classifier decision below).
3. **Ownership before a verdict or an upsell.** Before the extension asserts
   "your bundle leaks a key → buy the audit," the user affirms ownership with
   the same typed phrase the paid endpoint already requires
   (`i-own-this-project`, `app/routes/bundle_check.py`), not a checkbox. A
   secret spotted on a tab the user has not claimed is shown as neutral
   information about what that page exposes to every visitor, never as a target.

If these hold, the extension is the same read-only, consent-gated, prove-not-
exploit detector the rest of the product is. If any is dropped, it becomes the
mass-scanner the catalog marks ❌, and consent does not buy it back.

## Why the browser is the right surface

* **The bundle is already there.** When a developer opens their own deployment,
  the served JS is loaded into the tab. Classifying it is reading their own
  bytes in their own browser — categorically different from a server fetching a
  stranger's URL, which is the act every gate in `served_bundle.py` exists to
  vet.
* **The "before" arrives with no payment and no server round-trip.** Half the
  product's value is the live "we read your served JavaScript." The extension
  delivers that half at the top of the funnel, instantly, for free.
* **Rotation is the subscription hook.** The four verdicts proven live on
  2026-09-02 (`no_baseline → unchanged → replaced_still_shipped →
  gone_from_bundle`, `app/proof/rotation.py`) are the recurring paid offer:
  "we watch your bundle and tell you the day a key reappears." The extension
  gives a one-shot signal; drydock.co sells the standing watch.

## What is free, what stays paid — the funnel split

| tier | where | what it does | reuses |
|---|---|---|---|
| **free** | extension, local, current tab | secrets in the loaded bundle (`service_role` / `anon` / Stripe / LLM keys), demo-JWT carve-out, source maps served, `NEXT_PUBLIC_*` leakage, missing CSP/HSTS from the response already in the tab | the `secret_registry` classifier logic |
| **paid** | drydock.co | full audit (Auth / Money & Data LLM rubrics; Frontend / Deploy / Security static), Fix Pack with before/after, **rotation monitoring** | the whole engine |

The split is natural: the extension delivers one credible free finding and the
"before"; the site sells the proof, the fix, and the standing watch. The free
finding is deliberately narrow — the read-only, own-context signals — and never
the LLM rubrics, which cost money per run.

## The decision that must be made first: one classifier or two

The classifier is Python (`secret_registry.classify`, `scan_text`,
`_CANDIDATE`, plus `app/scan/secrets._is_demo_jwt`). A browser extension is
JavaScript. There are two ways to give it a verdict, and the choice is the
central engineering question, not a detail:

* **(A) Local JS port.** Port the JWT-candidate regex, the `role` decode, and
  the demo-signature carve-out to JS so the free path runs entirely in the
  browser, zero server contact. **Recommended** — it is the only shape that
  satisfies rule 2 (nothing leaves the browser) and needs no rate limiter, no
  `audit_id`, no consent plumbing for the free tier.
* **(B) Call the server classifier.** Reuse the one Python classifier via an
  endpoint. Rejected for the free tier: it means sending a token found on a
  page to our server (exfiltration of a secret), and it drags in the paid
  endpoint's consent/`audit_id`/rate-limit machinery for a free action.

**The cost of (A) is a second reader, and this codebase has paid for drifting
readers repeatedly** (the reason `served_bundle` was made to call the *same*
`_is_demo_jwt` rather than re-decode the role). So (A) ships with a guard, not
a hope: a shared golden-vector fixture — a fixed list of tokens with their
expected verdicts (real service_role, real anon, demo-signed, malformed) —
runs in **both** the Python suite and the extension's JS suite in CI. The two
classifiers are allowed to be two files only while a single fixture proves they
agree token-for-token. The day they diverge, CI is red.

The demo-JWT carve-out is not optional in the port: a `service_role`-shaped
token signed with the public local-Supabase secret is scaffolding anyone can
mint, not a credential, exactly as `_is_demo_jwt` encodes. Calling it a leak in
the extension would be the browser-side version of the CORS oracle's
false-positive.

## Permissions and store review — the go-to-market gate

* **`activeTab` on an explicit click, not a broad content script.** The MVP
  runs when the user clicks the extension on the tab they chose — it does not
  inject into `<all_urls>`. This both enforces rule 1 (passive, on the tab the
  user picked) and is far easier to pass Chrome Web Store review than broad
  host permissions, which trigger the strictest manual review.
* **Manifest V3, no remote code.** The classifier ships in the package; nothing
  is fetched and eval'd at runtime.
* **A privacy posture that is true and stated.** The free path makes zero
  network requests and stores nothing off-device. The store listing and the
  extension's own first-run screen say exactly that. Any future paid handoff to
  drydock.co is an explicit, per-action navigation the user initiates, carrying
  only the domain they claimed — never page contents scraped in the background.

## Reuse map — what already exists

| need | existing code |
|---|---|
| secret classification, redaction, fingerprint | `app/proof/secret_registry.py` (`classify`, `redact`, `fingerprint`, `Finding.evidence`) |
| demo-JWT carve-out, role/severity | `app/scan/secrets.py` (`_is_demo_jwt`, `_jwt_severity`) |
| the paid served-bundle proof the funnel lands on | `app/proof/served_bundle.py` (`fetch_served_bundle`) |
| rotation monitoring, the subscription hook | `app/proof/rotation.py` (seven verdicts) |
| consent phrase for the ownership gate | `app/routes/bundle_check.py` (`i-own-this-project`) |

Only the JS port and its golden-vector guard are new logic. Everything the paid
side does already exists.

## What must NOT be said or built

* That the extension "scans the web for vulnerable sites." It inspects the tab
  the user chose, and reports third-party exposure as neutral information, never
  as a target. A crawler across sites the user does not own is the ❌ line.
* That a `service_role`-shaped token in a page is automatically a live leak. A
  demo-signed one is scaffolding; the carve-out is mandatory in the port.
* That the free path phones home. It does not; the store listing says so, and a
  background request about page contents would make that a lie.
* That finding a stranger's leaking site gives us a path other than coordinated
  disclosure. It does not — there is no "probe their site" mode, in the
  extension or anywhere.

## Not in scope (yet)

* **Active checks from the page** (introspection, bucket list, missing-auth
  probe). Even read-only, these are dozaprosy the "passive on the tab" rule
  forbids from a browser; they belong to the consented server flow if anywhere.
* **A findings backend for the extension.** The free tier is local; any
  server-side aggregation is a separate consent and privacy decision.
* **Firefox / Safari ports.** MVP is one Chromium extension through one store
  review; a second store is a later, separate cost.
* **Auto-scan on page load.** Click-to-run only, until there is a reason and a
  review posture for anything broader.

## The decision this produces

If the local JS port lands with its golden-vector guard green, the extension is
a free, zero-server, own-context detector that reuses the entire paid engine
behind a single credible finding — and it cannot drift from the Python
classifier without CI saying so. The MVP is small: `activeTab` + click, the
ported classifier, a result panel that shows the redacted finding and a "full
audit on drydock.co" handoff gated on the typed ownership phrase. Nothing new on
the paid side; the funnel's floor is the product that already ships. Either the
port agrees with Python token-for-token and this is cheap, or it does not and CI
blocks it — the same measure-first discipline the rest of this repo runs on.

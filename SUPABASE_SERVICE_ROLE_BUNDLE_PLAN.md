# Service-role key in the browser bundle: the measurement before the feature

`SUPABASE_SERVICE_ROLE_BUNDLE_PLAN.md`

The RLS live-probe (`SUPABASE_RLS_YIELD_PLAN.md`) proved one thing beyond its
own finding: **a class that can be verified with a single HTTPS request against
an already-deployed project is the shape that fits this market.** No build, no
container, no sandbox — the three blockers that ended the runtime-CORS detector
at 0 of 26.

This document asks whether a *second* class has that shape:

> The Supabase **service_role** key — the one that bypasses every RLS policy —
> shipped into the client-side JavaScript bundle. Not committed in the repo
> (the secrets scanner already catches that), but **built into `dist/` /
> `.next/static/` and served to every visitor's browser.**

If that key is in the bundle, RLS is not a boundary at all: anyone who opens
devtools reads and writes every row of every table. And unlike the service-role
*route* class (`app/scan/service_role.py`), this one is verifiable end to end —
the credential is public by the time we see it, exactly like the anon key.

**Nothing gets built before the number exists.** That rule is the one thing
every prior experiment here confirmed the hard way (CORS: 0 of 26; RLS: went
because the number said go).

## The claim we would eventually want to make

> "We did not guess your key leaked. We downloaded your production JavaScript
> the same way a browser does, extracted the service_role key from it, read
> three rows the anonymous key is refused, redacted them, and put the shape in
> the report. The Fix Pack rotated the key and moved it server-side, and the
> same request now returns 401."

Verifiable before/after against the live deployment, no scanner opinion. The
measurement's only job is to find out how often the "before" half is actually
true.

## Why this is a different class from the two we already have

Three Supabase-credential findings now exist or are proposed; they are NOT the
same finding and must not collapse into one row.

| class | where the key is | who can reach it | verifiable live? |
|---|---|---|---|
| `secrets` service_role JWT | committed in repo source | anyone with the repo | key present, not consequence |
| `supabase-service-role-route` | server env var, in an HTTP handler | depends on route auth | **no** — a route may check the session |
| **this: service_role in bundle** | built into shipped client JS | **every website visitor** | **yes** — the key is already public |

The route class (`app/scan/service_role.py`) is deliberately left as a
`finding`, not a proof: `circletel` calls `authenticateAdmin()` first,
`usesafe-DPC-UI` checks the session in a documented bypass. We cannot tell the
guarded route from the unguarded one from outside, so a live probe there would
manufacture confidence — the same defect removed from the CORS oracle. **This
class has no such ambiguity:** a key in the bundle is reachable with no auth in
front of it, by construction. That is the whole reason it is provable.

## The hard constraint, stated first because it shapes everything

**The measurement must not read rows from a Supabase project we do not own.**

A service_role key in a public bundle lets anyone read and write that project's
entire database. The key is trivially extractable. But the *project* belongs to
a stranger, and this credential is far more dangerous than the anon key — it
**writes**, it bypasses everything, and a careless probe could corrupt or
destroy a real person's data. Everything the RLS plan said about consent
applies here with the volume turned up.

So the measurement splits into the same three parts with three different rights
to act:

| part | question | what it may touch |
|---|---|---|
| **A. Prevalence** | how often is the key *in the bundle*? | published bundles, read-only, no DB contact |
| **B. Oracle / e2e** | does our prover correctly call it a leak? | a Supabase + bundle we stand up and seed ourselves |
| **C. Live yield** | end to end on a real deployment | only a project we own, or a consented customer |

Part A produces the go/no-go number. Part B proves the prover. Part C is
deferred and never runs against a project without confirmed ownership.

**And one extra rule this class needs that RLS did not:** the live probe is
**read-only, `select` with `limit`, forever.** A service_role key can `INSERT`,
`UPDATE`, `DELETE`, `TRUNCATE`. The probe issues exactly one shape of request
and the code refuses any other, on an owned project no less — because a bug in a
write probe is not a false finding, it is data loss.

---

## Part A — prevalence, from the published bundle (no live DB contact)

### The subtlety that makes this NOT the secrets scanner

The secrets scanner reads **repository source**. This reads **build output**.
The two disagree constantly and that disagreement is the point:

* A key can be in the repo but tree-shaken out of the bundle (imported in a
  server-only module the client build drops) → secrets fires, this does not.
  This is the **false-positive** direction the bundle check removes.
* A key can be absent from the repo but **present in the bundle** — injected at
  build time from a `VITE_`/`NEXT_PUBLIC_`-prefixed env var, or hard-coded in a
  `dist/` a generator committed. → secrets is silent, this fires. This is the
  **miss** direction the bundle check covers, and it is the one that matters,
  because a `VITE_SUPABASE_SERVICE_ROLE_KEY` is the single most common way this
  actually happens: the developer prefixed it to make it "work", not knowing the
  prefix is precisely what publishes it.

⚠️ **Assumption to validate in A, not assert:** that build output is reachable
at all without running the build. Two sources, in order of trust:

1. **A committed build directory.** Some repos commit `dist/`, `build/`, or a
   `.next/` — measurable with zero build, zero network.
2. **The live deployment's served JS.** `https://<app>/assets/*.js` is what the
   browser downloads. This is a request to a **third party's web server**
   (static assets, not their database) — lower stakes than the DB, but still
   not zero, so in Part A it is used **only on projects we own or on the
   handful with a committed bundle.** The corpus-wide number comes from
   committed bundles; the live-fetch path is exercised in B/C.

### The oracle — and its trap, which is the whole point

A token that decodes to `role: service_role` is the finding **only if it is a
real credential.** The trap, inherited directly from `secrets.py`:

* **The demo key.** Every local Supabase stack ships a `service_role` JWT
  signed with the public secret
  `super-secret-jwt-token-with-at-least-32-characters-long`. It decodes to
  `role: service_role` and is **not a credential** — anyone can mint it, and a
  key everyone can forge opens nothing. `app/scan/secrets._is_demo_jwt` already
  encodes this exact check by verifying the HMAC signature against the published
  secret. **The bundle oracle must call the same function**, not re-implement
  the role decode — a second copy is how one of them goes stale on the next CLI
  bump (the two-readers failure this codebase has paid for repeatedly).

So a bundle token is **exposed_service_role** only when both hold:

1. Its payload claims `role == "service_role"` (decode the JWT `payload`,
   `app/scan/secrets._jwt_severity` shape), AND
2. It is **not** demo-signed (`not _is_demo_jwt(token)`).

Anything failing (2) is **local scaffolding served by accident** — worth a
`low`/informational line, exactly as `secrets.py` grades it, never the count.

### The denominator trap

A repo/deployment whose bundle we **cannot obtain** is not "clean" — it is
**"cannot be determined statically"**, the disjoint-population problem the CORS
detector hit and the RLS plan formalised. Part A reports two numbers, never one:

* exposed / bundles-we-could-read (the measurable rate), and
* deployments-with-no-reachable-bundle / corpus (the blind spot the live fetch
  in C exists to cover).

Collapsing these into a single "% vulnerable" repeats the CORS mistake of
implying a method saw a population it structurally cannot.

### The corpus

Reuse the **same 495-repo, three-strata corpus** as
`scripts/measure_service_role_routes.py` and `measure_rls_blind_spot.py` —
Lovable (`lovable-tagger`), bolt (`.bolt/`), and the no-marker control. Same
corpus means the bundle rate is directly comparable to the route rate measured
on it, which is the comparison that tells us whether this class is additive or
just re-finds the route cases. SHAs pinned (the lesson `batch_audit.py` paid
for).

A repo **qualifies** if it ships a Supabase client. It is **measurable** for
this class only if a bundle can be read — committed build dir, or (for the
subset we own/can fetch) served assets.

### The script — `scripts/measure_service_role_bundle_yield.py`

Pure static over committed bundles, zero network for the corpus-wide number.
Walks the funnel and prints where it goes silent, same shape as
`measure_supabase_rls_yield.py`:

```
repos in corpus                          : N
  uses Supabase                          : …
    a readable bundle exists             : …   ← the measurable denominator
      bundle contains a JWT              : …
        role == service_role             : …
          and NOT demo-signed            : …   ← exposed (the number)
  no readable bundle (blind spot)        : …   ← reported, never "clean"
```

Extraction: scan `*.js`/`*.mjs` under committed `dist/`, `build/`, `.next/`,
`out/`, `assets/` for JWT-shaped tokens (`eyJ…\.eyJ…\.…`, three base64url
segments), decode payload, apply the two-part oracle. Every "exposed" verdict
prints the file and the decoded `ref` claim so a human can spot-check —
a regex over minified JS is exactly the kind of thing that looks right and
counts wrong.

**The go/no-go decision A produces:** if committed bundles are almost never
present (plausible — generators emit source, not builds), the corpus-wide
*committed-bundle* rate is uninformative and the real signal moves entirely to
the live-fetch path. In that case A's job narrows to: "of the deployments we
own or can fetch, how many serve the key" — a smaller n, measured in B/C, and
the honest headline becomes a blind-spot statement, not a rate. That is a valid
outcome, not a failure, and it must be reported as such rather than dressed up
as coverage.

---

## Part B — the oracle end to end, on a stand we own

Mirror `scripts/e2e_proof_rls_probe.py`: prove the *live* prover before
trusting it, against a Supabase we control and no one else's.

`supabase start` gives Postgres + PostgREST + **both** keys (anon and
service_role). Build a tiny Vite app in two variants and take its `dist/`:

* **vulnerable**: `VITE_SUPABASE_SERVICE_ROLE_KEY` wired into the client →
  service_role JWT lands in `dist/assets/*.js`. Extract it, probe a table with
  RLS **on** and a restrictive policy. The anon key returns `[]`; the
  service_role key returns the rows → `success`.
* **patched**: key rotated and moved to a server route (or simply removed from
  the client env) → the old key now 401s, and the new client ships only anon →
  `failure`.

Assert `success → failure` through the existing
`app/proof/compare.build_proof_report`, the **same function** the CORS and RLS
pairs use. The template routing in `app/proof/routing.py` gains one entry; the
compare/gate/types layer is untouched.

The live probe itself is a single REST call, the RLS probe's twin with one
difference:

```
GET {project}/rest/v1/{table}?select=*&limit=3
  apikey: {service_role}
  Authorization: Bearer {service_role}
```

The oracle is the **inverse** of the RLS oracle, and this asymmetry is the
proof's backbone:

| | anon key | service_role key |
|---|---|---|
| RLS-protected table, has rows | `200 []` | `200 [rows]` |
| what it means | protected | **RLS bypassed — exposed** |

For the RLS class, `200 []` was the healthy answer and `200 [rows]` the hole —
and `200 []` was ambiguous with an empty table (`alone_proves_nothing`). **Here
the ambiguity moves:** a service_role key reading rows from an RLS-*on* table is
unambiguous exposure (RLS is bypassed by definition, so rows coming back proves
the key is service_role AND the table is non-empty). The remaining care is the
mirror: `200 []` from the service_role probe means the table is **empty**, not
protected — nothing bypasses an empty table into rows. So the BEFORE half must
read real rows, or it proves nothing; `empty_result` / `alone_proves_nothing`
carries over verbatim.

### Discipline carried over from the proof layer — unchanged, plus one

* **Sample-and-redact, never store.** ≤3 rows, PII masked at the column level
  before anything leaves the probe. Report records the *shape*, never values.
* **Raw rows are diagnostics, not evidence.** `proof_json` renders into a PR; a
  customer's user data must never reach it — the wall `app/proof/types.py` puts
  up.
* **`error` ≠ `failure`.** A 404/timeout/rejected-key tells us nothing and is
  `error`; only a genuine no-rows answer against a live reachable table with a
  key that WAS accepted is `failure`.
* **NEW — read-only, enforced in code.** The probe constructs exactly one
  request shape. `INSERT`/`UPDATE`/`DELETE`/`rpc` are not parameters that
  default to off; there is no code path that emits them. A service_role write
  probe is a separate, later, consent-gated decision and is out of scope here
  (mirrors the RLS plan's write-probe deferral, and it matters more here
  because this key actually can write).

### The negative control the e2e must carry from day one

The RLS plan's hardest-won lesson: its e2e **passed on the first attempt, which
is worth less than the CORS e2e failing on its first.** A green that has never
been red proves only that the script ran. So this e2e ships with
`NEGATIVE_CONTROL=1` from the start — it skips the patch (leaves the leaked key
live) and the run **must FAIL** (i.e. `verified=False`, exploit still succeeds
after). CI runs both directions on every change to the new probe, its oracle,
`compare.py`, or `types.py`.

---

## What must NOT be said, in advance

* That a `service_role`-shaped token in a bundle is automatically a live
  credential. A demo-signed one is scaffolding served by accident — the
  `_is_demo_jwt` carve-out is not optional, it is the inverse of the CORS
  `*`-credentials error.
* That the absence of a key in the bundle means the app is safe. It may be in
  an HTTP route instead (`supabase-service-role-route`), or the bundle may be
  unreadable — "cannot be determined", not "clean".
* Any live number, in marketing or a report, drawn from a project we do not
  own. Part C is the only source of a real end-to-end yield, and it is gated on
  consent.
* That this replaces the route finding. It does not — they cover disjoint
  cases (public bundle vs. server env), and a repo can have both, neither, or
  either.

---

## Not in scope (yet)

* **Part C live yield** against real deployments — deferred until Part A clears
  the bar and Part B proves the prover, and then only on owned/consented
  projects.
* **Write probes** (service_role `INSERT`/`UPDATE`/`DELETE`) — the most
  destructive RLS hole and a genuine finding, but a write touches state even on
  a consented project, and with this key it can wipe it. Read-only, permanently,
  until a separate plan with its own consent model says otherwise.
* **Live asset-fetch as the corpus-wide method** — fetching every deployment's
  `dist/*.js` is a third-party request at survey scale; A stays on committed
  bundles for the corpus number and uses live fetch only on owned/consented
  targets.
* **The route class becoming a proof** — it cannot, by the guarded/unguarded
  ambiguity above; it stays a finding.

## The decision this produces

If Part A comes back with committed bundles almost never present AND the
owned/fetchable subset almost never leaking, the class is rare-or-invisible and
this ends here, cheaply, having cost a day of static JS parsing and no live DB
contact. If the leak rate on readable bundles is high — and the
`VITE_/NEXT_PUBLIC_ + service_role` anti-pattern suggests it may be — there is a
real feature, and it reuses the entire RLS proof pipeline with one new template,
one inverse oracle, and one extra safety rule. Either way the number comes
first.

---

---

## Decisions taken 2026-08-28, before any of it is built

Recorded here rather than in a chat log so tomorrow starts from them.

### 1. Part A starts with a probe cheaper than Part A

The plan's own go/no-go (above, "The go/no-go decision A produces") already
anticipates that committed bundles may be almost never present. If that is
true, a full `measure_service_role_bundle_yield.py` — bundle walk, JWT decode,
demo-signed carve-out, two-denominator funnel — is a day spent to discover an
empty denominator.

So the first thing run is one pass over the same 495-repo corpus asking a
single question, with no JWT parsing and no network:

```
for repo in corpus:
    does a committed dist/ | build/ | .next/ | out/ contain any *.js?
→ N of 495 have a readable bundle
```

An hour, and it decides whether the corpus-wide path exists at all. If N is
near zero the corpus number is dead on arrival, the honest headline becomes a
blind-spot statement, and the signal moves entirely to the consented
live-fetch path — which is a valid outcome the plan already names, reached a
day earlier and for an hour's work.

### 2. Part C consent: the RLS model, plus read-only enforced in code

Same typed consent phrase the RLS live check uses (`app/routes/rls_check.py`
— `consent` is a phrase, not a boolean, and there is no default), and the
probe emits exactly one request shape. `INSERT` / `UPDATE` / `DELETE` / `rpc`
are not parameters defaulting to off; no code path constructs them. That is
the plan's own rule (see "NEW — read-only, enforced in code") adopted as the
decision rather than left as a proposal.

Ownership proof beyond the consent phrase was considered and NOT added. It
would be a second gate on a class that already refuses to run without a phrase
a human typed, and the write ban removes the failure mode that would justify
it. Revisit if a write probe is ever proposed.

### 3. A correction to what this class can prove, and when

The plan says a key in the bundle is reachable with no auth in front of it "by
construction", and that is right about the BEFORE half. It does not carry the
AFTER half, and the difference decides what can be sold and when.

The live probe reads the customer's DEPLOYED bundle. "After" only becomes
clean once they have merged, rotated the key, and redeployed. Until then the
same `dist/*.js` serves the same key, so **a verified pair cannot exist before
the customer acts** — and therefore cannot exist before payment, unless we
change something in their infrastructure, which we do not.

This is not an objection to the class. It is the same structural fact the RLS
class has, stated once so no funnel gets designed around a verified-before-pay
moment that cannot happen. What this class CAN do, and RLS cannot, is make the
after-half cheap: once the key is rotated the old one 401s, provable by us in
a single request with no build and no redeploy of theirs. The confirmation
loop closes in seconds rather than waiting on their release.

### 4. The measured fact that should govern expectations for Part A

From this project's own RLS run (`SUPABASE_RLS_YIELD_PLAN.md`, Part C,
2026-08-18): **the migrations in the repository do not describe the
deployment.** The one real exposure sat in a table absent from the migrations
entirely, and static analysis was wrong in BOTH directions on the other two.

Committed build output is the same kind of artifact as committed migrations —
generators emit source, not builds. Expect the bundle-presence probe in (1) to
come back low, and treat a high number as the surprise rather than the
baseline.

---

## Part A result — TODO (bundle-presence probe first, then, only if it clears,
`measure_service_role_bundle_yield.py`)
## Part B result — TODO (stand up owned Supabase + two-variant Vite bundle)
## Part C result — TODO (owned project, typed consent, read-only)

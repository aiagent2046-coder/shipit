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

## Part A result, measured 2026-08-29 on n = 495 — committed bundles are a dead end

`scripts/measure_service_role_bundle_yield.py`, the same three strata as the
route and blind-spot runs, 494 of 495 reachable.

| stratum | uses Supabase | commits a readable bundle | bundle ships service_role |
|---|---|---|---|
| Lovable | 76 | **6 = 8%** [4–16%] | 0/6 |
| bolt | 73 | **2 = 3%** [1–9%] | 0/2 |
| control (no marker) | 78 | **8 = 10%** [5–19%] | 0/8 |
| **pooled** | 227 | **16 = 7%** | **0/16** |

**Blind spot: 211/227 = 93% [89–96%] of Supabase repos commit no bundle at
all.** The committed-bundle denominator is 16 across the entire corpus, and
zero of those 16 shipped a real service_role key. No demo keys in bundles
either (0 carved out); 8 other JWTs seen — anon keys, correctly not counted.

### What this decides

This is a **blind-spot result, not a coverage result**, exactly as the script
was built to report. Generators emit source and build on a CI we cannot see —
93% of the market commits no build output, so static analysis over committed
bundles structurally cannot see this class. The 7% that do commit a bundle are
too few to carry a rate (0 of 16 has a 95% interval of roughly 0–20%), and are
plausibly not representative — a repo that commits its `dist/` is doing
something unusual.

So the corpus-wide committed-bundle path is **closed as uninformative**, and it
closed cheaply: a day of static JS parsing, no live contact. This is NOT the
same shape as the RLS Part A, which came back 2 of 4 measurable and said "go".
Here the measurable denominator itself is the finding.

### Where the signal actually is, and what it costs

The class is not disproven — it is **relocated**. A `service_role` key reaches
the browser at **runtime**, from a `VITE_`/`NEXT_PUBLIC_`-prefixed env var baked
in at build, whether or not the build is committed. The only way to see that is
to fetch the **served** `https://<app>/assets/*.js` — which the plan already
scoped to owned/consented targets only (a third-party asset fetch at survey
scale is its own consent question).

Two honest routes forward, both smaller-n than a repo survey:

1. **Part B on an owned stand** (unchanged): build the two-variant Vite bundle,
   extract the key from the *served* `dist/`, prove the before/after through
   `build_proof_report` with `NEGATIVE_CONTROL=1`. This validates the prover
   regardless of the Part A miss — the prover was never going to get its inputs
   from committed bundles.
2. **A served-asset prevalence pass on consented customers only.** When a
   customer runs an audit and consents, fetch their deployed JS and apply the
   same oracle. That is the real denominator, and it accrues one deployment at a
   time rather than from a corpus.

### The comparison that matters

The route class (`supabase-service-role-route`) fires on ~35% of Supabase repos
*that have a server*. This bundle class fires on 0% of committed bundles because
there are almost no committed bundles. **The route finding is where the shipped,
static, no-consent coverage of "service_role bypasses RLS" lives.** The bundle
class is a live-only proof that rides on top of it for consented deployments —
valuable as *proof* (the differentiator), not as *prevalence*. The plan's claim
at the top is still reachable; it is reached in B/C, never in a corpus survey.

## Part B result, measured 2026-08-29 — half 1 proven, half 2 harness ready

The stand is `smoke/service_role_bundle/` (one source, two builds) and the e2e
is `scripts/e2e_proof_bundle_probe.py`. Zero production code changed — the
script only imports `run_rls_probe`, `build_proof_report`, and the secrets
oracle.

### Half 1 — the leak survives a real production build (no Docker, proven here)

`build_variants.sh` builds the same `src/main.ts` twice, differing only in the
key bound to `VITE_SUPABASE_KEY`. Extracted from the emitted, minified bundle
and classified by production's `_jwt_severity` / `_is_demo_jwt`:

```
dist_vulnerable/  role=service_role  real  sev=critical  (full RLS bypass)
dist_patched/     role=anon          real  sev=low       (public by design)
```

The service_role key survived esbuild minification into `dist_vulnerable/assets/*.js`;
the patched build carries only the anon key. This is the class's core claim —
a service-role credential reaches the browser through an ordinary Vite build —
and it is checked against the actual bundle, not asserted.

### Half 2 — the bypass, wired and proven through the injected fetch

The pair reuses `run_rls_probe` verbatim, passing the EXTRACTED keys. The table
is RLS-**on** and correct throughout — unlike the RLS e2e, nothing about the
table changes; what changes is the key the bundle ships:

```
BEFORE (service_role key from dist_vulnerable): status=success  (read a row — RLS bypassed)
AFTER  (anon key from dist_patched):            status=failure  (200 [], policy denied)
verified=True  exploit succeeded before, failed after
```

The `200 []` ambiguity resolves inside the pair: BEFORE read a real row out of
that same table, so AFTER returning none is a change, not an empty table —
`build_proof_report` enforces exactly that shape, same as RLS.

### The negative control goes red, as required

`NEGATIVE_CONTROL=1` keeps the service_role key for the AFTER probe — the
developer who never removed it from the bundle. The exploit still succeeds,
the pair does NOT verify, and the run reports the control as correctly caught:

```
AFTER (service_role, control): status=success
verified=False  exploit still succeeds after patch
```

A green that has never been red proves only that it ran; this one has a red
direction that is exercised on every run.

### What is proven, and what still needs Don's Docker

Proven here, for real: the leak (half 1), and that the extraction produces two
keys the probe tells apart and that the compare/oracle/negative-control wiring
turns them into `verified` (half 2, injected fetch). **Not yet run:** the live
PostgREST half — `python scripts/e2e_proof_bundle_probe.py` (no flag) needs
Docker to confirm PostgREST actually assigns `service_role` → BYPASSRLS →
rows and `anon` → `200 []` from the signed JWTs. The harness is written and
mirrors `e2e_proof_rls_probe.py`; it is one `docker`-available run from closing.

The distinction the RLS plan drew holds here: this proves the **prover**, on
fabricated data, our own throwaway build — no customer's key, no live project.
The end-to-end yield on real deployments is Part C, gated on consent.

## Part C result, measured 2026-08-29 — the served-bundle path, guard-first

Part A closed the committed-bundle survey; the key lives in the SERVED bundle,
so Part C is the fetch that reads it. New production module
`app/proof/served_bundle.py`; e2e `scripts/e2e_proof_served_bundle.py`, all
runnable without Docker (the live-DB confirmation stays with Part B's harness).

### The guard came first, because it is the whole risk

This is the first primitive in the codebase that fetches an ARBITRARY
customer-supplied URL — `fetch_repo_zip` is locked to github.com, `rls_probe`
to `<ref>.supabase.co`. A deployment is on any domain, so the guard cannot be a
shape; it is IP vetting: resolve the host and refuse every private, loopback,
link-local, reserved, multicast or unspecified address, on EVERY resolved
record (a dual-record rebind is refused because any one private address rejects
the host). Exercised through a fake resolver:

```
metadata.evil -> 169.254.169.254   refused (link-local / cloud metadata)
internal.evil -> 10.0.0.5          refused (RFC-1918)
loop.evil     -> 127.0.0.1         refused (loopback)
ula.evil      -> fd00::1           refused (IPv6 unique-local)
rebind.evil   -> public + private  refused (any private rejects)
app.example   -> 93.184.216.34     passes
```

Plus URL-shape refusals (http without loopback, non-http schemes,
`user:pass@host` credential-smuggling, missing host), same-origin-only asset
following, no auto-redirects, read-only GET, and a body that yields only the
SHAPE of a service_role token — never the fetched bytes. The residual
resolve-then-connect TOCTOU is closed in the default fetch by pinning to the
vetted IP (original Host + SNI), documented in the module.

### The fetch reads the key from the SERVED bundle

A real loopback HTTP server serves `dist_vulnerable/`; `fetch_served_bundle`
follows the served `index.html` to its `/assets/*.js` and extracts the
service_role key, classified by production's oracle:

```
status=checked  leaked=True  assets_read=[…/assets/index-*.js]
evidence={reason: service_role_in_bundle, refs: [egoprezwkjaqacxtjwfl], …}
```

The extracted key is asserted **equal to the one the stand baked in** — proof
we read the served bundle, not something on disk — and the raw token never
enters evidence (only the `ref` and a mask). The served `dist_patched/` yields
`leaked=False`, as it must. No-consent and a metadata URL both return
`skipped`.

### The full path, end to end

```
URL -> served index.html -> /assets/*.js -> service_role key
    -> run_rls_probe(before=service_role) -> success
    -> run_rls_probe(after=anon)          -> failure
    -> build_proof_report                 -> verified
```

The claim at the top of this document is now demonstrated on the served-asset
path, on our own throwaway deployment: we read the service_role key out of the
served JavaScript, and the same key that read the rows is refused once it is
gone.

### What is proven, and the honest remainder

Proven here: the guard refuses every internal address; the fetch reads the key
from a real served bundle and matches it to the baked-in key; the extracted key
carries through to a `verified` before/after. Two things remain, both by
design:

* **Live PostgREST** — `e2e_proof_bundle_probe.py` under Docker confirms a real
  PostgREST assigns `service_role -> BYPASSRLS -> rows` from the signed JWT.
  The served-bundle path here uses the injected probe fetch for the DB half.
* **Real deployments** — this ran on our own loopback deployment. The
  served-asset prevalence pass on CONSENTED customer deployments is the real
  denominator, and it accrues one deployment at a time. The guard is what makes
  that safe to offer; nothing here quotes a rate from a deployment we do not
  own.

## BLOCKING PRECONDITION for Part C — the HTTPS transport smoke

```
python scripts/smoke_served_bundle_https.py     # must exit 0
```

**Part C does not point at a customer deployment until this passes.** It is a
gate, not a nicety, because of a gap the rest of the suite cannot close:
`tests/test_proof_served_bundle.py` proves the guard against every address
class we care about — metadata, RFC-1918, loopback, IPv6, dual-record rebind —
and every one of those tests injects a fake `fetch`. **Nothing exercises
`_default_fetch_text`**, the function that will carry every real request. The
guard is tested; the transport is not.

The specific doubt is `_default_fetch_text`'s own TOCTOU fix. It connects to a
vetted IP literal while carrying the original name in `Host` and
`sni_hostname`. Whether httpx then verifies the certificate against that SNI
name or against the IP in the URL is a property of the installed
httpx/httpcore, not of our code. If it verifies against the IP, every fetch of
a real deployment fails verification — and it fails CLOSED, as an `error`
result, indistinguishable from an unreachable site. The path would be dead and
look merely unlucky.

The smoke has two halves and **the second is the one that matters**:

1. a pinned fetch against a valid certificate must return 200 — the transport
   works;
2. the same code path pointed at a certificate that does not cover the name
   must be REJECTED — because half 1 passing is equally consistent with
   verification being off entirely, and that would trade the TOCTOU for a
   silent downgrade to unverified TLS.

`UNDETERMINED` (exit 78) is not a pass. Talking to the public internet means a
refusal can be a correct TLS rejection or a blocked network, and the script
refuses to collapse the two — the same disjoint-population rule Part A applies
to an unreadable bundle. Run it somewhere with outbound HTTPS; from a sandboxed
agent session it returns 78, which leaves Part C blocked, correctly.

### Result, measured 2026-08-31 on the production host — PASSED

```
HALF 1  connecting to 104.20.23.154  (Host + SNI = example.com)
        OK: status=200, 559 chars read over verified TLS
HALF 2  https://wrong.host.badssl.com/
        OK: rejected by certificate verification (ConnectError)
exit=0
```

**The doubt is resolved, in the good direction: httpx verifies the certificate
against the SNI hostname, not against the connected IP.** So
`_default_fetch_text` closes the resolve-then-connect TOCTOU *without* paying
for it in verification — the bytes come from the address the guard vetted, and
the certificate still has to be valid for the name. Half 2 is what establishes
the second clause; on its own, half 1 would have been equally consistent with
verification being off entirely.

Part C's transport precondition is met. What remains before a customer
deployment is wiring and a decision, not a transport unknown.

### The crawl is transitive, measured 2026-08-31 — and where it still stops

Three runs against our own deployment closed two defects the suite could not
show (an `assets_read` that only recorded files WITH a secret, and a duplicate
chunk spending the cap), and then a third fact: the served HTML names 8
scripts, and that is the ENTRY POINT, not the application. Next.js and Vite
load route chunks by dynamic import, named inside JavaScript and never in the
HTML — so a one-pass walk reads the shell and calls the app clean.

Fine for a claim about our own landing page. Not fine for a claim about
somebody else's application, which is what this endpoint exists to support. So
a fetched chunk's own same-origin `.js` references now join the queue, bounded
by MAX_ASSETS (40, a courtesy limit on the customer's server as much as ours).
No browser, no build, no container — the three blockers that ended the
runtime-CORS detector at 0 of 26 stay avoided.

**Where it still stops, and this belongs beside any published result.** The
walk follows references that are WRITTEN DOWN — quoted filenames, which is
what a chunk manifest is made of. A URL the code assembles at runtime from
pieces (`base + hash + ".js"`) is not written down anywhere and is not reached.
`assets_truncated` says when the CAP stopped us; nothing can say when a
computed name did. So the supportable sentence is "every script we could find
from what is written down", never "every script the app can load".

### The four phantom chunks are gone, measured 2026-09-01 on drydock.co

The transitive walk shipped in `v2026.08.31-5` and the first run after it says:

| | 2026-08-31, before | 2026-09-01, after |
|---|---|---|
| `assets_found` | 12 | **8** |
| JS actually read | 8 | **8** |
| `assets_unread` | (field not yet shipped) | **`[]`** |
| `assets_truncated` | false | false |

Twelve minus the four doubled turbopack manifest paths is eight, and the set of
chunks actually read did not change. So the fix removed phantoms rather than
narrowing the walk — which is the reading the numbers had to distinguish,
because a walk that found fewer things and read the same number of things looks
identical to a walk that broke.

**What this does NOT show.** `assets_unread` is empty here because nothing
failed, and that is only legible because the empty list is now written on every
run. A NON-empty `assets_unread` on a live deployment has still never been
observed — the reasons (`budget_exhausted`, `refused: …`, `fetch_failed: …`,
`http_<n>`) are covered by fixtures only. And drydock.co is a landing page: the
route-level chunk splitting that would exercise the transitive walk's real
purpose is not present on it, so the boundary described above is still
unmeasured, not disproved.

### The rotation verdict was unreachable on a clean deployment, found 2026-09-01

Six consented runs against drydock.co, and every one reported
`rotation: no_baseline`. Read as a fluke of ordering for a day; it was
structural, and the ledger says so plainly — five completed rows, all
`outcome = checked`, all with `jsonb_array_length(result_json->'findings') = 0`.

`compare_findings` inferred "no baseline" from an EMPTY baseline finding list.
Three unrelated situations produce that list, and they had one answer between
them:

* no earlier check of this deployment — genuinely `no_baseline`;
* an earlier check that found no credentials — the baseline exists and is clean;
* an earlier check whose findings carry no fingerprint (no pepper) — not
  comparable, which is a gap in OUR configuration, not a fact about theirs.

The consequence is not cosmetic. A credential appearing on a deployment that
was clean at the last check is the most valuable sentence this table can
produce, and it was being rendered as "nothing to compare against" — on the
class of deployment most likely to be re-checked on a schedule, since a clean
one is exactly the one a customer re-runs.

The caller now states `had_baseline` (a required keyword, no default: only the
caller knows whether a prior row exists), and two verdicts were added,
`still_clean` and `newly_exposed`, plus `not_comparable` for the missing
fingerprint. Two adjacent holes closed with it, both of which would have turned
"we never looked" into "it was clean": `latest_completed_for` accepted a
baseline row with `outcome` of `skipped` or `error`, and the ledger was keyed
on the URL as typed rather than as normalized, so `https://app.example` and
`https://app.example/` wrote two separate histories.

**Confirmed live on `v2026.09.01-1`**, the first rotation verdict that is not a
fixture:

```
"rotation": {"verdict": "still_clean",
             "detail": "no credentials in the previous check of this deployment
                        and none now, in the assets we were able to read —
                        unchanged, not audited clean"}
```

That single line exercises the whole chain in production: the baseline row was
found, `result_json.findings` came back out of jsonb as `[]`, `had_baseline`
reached `compare_findings`, and the answer was "clean then, clean now" instead
of "nothing to compare against". Six earlier runs could not produce it.

**And what that run did NOT prove, because two of the three fixes were not
reachable by it.** Every prior row was already `outcome = checked`, so the new
filter never had a failed row to exclude; and the URL was typed with its
trailing slash both times, so normalization changed nothing. Both are covered
against real Postgres in `tests/test_db_postgres_smoke.py`, which is a
different claim from "seen in production" and is written here as the weaker
one. The remaining five verdicts — `newly_exposed`, `unchanged`,
`replaced_still_shipped`, `gone_from_bundle`, `not_comparable` — need a
deployment that actually serves a credential, and are fixture-only.

**Where it was found matters more than what it was.** Not by a failing test —
the suite was green, and the fixtures asserted `no_baseline` as correct. By
looking at six identical live results and asking why they could not be anything
else. Same shape as the three defects before it: the fixture agreed with the
code, and reality did not.

### The class, assembled

Part A (repo static) is blind to this class by ~93%. Part B proved the leak
survives a production build and the bypass verifies. Part C built the only
thing that reaches the class in the wild — an SSRF-guarded fetch of the served
bundle — and showed the whole path resolve to `verified` without pointing at
anyone. What ships next is a decision, not a measurement: pass the transport
smoke above, then wire the served-bundle fetch behind consent into the audit,
give it its own `service_role_bundle_runtime` template id (so a stored
`proof_json` row is unambiguous), and run the first consented customer
deployment.

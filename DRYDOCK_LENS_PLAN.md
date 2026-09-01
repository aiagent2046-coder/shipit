# A free browser tier: the measurement before the product

`DRYDOCK_LENS_PLAN.md`

The proposal: a free browser extension as the top of the funnel — find the
problem free, sell the fix. Two versions were considered, and they are not the
same idea. The first is measured and answered here. The second is the one worth
testing, and this document says what would decide it.

**Nothing gets built before the number exists.** Same rule as
`SUPABASE_SERVICE_ROLE_BUNDLE_PLAN.md`, and it has already paid for itself
twice: the CORS detector went 0 of 26 for want of it, and the committed-bundle
survey closed in a day because of it.

---

## Version one — a credential scanner in the browser. Measured, and it is a no.

The engine exists (`app/proof/secret_registry.py` classifies credentials from
JS deterministically, with the secret/publishable split and the demo-key
carve-out). A passive extension would read only what the browser already
fetched — no new request to anyone, which sidesteps the entire consent and
SSRF apparatus the served-bundle check needed. Architecturally it is the
cheapest thing we could ship.

The question is not whether it works. It is whether it would ever have
anything to say.

### The number, measured 2026-08-31 on 115 production audits

Findings by origin, `basis = static+llm`, top 40 rule/severity pairs:

| | findings | of which critical |
|---|---|---|
| LLM (`llm-security` / `auth` / `money` / `web`) | 1270 | 109 |
| Static rules | 914 | **132** |

**Static carries more criticals than the LLM.** That was against expectation
and it is the one encouraging fact here: `aws-access-key-id` (47),
`private-key-block` (21), `anthropic-api-key` (17), `env-file-committed` (17),
`rls-table-anon-writable` (17), `stripe-live-key` (13) are all deterministic.

Then the subtractions, and they are large.

**243 of the 914 are invisible to a browser by construction** — facts about a
repository, not a deployment: `no-dockerfile` (104), `no-ci` (40),
`gitignore-missing-secrets` (34), `no-tests` (31), `env-file-committed` (17),
`rls-table-anon-writable` (17, read from migrations).

### The first per-repo number was 56.5%, and it was worthless

A naive count said 65 of 115 audits carry a credential finding. The file list
killed it:

* `aiagent2046-coder-shipit-*/tests/test_secrets.py` appeared **thirteen times
  in the top twenty**, nine findings each — our own repository, audited
  repeatedly, and the findings are the deliberate fixtures in our own secrets
  test. The damping vocabulary exists for exactly this (`test_fixture`,
  `doc_example`); the query did not use it.
* `security-senior-secops.md`, `docs/guides/ingest.md` — documentation.
* 188 findings with an empty `file`: the repo-level rules, filtered out of one
  query and forgotten in the next.
* 115 audits are not 115 repositories.

Corrected — distinct repositories, ours excluded, tests and docs excluded,
credential classes only:

> **5 of 40 repositories = 12.5%**

### And that is still an upper bound

Those findings are in the **repository**. An extension reads the **bundle**,
and the gap between the two is measured, not assumed: Part A of the
service-role plan found **0 of 16** committed bundles carrying a service_role
key. A key in a server-only module is tree-shaken out; `.env` never ships.

So a passive credential extension shows an empty screen on **more than seven
sites in eight**, probably far more. That is not a funnel. It is an
uninstall.

### The trap in the obvious rescue

The deterministic checks with near-universal incidence — missing CSP, HSTS,
`X-Frame-Options`, cookie flags, a source-map reference in the bundle — are
available from an already-loaded page and would fill the screen every time.

They are also, precisely, a list of warnings. The README's second paragraph is
"Most scanners stop at a list of warnings." High incidence is bought here at
the cost of the thing that makes the product not interchangeable.

**The structural conflict, stated once:** among things a browser can see with
no repository and no model, what is frequent is weak and what is strong is
rare.

---

## Version two — compile the LLM's reasoning into deterministic analyzers

The stronger proposal, and it changes the premise rather than the packaging.

The claim is that the LLM's real work is not speed or web knowledge but
**semantic joining across files** — where an id came from, whose it is, which
session was checked, which client issues the query — and that much of that
reasoning can be moved into an evidence graph plus deterministic rules.

### What is verified in this repository

Checked against the code, not taken on trust:

* **`app/scan/llm_scan.py`, frontend rubric, verbatim:** *"Six questions, and
  only these six. Each is settled by reading lines, not by reasoning about
  what happens between them."* The six are mechanical — an `error.tsx` exists
  or it does not; a `finally` is present or absent; a `setLoading(true)` clears
  after an `await` or inside one. This is close to an analyzer specification
  already, and it says so about itself.
* **Auth rubric, verbatim:** it asks for a record "chosen by an id from the
  request without tying it to that caller — `where id = $1` with no user_id,
  owner_id, team_id or workspace_id beside it". That is the IDOR predicate
  written as a data-flow condition, not as a vibe.
* **Six deterministic engines are already wired** (`run_checks`,
  `scan_ci_deploy_source`, `scan_rls`, `scan_schema_drift`, `scan_secrets`,
  `scan_service_role`), so the architecture the proposal describes is not a
  rewrite; it is a continuation.

### Three corrections the proposal needs

**1. The ground truth it plans to use does not exist.**

The proposal is to re-run new deterministic rules over the repository
snapshots of past LLM audits and compare. `audits` stores `repo_url`,
`content_hash`, `engine_version` — **and no commit SHA**. We do not keep the
archive. `content_hash` can tell us a repository has changed since; it cannot
give the old content back.

So past production audits are not a corpus. What IS reproducible is
`scripts/batch_audit.py`'s `SERIES`, which pins full commit SHAs for exactly
this reason ("a branch head would silently fork the series"). Ground truth has
to come from there — and comparing against LLM findings on those repos means
paying for the LLM runs, at the measured median of $0.96 each.

A cheap intermediate exists and should be run first: re-fetch the 40
non-ours audited repositories and count how many still produce the stored
`content_hash`. Every match is a snapshot we can legitimately re-analyse for
free.

**2. The baseline is a sample, not a truth.**

Measured on four same-engine runs of unchanged code (2026-08-18, recorded in
`SUPABASE_RLS_YIELD_PLAN.md`): high-severity LLM finding keys reproduce in
only **65–84%** of runs, and one real critical appeared in 2 of 4. So an
LLM finding list is not ground truth; it is one draw.

That has a direct methodological consequence the proposal does not account
for: **a deterministic rule that fires where the LLM did not is not
automatically a false positive.** It may be the 2-of-4 case. Precision cannot
be measured against the model alone — the disagreements have to be read by
hand, which is what the service-role route measurement did (eight hits read
individually, and the split was the finding).

**3. "Free: find + prove" is not free, and "prove" in a browser is not
passive.**

Proving requires either a sandbox — which is the thing that died at 0 of 26 —
or a live probe against a real system, which is why `app/proof/disclosure.py`
gates it on ownership and `app/routes/rls_check.py` on a typed phrase.

And the runtime half the proposal wants ("double click → POST /checkout
twice") is not observation. It is **causing** a second order on somebody's
live application. A browser extension that reproduces a defect by triggering
it has crossed from reading into acting, and every rule this codebase has
about consent applies with the volume turned up.

The defensible free tier is **find**, with the deterministic engine. "Prove"
belongs where it already is: gated, consented, and on the paid side or the
owner's own deployment.

---

## What would decide it, and it is cheap

Not a Chrome UI, and not a two-week rules rewrite. One number, from the
pinned corpus, with no LLM spend and no browser:

> Implement **two or three of the six frontend questions** as deterministic
> analyzers — the error boundary, the missing `finally`, the un-cleaned timer —
> run them over `batch_audit.py`'s pinned corpus, and measure **per-repository
> incidence**.

Why those: they are settled by reading lines (the rubric says so), they need no
data-flow engine, they have obvious fixes, and they are the classes an
AI-generated app produces constantly. If their per-repo incidence is high, a
free tier has something to say on most apps and the funnel is real. If it is
low, the answer is the same as version one's and it cost two days instead of
two weeks.

The credential measurement above is what this replaces: 12.5% was the honest
ceiling for the class we already had, which is why the class has to change
before the product can.

## What is NOT decided here

* Whether an evidence graph can carry the auth class. The IDOR predicate is
  writable; whether it holds across Supabase, Prisma, Drizzle, SQLAlchemy and
  raw SQL without drowning in false positives is unmeasured.
* Whether the intelligence layer (OSV and friends) is worth the operational
  weight. It is a separate decision and does not gate the experiment above.
* The name. `Drydock Lens` is a good one and nothing here depends on it.

## The first analyzer is written; the number is still owed

`app/scan/error_boundary.py` implements question 1 — the error boundary — with
`scripts/measure_error_boundary.py` to run it over a corpus. The analyzer is
proven; the measurement is not, and the two are separated on purpose below.

### Three defects, found by running the first draft rather than by reading it

**1. The UI gate named four shapes and stopped none of them.** The draft's
docstring said the gate was "not optional" and listed why: a component library,
a design system, react-email templates, a Storybook-only package. Built as
archives and run:

| shape | render root the draft found | verdict |
|---|---|---|
| component library | `src/components/Button/index.tsx` | FIRED |
| design system | `src/index.tsx` | FIRED |
| react-email | `emails/index.tsx` | FIRED |
| docs site | `website/examples/app/demo/page.tsx` | FIRED |

Four of four. One line did it: `(^|/)(src/)?(main|index|App)\.(t|j)sx$` matches
any `index.tsx` at any depth. Its fixture used `src/Button.tsx` — the single
library shape with no index barrel — so the suite agreed with the code.

A name cannot carry this question. "Can this go blank" is a property of
MOUNTING an app, so the signal is now the mount itself (`createRoot(`,
`hydrateRoot(`, `ReactDOM.render(`) or a root-anchored router entry.

**2. The read budget turned a miss into an accusation.** The draft capped at
1200 source files and emitted the finding anyway. A monorepo with a real
`componentDidCatch` and 1400 icon components was reported as having no error
boundary — a false positive on an app that is correct.

**3. `_SKIP_DIRS` matched substrings**, so `src/rebuild/` was excluded as build
output and its files never read — the same direction as (2).

### The signal a bounded reader owes the reader

Fixing (2) by suppressing the finding is only half an answer, and the wrong half
alone is worse than nothing: a silent scanner and a scanner that gave up look
identical. So `scan_error_boundary` returns a `BoundaryScan` — findings plus
`coverage` (`complete` / `budget_exhausted`), plus the `reason` that decided it.

`coverage` is a FIELD BESIDE THE FINDINGS, not a low-severity finding, and the
reason is in `scoring.py` already: `SEVERITY_WEIGHT` has no level below `low`
(0.1), so a "we did not finish looking" finding would deduct from the Frontend
subscore — and that file's own rule is that a number nothing measured must not
vote on the total. Same shape as `assets_truncated` in
`app/proof/served_bundle.py`: absence of evidence gets its own channel.

The asymmetry is recorded in the tests: a boundary token found at file 3 of 5000
is conclusive silence, because nothing later could unsee it. Only ABSENCE needs
the whole pass.

### What is proven, and what is not

Proven: 22 tests, one per decision, including all four measured shapes above and
both budget bounds. Mutation-checked — restoring the filename render-root turns
3 red, letting an exhausted budget fall through turns 2 red.

Not proven: **the incidence**. `batch_audit.SERIES` pins three repositories, and
three cannot decide this question at any outcome. The measurement script reports
over DECIDED repositories and prints the undetermined and unfetchable counts
beside it rather than absorbing them into a denominator — so a thin corpus reads
as a thin corpus.

The corpus has to be widened first, and the plan already named the free way: the
re-fetchable audited repositories, kept where they still reproduce their stored
`content_hash`.

## Result — TODO (per-repo incidence of the first deterministic frontend rules)

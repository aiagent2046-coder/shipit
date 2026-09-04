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

### First corpus run, 2026-09-01 — 2 of 3, and every call checked by hand

| repository | verdict | evidence |
|---|---|---|
| `ai-co-founder-matching` | MISSING | 100 of 100 source files read, `app/layout.tsx`, no `error.*` |
| `blank-slate` | ok | real class boundary, `<ErrorBoundary>` in the tree |
| `zombiecodersmarteditor` | MISSING | 40 of 40 source files read, `app/layout.tsx`, no `error.*` |

Not taken on the analyzer's word. Every boundary token and every mount in all
three was printed with its line, and `blank-slate`'s silence is genuine:
`src/components/ErrorBoundary.tsx` defines `getDerivedStateFromError` and
`componentDidCatch`, and `src/App.tsx:217` wraps the tree in `<ErrorBoundary>`.
Not a comment, not a string literal. **Zero false positives and zero false
silences on three repositories, hand-checked** — which fixtures could not have
established, since the fixtures were written by the same hand as the code.

**And the number means nothing yet.** 2 of 3 carries a 95% interval of roughly
9%–99%. It is not "67% of apps have no boundary"; it is "we looked at three".

### The plan conflated two experiments, and one of them is much cheaper

This document tied widening the corpus to re-fetching audited repositories and
keeping the ones that still reproduce their stored `content_hash`. That is the
right rule for ONE of the two uses, and the wrong rule for the one at hand:

* **comparing a deterministic rule against the stored LLM findings** needs the
  hash to match, or the comparison is against different code;
* **measuring the incidence of a deterministic rule** does not need it at all.
  Any real repository counts.

Requiring the match would have discarded most of the corpus for a property this
measurement never uses. The 43 audited repositories are usable today, and they
are a better population than a random GitHub sample: they are what people
actually brought to drydock, which is exactly who a free tier is for.

`--from-file` does this, and pins what it measured: each default branch is
resolved to a commit SHA, that SHA is what gets fetched, and the run prints the
`slug@sha` list to replay itself. A head fetched implicitly is not a measurement
anyone can repeat — the same rule that made `SERIES` pin full SHAs.

### The denominator is the other half of the number

Most of the 43 are not React apps. An incidence over "every repository somebody
submitted" is diluted by servers, CLIs and component libraries, none of which
have a screen to blank — and none of which are evidence either way. So
`BoundaryScan` carries `mount` (`mounted` / `no_mount` / `not_react` /
`undetermined`), and the report leads with **incidence among mounted apps**.

`undetermined` is there for the same reason `coverage` is. Finding a boundary
token ends the walk, correctly, and if no mount was seen before it, we do not
know whether this is an app or a component library that ships a boundary.
Counting those as apps would inflate the denominator with things never at risk.

## The 43-repository run, and why 100% was the warning and not the answer

Measured 2026-09-01 over the audited repositories. 14 heads could not be
resolved (unauthenticated GitHub allows 60 requests an hour and the run needs
two per repository), leaving 29 measured.

```
incidence among MOUNTED react/next apps: 8/8 = 100%
incidence over all decided repositories: 8/29 = 28%   (diluted by non-apps)
  mount classes: mounted=8, no_mount=4, not_react=16, undetermined=1
```

**A rule that fires on every member of its own denominator is a claim about the
denominator.** Reading the per-repository lines rather than the summary found
two defects, both of which removed real applications from that denominator, and
both in the same direction.

**1. The root layout was required to be exactly `app/layout.tsx`.** Next.js puts
it under route groups and dynamic segments constantly, and three repositories in
this very corpus do: `mckaywrigley/chatbot-ui` and `ixartz/Next-js-Boilerplate`
at `app/[locale]/layout.tsx`, `DayuanJiang/next-ai-draw-io` similarly. A Next.js
app has no `createRoot` to fall back on, so a missed layout is a missed
application. The run's own output gave it away before any repository was
re-fetched: `ixartz` came back `undetermined` while reporting
`app-router error file: src/app/global-error.tsx` — an app-router error file
in a repository we had just decided had no app-router entry.

**2. A workspace root was reported as "not a react/next app".** `dubinc/dub` is
a Next.js product; its react is in `apps/web/package.json`, and only the root
manifest was read. The report printed a false sentence about it after reading
zero files. This is now its own class, `workspace_not_analyzed` — no claim in
either direction, but counted and named, because "we do not analyze this shape"
and "this is not a React app" are different statements.

**The bias has a direction, and it is the flattering one.** Both defects
excluded the mature, well-maintained projects — the ones most likely to HAVE a
boundary — and left the small apps and boilerplates, which is how 8 of 8 became
100%. The corrected denominator will be larger and the rate lower; how much
lower is the re-run's job, not this paragraph's.

### And a caveat about the population, independent of the defects

The corpus is what people brought to drydock, which is the right population in
one sense and a mixed one in another: it contains `Blazity/next-enterprise`,
`ixartz/Next-js-Boilerplate`, `jvidalv/nextal`, `hadrysm/nextjs-boilerplate` —
curated starter templates, not applications somebody built in an evening. Any
published number has to say so.

## Result, 2026-09-01 — 11 of 12 mounted apps ship no error boundary

41 of the 43 audited repositories resolved (two are gone: private, renamed or
deleted since their audit).

```
incidence among MOUNTED react/next apps: 11/12 = 92%
incidence over all decided repositories: 11/41 = 27%   (diluted by non-apps)
  mount classes: mounted=12, no_mount=3, not_react=20, workspace_not_analyzed=6
```

### The three that decide whether to believe it, read by hand

The rate is only interesting if it survives the most reputable repositories in
the corpus, so those were checked rather than trusted:

| repository | boundary tokens in source | app-router error file |
|---|---|---|
| `vercel/nextjs-subscription-payments` | **none** | none |
| `Blazity/next-enterprise` | **none** | none |
| `mckaywrigley/chatbot-ui` | **none** | none |

Vercel's own subscription-payments template, an "enterprise-grade" Next.js
starter, and a 30k-star chat application all ship no error boundary. The 92% is
not the analyzer being wrong about serious projects.

### What the number does NOT support, stated before anybody quotes it

**Three of the twelve are ours** — `aiagent2046-coder/ai-co-founder-matching`,
`aiagent2046-coder/devtools-aggregator`, and the `donjonson-hash` fork of the
second. Exactly the contamination that killed the 56.5% figure earlier in this
document. Without them: **8 of 9 = 89%**.

**Six workspace repositories were not analyzed at all**, and they were the wide
part of the uncertainty. If every one of them had a boundary the figure would be
11/18 = **61%**; if none did, 17/18 = **94%**. That interval is why the next
change was to analyze them rather than publish a range — see below. Even its low
end answered the plan's question in the affirmative: at 61%, a free
deterministic tier has something to say about most applications it sees.

**The corpus is mixed.** `Blazity/next-enterprise`, `ixartz/Next-js-Boilerplate`,
`jvidalv/nextal`, `hadrysm/nextjs-boilerplate` are curated starter templates, not
applications somebody built in an evening. The single silent app is one of them.

### Two more mount defects, both found by reading the per-repository lines

**`Moscow2260/ai-productivity-hub` was dropped from the denominator, and it is
the target user.** `.lovable/`, `vite.config.ts`, `"dev": "vite dev"`,
`src/routes/index.tsx` — a Lovable-generated TanStack Start app with no boundary
anywhere. Next.js is not the only framework that writes the mount for you; when
it does, the author's source has no `createRoot` and the app reads as a library.
Now recognized, paired: the framework dependency AND its routing directory,
because a package that merely depends on `@tanstack/react-router` is a consumer
of it while one that also carries a `routes/` tree is an application built with
it.

**`anxelswanz/astraea-agent` was excluded CORRECTLY**, and for a better reason
than the run knew: `ink`, `ink-text-input`, `cli-highlight`, a `repl` script — it
is React rendered to a terminal. There is no white page to prevent. Kept as a
test, because it is the shape most likely to be swept back in by a future
widening of the mount rule.

### What this decides

The plan asked whether a deterministic free tier would have anything to say on
most apps. On this question, with this corpus: **yes**, with an interval of
61–94% and a hand-checked centre of 89–92%.

That is one of the six rubric questions. Whether the tier is worth building
rests on two or three of them together, and the cost of the next one is now
known: about a day, most of it spent on the mount gate rather than the rule.

### Workspaces are analyzed now, so the interval can close

Naming the six as `workspace_not_analyzed` was honest and not enough: an
interval of 61–94% is not a measurement, it is a confession. Each react package
inside a workspace is now analyzed as the application it is.

Three decisions in it worth keeping:

* **One finding per application, not per repository.** A monorepo's apps are
  separate deployables that blank separately. Collapsing them would let a
  protected `apps/web` report an unprotected `apps/admin` as fine — the exact
  failure a repository-level verdict produces, and it has its own test.
* **The read budget is shared across packages.** Per-package budgets would let
  a six-application monorepo cost six times a single app's reading for one
  audit. The allowance is what we are willing to spend on a repository.
* **The finding's path carries the package prefix back**, so it names a file
  that exists in the repository rather than one relative to a root only the
  analyzer knows about.

And a defect the change introduced and the tests caught: `_Budget` took the
limits as plain dataclass defaults, which are evaluated when the class is
defined. The two budget tests kept passing while silently exercising the real
4000-file allowance instead of the small one they set. `default_factory` fixes
it, and the mutation that restores the plain default now turns them red.

## The analyzer is wired into the product, 2026-09-01

Five files arrived from a session that had no access to this repository,
carrying the integration this plan said would follow the number: the scanner
wired into `app/scan/static.py`, `coverage` consumed by the pipeline and the
scorer, Frontend removed from `LLM_ONLY_CATEGORIES`, and a Fix Pack that writes
`app/error.tsx` and `app/global-error.tsx` for the app-router shape. The design
is the one this plan asked for and it is taken.

It was reviewed against the code, not against its own report, and that report
says why it had to be: *"all edits tested in isolation from conftest"*. Four
existing tests failed on the full suite and one import broke everything that
transitively loads `app/db.py`. Each is recorded because each is a shape the
next hand-off will repeat.

**What the integration did not know about this repository**

* `RULE_ID` did not exist in `app/scan/error_boundary.py`. The Fix Pack
  imported it, `pipeline.py` imports the Fix Pack, `db.py` imports the
  pipeline — so nothing that touches the database imported at all.
* `AUDIT_ENGINE_VERSION` was not bumped. `tests/test_engine_version_pins_the_
  scanners.py` exists because this exact omission shipped three times and left
  cached audits serving pre-change results; it fails now, and the version is
  `2026-09-01-1`. The pin's stub also had to learn that this scanner returns a
  `BoundaryScan`, not a list.
* Three tests in `test_checks_scoring.py`, one in `test_llm_scan.py` and one in
  `test_partial_llm_stage.py` asserted Frontend as LLM-only by literal. The
  partial-stage test was the interesting one: it lost the *last* rubric, which
  is `web`, and its premise — "nothing looked at this category" — is simply
  false for Frontend now. It picks an LLM-only rubric by property instead.
* `_backfill_unexamined` in `db.py` derived the historical answer from the
  *live* constant, on the argument that the backfill must agree with a fresh
  audit. That argument inverted the day Frontend left the set: a row without an
  `unexamined` key predates this analyzer by weeks, and on the engine that
  scored it nothing looked at Frontend. The set is frozen to what it
  historically was, with the reason beside it.

**The citation was replaced, and then the replacement was corrected.** The
uploaded comments justified the scoring change with *"72 of 103 decided apps
(70%, 95% CI 60–78%) across the three-strata corpus"*. The first review wrote
that this could not be reproduced here. That was wrong: `scripts/data/` holds
the corpus — 540 candidates across the Lovable, bolt and hand-written strata,
already used by four `measure_*` scripts. What remains true is narrower: the
analyzer version behind that run is not in this repository, and its early
draft fired on component libraries (measured, 4 of 4 shapes), so 70% may be
inflated and may not. The code cites what this document measured — 11 of 12
mounted apps, the reputable hits read by hand, interval 61–94% — and
`measure_error_boundary.py --strata` now runs the shipping analyzer over the
same corpus so the three-strata figure can be reproduced rather than argued
about.

**The Fix Pack placed the boundary in the wrong directory for two of the
shapes measured this morning.** `error.tsx` only catches for the layout it sits
beside; for chatbot-ui's `app/[locale]/layout.tsx` the Pack wrote
`app/error.tsx`, outside that layout, catching nothing. And a workspace app's
`apps/web/app/layout.tsx` lost its prefix and produced `app/error.tsx` at the
repository root — a directory that was not the application. Both now resolve
from the finding's own path: `error.*` beside the layout, `global-error.*` at
the app root, prefix kept. The first fix of that introduced a third defect —
excluding route groups as if they were framework labels, which skipped
`ai-co-founder-matching`'s real root — and the test for it is in the file.

### The calibration check that must run BEFORE this deploys

Frontend joining the mean on static-only audits moves every free-tier headline
for a repository where the analyzer finds nothing: a Flask API now carries a
Frontend 10.0 at 15/110 of the weight. The earlier Frontend join measured its
own effect on the average (+0.29) before landing; this one must too, and it is
one query over the stored rows, an estimate that ignores the gate because the
gate scales both sides by the same factor:

```sql
with s as (
  select id,
         (score_json->'categories'->>'Security')::numeric as sec,
         (score_json->'categories'->>'Testing')::numeric  as tst,
         (score_json->'categories'->>'Deploy')::numeric   as dep
  from audits
  where score_json->>'basis' = 'static_only'
    and score_json->'categories' ? 'Security'
)
select count(*)                                                    as rows,
       round(avg((0.25*sec+0.15*tst+0.15*dep)/0.55), 2)             as old_mean,
       round(avg((0.25*sec+0.15*tst+0.15*dep+0.15*10)/0.70), 2)     as new_mean_if_clean,
       round(avg((0.25*sec+0.15*tst+0.15*dep+0.15*9.2)/0.70), 2)    as new_mean_if_missing
from s;
```

`new_mean_if_clean` is the ceiling of the shift (every repo with a boundary or
no frontend at all); `new_mean_if_missing` is the floor (every repo firing the
rule). The real figure sits between them at the corpus's incidence. If the
ceiling moves the average by more than the +0.29 the last category cost, that
is a calibration decision to make deliberately, not a side effect to ship.

**Run 2026-09-01 on the 34 stored static-only rows, before the deploy:**

| | mean |
|---|---|
| before | 8.78 |
| after, ceiling (every repo clean) | 9.04 (+0.26) |
| after, floor (every repo firing) | 8.87 (+0.09) |

Both bounds sit under the +0.29 the previous category cost, so the change
shipped. The real shift is between them: mounted apps fire at the measured
incidence and pull toward the floor, non-frontend repositories sit at the
ceiling. That second group is the next calibration question, recorded below.

**Still open, and now the next calibration decision rather than this one:**
whether a repository with no frontend at all (`mount = not_react`) should have
Frontend *excluded* as not-applicable rather than counted at 10.0. The `mount`
field carries exactly that signal. It would also change paid audits, where the
web rubric already counts an empty Frontend at 10.0 today, so it is its own
measurement against the stored rows.

## Result, 2026-09-03/04 — the interval closes to two floors, on the shipping analyzer

The 61–94% interval was a confession, not a measurement. Both corpora were
re-run with the analyzer that ships (workspaces analyzed per package), and the
interval closes to two agreeing floors.

```
--strata     PER_STRATUM=40, 119 of 120 resolved (1 gone)
  incidence among MOUNTED react/next apps: 72/83 = 87%   <- discovery corpus
    by stratum (fired / mounted):
      Lovable       29/32 = 91%
      bolt          25/28 = 89%
      hand-written  18/23 = 78%
  mount classes: mounted=83, no_mount=4, not_react=19, undetermined=13

--from-file  55 audited repos, 30 of 31 resolved before the anon quota reset
  incidence among MOUNTED react/next apps: 16/17 = 94%   <- product corpus
  mount classes: mounted=18, no_mount=2, not_react=10; undetermined=1
```

The discovery corpus (three strata in `scripts/data/`) and the product corpus
(repositories that actually came through drydock.co, dumped from `audits`)
agree: **~87–94% of mounted react/next apps ship no error boundary.** The
vibe-coded strata (Lovable 91%, bolt 89%) run higher than hand-written (78%),
which is now a number rather than an impression. The plan's question — would a
free deterministic tier have something to say about most apps it sees — is
answered yes on both corpora, not just the discovery list.

### Both numbers are FLOORS, and this belongs beside any quote of them

**Two** rules can silence this finding, and both are blind to where the
boundary actually sits:

* the **file** rule credited an `error.tsx`/`global-error.tsx` anywhere under
  an `app/` tree (`_APP_ERROR_FILE`, "any of them buys silence"); and
* the **token** rule credits a boundary token — `componentDidCatch`,
  `<ErrorBoundary`, `react-error-boundary`, … — found in **any source file at
  all** (`_BOUNDARY_TOKENS`, and `test_a_class_boundary_anywhere_silences_it`
  is where that leniency is deliberately written down).

The finding is about the *root* white page, and neither a nested `error.tsx`
nor a boundary component living inside one route covers the root layout or the
sibling routes. So an app protected in one place reads as `ok`, and the true
incidence is **≥** these figures. Of the two, the **token rule is the dominant
source of the gap** — see the correction below, which is how that was
established rather than assumed.

### Correction, 2026-09-04 — the two repositories named here were not the symptom

This section first named `elevate-for-humanity/Elevate-lms` and
`iBob78/Apex-collector` as apps credited `ok` on a boundary sitting segments
deep, and the follow-up PR claimed both would fire once the file rule was
anchored to the root. **Both claims were wrong, and both were inferred from a
single line of run output without reading the repositories.**

Replaying the corpus on identical commits with the tightened rule settled it:

| repository | before | after | verdict |
|---|---|---|---|
| `iBob78/Apex-collector` | `app-router error file: src/app/app/error.tsx` | `root app-router error file: **src/app/error.tsx**` | `ok` → `ok` |
| `elevate-for-humanity/Elevate-lms` | `app-router error file: …/barber-shop-applications/error.tsx` | `boundary token in …/blog/management/error.tsx` | `ok` → `ok` |

`Apex-collector` **always had a real root boundary**; the old rule merely named
whichever error file it reached first, and that was read as if it were the only
one. `Elevate-lms` is silenced by a boundary **token** in a nested file, so
anchoring the file rule moved nothing for it — when one lenient path stopped
crediting, the other picked it up immediately. That is the evidence for the
claim above that the token rule, not the file rule, is what holds these numbers
down.

The failure mode is the one this document keeps recording: a verdict inferred
from output that agreed with the expectation, and reality checked only
afterwards. The measurement below is what checking looked like.

### The refinement's measured effect: none

`--strata` replayed on the **same 119 pinned commits** as 2026-09-03, on the
tightened engine (`AUDIT_ENGINE_VERSION` 2026-09-04-1):

```
incidence among MOUNTED react/next apps: 72/83 = 87%     <- identical
mount classes: mounted=83, no_mount=4, not_react=19, undetermined=13
```

Byte-identical inputs, byte-identical outcome: **zero verdicts changed**, two
reason strings changed (the table above). The tightening forbids a class of
false negative that this corpus does not happen to contain.

That is a reason to keep the rule — a nested `error.tsx` genuinely does not
cover the root, and the negative control confirms legitimate root boundaries
(`Next-js-Boilerplate`'s `src/app/global-error.tsx`) are still credited — but
it is **not** a reason to claim the change found anything. The engine-version
bump remains correct regardless: the rule *can* change a verdict on a
repository whose only boundary is nested and tokenless, and cached results must
not straddle a rule change.

The floors themselves are unmoved and their "≥" stands, now for the right
reason.

### The reputable hits reconfirm live

`vercel/nextjs-subscription-payments`, `Blazity/next-enterprise` and
`mckaywrigley/chatbot-ui` — hand-checked on 2026-09-01 — fire again in these
runs without a hand check, and `ixartz/Next-js-Boilerplate` is a genuine `ok`
on a *root* `src/app/global-error.tsx` (the shape the refinement will keep). A
30k-star chat app, an "enterprise" starter, and Vercel's own template are still
the analyzer's hits, not its mistakes.

### What the numbers do NOT support

* **Our own repositories are in the product corpus.** `aiagent2046-coder/shipit`
  (its `web/` app fires — our own frontend has no boundary, worth fixing),
  `ai-co-founder-matching`, both `devtools-aggregator` forks, and the
  `donjonson-hash` dev account. `--from-file` is a real denominator but a small
  and self-contaminated one (n=17), so 94% is a floor with a wide interval; the
  discovery corpus's 87% on n=83 is the sturdier number.
* **`dubinc/dub` is UNDETERMINED, not clean.** A 3587-file `apps/web` exhausted
  the shared 4000-file read budget, so it is reported as budget-exhausted and
  excluded from the denominator — the separate signal, never counted as "has a
  boundary."
* **The product run was rate-limited**, resolving 30 of 31 anonymously (the
  strata run had spent the hour's 60). Re-running after the reset with a
  `GITHUB_TOKEN` would add the one unresolved repo; the incidence is not
  expected to move on n that small.

### The error-file root-scoping refinement landed, 2026-09-04 (`AUDIT_ENGINE_VERSION` 2026-09-04-1)

`_APP_ERROR_FILE` became `_ROOT_APP_ERROR`, anchored exactly like
`_ROOT_APP_LAYOUT`: only an `error.tsx`/`global-error.tsx` at the app root —
through route groups `(group)` and dynamic segments `[param]` — silences the
finding. A plain named segment (`app/dashboard/error.tsx`) no longer does,
because it catches only its own subtree while the root layout and sibling
routes still blank. The route-group and dynamic-segment roots that `chatbot-ui`
and `Next-js-Boilerplate` use stay credited. Fixtures for all four cases are in
`tests/test_error_boundary.py`, and the version pin moved.

**This section first claimed the two 2026-09-03 hits (`Elevate-lms`,
`Apex-collector`) "fire now". They do not** — see the correction above. Neither
was a false negative of the file rule, and the replay on identical commits
moved no verdict at all. The rule is kept on its own correctness, not on a
result it did not produce.

**No re-calibration gate.** The change only makes the rule fire more (an app
credited on a nested boundary now fires), which moves a static-only score
toward the already-measured floor (8.87, +0.09), never past the ceiling (9.04,
+0.26) that the Frontend join was gated on. It stays inside the envelope
already approved, so it ships on the same calibration.

The reported floors do not move retroactively — they were measured on the
lenient rule, so the true incidence is at or above them, exactly as recorded.
A re-run on the tightened rule would raise them; it is not re-run here because
the floors already carry that "≥" honestly.

### Still open, carried forward

* **`mount = not_react` Frontend exclusion** — the calibration question recorded
  in the section above, unchanged by this run.

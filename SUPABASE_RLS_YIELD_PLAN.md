# Supabase RLS exposure: the measurement before the feature

The runtime-CORS experiment (PROOF_RUNTIME_CORS_PLAN.md) came back 0 of 26 and
taught one thing worth more than the zero: the runtime-proof idea is right, but
the target was wrong for this market. We tried to *build and boot the
customer's code*. Vibe-coded apps are already deployed — Vercel + Supabase,
with the anon key committed in the repo — so the proof that fits this market
hits the **already-running deployment**, not a container we have to build.

The most common real hole in that stack is a Supabase table with Row Level
Security misconfigured, so the public anon key reads rows that were never meant
to be public. This document is the measurement that decides whether that is a
feature or another 0 of 26. **Nothing gets built before the number exists** —
that rule is the one thing every prior experiment here confirmed the hard way.

## The claim we would eventually want to make

> "We did not guess your data was exposed. We read three of your rows through
> the front door with the public key from your own repo, redacted them, and put
> the shape in the report. The Fix Pack enabled RLS, and the same request now
> returns nothing."

Verifiable before/after against the live project, no scanner opinion. That is
the differentiator. The measurement's only job is to find out how often the
"before" half is actually true across real repos.

## The hard constraint, stated first because it shapes everything

**The measurement must not read rows from a Supabase project we do not own.**

A committed anon key lets anyone query that project's PostgREST endpoint. The
key is public by design (it ships to the browser); using it is trivial. But the
*project* belongs to a stranger, and querying their live database without their
consent is the exact thing PROOF_RUNTIME_CORS_PLAN.md ruled out of scope for
"live secret validation": a request to a third party's system, with legal
consequences, that a measurement has no standing to make. The whole product
premise is that the probe runs **with the customer's consent on the customer's
own project** — a premise a survey of strangers' repos cannot borrow.

So the measurement splits into three parts with three different rights to act:

| part | question | what it may touch |
|---|---|---|
| **A. Prevalence** | how often is the misconfiguration *present*? | the repo's own committed SQL — no live contact |
| **B. Oracle / e2e** | does our prover correctly call it a hole vs. a public API? | a Supabase we stand up and seed ourselves |
| **C. Live yield** | end to end on a real deployment | only a project we own, or a consented customer |

Part A produces the go/no-go number. Part B proves the prover. Part C is
deferred and never runs against a project without confirmed ownership.

## Part A — prevalence, from the repo's own schema (no live contact)

Supabase projects overwhelmingly commit their schema: `supabase/migrations/*.sql`,
a `schema.sql`, or the dashboard's SQL export. RLS state is *in that SQL* —
`ALTER TABLE <t> ENABLE ROW LEVEL SECURITY`, `CREATE POLICY …`. That makes the
misconfiguration measurable without querying anyone's database.

### The oracle — and its two traps, which are the whole point

This is where the measurement becomes the defect this project has fixed
repeatedly (CORS `*`-without-credentials scored as a hole; static scan 9.9 over
an RCE). A number that counts the wrong thing is worse than no number.

A table is **exposed** only when all three hold:
1. **It holds data the app treats as private.** Heuristic over column/table
   names: `email`, `phone`, `address`, `password`, `*_token`, `stripe_*`,
   `user_id` FKs; tables `users`, `profiles`, `accounts`, `orders`, `payments`,
   `messages`, `sessions`. NOT `posts`, `products`, `blog`, `public_*`.
2. **The anon role can read it.** Which means either:
   * RLS is never enabled on the table (`ENABLE ROW LEVEL SECURITY` absent), or
   * RLS is enabled but a policy is effectively public — `USING (true)`,
     `USING (1=1)`, or a `TO public/anon` policy with no predicate. **RLS-on is
     necessary, not sufficient**; a permissive policy is the same hole wearing a
     seatbelt. A measurement that only greps for `ENABLE ROW LEVEL SECURITY`
     will call these secure and undercount the real rate.
3. **It is reachable through PostgREST** — a table in an exposed schema
   (`public`), not an internal one.

Anything failing (1) is a **public API, not a hole** — the direct analogue of
`blank-slate`'s credential-less `*`. The oracle must say nothing about it, out
loud, the way the CORS oracle does.

### The denominator trap

A repo that does NOT commit its schema is not "secure" — it is **"cannot be
determined statically"**, exactly the disjoint-population problem the CORS
detector hit. Part A therefore reports two numbers, never one:
* exposed / repos-with-committed-schema (the measurable rate), and
* repos-with-no-committed-schema / corpus (the blind spot the live probe exists
  to cover).

Collapsing these into a single "% vulnerable" would repeat the CORS mistake of
implying a method saw a population it structurally cannot.

### The corpus

10–12 vibe-coded repos that actually use Supabase, chosen by structure not by
their RLS state, SHAs pinned (the lesson `batch_audit.py` paid for). Sources:
GitHub search for `@supabase/supabase-js` in repos tagged/described as
Lovable / bolt.new / v0 / Cursor output, plus any Supabase-using repo already
in our fixtures. A repo qualifies if it ships a Supabase client AND a project
ref; it is *measurable* only if it also commits schema SQL.

### The script — `scripts/measure_supabase_rls_yield.py`

Pure static, zero network, costs nothing. Walks the funnel and prints where it
goes silent, same shape as `measure_runtime_cors_yield.py`:

```
repos in corpus                     : N
  uses Supabase                     : …
    commits its own schema          : …   ← the measurable denominator
      has a PII-shaped table        : …
        that table anon-readable    : …   ← RLS off OR permissive policy
          => exposed (the number)   : …
  no committed schema (blind spot)  : …   ← reported, never counted as secure
```

Parsing: a small SQL reader for `CREATE TABLE`, `ALTER TABLE … ENABLE ROW LEVEL
SECURITY`, and `CREATE POLICY`, enough to answer (1)+(2). Not a full SQL
parser — it reads migrations, which are a narrow, generated dialect. Every
"exposed" verdict prints the table and the reason (`no RLS` / `USING(true)`) so
a human can spot-check, because a regex over SQL is exactly the kind of thing
that looks right and counts wrong.

## Part B — the oracle end to end, on a stand we own

Mirror `scripts/e2e_proof_cors_probe.py`: prove the *live* prover before
trusting it, against a Supabase we control and no one else's.

The Supabase CLI ships a full local stack (`supabase start` → Postgres +
PostgREST + the anon key). Seed a `users` table with fabricated PII, in two
variants:
* **vulnerable**: RLS off (or `USING (true)`) — anon `select` returns the rows.
* **patched**: RLS on with `USING (auth.uid() = id)` — anon `select` returns
  `[]`.

Assert success → failure through the existing `app/proof/compare.build_proof_report`,
the same function the CORS pair uses. This validates the oracle and the
before/after with zero third-party contact, and it is the artifact that lets us
claim the prover works without ever having pointed it at a stranger.

The live probe itself is a single authenticated-as-anon REST call:
`GET {project}/rest/v1/{table}?select=*&limit=3` with `apikey`/`Authorization:
Bearer {anon}`. No sandbox, no docker, no build — which is why this whole class
sidesteps every barrier the CORS detector died on.

## Discipline carried over from the proof layer

* **Sample-and-redact, never store.** At most 3 rows, PII masked at the column
  level before anything leaves the probe. The report records the *shape*
  ("anon read 3 rows from `users`, columns include `email`, `stripe_customer_id`"),
  never the values.
* **Raw rows are diagnostics, not evidence.** `proof_json` is rendered into a
  PR; a customer's user data must never reach it — the same wall
  `app/proof/types.py` puts up, and the reason the CORS probe forbids response
  bodies in evidence.
* **`error` ≠ `failure`.** A project that 404s, times out, or rejects the key
  tells us nothing and is `error`; only an anon read that genuinely returns no
  rows against a live, reachable table is `failure` ("checked, not exposed").

## What must NOT be said, in advance

* That committing an anon key is itself the finding. It is not a secret; the
  finding is what RLS does or does not do behind it. Conflating the two would
  be the inverse of the CORS `*`-credentials error.
* That a repo with RLS enabled is safe. A `USING (true)` policy is RLS enabled
  and wide open.
* Any live number, in marketing or a report, drawn from a project we do not
  own. Part C is the only source of a real end-to-end yield, and it is gated on
  consent.

## Part B result, measured 2026-08-18

Run against a real Postgres + PostgREST on the host (`scripts/e2e_proof_rls_probe.py`):

```
BEFORE: status=success  анонимный ключ прочитал 3 строк(и) из `founders`
        rows_read=3 columns=[id, email, phone, sentiment]
        shapes={id: str(36), email: str(19), phone: str(12), sentiment: str(8)}
AFTER : status=failure  анонимный запрос вернул пустой результат
        rows_read=0  alone_proves_nothing=True
verified=True  exploit succeeded before, failed after
```

`email: str(19)` is the length of the fabricated address in the fixture, which
is how the run shows it read the rows rather than reporting that it did. No
value reached the evidence.

**It passed on the first attempt, which is worth less than the CORS e2e
failing on its first.** That one earned its keep immediately by catching a
missing Cookie; this one has never been seen to go red, and a green that has
never been red proves only that the script ran. So the e2e now has a NEGATIVE
CONTROL — `NEGATIVE_CONTROL=1` skips the fix and the run must FAIL — and CI
executes both directions on every change to the probe, the oracle, `compare.py`
or `types.py`. Same shape as the `TMPDIR=/tmp` control that guards the runner's
bind-mount test.

**Part B is closed.** The prover works, and it was proven without pointing it
at anyone: fabricated data, our own throwaway containers, no customer's key,
no live project.

### The two rules that live in code rather than in this document

A plan cannot stop a caller and a default can, so both are branches with tests
and every one is mutation-checked:

* **`consent` has no default.** A caller that has not thought about it cannot
  accidentally read a real person's database, and the result is `skipped` —
  never `failure`, because "the attack did not work" over a check that never
  ran is the inflation removed twice already.
* **The URL is not the repository's to choose.** It is read out of the
  customer's own source, so an unrestricted request is an SSRF primitive: a
  repo could aim our infrastructure at a metadata endpoint or an internal
  service and collect the answer. Only `https://<ref>.supabase.co` is accepted;
  loopback needs a flag production never sets. The table name is validated too
  — it comes from parsed customer SQL and goes into the request path.

### What PostgREST actually does, recorded because the intuition is wrong

RLS **filters** rows, it does not deny. A correctly secured table answers
`200 []`, not `403`. Anyone expecting a denial reads the normal secure case as
an error and the exposed case as normal — and `200 []` is also what an EMPTY
table returns, which is why `empty_result` carries `alone_proves_nothing` and
means something only as the after half of a pair whose before half read real
rows out of that same table.

## Part C result, measured 2026-08-18 — and it contradicts Part A

Run against our own project (`egoprezwkjaqacxtjwfl`), owner consenting, three
rows maximum, no value stored.

| table | rows in DB | anon read | verdict |
|---|---|---|---|
| `agent_projects` | 14 | **3** | **EXPOSED** — real rows returned |
| `founder_profiles` | 24 | 0 | protected — ambiguity resolved by the row count |
| `avatar_interactions` | 0 | 0 | undetermined — the table is empty |

`agent_projects` handed a public key `idea` (111 chars), `summary` (220),
`domain` and the match it belongs to: startup ideas and model-written debriefs
of founder conversations, readable by any visitor.

### Static was wrong on both counts, in both directions

| table | Part A, from committed migrations | Part C, live |
|---|---|---|
| `founder_profiles` | EXPOSED (`USING (true)`) | **protected** — false positive |
| `avatar_interactions` | EXPOSED (RLS never enabled) | RLS **is** enabled live — false positive |
| `agent_projects` | **never seen** | EXPOSED |

The migrations in the repository do not describe the deployment. Both static
findings are stale, and the one real exposure sits in a table that is not in
the migrations at all — created through the dashboard or some other path, so no
amount of SQL parsing could have found it.

The oracle's heuristics were not the problem: `agent_projects` carries
`summary`, which is a STRONG hint, so it WOULD have been flagged had it been in
the input. The input was incomplete, which is a different failure and not one
better patterns can fix.

### What this does and does not prove

n = 1 project. One deployment drifting from its migrations does not establish
that all do, and this is our own project rather than a customer's.

But the direction is what matters: static erred **both ways at once** — two
false positives and one miss — and the miss was invisible by construction. So
the Part A rate (2 of 4) is a statement about repositories, not deployments,
and it must never be quoted as the second. That distinction was already written
into this plan; what is new is knowing how large the gap can be.

### The consequence for the product

A static RLS finding cannot be shipped to a customer as "your data is exposed".
On the only deployment we have been able to check, that sentence would have
been wrong twice and silent about the one case that was true. It can be shipped
as "your committed migrations say X — here is a one-request check against your
deployment", which is the live probe, and which is why it exists.

The `empty_result` caveat also earned itself here. `founder_profiles` returned
nothing, and that only became "protected" because an independent row count said
the table holds 24 rows. `avatar_interactions` returned the identical answer
and stays undetermined, because it is empty. Same response, two different
truths — exactly what `alone_proves_nothing` is for.

### The first verified before/after on a live deployment

| | anon reads | rows in table |
|---|---|---|
| before | **3** (`idea`, `summary`, `domain`, …) | 14 |
| after `enable_rls_on_agent_projects` | **0** | 14 |

The fix is the policy `messages_select` already uses, pointed at the same
`match_id`: readable by the two founders in that match and nobody else.

Two checks separate a fix from breakage, and both were run:

* **the rows are still there** — 14 before, 14 after. A table emptied by a
  migration would give the same probe result and none of the value.
* **a legitimate participant still sees their own** — simulated as
  `authenticated` with a real participant's `sub`: 3 of 14 visible, which is
  their matches. Enabling RLS without a workable policy closes the table to the
  application too, and that failure surfaces in production rather than here.

The `empty_result` ambiguity resolves itself in this pair without any
out-of-band help: the BEFORE half read real rows out of that same table, so the
after half returning none is a change rather than an empty table. The
independent row count was belt-and-braces, not the proof.

So the claim at the top of this document is now literally true, once, on a real
deployment:

> "We did not guess your data was exposed. We read three of your rows through
> the front door with the public key from your own repo… The Fix Pack enabled
> RLS, and the same request now returns nothing."

What remains unproven is that it generalises. One project, ours, and the fix
was applied by hand rather than by a Fix Pack. The class is real; the pipeline
around it is not built.

## Not in scope (yet)

* **Part C live yield** against real deployments — deferred until Part A clears
  the bar and Part B proves the prover, and then only on owned/consented
  projects.
* **Write probes** (anon `INSERT`/`UPDATE`) — a genuine and common RLS hole,
  but a write touches state even on a consented project; read-only first.
* **Storage buckets and Edge Functions** — same live-target family, worth their
  own measurement once the read-RLS number exists. One class at a time, each
  with its own number.

## The decision this produces

If Part A comes back like CORS — 1 in 9 — the class is rare and this ends here,
cheaply, having cost a day of static parsing and no live contact. If it comes
back 5+ in 9, there is a real feature, and Part B is the next build. Either way
the number comes first.

---

## Part A result, measured 2026-08-17

| stage | count |
|---|---|
| repos examined | 9 |
| uses Supabase | **7 (78%)** |
| commits its own schema | 4 (57% of those) |
| has a private-shaped table | 4 |
| anon can read one | **2** |

**Exposure rate: 2 of 4** repos whose schema can be read.
**Blind spot: 3 of 7** Supabase repos commit no schema — undetermined, not
secure, and precisely the population Part C exists for.

This is the opposite of the CORS result, and the applicability number carries
it: 78% of this corpus uses Supabase at all, against a CORS shape that turned
out to be genuinely rare. **Go.**

### The findings, and why they are not heuristic

Both are the same shape, and the evidence is the author's own words:

```sql
-- servexaapp
CREATE POLICY "Anyone can view an invitation by token (validated in code)"
  ON public.organisation_invitations FOR SELECT USING (true);
CREATE POLICY "Public can read by token"
  ON public.handover_tokens FOR SELECT TO anon, authenticated USING (true);
```

The names promise a scope the predicates do not enforce. The developer
believes the token gates the read — `.eq('token', …)` in client code — and the
database was never told, so the anon key returns **every invitation with its
email address** and **every handover token**. That is not an inference about
what data looks sensitive; it is a documented intent-implementation mismatch,
and the oracle now reports it as such (`intent_mismatch`).

### A correction the first run forced, and what it did NOT clear

`founder_profiles` in our own customer's repo was flagged on the column
`user_id`. That was indefensible: nearly every table in a multi-tenant app
carries it, public ones included, so it cannot distinguish a leak from a
directory. `user_id`, `owner_id`, `notes`, `content` are now WEAK hints
yielding **`uncertain`** — printed for a human, kept out of the count. The
verdict has three states because two forced this table into a bucket where
both answers were wrong.

**The correction changed the reason and not the verdict.** Re-run, the table is
still counted — on `birth_month`, a STRONG hint. The tightening was real
(private-table counts fell from 56 to 21 and 84 to 52 across the two large
schemas), and it did not clear this finding: a table declared world-readable
that carries a fragment of a date of birth is a defensible observation, and an
earlier read of it as "almost certainly a false positive" was wrong.

But it is not the same KIND of finding as servexaapp's, and the summary now
says so. An intent mismatch is the author contradicting their own predicate —
provable as a bug without knowing anything about the product. A deliberate
public policy over a table that happens to carry PII is a judgement about what
the customer meant to publish: worth telling them, in a different sentence.
Reporting both as "your data is exposed" is how a true finding and a debatable
one arrive with equal weight and the reader ends up trusting neither.

A second false-positive path was found the same way, before it could be
quoted: `ALTER TABLE IF EXISTS … ENABLE ROW LEVEL SECURITY` went unmatched, so
any table protected that way read as "RLS never enabled".

### Reading `avatar_interactions` — and the class the hints did not model

`uncertain` did its job: it sent someone to look, and looking changed the
answer. The table is

```sql
user_id    uuid NOT NULL REFERENCES auth.users(id),
match_id   uuid NOT NULL REFERENCES public.matches(id),
summary    text,      key_points   text[],
next_actions text[],  sentiment    text
```

— a model-written debrief of a conversation between two matched founders:
what was said, what to do next, and **how one of them feels about the other**.
RLS never enabled, so the anon key returns that for every user. It is arguably
the most sensitive table in the application, and the oracle had shrugged at it
because the only name it recognised was `user_id`.

The miss was not "user_id should be strong". It was a whole missing class:
**model-derived judgements about people**. In an AI product the most sensitive
rows are rarely the profile — they are what the model concluded about someone,
and a leaked `sentiment` toward another user is worse than a leaked email
address. That class is what this market is made of, so `sentiment`, `summary`,
`transcript`, `analysis`, `assessment`, `key_points`, `insight`,
`recommendation`, `diagnosis`, `evaluation` are now STRONG.

Reading the DDL also produced a better signal than any name list:
**`REFERENCES auth.users`**. That is structural — it says the row belongs to
one authenticated person — and paired with any free-text column it means anon
reading the table crosses tenants. It replaces `user_id` as the deciding
ownership signal, being the thing `user_id` was a bad proxy for.

The pairing is load-bearing in both directions: the FK alone convicted a
two-column join table in the first draft, because `_has_free_text` was asking
the wrong list and `user_id` satisfied both halves by itself.

### The number held while the oracle changed underneath it

Three runs, with the oracle tightened once (weak hints demoted) and widened
twice (the AI-judgement class, the auth.users key). The headline did not move:

| | run 1 | run 2 | run 3 |
|---|---|---|---|
| uses Supabase | 7/9 | 7/9 | 7/9 |
| exposed / measurable | 2/4 | 2/4 | 2/4 |
| blind spot | 3/7 | 3/7 | 3/7 |

What moved is completeness *inside* the repositories — private-table counts
went 56 → 21 → 32 for blank-slate and 84 → 52 → 61 for servexaapp as the hints
were corrected in both directions — and which tables are named. A rate that
survives its own oracle being rewritten twice is the reproducibility check the
CORS measurement did not get until late.

`blank-slate` is the strongest single evidence that this oracle can say NO: 140
tables, 32 of them private-shaped, zero exposed. And its one `uncertain` —
`airspace_layers`, open, carrying only `description` — is public aviation
reference data, correctly kept out of the count by the third state.

**Part A is closed. Go.**

### What this changes about Part C

The customer repo is the natural first live target: we have the relationship,
so consent can actually be asked for, which no repository in a survey can
offer. That is the only route to an end-to-end number, and it stays gated on
their explicit yes.

---

## The blind spot, measured 2026-08-18 on n = 199

Part A left the coverage question answered by **3 of 7**. That is not a rate:
its 95% interval runs 16%–84%, which spans "static analysis covers most of this
market" and "static analysis covers almost none of it". Those are different
products. `scripts/measure_rls_blind_spot.py` replaces the 7.

| stage | count |
|---|---|
| candidates from GitHub code search | 199 |
| not inspected (gone / failed) | 0 |
| carries `lovable-tagger`, verified in-repo | 195 |
| uses `@supabase/supabase-js` | 76/195 = 39% [32–46%] |
| **commits its schema** | **52/76 = 68% [57–78%]** |
| **commits NO schema — the blind spot** | **24/76 = 32% [22–43%]** |

**Static analysis can see the schema in roughly two thirds of this market.**
The old 3-of-7 (43%) sits inside the new interval, so nothing is contradicted —
what changed is that the answer is now precise enough to act on. Of the 24
blind repos, 15 carry a `supabase/` directory with no schema SQL in it: the CLI
or the dashboard was used, and the tables live only in the project.

Secondary, within the 52 whose schema can be read — and a statement about
**repositories**, never deployments, per Part C:

| | repos |
|---|---|
| a private-shaped table is anon-readable | 22/52 = 42% [30–56%] |
| a table is anon-writable | 24/52 = 46% [33–59%] |

### What the sample is, and what it is not

Discovery was GitHub code search for `lovable-tagger`, pages 1–2 in the order
returned, deduped by repository. Membership was then re-decided by reading each
repository's own `package.json` out of the pinned tree — search says where to
look and is not trusted for what is there; four hits dropped out that way.

Every number above is conditional on **"generated by Lovable"**. The 9-repo
corpus in `measure_supabase_rls_yield.py` remains the only unfiltered one — it
was assembled in July for the CORS experiment, so it cannot have been selected
on its RLS state. The two must not be pooled.

GitHub's relevance ordering is not a uniform sample and there is no way to draw
one. What can be said is that nothing in that ranking is plausibly correlated
with whether a repo commits migrations, which is the only quantity at stake.

Two sampling decisions point straight at the measured quantity, so both are
deliberate and written into the code. The generator marker is read from any
`package.json` **variant**, backups included — dropping repos whose manifest
was hand-edited would select for untouched scaffolding, plausibly the half
least likely to have acquired committed migrations. The Supabase dependency is
read only from a current `package.json`, where a stale copy is the wrong
evidence in the other direction.

### The run's real payoff: three false-positive classes in shipped code

The number was the reason to run it. The findings below are worth more.

**1. `DROP POLICY` was not read.** One repository carried, in
`supabase/migrations/archive/`, a `FOR INSERT TO anon … WITH CHECK (true)` on a
KYC document table — and, four migrations later, the developer's own
`DROP POLICY IF EXISTS`. We would have reported the hole its owner had already
closed, citing a file inside a directory named `archive`. Not a guess that
missed: a confident accusation the customer's own commit refutes.
`DISABLE ROW LEVEL SECURITY` had the same gap, pointing the other way.

Both were unfixable in the old shape — `parse_schema` ran three independent
passes over the text, and no set of statements can express one being undone.
Statements are now applied **in order**.

**2. The order files were read in was wrong.** The same repository keeps 258
superseded migrations in `migrations/archive/` beside 50 live ones. Sorted by
full path, `…/archive/2025…` lands *after* `…/2026…` because "a" is greater
than "2" — the oldest migrations applied last, the schema reading like 2025.
The timestamp prefix is what encodes time, and it is in the filename.

Alongside it, the two spellings of a repeated `CREATE TABLE` now mean what they
mean in Postgres: `IF NOT EXISTS` merges (an idempotent migration exists to do
nothing, and resetting on it fabricated an exposure out of a no-op), a plain
re-CREATE resets (a pg_dump or squashed baseline restates the schema, and
merging left a 2026 baseline carrying 2025 policies it existed to replace).

On that repository: **15 read + 46 write findings before, 11 + 17 after.** The
survivors were checked by hand and are real — `anon_select_customers … TO anon
USING (true)`, and an `"Admin can view suppliers"` policy with no `TO` clause
and no predicate, which is the intent-mismatch class Part A documented.

**3. Comments were parsed as SQL.** A header reading
`-- CREATE TABLE STATEMENT (generated)` produced a table named `statement`, and
its `(` opened a body that ran to the next `);`, swallowing the real
`CREATE TABLE` underneath — so a table the customer has vanished from the
schema. Both directions again: a commented-out `ENABLE ROW LEVEL SECURITY`
counted as protection, a commented-out permissive policy counted as a hole.

Dollar-quoted bodies are passed over intact rather than dropped, because
Supabase migrations routinely wrap real policies in `DO $$ … END $$;`.

Twelve mutants across the three fixes, all caught. One survived its first test
— being "inside a string" does not stop a regex from matching text nobody
blanked, so the assertion had to turn on a commented-out `ENABLE` instead.

### What this does not settle

* **Nothing about deployments.** Part C stands: on the one project we could
  check, the committed migrations were wrong about two tables and silent about
  the one that was open. 42% is a statement about repositories.
* **Nothing about non-Lovable generators.** bolt.new, v0 and Cursor output are
  unmeasured, and a generator's scaffold plausibly decides whether migrations
  get committed at all.
* **Presentation is now a real problem.** The heaviest repository produces 33
  RLS findings, the median affected one produces 3. A report with 33 of
  anything is unread. Grouping is a product decision and is not made here.

---

## Does the generator decide it? Three strata, measured 2026-08-18

The 68% above is conditional on "generated by Lovable", and a generator's
scaffold plausibly decides whether migrations get committed at all. Two more
strata make that testable: bolt, and a control of Supabase projects carrying no
generator marker.

| stratum | candidates | members | uses Supabase | **commits schema** | blind spot |
|---|---|---|---|---|---|
| Lovable (`lovable-tagger`) | 199 | 195 | 76 = 39% | **52/76 = 68%** [57–78] | 24/76 = 32% [22–43] |
| bolt (`.bolt/`) | 199 | 199 | 73 = 37% | **55/73 = 75%** [64–84] | 18/73 = 25% [16–36] |
| no generator marker | 97 | 89 | 77 (entry) | **45/77 = 58%** [47–69] | 32/77 = 42% [31–53] |

```
lovable vs bolt        p = 0.348   not distinguishable
lovable vs control     p = 0.200   not distinguishable
bolt    vs control     p = 0.028   below 0.05, NOT below the corrected threshold
```

**No, it does not.** Three comparisons were made, so the threshold is 0.05/3 =
0.017, not 0.05 — three tests at 0.05 each carry a 14% chance of at least one
false positive when nothing differs at all, and one p just under 0.05 out of
three is the expected amount of noise. The script printed "distinguishable" for
0.028 on its first run and now does not.

This is a useful negative. All three strata sit in a 58–75% band, so **the 68%
measured on Lovable generalises further than it had any right to** — the blind
spot is roughly a quarter to two fifths of Supabase projects however they were
built. The secondary exposure rates hold up the same way: 42% / 42% / 51%
anon-readable and 46% / 51% / 56% anon-writable across the three.

### Entry criteria differ, so the strata are not pooled

Lovable and bolt are drawn on a **generator** marker, which leaves "uses
Supabase" a funnel stage whose rate means something — 39% and 37%, reassuringly
close. The control is drawn on the Supabase dependency **itself**, so that rate
is how the sample was built and is not reported as a finding. The conditional
rate — given Supabase, is the schema committed — is the same question in all
three, which is why it is the one compared.

The control is defined by absence, so it carries the exclusions: 8 of its 89
members turned out to be Lovable or bolt output and were dropped. bolt
membership is the `.bolt/` scaffolding directory, structural and in the tree.
It does not separate bolt.new from bolt.diy, and several candidates are plainly
forks of the tool rather than apps built with it; the Supabase stage removes
most of those anyway.

### What differs is the SHAPE of the blindness, not its frequency

| stratum | blind repos carrying `supabase/` with no SQL in it |
|---|---|
| Lovable | **15/24 = 62%** |
| bolt | 3/18 = 17% |
| control | 4/32 = 12% |

Large (p ≈ 0.00002) — and **post hoc**. It was not the question this run went
looking for; it was seen in the results, so it generates a hypothesis rather
than confirming one, and it needs a fresh sample before it is quoted.

If it holds, it is directly actionable. "A live Supabase project is configured
here and its tables are written down nowhere" is a different state from
"Supabase does not really appear in this repository", and only the first is a
case where offering the live probe makes sense. Lovable puts most of its blind
repos in the first state; the other two put most of theirs in the second.

### Still unmeasured

v0 (its marker is recognised only so the control can exclude it), Cursor, and
Replit. And the whole thing remains a statement about repositories: Part C's
n = 1 is unchanged, and nothing here says what any deployment actually does.

---

## The first end-to-end run of the shipped pipeline, 2026-08-18

Migration 0031 applied (backup verified, 31 of 31, `State: OK`), then the probe
run against our own project with consent — the first time the pieces built in
#285–#291 were exercised together against a live database.

Nine tables asked, nine `200 []`. That result **on its own establishes almost
nothing**, and the run is a good demonstration of why `alone_proves_nothing`
exists: an empty answer from a protected table and an empty answer from an
empty table are the same bytes. What separates them is an independent row
count, taken through the service role on a project we own.

| table | rows | anon read | verdict |
|---|---|---|---|
| `messages` | 1939 | 0 | protected |
| `swipes` | 81 | 0 | protected |
| `founder_profiles` | 24 | 0 | protected |
| `agent_messages` | 20 | 0 | protected |
| `video_rooms` | 15 | 0 | protected |
| `matches` | 14 | 0 | protected |
| `agent_context` | 1 | 0 | protected |
| `github_connections` | 1 | 0 | protected |
| `avatar_interactions` | 0 | 0 | **undetermined — the table is empty** |

Eight of nine settled. `founder_profiles` matches Part C exactly (24 rows, anon
reads 0), which is the only independent cross-check available and it agrees.

The key was accepted: a rejected one answers 401 and the oracle returns
`error`, not `failure`. That distinction is what makes the nine `failure`s
readable at all.

### The measured ceiling of a repository-derived table list

The project has **11** public tables. The probe asked about **9**. It did not
ask about:

* **`agent_projects`** — 14 rows, RLS on, one policy. The only table ever found
  genuinely exposed on this deployment, and the one we closed in Part C. It
  appears in neither the migrations nor the client code, so **the probe would
  never have asked about it**.
* `tool_events` — empty, RLS on, no policies (default deny).

Part C established that static analysis could not see this table. This run
establishes that the *live probe*, given table names from the same repository,
cannot either. The client-code source added in #291 rescues the case where the
schema is uncommitted; it does not rescue the case where nothing in the
repository names the table at all.

**The wording consequence is not optional.** A report may say "we checked the
N tables we could name from your repository". It may not say "we checked your
tables". `not_checked` names what did not fit under the request ceiling — a
table we never found cannot appear there by construction, which is exactly the
gap a customer would otherwise read as covered.

### What would close it, and what would not

Not enumeration: PostgREST's OpenAPI document is refused to the anon key
(recorded above), and the only credential that could list the tables is the
one we refuse to send anywhere.

The remaining honest routes are asking the customer for names, or reading them
from a Supabase session they authorise separately. Both are new decisions with
their own consent questions, and neither is made here.

### What the endpoint run added, 2026-08-18

The layer-level run above went straight to the probe. Running the same check
through `POST /v1/rls-check` closed the last gap — the consent ledger, which
nothing before it could exercise. Two rows, both closed: the `checked` run with
nine tables, and a `refused` one from a masked key paste. **A refusal is
recorded**, which was the behaviour the tests asserted and the ledger now
demonstrates.

The masked-key guard added the same day fired on its first real use, naming
the cause instead of surfacing as a request failure. That paste has now failed
three times in this project and produced three different symptoms; only the
third was legible.

**And the run exposed a defect in the response itself.** The summary read

    "exposed_tables": [],
    "inconclusive": 0,

over nine attempts that each carried `alone_proves_nothing`. Both numbers were
correct and the pair reads as "nothing open, everything settled". What
actually settled that run was a row count through the service role — which a
customer does not have.

`empty_but_unproven` now sits beside the other two counts. It counts only the
`failure`s that carry the caveat: a database that REFUSED the key (`42501`)
and a table PostgREST does not expose are also `failure`, they stand on their
own, and counting them would file every correctly-locked table under "we could
not tell". That control is a test, because without it the counter would be a
worse lie than the omission it fixes.

---

## A third source of table names, measured 2026-08-18

The probe can only ask about tables something in the repository names. Part C
and the first end-to-end run both landed on the same limit: `agent_projects`,
the one table ever found genuinely exposed on the deployment we own, is in
neither the migrations nor the client code.

`supabase gen types typescript` writes its file **from the live project**, so
it is the only thing in a repository that can name a table no migration
declares. Whether that helps is a number.

| | |
|---|---|
| Supabase repositories in the corpus | 226 |
| carrying a generated types file | 98 (43%) |

**Where there is no schema at all — the blind spot:**

| stratum | rescued |
|---|---|
| Lovable | 13/24 = 54% [35–72%] |
| bolt | 1/18 = 6% [1–26%] |
| no generator marker | 2/32 = 6% [2–20%] |
| **all** | **16/74 = 22% [14–32%]** |

Tables gained by those 16: min 1, median 4, max 52. For them the difference is
not "a few more tables" but "nothing to check" against "a real check".

The split by generator is large and the paths explain it: almost every one is
`src/integrations/supabase/types.ts`, Lovable's own scaffold. It writes the
integration and the types, and not the migrations — which fits the earlier
post-hoc finding that 62% of Lovable's blind repositories carry a `supabase/`
directory with no SQL in it.

**Where a schema DOES exist — the `agent_projects` case:**

| | |
|---|---|
| commit a schema | 152 |
| and carry generated types | 82 |
| whose types name a table the SQL does not | **36/82 = 44% [34–55%]** |
| as a share of all schema-committing repos | 24% [18–31%] |
| tables reachable only this way, corpus-wide | **643** |

So nearly a quarter of the repositories that DO commit migrations still hold
tables the schema reader cannot see, and the types file names them. That is
the measured form of what Part C found once by hand.

### Two decisions in the reader

Table entries are matched on `<name>: { Row:`, the shape the generator emits,
rather than on the file's name — the name is a convention and several of the
16 use a different one. `Tables: {` scopes it: `Row:` appears in ordinary
hand-written TypeScript, and without the scope any interface with a Row field
would put invented names into a URL aimed at a customer's database.

### What it still does not close

A table that no migration declares, no code queries, and no generated file
names remains invisible, and 42% of the blind spot gains nothing here. The
honest routes left are asking the customer for names or reading them from a
session they authorise separately — both new consent questions, neither taken.

### A note on the measurement itself

The script carried its own copy of the matcher and drifted from production
within the hour — the same two-readers failure this document's own tooling
section describes. It did not move any number here, which is luck rather than
design, so the script now imports the matcher rather than restating it.

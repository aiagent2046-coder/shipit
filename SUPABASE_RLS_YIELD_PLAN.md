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

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

### A false positive the first run produced, and the correction

`founder_profiles` in our own customer's repo was flagged on the column
`user_id`. Its policy is the Supabase quickstart's own text — "Public profiles
are viewable by everyone." — in a founder-MATCHING app where profiles are
meant to be browsable. Telling that customer their public profiles are exposed
is the `*`-without-credentials error running in the opposite direction, and
that direction is more expensive: it is the one that reaches a report.

`user_id`, `owner_id`, `notes`, `content` are now WEAK hints. Nearly every
table in a multi-tenant app carries them, public ones included, so a weak hint
alone yields **`uncertain`** — printed for a human, kept out of the count. The
verdict has three states because two forced this table into a bucket where
both answers were wrong.

A second false-positive path was found the same way, before it could be
quoted: `ALTER TABLE IF EXISTS … ENABLE ROW LEVEL SECURITY` went unmatched, so
any table protected that way read as "RLS never enabled".

**So the honest headline is 2 of 4, with `avatar_interactions` (RLS never
enabled, flagged only on `user_id`) still to be confirmed by eye.** Both
servexaapp findings are solid; the customer repo's remaining one is not yet.

### What this changes about Part C

The customer repo is the natural first live target: we have the relationship,
so consent can actually be asked for, which no repository in a survey can
offer. That is the only route to an end-to-end number, and it stays gated on
their explicit yes.

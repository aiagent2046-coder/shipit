# Phase B — Fix Outcome Knowledge Base (instrumentation only)

**Status:** Step 1 (recon + plan) — awaiting approval before implementation.

## Goal & scope (as approved)

Start accumulating the history that becomes Drydock's long-term moat: for every
Fix Pack job, persist *what was fixed* (rule_ids), *on what kind of repo*
(stack), *how the Fix Pack ended* (delivered / blocked / failed / no_fix_needed),
*whether our semantic gate flagged a regression*, and — later, via a GitHub
webhook — *whether the customer actually merged the PR* (`pr_merged`).

This phase is **collection only**. No scoring, no UI, no prompt adaptation, no
"patterns/rules" table beyond `fix_outcomes`. Real volume today is ~4 jobs/week
(mostly internal tests); building learning/heuristics on empty data now would be
over-engineering. We just want the durable substrate so the data exists when
there's enough of it to learn from.

---

## Step 1 — Reconnaissance findings (verified against the code, not guessed)

### 1. Where the "stack" field comes from

`stack` is a **real database column**, not a frontend-computed value.

- Detected by `detect_stack()` in `app/ingest/stack_detect.py` — returns a
  `Stack` enum (`nextjs`, `vite-react`, `fastapi`, `unsupported`); its `.value`
  is the string shown in the sample report ("stack: nextjs").
- Persisted on `audits.stack` (`text not null`) at audit creation
  (`migrations/0001_audits_and_fixpack_jobs.sql`; written via
  `AuditRepository.create(..., stack=...)` in `app/db.py`).
- **Already denormalized onto `fixpack_jobs.stack`** as well (also `text not
  null` in migration 0001). `app/billing/__init__.py` reads the audit's stack
  (`stack = (audit or {}).get("stack") or "unknown"`) and passes it to
  `FixpackJobRepository.create_paid(audit_id=..., stack=stack)`.

**Implication:** `fix_outcomes` can copy `stack` straight from the `fixpack_jobs`
row we're already handling — no new detection logic, no join required at write
time.

### 2. How many findings / rule_ids map to one Fix Pack job — **1:N**

One Fix Pack job produces **one** `FixpackPlan` (`app/fixpack/generate.py`,
`build_fixpack_plan(zip_bytes, findings)`), and one plan can fix **many**
findings:

- `FixpackPlan.secret_fixes: list[SecretFix]` — each `SecretFix` has a `rule_id`.
- `FixpackPlan.config_fixes: list[ConfigFix]` — each `ConfigFix` has a `rule_id`.
- (`FixpackPlan.skipped: list[SkippedFinding]` — findings that no longer match on
  re-fetch; not "fixed", so excluded from the outcome's rule_ids.)

`create_paid` inserts exactly one job per purchase per audit; the audit carries
many findings and the plan filters the eligible ones
(`SECRET_RULE_IDS | _CHECK_RULE_IDS`).

**Implication:** `fix_outcomes` must store a **list** of rule_ids, not a single
`rule_id`. We'll store the deduplicated union of `rule_id` across
`plan.secret_fixes + plan.config_fixes` as a JSONB array (empty array for
`no_fix_needed`, or for early failures where no plan was built).

### 3. Existing GitHub-App webhook infrastructure — **none**

The only webhook today is Telegram: `POST /v1/webhooks/telegram` in
`app/main.py`. Its auth is Telegram's `secret_token` scheme — a constant-time
compare of the `X-Telegram-Bot-Api-Secret-Token` header against
`TELEGRAM_WEBHOOK_SECRET` (`hmac.compare_digest`). That is **not** HMAC-over-body
and is not reusable for GitHub.

There is **no** `X-Hub-Signature`, `X-GitHub-Event`, or `/webhook/github`
handling anywhere in `app/`. GitHub App PR-delivery code exists
(`app/deploypack/github_app.py`, `app/deploypack/delivery.py`) but only for
*minting installation tokens and opening PRs* — nothing receives webhooks.

**Standard GitHub App webhook verification (what we will implement):**
GitHub signs each delivery with `X-Hub-Signature-256: sha256=<hex>`, where the
hex is `HMAC-SHA256(secret, raw_request_body)` and `secret` is the App's
configured webhook secret. Verify by recomputing over the **raw** body (not
re-serialized JSON) and `hmac.compare_digest` against the provided hex. The
event type arrives in the `X-GitHub-Event` header (we want `pull_request`), and
the action is in the JSON body (`action == "closed"`).

### 4. Is the App subscribed to `pull_request` events? — requires a MANUAL step

Event subscriptions for an installed GitHub App live in the App's own settings on
GitHub, **not** in this repo. There is no code or config here that declares
subscribed webhook events, and no `GITHUB_APP_WEBHOOK_SECRET` in `.env.example`
(only `GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY`, `GITHUB_PR_TOKEN`,
`GITHUB_APP_SLUG`).

**This is a manual GitHub-UI step the founder performs** (same class as the prior
Setup URL / Public app steps this session): in the GitHub App settings, set the
**Webhook URL** to `…/v1/webhooks/github`, set a **Webhook secret**, and
subscribe to the **Pull request** event. The code will not (and cannot safely)
change this programmatically. The plan only adds the receiving endpoint + the
`GITHUB_APP_WEBHOOK_SECRET` env var the endpoint reads, and documents the manual
step in the README.

### 5. Where to write the outcome row, and where to handle the webhook

**Write point — at the terminal outcome inside `_process_one_paid_job`
(`app/main.py`), not at purchase time.** Rationale:

- `rule_ids` are only known **after** `build_fixpack_plan` runs.
- `is_regression` is only known **after** `run_semantic_check` runs.
- The `outcome` is by definition only known at the terminal state.

Writing once, at the point each terminal state is decided, captures every column
in a single insert with no later mutation (except `pr_merged`, filled by the
webhook). Purchase-time writing would force a create-then-update dance and store
mostly-null rows for jobs that never reach a plan.

`_process_one_paid_job` already has exactly four terminal branches; we add one
`fix_outcomes` insert at each:

| Branch | outcome | rule_ids | is_regression | pr_url |
|---|---|---|---|---|
| `mark_fixpack_delivered` | `delivered` | plan's rule_ids | `false` | `opened.html_url` |
| semantic `regression` | `blocked` | plan's rule_ids | `true` | `null` |
| `no_fix_needed` (no changes) | `no_fix_needed` | `[]` | `false` | `null` |
| any exception / early guard | `failed` | `[]` (plan may not exist) | `false` | `null` |

Scope named delivered/blocked/failed; `no_fix_needed` is the fourth existing
terminal state and is a legitimate learning signal ("we had findings but nothing
auto-fixable"), so recording it too is trivial and stays within "collect the
finding→outcome history". Only `delivered` rows get a non-null `pr_url` and are
thus the only rows a merge webhook can ever update — which is correct (you can't
merge a PR that was never opened).

**Webhook handler — new endpoint `POST /v1/webhooks/github`** (mirrors the
`/v1/webhooks/telegram` naming already in `app/main.py`). On a verified
`pull_request` / `action=="closed"` delivery, look up the outcome by PR URL and
set `pr_merged`.

**Matching a webhook to a stored outcome — by `pr_url` (the PR's `html_url`).**
The delivered PR's `html_url` (e.g. `https://github.com/owner/repo/pull/123`) is
what we already persist to `fixpack_jobs.pr_url` and will copy to
`fix_outcomes.pr_url`. The `pull_request.closed` payload contains
`pull_request.html_url`, so an exact `pr_url == html_url` match is unambiguous
(it encodes owner+repo+number in one string) and needs no parsing. Unknown URL →
no matching row → no-op.

---

## Proposed migration — `migrations/0014_fix_outcomes.sql`

New table only (no changes to `fix_outcomes`-adjacent tables beyond FKs).
Follows existing conventions: plain-text status-like columns (no enum/CHECK, per
migrations 0003/0007/0011), JSONB for lists (like `audits.findings_json`), RLS
default-deny (per migration 0002).

```sql
create table if not exists fix_outcomes (
    id uuid primary key default gen_random_uuid(),
    fixpack_job_id uuid references fixpack_jobs(id),
    audit_id uuid references audits(id),
    rule_ids jsonb not null default '[]'::jsonb,   -- list of fixed rule_id strings
    stack text not null,
    outcome text not null,                          -- delivered|blocked|failed|no_fix_needed
    is_regression boolean not null default false,
    pr_url text,                                    -- set only for 'delivered'
    pr_merged boolean,                              -- null until pull_request.closed webhook
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create index if not exists fix_outcomes_fixpack_job_id_idx on fix_outcomes (fixpack_job_id);
create index if not exists fix_outcomes_pr_url_idx on fix_outcomes (pr_url) where pr_url is not null;
create index if not exists fix_outcomes_created_at_idx on fix_outcomes (created_at desc);

alter table fix_outcomes enable row level security;  -- default-deny, matches 0002
```

`audit_id` is denormalized (nullable, FK) for later query convenience; `stack` is
copied from the job row we already hold. Neither adds a write-time join.

---

## Proposed code changes (surgical)

1. **`migrations/0014_fix_outcomes.sql`** — the table above.

2. **`app/db.py`** — add `FixOutcomeRepository` (same real/fake, "None when
   `DATABASE_URL` unset" contract as the other repos):
   - `record(*, fixpack_job_id, audit_id, rule_ids, stack, outcome, is_regression, pr_url) -> dict|None`
     — single INSERT.
   - `set_pr_merged_by_pr_url(pr_url, merged: bool) -> int` — `update … set
     pr_merged=%s, updated_at=now() where pr_url=%s`; returns rowcount so the
     webhook can distinguish "matched" from "no-op unknown PR".
   - Add a `_row_to_fix_outcome` mapper (uuid→str, JSONB decode) mirroring
     `_row_to_fixpack_job`.

3. **`app/main.py`**:
   - A small helper `_rule_ids_from_plan(plan)` → sorted unique rule_ids from
     `plan.secret_fixes + plan.config_fixes`.
   - In `_process_one_paid_job`, record a `fix_outcomes` row at each of the four
     terminal branches (values per the table above). A recording failure must
     **never** change a job's real outcome — wrap the insert so a bookkeeping
     error is logged, not raised into the delivery path (the paying customer's PR
     matters more than the analytics row).
   - New `get_fix_outcome_repo()` dependency + module-level singleton, same
     pattern as `get_fixpack_repo`.
   - New `POST /v1/webhooks/github`:
     - Read `GITHUB_APP_WEBHOOK_SECRET`; **503** if unset (same "unconfigured
       webhook is an operational gap, not a silent no-op" posture as
       `/v1/webhooks/telegram`).
     - Read the **raw** body, verify `X-Hub-Signature-256` =
       `sha256=HMAC-SHA256(secret, body)` via `hmac.compare_digest`; **401** on
       missing/invalid signature.
     - If `X-GitHub-Event != "pull_request"` or `action != "closed"`: **200**
       no-op (ack so GitHub stops retrying).
     - Else `set_pr_merged_by_pr_url(pull_request.html_url, pull_request.merged)`.
       Return `{"updated": <rowcount>}`; unknown PR ⇒ `updated: 0`, still 200.

4. **`.env.example`** — add `GITHUB_APP_WEBHOOK_SECRET=` under the GitHub App
   block, with a comment that it must equal the secret configured in the App's
   webhook settings and that the App must be subscribed to the Pull request event
   (manual GitHub-UI step). Suggest `openssl rand -hex 32`.

5. **`README.md`** — extend the webhooks section: document `POST
   /v1/webhooks/github`, the `X-Hub-Signature-256` HMAC verification, the
   `GITHUB_APP_WEBHOOK_SECRET` env var, and an explicit note that subscribing the
   GitHub App to the `pull_request` event is a **manual step in the App's GitHub
   settings** (done by the founder after merge), needed only to populate the
   `pr_merged` signal.

**Explicitly NOT doing:** no scoring/heuristics, no UI, no prompt changes, no
extra "patterns"/"rules" table, no programmatic change to the App's event
subscription.

---

## Test plan (Step 2)

New `tests/test_fix_outcomes.py` (+ a fake `FixOutcomeRepository` and small
extensions to the existing `FakeFixpackRepo` pattern in
`tests/test_fixpack_process_endpoint.py`, all in-memory, no DB/network):

**(a) Outcome recording at each terminal state** — drive `_process_one_paid_job`
(or the `/internal/fixpack/process-paid` endpoint with injected fakes) and assert
a `fix_outcomes` row is recorded with the right `outcome`, `rule_ids`, `stack`,
`is_regression`, and `pr_url`:
- delivered → outcome `delivered`, rule_ids = plan's fixed rules, `pr_url` set,
  `is_regression=false`, `pr_merged=null`.
- blocked (semantic regression) → `blocked`, `is_regression=true`, `pr_url=null`.
- failed (e.g. audit missing repo_url) → `failed`, `rule_ids=[]`, `pr_url=null`.
- no_fix_needed (plan has no changes) → `no_fix_needed`, `rule_ids=[]`.
- Recording error is swallowed: a repo whose `record` raises must not change the
  job's returned outcome.

**(b) Webhook, valid signature, `merged:true`** — POST a `pull_request`/`closed`
payload signed with the test secret; assert the matching outcome's `pr_merged`
becomes `true` and the response is `{"updated": 1}`. A companion case with
`merged:false` (closed unmerged) sets `pr_merged=false`.

**(c) Webhook, invalid signature** — wrong/missing `X-Hub-Signature-256` ⇒ 401,
no repo mutation. Also: secret unset ⇒ 503.

**(d) Webhook, unknown/unrelated PR** — valid signature but an `html_url` no
outcome has (and separately, a non-`pull_request` event / non-`closed` action) ⇒
200 no-op, `{"updated": 0}`, no error.

---

## Open assumptions (flagging, not blocking)

- Recording all four terminal outcomes (incl. `no_fix_needed`) rather than only
  the three named — kept because it's trivial and is genuine finding→outcome
  history; happy to drop `no_fix_needed` if you'd rather stay literal to scope.
- Matching webhooks by `pr_url`/`html_url` (vs. repo full_name + number). Chosen
  because it's an exact single-field match with no parsing; the payload always
  carries `html_url`.

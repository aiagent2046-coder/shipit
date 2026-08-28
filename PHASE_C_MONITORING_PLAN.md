# Phase C — Continuous Monitoring (MVP) — Plan

Client subscribes to continuous monitoring of a specific repository. On a push
to the repo's default branch (at most once per 24h per repo), we re-run the
audit. If the new audit surfaces **new** critical/high findings that weren't in
the previous audit of that same repo, we send the subscriber a Telegram
notification.

This is **Step 1 (recon + plan)**. No code yet — awaiting approval.

> **Later note (2026-08-28).** Every "24h" below is the number this plan was
> written with. The gate is now `MONITORING_INTERVAL_HOURS` in `app/monitor`,
> set to **72** — a monitoring run is a full one-pass audit of the whole
> repository (median $0.96 measured), and each run audits HEAD rather than the
> push that triggered it, so widening the window costs latency and not
> coverage. Read the constant, not this document, for the current value.

---

## 0. Reconnaissance findings (what the code actually does)

Every design decision below is anchored to these verified facts.

### 0.1 Fix Pack purchase mechanism — **founder's hypothesis is partly wrong, documented here**

The founder's brief assumed Fix Pack uses a Telegram **deep-link**
(`t.me/bot?start=<payload>` → `/start <payload>`). **It does not.** The real
mechanism (`web/src/components/FixpackPurchase.tsx:207-262`, `StarsCard`):

1. The audit page shows a plain **"Open @bot in Telegram"** button — the href is
   `https://t.me/${TELEGRAM_BOT_USERNAME}` with **no `?start=` parameter**
   (line 232).
2. Right below it, the page renders a **copyable command** `/fixpack <auditId>`
   (line 209) with a "Copy" button. The user opens the bot and pastes/sends
   that command manually.
3. The bot dispatches on the first word of the message text
   (`app/billing/telegram_stars.py:459-489`). `/fixpack` routes to
   `_handle_fixpack` (line 690), which extracts the audit id with
   `text.split(maxsplit=1)[1]` (line 700-701), looks the audit up, and sends the
   Stars invoice with payload `fixpack:<audit_id>`.

There is **no `/start`-with-payload handler anywhere** in the bot — deep-links
are not implemented.

**Consequence for this plan:** we mirror the *real* Fix Pack mechanism, not the
hypothesised one. The audit page gets an **"Enable continuous monitoring"**
section with the same "Open @bot" button + a copyable **`/monitor <auditId>`**
command. This keeps Phase C consistent with the shipped Fix Pack UX and avoids
introducing a brand-new deep-link code path the codebase has never used.
(If the founder specifically wants true `t.me/bot?start=` deep-links, that's a
separate, larger change to both the button href and a new `/start` handler —
flagged, not assumed.)

### 0.2 Finding structure & stable identity

`ScoredFinding` dataclass — `app/scan/scoring.py:34-56`:

```python
@dataclass(frozen=True)
class ScoredFinding:
    rule_id: str
    title: str
    severity: str          # one of: "critical" | "high" | "medium" | "low"
    confidence: float
    category: str
    file: str = ""
    line: int = 0
    masked: str = ""
    explanation: str = ""
    fix_hint: str = ""
    context: str | None = None
```

Severity vocabulary from `SEVERITY_WEIGHT` (`scoring.py:20`):
`critical`, `high`, `medium`, `low`.

Findings are persisted as a **JSONB array** in `audits.findings_json` — there is
**no separate `findings` table** (`app/db.py:253-258` INSERT; migration
`0001_audits_and_fixpack_jobs.sql`). So a diff must load the JSON arrays of two
audit rows and compare in Python.

**Stable key for "was this finding here before?":** `(rule_id, file)`.
- We deliberately **exclude `line`**: line numbers shift when unrelated code is
  added/removed above a finding, which would make every trivial edit look like a
  "new" finding and spam notifications.
- `(rule_id, file)` is stable across re-audits of the same logical issue and is
  the tightest key that survives incidental line drift. (`rule_id` examples:
  `llm-auth`, `env-file-committed`, `aws-access-key-id`.)

### 0.3 Audit ↔ repo link

- `audits.repo_url` (text, nullable) — added in `0006_audits_repo_url.sql`,
  written at `app/db.py:256` from `create_audit`'s `source_url`
  (`app/main.py:1238, 1336`). Stores the **full URL**
  `https://github.com/<owner>/<repo>` for GitHub-intake audits; `NULL` for zip
  uploads.
- Repo URL is validated by `_parse_github_repo_url` / `_GITHUB_REPO_URL`
  (`app/main.py:258`) → `(owner, repo)`.
- **No index on `repo_url`** today (only `audits_created_at_idx`). Finding "the
  previous audit for this repo" today would be a full scan
  `WHERE repo_url = %s ORDER BY created_at DESC` — fine at current volume but we
  add an index (§3.1) since monitoring queries it on every eligible push.

### 0.4 Audit creation entrypoint & the re-audit reuse question

`create_audit` (`app/main.py:1177-1355`) is an **HTTP endpoint**, not a plain
callable — its core work is inline:

1. fetch: `repo_fetcher(owner, repo)` → `fetch_repo_zip`
   (`app/ingest/github_fetch.py:39`)
2. validate: `validate_zip` (line 1256)
3. detect stack: `detect_stack` (line 1264)
4. **content-hash cache check**: `audit_repo.get_by_content_hash(digest,
   AUDIT_ENGINE_VERSION)` (line 1310) — if byte-identical content was already
   audited by the current engine version, it **returns the cached audit with no
   LLM call** (line 1311-1327).
5. scan: `run_scan(raw, llm_client)` (`app/scan/pipeline.py:78`) — the paid LLM
   stage.
6. persist: `audit_repo.create(...)` (line 1333).

**We will extract steps 1-6 into a reusable internal coroutine**
`run_repo_audit(repo_url, *, llm_client, audit_repo, repo_fetcher)` and have both
`create_audit` (the endpoint, for the GitHub-URL path) and the monitoring push
handler call it. This is the "reuse the existing pipeline" requirement made
concrete — one code path, one cache, one scoring engine.

### 0.5 Cost & scale — the content-hash cache is the cost guard

The re-audit is a real LLM run (`run_scan`) **only when the repo content
changed**. The content-hash cache (§0.4 step 4) means: if a push touched files
that don't change the audited content digest (or the push is to a branch we
re-fetch to identical bytes), the re-audit **returns the cached prior audit with
zero LLM cost** — and by construction its findings equal the previous audit's,
so the diff is empty and no notification fires. **We pay for an LLM run exactly
when the code actually changed**, which is the intended semantics.

### 0.6 Public vs private repos — **hard limitation, verified current**

`fetch_repo_zip` (`app/ingest/github_fetch.py:39-91`) fetches
`GET /repos/{owner}/{repo}/zipball` with **no Authorization header** — public
repos only, by design (comment at lines 12-14). The GitHub App installation
token is acquired **only in the Fix Pack PR path** (`_resolve_pr_token`,
`app/main.py:1058`), **never during an audit**. The founder's statement holds:
**audit is public-repo-only; the GitHub App is not used for cloning during
audit.**

**Consequence:** continuous monitoring re-audits only work for **public**
repos in this MVP. A private repo's `fetch_repo_zip` returns `repo_not_found`
(404 — private and missing are indistinguishable by design). We handle that
gracefully (§5.4) rather than pretending private monitoring works. Private-repo
monitoring is out of scope until the audit path gains authenticated cloning
(separate initiative).

### 0.7 Subscriptions table & billing flow (already built — do not duplicate)

`subscriptions` DDL — `0015_subscriptions.sql`:

```sql
create table if not exists subscriptions (
    id uuid primary key default gen_random_uuid(),
    account_id uuid references accounts(id),
    telegram_user_id text not null,
    telegram_chat_id text,
    tier text not null,
    invoice_payload text not null,
    telegram_payment_charge_id text,
    status text not null default 'active',
    expires_at timestamptz,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);
```

- Natural key: `(telegram_user_id, invoice_payload)` (unique).
- `SubscriptionRepository` (`app/db.py:1109-1266`): `get_by_user_and_payload`,
  `get_active_by_user`, `upsert_first`, `renew`, `set_status`.
- Billing flow: `/subscribe` → `create_invoice_link` with a **static** payload
  `SUBSCRIPTION_PAYLOAD = "sub:test-monitoring"`
  (`telegram_stars.py:143-145`), `subscription_period` = 30 days. On
  `successful_payment` whose payload starts with `"sub:"`,
  `_handle_subscription_payment` (line 566) → `grant_subscription`
  (`app/billing/__init__.py:172`) → `upsert_first`/`renew`.
- Payload currently carries **no repo** — the row does not know what to monitor.
- `send_message(chat_id, text, *, token, ...)` (`telegram_stars.py:312`) is the
  ready-made plain-notification helper.

### 0.8 GitHub webhook endpoint (already built)

`POST /v1/webhooks/github` (`app/main.py:568-622`):
- Secret env `GITHUB_APP_WEBHOOK_SECRET`; header `X-Hub-Signature-256`;
  constant-time HMAC-SHA256 over raw body (`_verify_github_signature`,
  line 554). 503 if unconfigured, 401 on bad signature.
- Dispatches on `X-GitHub-Event`. Currently only `pull_request` + action
  `closed` does work (fix-outcome recording); everything else is a 200 ack.
- The App must be **manually subscribed** to each event in its GitHub settings
  (README notes this for `pull_request`).

---

## 1. Design decisions summary

| Decision | Choice | Rationale |
|---|---|---|
| Repo→subscription binding UX | Mirror Fix Pack: audit-page button opens bot + copyable `/monitor <auditId>` command | Deep-links don't exist in this codebase (§0.1); consistency with shipped Fix Pack UX; no new `/start` path |
| Where to store the repo | **Extend `subscriptions`** with `repo_full_name` + `last_monitored_at` | Billing already lives on `subscriptions` (§0.7); monitoring is a property of the subscription, not a new billing object. A separate table would duplicate the user/charge/status plumbing |
| Bind repo or audit_id? | **`repo_full_name`** (`owner/repo`), not `audit_id` | Monitoring tracks the repo *going forward*; each re-audit makes a new audit row, so an audit_id binding is stale immediately. `/monitor` still takes an `audit_id` as the *entry point* (to derive the repo), but the stored binding is the repo |
| Finding stable key | `(rule_id, file)` | Survives line drift (§0.2); tightest key that doesn't spam on trivial edits |
| Webhook | **Extend** existing `/v1/webhooks/github` with a `push` branch | Signature verification already there for that path; one endpoint, one secret |
| 24h gate | `subscriptions.last_monitored_at` (per repo) | No extra table; the gate is a property of the monitored repo |
| Re-audit engine | Extract `run_repo_audit()` from `create_audit`, call from both | One pipeline, one content-hash cache = cost guard (§0.4-0.5) |

---

## 2. Repo→subscription binding (UX + bot)

### 2.1 Website — audit page

Add an **"Enable continuous monitoring"** section to the audit page (same page
that renders `FixpackPurchase`). It reuses the exact `StarsCard` pattern:

- "Open @bot in Telegram" button → `https://t.me/${TELEGRAM_BOT_USERNAME}`.
- Copyable command **`/monitor <auditId>`**.
- Only shown when `repoUrl` is non-null (a zip-upload audit has no repo to
  monitor — same guard Fix Pack uses at `FixpackPurchase.tsx:50-62`).

Surgical: a small new component (or a sibling block) next to `FixpackPurchase`;
no new API endpoints needed for the binding itself (the bot does the work).

### 2.2 Bot — new `/monitor <audit_id>` command

New dispatch branch in `telegram_stars.py:459-489` and a `_handle_monitor`
handler, mirroring `_handle_fixpack` (line 690):

1. Extract `audit_id` from the message text.
2. `audit_repo.get(audit_id)`; 404-style reply if not found.
3. Reject if `audit.repo_url` is null (zip audit — nothing to monitor).
4. Derive `repo_full_name = owner/repo` from `audit.repo_url`.
5. Send a **subscription** invoice via `create_invoice_link` (recurring Stars,
   30-day period — same as `/subscribe`) with a **repo-scoped payload**:
   `sub:monitor:<repo_full_name>` (extends `SUBSCRIPTION_PAYLOAD_PREFIX="sub:"`,
   so the existing `payload.startswith("sub:")` routing at line 420 still
   catches it).

Using the repo in the payload means the **natural key
`(telegram_user_id, invoice_payload)`** is naturally distinct per repo per user —
one user can monitor several repos, each its own subscription row, with no schema
gymnastics.

### 2.3 Bot — recording the repo on payment

`_handle_subscription_payment` (line 566) → `grant_subscription`
(`app/billing/__init__.py:172`). Extend both to parse `repo_full_name` out of a
`sub:monitor:<repo>` payload and pass it into `upsert_first`/`renew`, which set
`subscriptions.repo_full_name`. The legacy static `sub:test-monitoring` payload
(no repo) continues to work unchanged → `repo_full_name` stays NULL for it.

---

## 3. Schema changes

### 3.1 Migration `0016_subscriptions_monitoring.sql`

```sql
alter table subscriptions add column if not exists repo_full_name text;
alter table subscriptions add column if not exists last_monitored_at timestamptz;

-- Push handler looks up active monitoring subs by repo on every eligible push.
create index if not exists subscriptions_repo_full_name_idx
    on subscriptions (repo_full_name) where repo_full_name is not null;

-- "Previous audit for this repo" lookup on every eligible push.
create index if not exists audits_repo_url_created_at_idx
    on audits (repo_url, created_at desc) where repo_url is not null;
```

- `repo_full_name` stored as canonical `owner/repo`. (The push payload gives us
  `repository.full_name` directly as `owner/repo`; the audit stores the full URL,
  so the lookup joins on the derived full URL — see §5.3.)
- `last_monitored_at` NULL means "never monitored" → first eligible push runs.

### 3.2 `SubscriptionRepository` additions (`app/db.py`)

- Extend `upsert_first` / `renew` to accept and write `repo_full_name`.
- `list_active_for_repo(repo_full_name) -> list[dict]`: rows where
  `repo_full_name = %s AND expires_at > now()` (access boundary honours
  canceled-but-still-in-period subs; see `0015` comments).
- `mark_monitored(repo_full_name, at)`: set `last_monitored_at = at` for all
  active subs of that repo (the 24h gate is per repo, so stamping all matching
  rows keeps it consistent).

---

## 4. Finding diff logic

New module `app/monitor/diff.py` (or a function in the push handler):

```python
def new_high_severity_findings(previous: list[dict], current: list[dict]) -> list[dict]:
    prev_keys = {(f["rule_id"], f.get("file", "")) for f in previous}
    out = []
    for f in current:
        if f.get("severity") in ("critical", "high"):
            if (f["rule_id"], f.get("file", "")) not in prev_keys:
                out.append(f)
    return out
```

- "New" = key `(rule_id, file)` absent from the **entire** previous findings set
  (any severity), and the new finding is critical/high. This means a finding
  that was `medium` before and is now `high` on the *same* `(rule_id, file)` is
  **not** flagged as new — it's the same finding, re-scored. (Documented choice;
  we can add severity-escalation detection later if desired — flagged as a
  possible v2 refinement, not built now.)
- `previous` = the most recent audit for the repo that existed **before** this
  re-audit; `current` = the re-audit's findings.

---

## 5. Push webhook handler

### 5.1 Extend `/v1/webhooks/github`

After the signature check (unchanged), add a `push` branch alongside
`pull_request` (`app/main.py:607-609`). Needs new dependencies injected into the
endpoint: `subscription_repo`, `llm_client`, `repo_fetcher` (and the
notification transport/token), matching how `create_audit` gets them.

### 5.2 Push event validation

From the `push` payload:
- `ref` — must equal `refs/heads/<default_branch>`, where default branch is
  `payload["repository"]["default_branch"]`. Non-default-branch pushes → 200 ack
  no-op (`{"ignored": true, "reason": "not_default_branch"}`).
- `repository.full_name` → `repo_full_name` (`owner/repo`);
  `repository.html_url` → the URL to feed the audit (`https://github.com/owner/repo`).

### 5.3 Subscription + 24h gate

1. `subs = subscription_repo.list_active_for_repo(repo_full_name)`.
   - Empty → **no-op**, 200 `{"ignored": true, "reason": "no_active_subscription"}`.
     (**Test (a)**)
2. 24h gate: `last = max(s["last_monitored_at"] for s in subs if set)`. If
   `last is not None and now - last < 24h` → **no-op**, no re-audit
   (`{"ignored": true, "reason": "throttled_24h"}`). (**Test (b)**)
3. Otherwise proceed.

### 5.4 Re-audit + diff + notify

1. **Baseline**: `previous = audit_repo.get_latest_by_repo_url(repo_html_url)`
   (new method: `WHERE repo_url = %s ORDER BY created_at DESC LIMIT 1`) — captured
   **before** the re-audit so it's the true prior state. If none exists (repo
   never audited via the site), baseline = empty findings.
2. **Re-audit**: `result = await run_repo_audit(repo_html_url, ...)` (§0.4). On
   `RepoFetchError` (e.g. repo went private / was deleted → `repo_not_found`):
   log, stamp `last_monitored_at` (so we don't hammer), no notification. (§0.6)
3. **Diff**: `new = new_high_severity_findings(previous_findings, result_findings)`.
4. **Notify** each subscriber via `send_message(s["telegram_chat_id"], text)` if
   `new` is non-empty. Message lists the new critical/high findings (rule_id,
   file, title) + a link to the new audit page. (**Test (c)**)
   - If `new` is empty → **no notification**. (**Test (d)**)
5. `subscription_repo.mark_monitored(repo_full_name, now)`.

### 5.5 GitHub App configuration (README)

The App must be **subscribed to the `Push` event** in its GitHub settings (in
addition to the existing `Pull request` subscription). One-time manual UI step —
documented in README next to the existing `pull_request` note.

---

## 6. Testing plan

Unit/integration tests (mirroring existing webhook + billing test style; LLM and
Telegram network calls stubbed):

- **(a)** push to a repo with **no active subscription** → handler returns
  no-op, `run_repo_audit` **not** called, no `send_message`.
- **(b)** push to a monitored repo, `last_monitored_at` < 24h ago → no-op,
  `run_repo_audit` **not** called (asserts the cost gate).
- **(c)** push, ≥24h (or never monitored), re-audit yields a new
  `(rule_id, file)` critical finding absent from the previous audit →
  `send_message` called once per subscriber with that finding;
  `last_monitored_at` updated.
- **(d)** push, ≥24h, re-audit yields **no** new critical/high (identical
  findings, or only new medium/low) → **no** `send_message`;
  `last_monitored_at` still updated.
- Diff unit tests: line-drift (same `(rule_id, file)`, different `line`) is **not**
  new; brand-new `(rule_id, file)` critical **is** new; medium→high on same key is
  **not** flagged (documented behavior).
- Signature/gate: non-default-branch push → no-op; bad signature → 401 (existing
  behavior preserved for `pull_request`).

---

## 7. Files touched (Step 2 preview)

- `migrations/0016_subscriptions_monitoring.sql` — new columns + indexes.
- `app/db.py` — `SubscriptionRepository` (`repo_full_name` in upsert/renew,
  `list_active_for_repo`, `mark_monitored`); `AuditRepository.get_latest_by_repo_url`.
- `app/main.py` — extract `run_repo_audit()`; `push` branch in `github_webhook`.
- `app/billing/telegram_stars.py` — `/monitor` command + `_handle_monitor`;
  parse `sub:monitor:<repo>` payload in subscription-payment path.
- `app/billing/__init__.py` — `grant_subscription` carries `repo_full_name`.
- `app/monitor/diff.py` (new, small) — finding diff.
- `web/src/components/` — "Enable continuous monitoring" block on the audit page.
- `README.md` — Push event subscription + monitoring overview.
- Tests under existing test dir.

---

## 8. Open items / divergences flagged (not silently resolved)

1. **Deep-link vs copy-command (§0.1):** implemented as copy-command to match the
   real Fix Pack UX. If true `t.me/bot?start=` deep-links are wanted, that's an
   extra `/start`-payload handler + button-href change — call it out for scope.
2. **Public repos only (§0.6):** monitoring works for public repos only until the
   audit path gets authenticated cloning. Private repos degrade gracefully
   (fetch 404 → no crash, no notification).
3. **Severity escalation (§4):** medium→high on the same `(rule_id, file)` is not
   currently flagged as "new". Easy to add if the founder wants escalation
   alerts; left out of MVP to keep the signal precise.

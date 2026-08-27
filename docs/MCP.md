# MCP for Cursor — the contract, and what Phase 1 built

What Drydock exposes to an agent inside an editor, and what it refuses to.

Written 2026-08-26 as Phase 0, when nothing was implemented. Phase 1 landed
the same day; §7 at the end records what exists now, what the code corrected
about this document, and what is still open. Sections 1–6 are left as they
were written, because a decision record that is edited to match the code
stops being able to say the code went somewhere else.

Every number in it is read out of the tree, not chosen here, and the file
paths are given so a later reader can check rather than trust.

---

## 1. Who gets a key, and why that was the first question

The original plan said the key would be "the account/email from the existing
model (or a new `mcp_tokens` table)", and that it would be handed out "in the
dashboard / after an audit". All three of those are empty:

- **There is no dashboard.**
- **After an audit there is no account.** An audit is anonymous; what
  authorises reading it is a per-row `access_token` (migration 0010), not an
  identity.
- **After a Fix Pack purchase there is no account either.** `grant_fixpack`
  mints none, deliberately — "a Fix Pack is a one-off per-audit product, not
  an account upgrade" (`app/billing/__init__.py`).
- **Pro is not sold.** `app/routes/storefront.py` records the decision:
  "FIX PACK ONLY, by product decision… Pro's single live benefit — a higher
  daily audit limit — is not something we are willing to take money for. The
  Pro purchase routes stay reachable for the existing customer and the bot;
  they are simply no longer advertised."

So "MCP is a Pro feature" would have meant "MCP is for one existing customer".

### The decision

**A free, self-service key, rate-limited like an anonymous caller.**

MCP is the funnel into the paid Fix Pack, not a thing sold on its own. A
developer tries an audit from inside Cursor, sees the findings against their
own code, and buys the fix in the same place. The thing being protected is
not revenue from the key — it is the LLM budget behind it.

New table `mcp_api_keys`, not a reuse of `accounts`:

| column | why |
| --- | --- |
| `key_hash`, `key_prefix` | same posture as `accounts` after migration 0019 — the plaintext exists once, in memory, and is never stored. A lost key is rotated, not recovered. |
| `created_at`, `last_used_at` | a key nobody has used in months is a key to expire. |
| `revoked_at` | revocation without deleting the row, so the audits it created still trace back. |
| `label` | what the holder called it, for their own list. |

Deliberately **no `account_id`**. Tying MCP keys to a table that exists to
carry a tier would reintroduce the coupling this decision removes, and the
first person to buy Pro again would silently change what their MCP key can do.

---

## 2. What a key may read, and the answer that is not "anything"

**A key may read only the audits it created.** Not "any audit whose id you
know", and not "any audit at all".

This is not caution for its own sake. `access_token` (migration 0010) is a
per-row capability precisely so that knowing an `audit_id` is not enough — a
leaked UUID reads nothing. An MCP key that could fetch any audit by id would
step around that, and the thing it would expose is a map of somebody else's
vulnerabilities.

The product's own pitch is finding broken object-level authorisation. Shipping
one in the tool that reports it is not a trade worth making for a smaller
schema.

Two consequences:

- every audit created through MCP records the key that created it;
- `drydock_get_audit` takes an `audit_id` **and** either that ownership or an
  explicit `access_token` argument — the same capability the web report uses,
  so a developer can hand an audit they already own to their editor.

---

## 3. Rate limiting is Phase 1, not Phase 2

The original plan put `drydock_start_audit` in the read-first MVP and rate
limiting one phase later. That is backwards: `start_audit` is the one tool
that **spends money**, and it would ship before the thing that bounds it.

What already exists, and what MCP must reuse rather than duplicate:

- **`RateLimiter`** (`app/ratelimit.py`) — fixed window, per key, with a
  per-call limit override; that override is exactly how tier-aware limits are
  enforced today without a second limiter. Default: **3 calls per 24 h**.
- **The anonymous LLM spend cap** (`app/main.py`) — `$20.00/day` by default,
  summed over rows with `account_id IS NULL` since UTC midnight. Crossing it
  **soft-degrades new anonymous audits to static-only**, never a 402 or 429,
  because an anonymous caller has nothing to pay. An operator alert fires at
  80 %.

An MCP key is anonymous traffic by construction, so it lands under the same
cap. Which produces the one behaviour this document most wants a reader to
notice:

> **When the budget is spent, an audit comes back `static_only` and looks
> fine.** No error, no warning — a thinner report that reads like a clean one.
> Issue #174 was opened because four external audits were run on a spent
> budget and nobody could tell.

So `drydock_start_audit` **must return `basis` in its result**, and the tool
description must say what `static_only` means. An agent that cannot tell a
full review from a degraded one will summarise the degraded one as good news.

---

## 4. Tool output is data, not instructions

The risk specific to this product, and absent from the original plan.

MCP output lands in the context of an agent that can write files and run
commands. Part of a finding is **controlled by the repository being audited**:
file paths, the LLM-authored `title` and `fix_hint`, and sometimes a snippet
(`app/scan/llm_scan.py`). So the chain is:

> someone commits a file whose content reads as instructions → a developer
> audits that repository → the findings travel through MCP into their editor.

Drydock would be the delivery channel for text an attacker wrote, into a tool
with filesystem and shell access.

Mitigations, in descending order of usefulness:

1. **Every tool description states that finding content is untrusted data from
   a third-party repository, never instructions.** This is the mitigation that
   works, because it addresses the reader.
2. **No raw file content is ever returned** — paths and normalised fields
   only. The MVP has no tool that returns source, and that is a rule rather
   than an omission.
3. **Repository-derived free text is length-capped** before it goes out.
4. **Repository-derived text is wrapped in an explicit data marker** so the
   boundary is visible in the transcript.

**Secrets are already safe here** and need no new work: `app/scan/secrets.py`
stores `AKIA****(20 chars)` and says so in the field's own comment — "value
itself is never stored". The plan listed "masked secrets" as a requirement; it
is already a property.

---

## 5. The MVP surface

Transport: **remote HTTP**, `Authorization: Bearer <key>`. Not stdio: the
audit runs on our infrastructure either way, and a local process would be a
second thing to install for no gain.

| Tool | Reads or spends | Notes |
| --- | --- | --- |
| `drydock_get_version` | neither | sanity check; the same commit `GET /version` reports |
| `drydock_start_audit` | **spends** | rate-limited; returns `audit_id`, `access_token`, **and `basis`** |
| `drydock_get_audit` | reads | findings and score, own audits only, secrets already masked |
| `drydock_fixpack_status` | reads | status and `pr_url` |
| `drydock_list_recent` | reads | audits belonging to this key |

**Not in the MVP:** card payment, refunds, operator actions, private
repositories, anything that writes to a user's filesystem, and any tool that
returns file contents.

Buying stays in a browser. A `create_payment_session` tool returning a ЮKassa
URL is a Phase 3 question, and a card number never touches MCP under any
phase.

Feature flag `MCP_ENABLED`, off by default, in the same spirit as every other
rail this deployment can turn off without a code change.

---

## 6. What Phase 1 must prove before it is called done

- Cursor lists the tools.
- `start_audit` then `get_audit` on a public repository, end to end.
- A **second key cannot read the first key's audit** — the check that keeps
  §2 honest, and the one worth writing first.
- An invalid key gets 401, and an unknown `audit_id` is indistinguishable from
  one belonging to somebody else.
- `basis` is present in the `start_audit` result and the tool description
  explains `static_only`.
- A CI check pins the tool schema, so a rename is a diff rather than a silent
  break in somebody's editor.

---

## Open, and deliberately not decided here

- **Key issuance UI.** Self-service implies a page; there is no dashboard, and
  building one is larger than this document.
- **Expiry.** `last_used_at` is recorded from the start so the policy can be
  chosen from data instead of guessed now.
- **Marketplace and OAuth.** Cursor's submission process is a separate
  exercise and blocks nothing: docs plus a key are enough for the first users.
  *(Written in Phase 0. §8 records what was found when a marketplace was
  actually opened, and "blocks nothing" is the part that held — for a
  different reason than assumed.)*

---

## 7. What Phase 1 built, and what it corrected

Landed 2026-08-26 in two pull requests: the credential (#347) and the endpoint.

### The shape

| what | where |
| --- | --- |
| the tables | `migrations/0036_mcp_api_keys.sql` — `mcp_api_keys`, `mcp_key_audits` |
| the credential | `app/mcp/keys.py`, `McpKeyRepository` in `app/db.py` |
| the fence | `app/mcp/untrusted.py` |
| the endpoint and the five tools | `app/mcp/server.py`, `POST /mcp` |
| minting a key | `scripts/mint_mcp_key.py`, run on the box |
| the flag | `MCP_ENABLED`, off by default — unset means the endpoint **404s** |

### Three things the code corrected about §1–§6

**`basis` for an MCP key is `static+preview`, not `static+llm`.** §3 says
`start_audit` must return `basis` and warns that a spent budget degrades an
audit to `static_only`. Both are right. What §5's table implies and the code
disproves is the good case: `basis_for_account(None)` returns `BASIS_PREVIEW`
(`app/scan/pipeline.py`), so a free key's healthy result is `static+preview` —
static rules, secret scanning, and one rubric on a small model. `static+llm`
is the paid depth and no MCP key receives it today. There is also a fourth
value, `static+partial`, for an audit that started at full depth and lost a
rubric. All four are named in the tool description, because an agent that
cannot tell them apart will summarise the degraded one as good news.

**At enqueue time there is no `basis` to report, only a forecast.** A queued
audit has no audit row yet and its depth is decided by the worker. Reporting
the entitled basis there would be exactly the false reassurance §3 is about,
so `drydock_start_audit` returns `basis` only on a cache hit — where the row
exists and the value is real — and otherwise returns `basis_expected` with a
note saying it is the budget as it stands and not a promise. The real value is
read back through `drydock_get_audit`.

**The rate limit is charged per key *and* per IP, and the shape check comes
first.** §3 says reuse `RateLimiter` rather than duplicating it, and that is
what happens: the MCP tool charges `mcp:<key_id>` and the delegated
`create_audit` still charges the client IP. Both windows apply on purpose — an
MCP key is anonymous traffic under the same cap. The one addition is that the
repository URL is shape-checked **before** the charge, so a typo in an editor
costs nothing; the SSRF guard inside `create_audit` still runs and is not
replaced by it.

### What §6 asked for, and where it is proved

| §6 | proved by |
| --- | --- |
| a second key cannot read the first key's audit | `tests/test_mcp_server.py`, and against real SQL in `tests/test_db_postgres_smoke.py` |
| an unknown `audit_id` is indistinguishable from somebody else's | `test_a_stranger_audit_and_a_nonexistent_one_read_identically` |
| an invalid key gets 401 | `test_every_bad_credential_gets_the_same_401` — one answer for no key, a wrong-shaped key, an unminted key and a revoked one |
| `basis` is returned and `static_only` is explained | `test_the_two_tools_that_report_findings_explain_static_only` |
| a CI check pins the tool schema | `tests/test_mcp_tool_schema.py` against `tests/data/mcp_tools.json` |
| Cursor lists the tools | **partly.** `tools/list` was answered over the live deployment on 2026-08-27 with a minted key, and an unminted key of the right shape got 401 — so the protocol works against production, not only `TestClient`. What has still not happened is an editor doing it. |

### Still open

- **An editor, specifically.** `MCP_ENABLED=1` is set in production and a key
  is minted; `tools/list` over HTTPS returns the five tools and a bad key gets
  401. What remains is a real client — Cursor or another — doing the same
  thing, which proves the parts a `curl` cannot: that the tool descriptions
  read usefully to a model, and that the transport suits a client that speaks
  MCP rather than one that speaks JSON-RPC by hand.
- **Key issuance UI.** Unchanged from §"Open": there is no dashboard, and
  `scripts/mint_mcp_key.py` is an operator running a command, not
  self-service.
- **Expiry.** `last_used_at` is written on every authenticated call from the
  first day, so the policy can be chosen from data.

---

## 8. What a marketplace can carry, and what it cannot

Written 2026-08-27, after opening MCPMarket Hub with the intention of selling
the scanner there. The answer is no, for three separate reasons, and each one
would have been enough on its own. Recorded so the next person does not spend
an afternoon rediscovering them.

### It sells Skills, not services

The seller area is "Sell your skills": listings are Skills, which the product
defines as "instructions and assets your agent loads on demand", authored or
synced from a GitHub repository. MCP servers are a different section — they
are **added to your org**, not sold.

Drydock is not a bundle of instructions. The scan runs on our infrastructure
and costs money per run. A Skill saying "call api.drydock.co" carries none of
the value and still leaves the buyer needing a key, so there is nothing there
to charge for.

### It cannot host what we have

"Deploy custom MCP" takes a **source to build from** — GitHub, npm, PyPI or
Docker — and nothing else. There is no field for an existing HTTPS endpoint
and no field for an authorization header: the platform runs the server itself,
which is why the form warns that "MCP servers can access your data and execute
arbitrary code".

Our MCP is an endpoint inside the FastAPI application, backed by Postgres, the
audit worker and the payment rails. Handed the repository, a third party would
run code that does nothing without our database and our provider keys. This is
not a packaging gap to close later; a hosted-service MCP is a different shape
from the one this form accepts.

### The money has nowhere to land

"Sales settle to your Stripe balance", at a flat 20% commission. The seller of
record here is an individual entrepreneur in Russia and the rail is ЮKassa;
Stripe does not open accounts there. That is a missing rail, not a paperwork
problem, and no amount of engineering on our side reaches it.

*(Cursor's own marketplace was looked at separately and reportedly pays
publishers nothing at all — plugins are free to install. Not verified here:
`cursor.com` is unreachable from the development sandbox. If it holds, that
marketplace is a distribution channel and not a revenue one, which changes
nothing below.)*

### So the Phase 0 decision stands, and for a better reason

§1 already said it: **MCP is the funnel into the paid Fix Pack, not a thing
sold on its own**, and buying stays in a browser (§5). That was written as a
product judgement. It now also happens to be the only arrangement the rails
permit: a marketplace can send people to Drydock, and the money comes back
through ЮKassa on drydock.co either way.

"Marketplace and OAuth blocks nothing" in the Open section above turns out to
be true — not because submission is easy, but because there is nothing on the
other side of it worth blocking on.

### What actually blocks distribution

Not the marketplaces. **Key issuance.** Every channel — a registry entry, a
blog post, an editor's docs — ends with a stranger needing a key, and today a
key exists only when an operator runs `scripts/mint_mcp_key.py` on the box.
Until that is self-service, any listing is a shopfront nobody can enter.

And self-service is not one endpoint. A free key spends the shared anonymous
LLM budget (`DEFAULT_DAILY_SPEND_CAP_USD`, $20/day), the per-key limit is 3
audits per 24h, and nothing stops one person from minting many keys. When the
budget is gone, audits do not fail — they **silently degrade to
`static_only`**, for everybody, including the visitor who arrived intending to
buy. Opening issuance without bounding that turns the funnel into a way to
switch the product off for free. Whatever it becomes, it needs at minimum a
per-IP mint limit, a bound on MCP traffic separate from the site's own, and an
operator alert when it is approached.

# PayPal Checkout — alternative payment method alongside Telegram Stars

**Status:** Step 1 (recon + plan) — awaiting founder approval before any code is written.

## Goal & scope

Add **PayPal Checkout as an *alternative* payment method, side by side with the
existing Telegram Stars flow** (not a replacement), for the three paid products:

| Product | Command | Billing type (verified below) | PayPal API |
|---|---|---|---|
| **Fix Pack** | `/fixpack <audit_id>` | **one-time** | Orders API (capture) |
| **Pro tier** | `/upgrade` | **one-time** | Orders API (capture) |
| **Continuous Monitoring** | `/monitor <audit_id>` | **recurring (30-day)** | Subscriptions API (plan + subscription) |

Constraints from the founder:

- **No real PayPal credentials exist yet.** We build and test against PayPal
  **sandbox**. Real keys are wired in *after* this plan is approved, through a
  secure form — **never committed to code, `.env`, or chat.** `.env.example`
  documents the variable *names* only, with empty values.
- Keep the existing Stars (and USDT) flows byte-for-byte unchanged. PayPal is
  purely additive.
- Reuse the **existing entitlement-grant layer** (`grant_pro_tier` /
  `grant_fixpack` / `grant_subscription`) rather than duplicating access-granting
  logic in a PayPal branch. Recon below confirms this layer is already
  provider-agnostic, so this is achievable with **no refactor**.

---

## Step 1 — Reconnaissance findings (verified against the code, not memory)

### 1.1 Which products are one-time vs recurring — CONFIRMED

Read `app/billing/telegram_stars.py`, `app/billing/__init__.py`, and the
`handle_update` dispatcher.

- **Pro (`/upgrade`)** — `_handle_upgrade` (telegram_stars.py:545) calls
  `send_invoice(...)` → `_call("sendInvoice", ...)`. `sendInvoice` is a
  **one-shot** invoice (no `subscription_period`). On `successful_payment` with
  the bare `"pro"` payload, `handle_update` (telegram_stars.py:463-494) calls
  **`grant_pro_tier`**. → **ONE-TIME.**
- **Fix Pack (`/fixpack <audit_id>`)** — `_handle_fixpack` (telegram_stars.py:744)
  also uses `send_invoice` (one-shot). On `successful_payment` with a
  `fixpack:<audit_id>` payload → `_handle_fixpack_payment` → **`grant_fixpack`**.
  → **ONE-TIME.**
- **Continuous Monitoring (`/monitor <audit_id>`)** — `_handle_monitor`
  (telegram_stars.py:809) uses **`create_invoice_link(..., subscription_period=
  SUBSCRIPTION_PERIOD_SECONDS)`** — the recurring path. On `successful_payment`
  with a `sub:monitor:<owner/repo>` payload → `_handle_subscription_payment` →
  **`grant_subscription`**. Renewals arrive as further `successful_payment`
  updates; cancel/active/failed arrive as `BotSubscriptionUpdated`
  (`subscription` field) → `_handle_subscription_updated`. → **RECURRING (30d).**

**Conclusion:** the founder's memory was correct. Pro + Fix Pack → PayPal
**Orders API** (one-time capture). Monitoring → PayPal **Subscriptions API**
(billing plan + subscription + recurring `PAYMENT.SALE.COMPLETED`).

### 1.2 The shared "payment → access" grant points — CONFIRMED reusable

All three entitlement grants live in **`app/billing/__init__.py`** and are
**already provider-agnostic** — they take `provider` and `external_ref`
parameters and key idempotency off `(provider, external_ref)`. The USDT provider
already reuses them with `provider="usdt_trc20"`, proving the pattern:

- **`grant_pro_tier(*, account_repo, payment_repo, provider, external_ref,
  amount, currency, invoice_payment_id=None)`** (`__init__.py:43`) — idempotent
  on `(provider, external_ref)`; inserts a completed `payments` row + an
  `accounts` row with tier `pro`, returns the account (with `api_key`).
  `invoice_payment_id` lets a provider *transition an existing pending row*
  (USDT) instead of inserting a fresh one (Telegram). PayPal one-time-Pro will
  call this with `provider="paypal"`, `external_ref=<capture id>`.
- **`grant_fixpack(*, fixpack_repo, payment_repo, audit_repo, provider,
  external_ref, amount, currency, audit_id, invoice_payment_id=None)`**
  (`__init__.py:108`) — idempotent on `(provider, external_ref)`; records the
  payment and creates the `fixpack_jobs` row with status `paid` that the existing
  `/internal/fixpack/process-paid` worker picks up. PayPal Fix Pack calls this.
- **`grant_subscription(*, subscription_repo, payment_repo, provider,
  external_ref, amount, currency, telegram_user_id, telegram_chat_id,
  invoice_payload, tier, expires_at, is_first_recurring, repo_full_name=None)`**
  (`__init__.py:172`) — records each charge as a `payments` row (idempotent on
  `(provider, external_ref)`), and upserts/renews a `subscriptions` row.

**Key takeaway:** for one-time products **no refactor is required** — the PayPal
webhook handler calls the exact same `grant_pro_tier` / `grant_fixpack` the Stars
path calls, with `provider="paypal"`. For **subscriptions**, `grant_subscription`
is currently shaped around Telegram identifiers (`telegram_user_id` +
`invoice_payload` as the natural key). It needs a **small, additive signature
change** so PayPal can key a subscription on `(payment_provider,
paypal_subscription_id)` instead — see §2.3 and §2.6. This is the one place a
targeted refactor is warranted; it is additive (existing Telegram callers keep
working) rather than a rewrite.

### 1.3 How order/product context travels today (no DB lookup needed)

Telegram carries the product + audit context **inside the invoice payload**
(`"pro"`, `"fixpack:<audit_id>"`, `"sub:monitor:<owner/repo>"`) and reads it back
off `successful_payment.invoice_payload`. PayPal has the equivalent: an Order can
carry **`purchase_units[].custom_id`** and **`reference_id`**, and a Subscription
can carry **`custom_id`**. We will encode the same routing string there, so the
webhook routes a PayPal event **without a DB round-trip**, exactly mirroring the
Stars design. This avoids introducing a new order→product mapping table.

### 1.4 How webhooks are verified today — and why PayPal differs

- **Telegram** (`app/main.py:624`): constant-time compare of the
  `X-Telegram-Bot-Api-Secret-Token` header against `TELEGRAM_WEBHOOK_SECRET`
  (`hmac.compare_digest`). No crypto, no outbound call.
- **GitHub** (`app/main.py:675`): `X-Hub-Signature-256` =
  `sha256=HMAC-SHA256(GITHUB_APP_WEBHOOK_SECRET, raw_body)`, verified locally
  with `hmac.new(...)` + `compare_digest`.

**PayPal is architecturally different and must not be forced into the HMAC
mold.** PayPal signs webhooks with an RSA cert (headers `paypal-transmission-id`,
`paypal-transmission-time`, `paypal-transmission-sig`, `paypal-cert-url`,
`paypal-auth-algo`). The two supported verifications are:

1. **API verification (chosen):** POST the received headers + raw body +
   `PAYPAL_WEBHOOK_ID` to PayPal's **`POST /v1/notifications/verify-webhook-
   signature`**, which returns `{"verification_status": "SUCCESS"|"FAILURE"}`.
   Requires an OAuth2 bearer token (client-credentials grant against
   `/v1/oauth2/token`). This is the option the founder specified.
2. Offline crypto verification (fetch `paypal-cert-url`, verify RSA-SHA256). More
   moving parts, requires pinning/validating the cert URL host — rejected as
   heavier and easier to get subtly wrong.

**Consequence for the code:** unlike Telegram/GitHub, PayPal verification needs
an **outbound HTTPS call plus a cached OAuth token**. We isolate this in
`app/billing/paypal.py` behind the same injectable-`transport` seam the Stars
module uses, so tests fake it with `httpx.MockTransport`.

### 1.5 Dependency choice — httpx, no new SDK

`requirements.txt` pins `httpx==0.28.1`. The entire project talks to the Telegram
Bot API, the LLM providers, GitHub, and the TRON explorer via **`httpx`
directly** — no vendor SDKs. PayPal's REST surface we need is tiny (OAuth token,
create order, capture status is delivered by webhook, create plan/subscription,
verify webhook). **Decision: pure `httpx`, no `paypal-server-sdk`.** Rationale:
consistency with the existing codebase, one fewer dependency to vet/patch, full
control over the injectable transport used everywhere for tests, and the SDK
adds no meaningful safety for ~5 endpoints. This matches the precedent set by
`telegram_stars.py` (hand-rolled Bot API client) and `usdt_trc20.py`.

### 1.6 Frontend precedent for embedded checkout

- Stars is **not** embedded in the browser — the web UI (`pricing/page.tsx`,
  `FixpackPurchase.tsx` `StarsCard`, `MonitoringPurchase.tsx`) shows a deep link
  to the Telegram bot plus a copy-command. Stars checkout happens *inside
  Telegram*.
- **USDT *is* embedded** as a real web widget: `UsdtCheckout` /
  `ProUsdtCheckout` (`web/src/components/UsdtCheckout.tsx`) call a backend
  endpoint to open an invoice, then poll a status endpoint. `api.ts` has
  `createUsdtInvoice` / `getUsdtInvoice` / `createFixpackUsdtInvoice`.

**PayPal will follow the USDT precedent** (embedded web widget calling our
backend), because PayPal checkout genuinely runs in the browser. No existing
external JS widget is loaded via `<script>` today, but PayPal's JS SDK is loaded
that way by design; see §3 for how we scope it.

### 1.7 Schema recon

- `payments` (`0003`, `0007`): `provider` and `product` are free-text (no enum),
  `external_ref` is the provider charge id, unique partial index on
  `(provider, external_ref) WHERE external_ref IS NOT NULL` (`0004`) is the
  idempotency backstop. **`provider="paypal"` needs no schema change here** for
  one-time products.
- `subscriptions` (`0015`, `0016`): natural key
  `(telegram_user_id, invoice_payload)`; `telegram_user_id` is `NOT NULL`; there
  is **no provider column**. PayPal subscriptions have neither a Telegram user id
  nor a Telegram invoice payload → this table **needs an additive migration**
  (see §2.3).

---

## Step 2 — Proposed design (backend)

New module **`app/billing/paypal.py`** (mirrors `telegram_stars.py`'s shape:
env-readers returning `None` when unset, pure body-builders, an injectable
`_call(..., transport=)` HTTP seam, a `handle_webhook_event(...)` dispatcher).

### 2.1 Environment / config (documented in `.env.example`, values empty)

```
PAYPAL_CLIENT_ID=
PAYPAL_CLIENT_SECRET=
PAYPAL_WEBHOOK_ID=
PAYPAL_ENV=sandbox         # sandbox | live — selects api-m.sandbox.paypal.com vs api-m.paypal.com
PAYPAL_MONITOR_PLAN_ID=    # PayPal billing plan id for the monitoring subscription (created once, see §6)
```

- `PAYPAL_ENV` selects the API base (`https://api-m.sandbox.paypal.com` vs
  `https://api-m.paypal.com`) — same "one deployment, one environment" posture as
  the rest of the config. Unset/`sandbox` = sandbox.
- Every PayPal endpoint **503s when `PAYPAL_CLIENT_ID`/`PAYPAL_CLIENT_SECRET` are
  unset**, exactly like the Telegram (`telegram_not_configured`) and USDT
  (`usdt_not_configured`) endpoints — an unconfigured payment path is an
  operational gap to surface, never a silent half-working state.
- **No credential values are committed.** The founder supplies them post-approval
  via the secure form; `.env.example` carries names + explanatory comments only
  (matching the existing comment style — no inline comments after values, per the
  file's own rule).

### 2.2 OAuth token helper

`_access_token(*, transport=None)` — client-credentials grant against
`/v1/oauth2/token`, cached in-process until shortly before `expires_in`. Bounded
timeout like `PRE_CHECKOUT_TIMEOUT_S`. Injectable transport for tests.

### 2.3 New endpoints

**Order creation (one-time: Pro + Fix Pack):**

- `POST /v1/paypal/orders` — body `{ "product": "pro" }` **or**
  `{ "product": "fixpack", "audit_id": "<uuid>" }`. Server-side:
  - looks up price (reusing `pro_stars_price` analogue → a new
    `PAYPAL_*_PRICE`/USD amount; see §2.7 on pricing/currency),
  - for `fixpack`, re-validates the audit exists and has a `repo_url` (mirrors
    the Stars `_handle_fixpack` and the USDT `create_fixpack_usdt_invoice` gate —
    422 `not_github_audit` otherwise),
  - calls PayPal **Create Order** (`POST /v2/checkout/orders`, `intent=CAPTURE`)
    with `purchase_units[0].custom_id` = the routing string (`"pro"` /
    `"fixpack:<audit_id>"`) and `amount`,
  - returns `{ "order_id": "<id>" }` to the browser for the JS SDK to approve.
  - **We do NOT pre-create a `payments` row here** — mirroring Telegram (which
    inserts the completed row only on `successful_payment`). The `custom_id`
    carries all routing context, so no pending-row bookkeeping is needed. (USDT
    pre-creates a pending row only because an on-chain transfer has no callback
    that carries context; PayPal's webhook echoes `custom_id`, so we follow the
    simpler Telegram pattern.)

**Subscription creation (recurring: Monitoring):**

- `POST /v1/paypal/subscriptions` — body `{ "audit_id": "<uuid>" }`. Server-side:
  - re-validates audit + `repo_url` → `normalize_repo_full_name` (same gate as
    `_handle_monitor`),
  - calls PayPal **Create Subscription** (`POST /v1/billing/subscriptions`) for
    `PAYPAL_MONITOR_PLAN_ID`, with `custom_id` = `"monitor:<owner/repo>"`,
  - returns `{ "subscription_id": "<id>", "approve_url": "<links.approve>" }` for
    the browser to redirect/approve.

**Webhook:**

- `POST /v1/webhooks/paypal` — verifies via
  `/v1/notifications/verify-webhook-signature` (§1.4), then dispatches on
  `event_type`:
  - **One-time:** `PAYMENT.CAPTURE.COMPLETED` is the authoritative "money
    captured" event → route by `custom_id`:
    - `"pro"` → `grant_pro_tier(provider="paypal", external_ref=<capture id>,
      amount, currency)`. **Delivery of the API key** differs from Stars: there's
      no Telegram DM. The browser widget polls a status endpoint (see §2.4) and
      shows the key on completion — same model as `getUsdtInvoice` revealing the
      key.
    - `"fixpack:<audit_id>"` → `grant_fixpack(provider="paypal",
      external_ref=<capture id>, audit_id=...)`. The existing
      `GET /v1/audits/{audit_id}/fixpack-status` poll already drives the UI.
    - (`CHECKOUT.ORDER.APPROVED` is acknowledged/ignored — we act on the capture,
      not the approval, so we never grant on an un-captured order.)
  - **Recurring:** 
    - `BILLING.SUBSCRIPTION.ACTIVATED` → first-period grant:
      `grant_subscription(provider="paypal", is_first_recurring=True, ...)` keyed
      on the PayPal subscription id (see §2.6).
    - `PAYMENT.SALE.COMPLETED` (carries `billing_agreement_id` = the subscription
      id) → renewal: `grant_subscription(..., is_first_recurring=False,
      external_ref=<sale id>)`, pushing `expires_at` out one period.
    - `BILLING.SUBSCRIPTION.CANCELLED` / `...SUSPENDED` / `...EXPIRED` → set the
      subscriptions row status (`canceled`/`suspended`/`expired`); **access stays
      `expires_at`-based** — a cancel does not revoke the paid period, matching
      the existing Stars semantics documented in `0015`.
  - Any other `event_type` → 200 + ignored (PayPal, like Telegram, sends many
    event types to one URL).

**Migration (subscriptions, additive):** new `migrations/0018_subscriptions_paypal.sql`:

- `payment_provider text not null default 'telegram_stars'` — labels which
  provider owns the row (existing rows are all Stars, hence the default; no
  backfill needed).
- `paypal_subscription_id text` — the PayPal `I-XXXX` id; nullable (Stars rows
  leave it null).
- Make `telegram_user_id` **nullable** (PayPal rows have none). Existing NOT NULL
  drops to nullable — safe, additive, no data rewrite.
- New **partial unique index** `on subscriptions (paypal_subscription_id) where
  paypal_subscription_id is not null` — the PayPal natural key, parallel to the
  existing `(telegram_user_id, invoice_payload)` unique index which stays for
  Stars.
- Plain-text `payment_provider`/status, no enum — same rationale as every other
  status/provider column (`0003`/`0007`/`0015`).

### 2.4 API-key delivery for one-time PayPal Pro

Stars DMs the key over Telegram. PayPal has no DM channel, so we mirror **USDT**:
`GET /v1/paypal/orders/{order_id}` returns `{ "status": "pending"|"completed",
"api_key": <only when completed> }`. The browser widget polls it after approval;
the key is revealed **only** once the webhook has run `grant_pro_tier` and marked
the payment completed. (Fix Pack needs no new poll endpoint — the existing
`fixpack-status` route already covers it.) To resolve order→account on poll we
read the completed `payments` row by `(provider="paypal", external_ref)`; since
the capture id isn't known to the browser, the poll keys on the **order id**,
which means we **do** need to persist the order id. Two clean options:

- **(a, preferred)** add `paypal_order_id text` to `payments` (partial-unique,
  nullable) and set it when the webhook grants Pro, so the poll can find the row
  by order id; **or**
- (b) create the pending `payments` row at order-creation time (USDT-style) with
  `paypal_order_id` set, and let the webhook transition it via
  `invoice_payment_id` (the mechanism `grant_pro_tier` already supports).

**Recommendation: (b)** — it reuses the *exact* `invoice_payment_id` transition
path USDT already exercises (less new code in the grant layer), and gives the
poll a row to read immediately. This adds `paypal_order_id` to the `0018`
migration (on `payments`). Trade-off noted for the founder to confirm.

### 2.5 Idempotency & double-grant protection

- **One-time:** `(provider="paypal", external_ref=<capture id>)` hits migration
  `0004`'s partial unique index — a retried `PAYMENT.CAPTURE.COMPLETED` (PayPal
  *does* retry until 200) finds the completed payment and re-returns without a
  second grant, identical to the Stars/USDT guarantee. The check-then-write race
  is closed at the DB by that unique index.
- **Recurring:** each charge (`external_ref` = sale id) is unique in `payments`;
  the subscription row is upserted on the PayPal-subscription-id unique index. A
  duplicate `ACTIVATED` lands on the same row (upsert), a duplicate
  `SALE.COMPLETED` is a no-op via the payments unique index — same design as
  `grant_subscription`'s existing renewal idempotency.
- **Belt-and-braces:** PayPal webhook events carry a unique `id`; we may
  additionally short-circuit on a seen-event-id set, but the payment/subscription
  unique indexes are the real guarantee (we won't add a table just for event
  ids unless the founder wants an audit log).

### 2.6 `grant_subscription` signature change (additive)

Today it requires `telegram_user_id` (non-null) and keys on
`(telegram_user_id, invoice_payload)`. Proposed additive change:

- add `payment_provider: str = "telegram_stars"` and
  `paypal_subscription_id: str | None = None` params;
- make `telegram_user_id` / `invoice_payload` optional (default `None`);
- branch the upsert/renew on provider: Stars keeps the
  `(telegram_user_id, invoice_payload)` path unchanged; PayPal uses the
  `paypal_subscription_id` path. The `SubscriptionRepository` gains
  `upsert_first_paypal` / `renew_paypal` / `get_by_paypal_subscription_id` /
  `set_status_paypal` (or provider-parameterized variants). Existing Telegram
  callers pass nothing new and behave identically.

This is the single targeted refactor in the plan; it is additive and covered by
regression tests on the existing Stars subscription flow.

### 2.7 Pricing & currency

Stars prices are integers in XTR; USDT is a USD-pegged amount. PayPal charges
**fiat** (USD). New env-overridable-with-default knobs, matching the
`FIXPACK_STARS_PRICE`/`FIXPACK_USDT_PRICE` pattern:
`PAYPAL_PRO_PRICE_USD`, `PAYPAL_FIXPACK_PRICE_USD`, and the monitoring price is
baked into the PayPal billing **plan** (`PAYPAL_MONITOR_PLAN_ID`), created once
out-of-band (§6). Exact USD amounts are a founder decision; the plan uses
placeholders until confirmed.

---

## Step 3 — Frontend design

Follow the **USDT embedded-widget precedent**, not the Stars deep-link one.

- New `web/src/components/PayPalButton.tsx` — loads the **PayPal JS SDK via a
  `<script>` tag** (`https://www.paypal.com/sdk/js?client-id=<NEXT_PUBLIC_
  PAYPAL_CLIENT_ID>&...`), rendered lazily and only when the client id is
  configured (mirrors the `TELEGRAM_BOT_USERNAME.length > 0` "configured?" guard
  — an unconfigured PayPal shows an explanatory box, never a broken button). No
  npm PayPal package; the `<script>` tag is the vendor-recommended load and keeps
  us off another dependency, consistent with §1.5.
- New env for the web app: `NEXT_PUBLIC_PAYPAL_CLIENT_ID` (public client id is
  safe to expose; the **secret** stays backend-only).
- New `api.ts` helpers: `createPaypalOrder(product, auditId?)`,
  `getPaypalOrder(orderId)`, `createPaypalSubscription(auditId)`.
- **Placement — a second payment card beside the existing ones:**
  - `pricing/page.tsx` (Pro): today a two-card grid (Stars | USDT). Add a
    **third** PayPal card (Orders API, product `pro`), grid → 3 columns.
  - `FixpackPurchase.tsx`: `StarsCard` + `UsdtCheckout` grid → add `PayPalButton`
    (product `fixpack`). Lives **inside the existing `InstallGate`** so PayPal is
    only offered once the GitHub App is installed (a Fix Pack still opens a PR).
  - `MonitoringPurchase.tsx`: today Stars-only. Add a PayPal **subscription**
    button (Subscriptions API). This is the first non-Stars option for
    monitoring (USDT was excluded because it can't auto-charge; PayPal *can*).
- The Fix Pack / monitoring status polling (`getFixpackStatus`, and a new
  `getPaypalOrder` for Pro) drives the post-payment UI — no new polling *pattern*,
  just new endpoints.

---

## Step 4 — Testing (mirror the existing httpx-mock style)

Match `tests/test_billing_telegram.py`: `httpx.MockTransport` for all outbound
PayPal calls, in-memory `Fake*Repo` stand-ins, FastAPI `TestClient`, DI overrides
via `app.dependency_overrides` (the repos + a `get_paypal_transport` seam added
alongside the existing `get_billing_transport`).

Coverage:

1. **Order creation** — `POST /v1/paypal/orders` for `pro` and `fixpack`
   (including the `not_github_audit` 422 gate and the `503` when unconfigured).
2. **Subscription creation** — `POST /v1/paypal/subscriptions` (audit gate,
   returns approve_url).
3. **Webhook signature** — mock `verify-webhook-signature` returning `SUCCESS`
   (accepted) and `FAILURE` (401, no grant). Assert we never grant when
   verification fails.
4. **One-time grant** — `PAYMENT.CAPTURE.COMPLETED` for `pro` grants a Pro
   account + key becomes readable via `GET /v1/paypal/orders/{id}`; for
   `fixpack:` creates the `paid` fixpack_jobs row.
5. **Retry idempotency** — the same capture event twice grants once (one account,
   one payment row, one job).
6. **Recurring lifecycle** — `ACTIVATED` (first period, subscription row created),
   `SALE.COMPLETED` (renewal pushes `expires_at`), `CANCELLED` (status flips,
   access retained to period end). Duplicate `SALE.COMPLETED` is a no-op.
7. **Regression** — existing Stars subscription tests still pass unchanged after
   the additive `grant_subscription` change.

No real PayPal round trip is possible in this sandbox (no keys); a
`scripts/verify_paypal_sandbox_locally.py` helper (parallel to
`scripts/verify_telegram_stars_locally.py`) lets the founder drive one real
sandbox order/subscription once keys are wired.

---

## Step 5 — Files touched (implementation preview — NOT done in this PR)

- **New:** `app/billing/paypal.py`, `migrations/0018_subscriptions_paypal.sql`
  (+`payments.paypal_order_id`), `web/src/components/PayPalButton.tsx`,
  `tests/test_billing_paypal.py`, `scripts/verify_paypal_sandbox_locally.py`.
- **Edited:** `app/main.py` (3 endpoints + webhook + a `get_paypal_transport`
  dep), `app/billing/__init__.py` (additive `grant_subscription` params),
  `app/db.py` (`SubscriptionRepository` PayPal methods; possibly a
  `PaymentRepository.get_by_paypal_order_id`), `web/src/lib/api.ts` (+types),
  `web/src/app/pricing/page.tsx`, `web/src/components/FixpackPurchase.tsx`,
  `web/src/components/MonitoringPurchase.tsx`, `.env.example`, `README.md`.

---

## Step 6 — How the founder tests the real sandbox (post-approval)

1. Create a **PayPal Developer sandbox app** (developer.paypal.com) → get sandbox
   `client_id` / `secret`. Create the sandbox **business (seller)** and
   **personal (buyer)** test accounts PayPal auto-generates.
2. Create the monitoring **billing plan** once (a `POST /v1/billing/plans` call, or
   via the dashboard) → record `PAYPAL_MONITOR_PLAN_ID`. (We can ship a one-shot
   `scripts/create_paypal_plan.py` to do this from the recorded price.)
3. Register the webhook URL (`https://<api-host>/v1/webhooks/paypal`) in the
   sandbox app, subscribe it to `PAYMENT.CAPTURE.COMPLETED`,
   `BILLING.SUBSCRIPTION.ACTIVATED`, `PAYMENT.SALE.COMPLETED`,
   `BILLING.SUBSCRIPTION.CANCELLED` → record `PAYPAL_WEBHOOK_ID`.
4. Supply all `PAYPAL_*` + `NEXT_PUBLIC_PAYPAL_CLIENT_ID` **through the secure
   form** (never chat/code), with `PAYPAL_ENV=sandbox`.
5. From the audit results page / pricing page, click the PayPal button, pay with
   the **sandbox buyer** account, and confirm: Pro key appears (poll), Fix Pack
   PR is generated, monitoring subscription activates and a renewal advances
   `expires_at`. PayPal's sandbox webhook simulator can replay each event.
6. Flip `PAYPAL_ENV=live` + live credentials only after sandbox passes.

---

## Open questions for the founder (please confirm before implementation)

1. **Pro key delivery via web poll** (§2.4) — OK to reveal the Pro API key in the
   browser after PayPal payment (same as USDT does today), rather than a
   Telegram DM?
2. **Pending-row approach (2.4b)** vs storing `paypal_order_id` on the completed
   row (2.4a) — recommendation is (b); confirm.
3. **USD prices** for `PAYPAL_PRO_PRICE_USD`, `PAYPAL_FIXPACK_PRICE_USD`, and the
   monitoring plan amount (§2.7).
4. Do you want a **webhook-event audit log** table (§2.5), or are the existing
   unique indexes sufficient (recommended: sufficient)?

**This PR contains the plan only — no code. It stays open, ready for review. Do
not merge; implementation begins only after explicit approval in a separate
message.**

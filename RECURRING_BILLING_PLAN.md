# Recurring Billing — Telegram Stars subscriptions (billing plumbing only)

**Status:** Step 1 (recon + plan) — awaiting approval before implementation.

## Goal & scope (as approved)

Phase C (Continuous Monitoring) of the CTO roadmap is a *subscription* product,
but today the entire billing stack (`app/billing/telegram_stars.py`,
`app/billing/usdt_trc20.py`) only knows how to take **one-shot** payments. The
founder's decision: build recurring billing **now, separately** from the
monitoring feature, and prove a real subscription charges, renews, and cancels
end-to-end *before* any monitoring logic is layered on top.

This phase is **billing plumbing only**:

- No continuous-monitoring logic.
- No new website UI / pricing tier / real price. The one tier introduced is a
  throwaway test tier named literally `test-monitoring` at **1 Star**, purely so
  a real subscription can be exercised live. It is **not** the product's final
  price.
- Recurring is Telegram-Stars-only. USDT/TRC20 has no native auto-charge
  mechanism (crypto can't auto-debit without allowance contracts), so it stays
  one-time exactly as today. Nothing in this plan touches `usdt_trc20.py`.

---

## Step 1 — Reconnaissance findings (verified against the code, not guessed)

### 1. How a one-shot invoice is built today

`app/billing/telegram_stars.py`:

- `build_invoice_payload(*, chat_id, title, description, payload, stars)` returns
  the pure JSON body for **`sendInvoice`**: `currency="XTR"`,
  `provider_token=""` (the two things that make it a Stars invoice), and
  `prices=[{"label": title, "amount": stars}]` (whole-Star integer, no
  minor-unit multiplier).
- `send_invoice(...)` POSTs that body via `_call("sendInvoice", ...)`.
- The user-facing entry point is the **`/upgrade`** bot command
  (`_handle_upgrade`), which calls `send_invoice` with the `PRO_*` constants and
  `pro_stars_price()`. `/fixpack <audit_id>` (`_handle_fixpack`) does the same
  for the per-audit Fix Pack product.

**Note on `createInvoiceLink` vs `sendInvoice`:** the task's verified facts cite
`subscription_period` on `createInvoiceLink`. The Bot API supports
`subscription_period` on **both** `createInvoiceLink` and `sendInvoice`. The
existing `/upgrade` flow uses `sendInvoice` (it pushes the Pay button straight
into the chat, no intermediate link). To keep the subscription flow consistent
with the flow the operator has already verified live, we will **add an optional
`subscription_period` to the existing `sendInvoice` path** rather than introduce
`createInvoiceLink`. This is the minimal change and leaves the one-shot path
byte-for-byte identical when the parameter is omitted.

### 2. How `successful_payment` is handled today

`handle_update()` dispatches, in order:

1. `pre_checkout_query` → `answerPreCheckoutQuery(ok=True)` **first, before any
   DB work** (Telegram's ~10s deadline). Unconditional approve; payload not even
   read here. **This path is product-agnostic and needs no change** — a
   subscription's first charge also emits a `pre_checkout_query`, and approving
   it unconditionally is still correct.
2. `message.successful_payment` → branch on `invoice_payload`:
   - prefix `fixpack:` → `_handle_fixpack_payment` → `grant_fixpack`.
   - else (Pro) → `grant_pro_tier` → mint account + DM the API key; then stamp
     `chat_id` onto the payment via `link_telegram_chat_id`.
3. text commands: `/upgrade`, `/fixpack`, `/mykey`, `/link`.
4. anything else → `{"ok": True, "handled": "ignored"}`.

The `successful_payment` object today is read for: `invoice_payload`,
`telegram_payment_charge_id` (the idempotency key), `total_amount`, `currency`.
For recurring it gains `subscription_expiration_date`, `is_recurring`,
`is_first_recurring`.

### 3. How a payment is recorded and access is granted

- `app/billing/__init__.py`:
  - `grant_pro_tier(...)` — idempotent on `(provider, external_ref)`: mints an
    `accounts` row (`tier='pro'`, opaque `sk_live_...` key) and inserts a
    completed `payments` row, or re-returns the existing account on a retry.
  - `grant_fixpack(...)` — idempotent likewise; creates a paid `fixpack_jobs`
    row, **no account/tier/key**.
- `app/db.py`: `AccountRepository` and `PaymentRepository` are the real
  psycopg3 repos; both honor the **not-configured contract** (`DATABASE_URL`
  unset → `create`/`get` return `None`/`[]`, never raise). Row-dict shape is
  normalized by `_row_to_account` / `_row_to_payment`.
- Tests use in-memory `FakeAccountRepo` / `FakePaymentRepo` (defined in
  `tests/test_billing_telegram.py`), injected through the FastAPI dependency
  overrides `get_account_repo` / `get_payment_repo` / `get_billing_transport`.

### 4. Schema & migration conventions

- Migrations are sequential SQL files under `migrations/`; latest is
  **`0014_fix_outcomes.sql`**, so the new one is **`0015_...`**.
- Status/provider/product/outcome columns are **plain `text`, no enum/CHECK**
  (migrations 0003/0007/0011/0014) — a new status value must never require its
  own migration.
- Every new table gets **default-deny RLS** with no policies
  (`alter table X enable row level security;`), same as migrations 0002/0014.
- `telegram_chat_id` is stored as **`text`** (migration 0005) to match
  `provider`/`external_ref` and dodge 64-bit edges. We follow that for
  `telegram_user_id`.

### 5. Webhook authenticity & the new update type

- `POST /v1/webhooks/telegram` (`app/main.py:496`) validates the
  `X-Telegram-Bot-Api-Secret-Token` header (constant-time), 503s if
  `TELEGRAM_BOT_TOKEN` / `TELEGRAM_WEBHOOK_SECRET` are unset, then hands the raw
  JSON to `handle_update`. **No signature change needed** — a
  `bot_subscription_updated` update arrives on the same URL with the same secret
  header, so `handle_update` just needs a new branch.
- The new update type is `BotSubscriptionUpdated`. Its **Update field key** is
  taken to be `bot_subscription_updated` (snake_case of the type name, matching
  every existing Update field: `pre_checkout_query`, `my_chat_member`, etc.).
  This is the one thing not provable from the sandbox; it is called out in the
  live-test checklist below and is the first thing to confirm against a real
  delivery.
- The `BotSubscriptionUpdated` payload carries `user`, `invoice_payload`, and
  `state ∈ {"canceled", "active", "failed"}`. **Crucially it does NOT carry a
  `telegram_payment_charge_id`** — so the only stable way to match it back to a
  stored subscription is `(telegram_user_id, invoice_payload)`. That constraint
  drives the natural key chosen below.

---

## Step 2 — Design (what will be built)

### A. New constants & invoice function (`app/billing/telegram_stars.py`)

```python
# Bot API: the ONLY permitted subscription period is 30 days, expressed in
# seconds. Any other value is rejected by createInvoiceLink/sendInvoice.
SUBSCRIPTION_PERIOD_SECONDS = 2592000  # 30 days, the sole allowed value

# Throwaway tier to prove the subscription plumbing end-to-end. NOT the
# Phase C monitoring price — 1 Star keeps the live test cheap.
SUBSCRIPTION_TIER = "test-monitoring"
SUBSCRIPTION_PAYLOAD = "sub:test-monitoring"   # sub: prefix mirrors fixpack:
SUBSCRIPTION_TITLE = "Drydock Monitoring (test)"
SUBSCRIPTION_DESCRIPTION = (
    "Test subscription for Drydock continuous monitoring — billing "
    "verification only, not the final product price."
)
_DEFAULT_SUBSCRIPTION_STARS = 1

def subscription_stars_price() -> int: ...   # env SUBSCRIPTION_STARS override, same pattern as pro_stars_price
```

- Add an optional `subscription_period: int | None = None` to
  `build_invoice_payload` and `send_invoice`. When `None` (every existing
  caller), the body is unchanged. When set, add `"subscription_period":
  subscription_period` to the body. The subscription caller passes
  `SUBSCRIPTION_PERIOD_SECONDS`.
- Price guard: `sendInvoice` will reject > 10000 Stars for a subscription; our
  default is 1 and the env override is operator-controlled, so no runtime clamp
  is added (documented, not enforced — consistent with `pro_stars_price()` being
  unclamped today).

### B. New `/subscribe` command (`_handle_subscribe`)

Mirrors `_handle_upgrade`: sends the Stars invoice with `payload=SUBSCRIPTION_PAYLOAD`,
`stars=subscription_stars_price()`, `subscription_period=SUBSCRIPTION_PERIOD_SECONDS`.
Dispatched from `handle_update` on `text == "/subscribe"`.

### C. `successful_payment` routing for subscriptions

In `handle_update`, before the Pro branch, add:

```python
if payload.startswith("sub:"):
    return await _handle_subscription_payment(message, sp, subscription_repo=..., token=..., transport=...)
```

`_handle_subscription_payment` (calls a new converging helper
`grant_subscription` in `app/billing/__init__.py`):

- Reads `is_first_recurring`, `is_recurring`, `subscription_expiration_date`
  (→ `expires_at`), `telegram_payment_charge_id`, `invoice_payload`, and
  `message.from.id` (telegram_user_id) + `message.chat.id`.
- **First payment** (`is_first_recurring == True`): **upsert** a `subscriptions`
  row keyed on `(telegram_user_id, invoice_payload)` with `status='active'`,
  `expires_at`, and the current `telegram_payment_charge_id`.
- **Renewal** (`is_recurring == True` and not first): **update the existing**
  row's `expires_at` and `telegram_payment_charge_id` (the charge id rotates
  each period and `editUserStarSubscription` needs the latest one); do **not**
  insert a new row, do **not** create a second account.
- Also records a completed `payments` row per charge (each renewal is a real
  charge with its own `telegram_payment_charge_id`) for revenue bookkeeping,
  idempotent on `(provider, external_ref)` — reuses the existing
  `payments`/migration-0004 backstop. No account/tier/key is minted (this is
  `test-monitoring`, not Pro — see rationale below).
- DMs a short confirmation with the `expires_at` date; **no API key** (there is
  no product to unlock yet).

**Why no account/API key for the subscription:** Pro mints a key because the key
*is* the product (API access). `test-monitoring` unlocks nothing today — the
Phase C monitoring feature that consumes it doesn't exist. Minting a key now
would be dead plumbing. The `subscriptions` row keys off `telegram_user_id`
directly; `account_id` is kept as a **nullable** column so the future monitoring
feature can link an account without a migration.

### D. `bot_subscription_updated` handling

New branch in `handle_update`:

```python
bsu = update.get("bot_subscription_updated")
if bsu is not None:
    return await _handle_subscription_updated(bsu, subscription_repo=...)
```

- Match the row on `(telegram_user_id, invoice_payload)` (the only keys the
  payload provides).
- Map `state` → `status`: `"canceled"` → `canceled`, `"active"` → `active`
  (re-enabled), `"failed"` → `failed`.
- **`failed` does NOT revoke access immediately.** The current period was already
  paid through `expires_at`; a failed *renewal* only means the *next* period
  wasn't charged. Access therefore remains until `expires_at` lapses naturally.
  This matches Telegram's own cancel semantics (cancel keeps access to period
  end) and keeps a single, consistent access rule.
- **Access rule (documented for the future monitoring feature to consume):**
  a subscription is *active-for-access* when `expires_at > now()`, regardless of
  whether `status` is `active`, `canceled`, or `failed`. `status` is the
  *renewal* state (will it charge again?); `expires_at` is the *access* boundary.
  A row is `expired` only after a sweep/lazy-check finds `expires_at <= now()`
  (that sweep is **out of scope** here — noted as a follow-up; nothing consumes
  access yet).

### E. Cancellation — `editUserStarSubscription` + `/unsubscribe`

- New function `cancel_subscription(*, user_id, telegram_payment_charge_id, token, transport)`
  → `_call("editUserStarSubscription", {"user_id":..., "telegram_payment_charge_id":..., "is_canceled": True})`.
  A `re_enable_subscription` counterpart (`is_canceled=False`) is trivial but
  **not** built unless needed — no current caller (YAGNI).
- New `/unsubscribe` command (`_handle_unsubscribe`): looks up the active
  subscription for this `telegram_user_id`, reads its stored
  `telegram_payment_charge_id`, calls `cancel_subscription`, and (on Telegram
  returning `True`) sets the row `status='canceled'`. DMs that access continues
  until `expires_at`.
- Rationale for a bot command over an HTTP endpoint: it mirrors `/upgrade` and
  is directly exercisable in the same live Telegram test, and cancellation needs
  the payer's `user_id` which the bot message already carries.

### F. New migration `0015_subscriptions.sql`

```sql
create table if not exists subscriptions (
    id uuid primary key default gen_random_uuid(),
    account_id uuid references accounts(id),          -- nullable; linked later by Phase C
    telegram_user_id text not null,                   -- who pays (from message.from.id / BotSubscriptionUpdated.user)
    telegram_chat_id text,                            -- where to DM renewal/cancel notices
    tier text not null,                               -- 'test-monitoring' for now; text for future tiers
    invoice_payload text not null,                    -- matches BotSubscriptionUpdated (no charge_id there)
    telegram_payment_charge_id text,                  -- latest charge id; needed by editUserStarSubscription
    status text not null default 'active',            -- active | canceled | failed | expired (plain text, no enum)
    expires_at timestamptz,                           -- from successful_payment.subscription_expiration_date
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

-- Natural key: a BotSubscriptionUpdated carries only (user, invoice_payload),
-- so that pair must resolve to at most one row. Unique so renewal upserts and
-- state updates target exactly one subscription.
create unique index if not exists subscriptions_user_payload_key
    on subscriptions (telegram_user_id, invoice_payload);

create index if not exists subscriptions_expires_at_idx
    on subscriptions (expires_at);

-- Default-deny RLS, no policies — same posture/rationale as 0002 and 0014.
alter table subscriptions enable row level security;
```

*Concurrent-subscription note:* the Bot API allows one user to hold several
subscriptions at once, distinguished by `invoice_payload`. With a single test
tier there is exactly one payload, so `(user, payload)` is unique. When Phase C
adds real tiers, each tier gets its own payload and the key still holds. Two
concurrent subscriptions to the *same* payload is the one shape this key can't
represent — out of scope and noted for Phase C.

### G. `SubscriptionRepository` (`app/db.py`)

Real psycopg3 repo mirroring `PaymentRepository`'s shape and the
not-configured contract (return `None` when `DATABASE_URL` unset). Methods:

- `get_by_user_and_payload(telegram_user_id, invoice_payload)` — the natural-key
  lookup for renewals and `bot_subscription_updated`.
- `get_active_by_user(telegram_user_id)` — backs `/unsubscribe`.
- `upsert_first(...)` — insert-or-update on the natural key for the first
  payment (`insert ... on conflict (telegram_user_id, invoice_payload) do update`).
- `renew(id, *, expires_at, telegram_payment_charge_id)` — update on renewal.
- `set_status(id, status)` — for `bot_subscription_updated` and `/unsubscribe`.

Plus a `_row_to_subscription` normalizer (uuid → str, like the others). A
`FakeSubscriptionRepo` goes in `tests/test_billing_telegram.py`, and a
`get_subscription_repo` dependency + module-level `_subscription_repo` instance
are added to `app/main.py`, wired into the `telegram_webhook` handler and passed
through to `handle_update`.

---

## Testing

### Unit / integration tests (`tests/test_billing_telegram.py`)

Using the existing `httpx.MockTransport` + in-memory fakes (add
`FakeSubscriptionRepo`):

- **(a) first payment** — `successful_payment` with `is_first_recurring=True`,
  `subscription_expiration_date` set, payload `sub:test-monitoring` → creates
  exactly one `subscriptions` row, `status='active'`, `expires_at` == the given
  date, `telegram_payment_charge_id` stored.
- **(b) renewal** — a second `successful_payment` with `is_recurring=True` (no
  `is_first_recurring`), new charge id, later `subscription_expiration_date` →
  the **same** row's `expires_at` advances and `telegram_payment_charge_id`
  rotates; **no** second subscription row is created.
- **(c) canceled** — `bot_subscription_updated` with `state="canceled"` →
  row `status='canceled'`, `expires_at` untouched (access preserved to period
  end).
- **(d) failed** — `bot_subscription_updated` with `state="failed"` →
  `status='failed'`, `expires_at` untouched (**access not revoked immediately**;
  asserts the documented access rule).
- **Plus:** invoice-body test — `build_invoice_payload(..., subscription_period=
  SUBSCRIPTION_PERIOD_SECONDS)` includes `"subscription_period": 2592000`, and
  omitting it leaves the body identical to today (one-shot path unchanged).
- **Plus:** `/subscribe` sends an invoice carrying `subscription_period`;
  `/unsubscribe` calls `editUserStarSubscription` with `is_canceled=True` and
  flips the row to `canceled`.
- **Plus:** idempotency — the same first-payment charge delivered twice (Telegram
  retry) yields one row and one `payments` record.

Full `pytest` run must stay green.

### Live test (operator, real Telegram Stars — the real proof)

The mocked tests cannot prove the webhook half; this is the acceptance gate the
operator runs with a real bot token + public HTTPS webhook (Stars payment is
already configured for this session's bot):

1. Set `SUBSCRIPTION_STARS=1` (or accept the default), deploy, ensure the
   webhook secret is set.
2. DM the bot `/subscribe` → tap the Pay button → complete a **1-Star**
   subscription.
3. Confirm the webhook received `successful_payment` with `is_first_recurring=
   true` and `subscription_expiration_date`, and that a `subscriptions` row
   exists with `status='active'` and the right `expires_at`.
4. **Confirm the `bot_subscription_updated` Update field key** against the real
   delivery (the one assumption in this plan) — adjust the branch key if
   Telegram names it differently.
5. DM `/unsubscribe` → verify `editUserStarSubscription` returns `True`, the row
   flips to `status='canceled'`, and a `bot_subscription_updated` with
   `state="canceled"` arrives and is handled; access (`expires_at`) is unchanged.
6. (If feasible) re-enable via Telegram's UI → observe `state="active"` handled.

---

## README updates (Step 2)

- Document the new `bot_subscription_updated` webhook update type alongside the
  existing `pre_checkout_query` / `successful_payment` description.
- Document the `SUBSCRIPTION_PERIOD_SECONDS = 2592000` constant (sole allowed
  value), the `test-monitoring` throwaway tier, the `/subscribe` and
  `/unsubscribe` commands, and the `SUBSCRIPTION_STARS` env override.
- State the access rule (`expires_at`-based) and that recurring is Stars-only
  (USDT stays one-time).

---

## Explicitly out of scope

- Any continuous-monitoring behavior or product wiring.
- Website pricing UI / real subscription price / non-test tiers.
- A background sweep to flip `active`→`expired` at `expires_at` (nothing
  consumes access yet; noted as the immediate Phase C follow-up).
- `re_enable_subscription` (is_canceled=False) beyond what `/unsubscribe`
  needs — added only if a caller appears.
- Any change to `usdt_trc20.py` (crypto can't auto-charge).

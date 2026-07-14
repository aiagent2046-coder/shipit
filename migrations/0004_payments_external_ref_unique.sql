-- Paywall Stage 2: payment providers (Telegram Stars, USDT/TRC20).
-- No new tables -- `accounts` and `payments` from 0003 are exactly what
-- Stage 2 writes to. This migration only hardens `payments` for the
-- idempotency both providers rely on.
--
-- external_ref holds the provider's own charge/transaction id
-- (telegram_payment_charge_id for Stars, the on-chain transaction_id for
-- USDT/TRC20). Both providers can deliver the same event more than once
-- -- Telegram retries a webhook until it gets 200, and a single TRC20
-- transfer is seen on every poll until it scrolls out of the window --
-- so "one completed payment per external_ref" must hold even under a
-- race between two concurrent handlers. The app checks
-- get_by_external_ref before granting, but that check-then-insert has a
-- TOCTOU window; this partial unique index closes it at the database.
--
-- Partial (WHERE external_ref is not null) because a freshly created
-- USDT invoice is a pending row with no external_ref yet (it gets one
-- when an on-chain transfer is matched to it), and several such nulls
-- must be allowed to coexist.
create unique index if not exists payments_provider_external_ref_key
    on payments (provider, external_ref)
    where external_ref is not null;

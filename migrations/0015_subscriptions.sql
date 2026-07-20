-- Recurring billing foundation: Telegram Stars subscriptions.
--
-- Until now all billing is one-shot (a completed `payments` row grants Pro
-- or a Fix Pack, migrations 0003/0004/0007). Phase C (Continuous Monitoring)
-- is a subscription product, so this adds the durable record of an ongoing
-- Stars subscription -- built and proven now, separately from the monitoring
-- feature that will later consume it. Stars is the ONLY provider here: USDT
-- can't auto-charge (no allowance contracts), so it stays one-time.
--
-- This is billing plumbing only. The single tier written today is a throwaway
-- 'test-monitoring' (see app/billing/telegram_stars.SUBSCRIPTION_TIER) priced
-- at 1 Star, purely to exercise a real subscription end to end. It is NOT the
-- product's final price and nothing consumes access yet.
--
-- Natural key (telegram_user_id, invoice_payload): the BotSubscriptionUpdated
-- update (Bot API `subscription` field) carries only the user and the
-- invoice_payload -- NOT a telegram_payment_charge_id -- so that pair is the
-- only stable way to match a state change (canceled/active/failed) back to a
-- stored subscription. The renewal successful_payment also matches on it (the
-- charge id rotates every period). Unique so a renewal upsert and a state
-- update each hit exactly one row. One user may hold several concurrent
-- subscriptions, distinguished by payload; with one test tier there is exactly
-- one payload, so the key holds (Phase C's real tiers each get their own).
--
-- telegram_payment_charge_id holds the LATEST period's charge id, refreshed on
-- every renewal, because editUserStarSubscription (cancel/re-enable) needs the
-- current one. Nullable only defensively; the first payment always sets it.
--
-- status is plain text (active | canceled | failed | expired), no enum/CHECK,
-- same rationale as the status/provider/product columns in 0003/0007/0011: a
-- new status value must never require its own migration. IMPORTANT: status is
-- the *renewal* state (will it charge again?), not the *access* boundary.
-- Access is expires_at-based -- a subscription grants access while
-- expires_at > now() regardless of status, because a canceled or failed-renewal
-- subscription keeps the period it already paid for (matches Telegram's own
-- cancel semantics). 'expired' is only set once expires_at has passed; the
-- sweep that does so is a Phase C follow-up (nothing consumes access yet).
--
-- account_id is nullable: 'test-monitoring' mints no account/API key (the key
-- IS the Pro product; this tier unlocks nothing today, so a key would be dead
-- plumbing). The column exists so Phase C can link an account without a
-- migration.
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

create unique index if not exists subscriptions_user_payload_key
    on subscriptions (telegram_user_id, invoice_payload);

-- The access boundary is queried by expires_at (a future sweep flips lapsed
-- rows to 'expired'); index it so that scan stays cheap.
create index if not exists subscriptions_expires_at_idx
    on subscriptions (expires_at);

-- Default-deny RLS with no policies, same posture and rationale as migrations
-- 0002 (audits, fixpack_jobs) and 0014 (fix_outcomes): no user/auth model to
-- write a per-row policy against, and the app connects as the table-owning
-- `postgres` role (RLS never applies to the owner without FORCE ROW LEVEL
-- SECURITY, which this deliberately does not set), so this only closes the
-- "RLS Disabled in Public" advisory for a role reaching the table via
-- PostgREST. `subscriptions` is billing data and must never be readable
-- through the anon/publishable key.
alter table subscriptions enable row level security;

-- Paywall foundation, Stage 1: the FIRST identity concept in this
-- codebase. Until now the app is fully anonymous -- ratelimit.py keys by
-- client IP, there's no users/accounts table anywhere (see 0001's
-- comment on why `users` was deliberately deferred). This introduces
-- accounts and payments so a follow-up (Stage 2) can plug in real
-- payment providers (Telegram Stars, USDT/TRC20) on top.
--
-- No email/password login: there is no auth system, and the actual
-- onboarding flow is payment-driven (a successful payment creates or
-- upgrades an account and hands back an API key), so an account is
-- identified by a server-generated opaque API key (`sk_live_<random>`,
-- see app/accounts.py) carried as `Authorization: Bearer <key>`. No key
-- or an unknown key = anonymous `free`, exactly today's behavior --
-- existing unauthenticated usage is completely unaffected.

create table if not exists accounts (
    id uuid primary key default gen_random_uuid(),
    -- Opaque server-generated secret. Unique so a lookup by key resolves
    -- at most one account; indexed because every authenticated request
    -- resolves the caller by this column.
    api_key text not null unique,
    -- Two tiers only for now (free / pro) -- kept a plain text column, not
    -- an enum, so adding a tier later is a data change, not a migration.
    tier text not null default 'free',
    created_at timestamptz not null default now()
);

-- `payments` records purchase attempts/completions generically. No
-- provider logic writes here yet -- this table exists so Stage 2 has
-- somewhere to write to. `provider` is plain text on purpose (will be
-- 'telegram_stars' / 'usdt_trc20' later): no enum/check constraint that
-- would itself need a migration when a real provider is added. Same
-- reasoning for `status` and `tier_granted`.
create table if not exists payments (
    id uuid primary key default gen_random_uuid(),
    account_id uuid references accounts(id),
    provider text not null,
    external_ref text,          -- the provider's own charge/transaction id
    amount numeric,
    currency text,
    status text not null default 'pending',   -- pending / completed / failed
    tier_granted text,          -- which tier this payment unlocks
    created_at timestamptz not null default now()
);

create index if not exists payments_account_id_idx on payments (account_id);
create index if not exists payments_created_at_idx on payments (created_at desc);

-- RLS default-deny on both new tables, same posture and reasoning as
-- 0002: no permissive policies, so anon/authenticated via PostgREST get
-- zero rows. This matters more here than for audits/fixpack_jobs --
-- `accounts.api_key` is a live secret, and `payments` is billing data;
-- neither may ever be readable through the anon/publishable key. This
-- app's own access is unaffected: app/db.py connects as the `postgres`
-- table owner via the Supavisor pooler, and RLS never applies to the
-- owner unless FORCE ROW LEVEL SECURITY is set, which this does not set.
alter table accounts enable row level security;
alter table payments enable row level security;

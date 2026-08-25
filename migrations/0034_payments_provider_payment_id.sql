-- rollback-safe: yes
--
-- A nullable column nothing older reads or writes. A release rolled back to the
-- previous code ignores it, and every existing row stays valid.
--
-- The payment's identity in the payment system that took the money.
--
-- WHY IT IS NOT external_ref. That column already holds our own order
-- reference -- the DRY-XXXXXX code the buyer quotes to support and types into
-- the Telegram bot to collect a key -- and it is what the CAS-gated grant in
-- mark_completed_fixpack keys on. Both identifiers are needed and they are not
-- the same thing: ours is the one a human reads out over email, theirs is the
-- one that addresses POST /v3/refunds.
--
-- WHY NOT REUSE paypal_order_id (migration 0018). It is the same shape and the
-- temptation is real. It is also a column named after a rail that was removed
-- on 2026-08-20, still carrying the historical rows that rail wrote, under a
-- unique index scoped to it. Storing a ЮKassa id there would make those rows
-- indistinguishable from PayPal ones in exactly the table where "which system
-- has this money" is the question being asked.
--
-- WHY RECORD IT AT ALL, when the join already works without it. The
-- notification handler finds our row through the metadata we set on the
-- payment, so nothing in the current flow reads this column. What reads it is
-- the refund that does not exist yet: POST /v3/refunds is addressed by the
-- payment id, and an operator who has to find it by hand -- searching a
-- dashboard by amount and time -- is an operator who will eventually refund
-- the wrong one. The value is free to keep now and expensive to reconstruct
-- for every historical row later, which is the same argument migration 0033
-- made about the payer's language.
--
-- Nullable, no backfill, no default. Every payment before this migration was
-- taken by a rail that had no such id, and inventing one would be a claim that
-- some other system holds money it does not.
--
-- Unique where present, and that is not decoration. One charge in their system
-- must not be able to complete two orders here: the index is what makes a
-- second row carrying the same id fail loudly instead of quietly granting a
-- Fix Pack for a payment that already bought one.
alter table payments add column if not exists provider_payment_id text;

create unique index if not exists payments_provider_payment_id_key
    on payments (provider_payment_id)
    where provider_payment_id is not null;

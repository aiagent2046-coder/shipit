-- PayPal Checkout as an ALTERNATIVE payment method alongside Telegram Stars.
-- Purely additive: the Stars (and USDT) flows are unchanged. One-time products
-- (Pro, Fix Pack) need NO schema change on `payments` for `provider='paypal'`
-- -- provider/product/external_ref are free-text and the (provider,
-- external_ref) partial unique index from 0004 is the idempotency backstop for
-- PayPal too (external_ref = the capture/sale id). This migration only adds
-- what the two providers genuinely don't share: a PayPal order id to poll a Pro
-- key back with, and PayPal's own subscription identity on `subscriptions`.
--
-- payments.paypal_order_id: the PayPal Order id (created before the buyer
-- approves in the browser). Stars/USDT rows leave it null. It exists so
-- GET /v1/paypal/orders/{order_id} can find the pending row created at order
-- time and, once the webhook captures, read the granted account's key back to
-- the browser -- the web-poll delivery that replaces Stars' Telegram DM. The
-- webhook keys the grant on the capture id (external_ref) via the same
-- invoice_payment_id transition USDT already uses; the order id is only the
-- browser's poll handle. Partial-unique so a retried order-create can't create
-- two rows for one order, while the many null Stars/USDT rows coexist.
alter table payments add column if not exists paypal_order_id text;

create unique index if not exists payments_paypal_order_id_key
    on payments (paypal_order_id)
    where paypal_order_id is not null;

-- subscriptions: PayPal monitoring subscriptions have neither a
-- telegram_user_id nor a Telegram invoice_payload, so the (telegram_user_id,
-- invoice_payload) natural key from 0015 can't identify them. Add PayPal's own
-- identity additively and let telegram_user_id go nullable for PayPal rows.
--
-- payment_provider: which provider owns the row. Existing rows are all Stars,
-- hence the default -- no backfill needed. Plain text, no enum/CHECK, same
-- rationale as status/provider/product in 0003/0007/0015.
alter table subscriptions
    add column if not exists payment_provider text not null default 'telegram_stars';

-- paypal_subscription_id: PayPal's 'I-XXXX' subscription id. Nullable (Stars
-- rows leave it null); it is the PayPal natural key, parallel to Stars'
-- (telegram_user_id, invoice_payload). BILLING.SUBSCRIPTION.* events and the
-- renewal PAYMENT.SALE.COMPLETED (billing_agreement_id) all resolve back to a
-- row through it.
alter table subscriptions add column if not exists paypal_subscription_id text;

-- Stars requires telegram_user_id and invoice_payload (its natural key); PayPal
-- rows have neither -- they key on paypal_subscription_id instead. Drop the NOT
-- NULL on both so the two providers coexist. Safe/additive -- no data rewrite,
-- existing rows keep their values and the Stars code path still always sets them.
alter table subscriptions alter column telegram_user_id drop not null;
alter table subscriptions alter column invoice_payload drop not null;

-- The PayPal natural key: at most one subscriptions row per PayPal subscription
-- id, so a duplicate ACTIVATED upserts onto the same row. Partial (only PayPal
-- rows carry the id) so the many null Stars rows coexist -- exactly parallel to
-- 0015's (telegram_user_id, invoice_payload) unique index, which stays for Stars.
create unique index if not exists subscriptions_paypal_subscription_id_key
    on subscriptions (paypal_subscription_id)
    where paypal_subscription_id is not null;

-- Paywall Stage 2, follow-up: API-key recovery over the Telegram bot.
--
-- Until now a payer's Telegram chat_id was used once (to DM the key on a
-- successful Stars payment) and then thrown away -- it was never stored,
-- so a payer who lost their key had no way to ask the bot for it again,
-- and a USDT payer had no identity on file at all. This adds a single
-- nullable column that both recovery commands hang off:
--
--   * /mykey  -- resend the delivery message to a chat_id that already
--     has a completed payment linked to it (Stars links this
--     automatically at purchase; USDT links it via /link).
--   * /link <tx_hash>  -- a USDT payer proves ownership of an already
--     credited on-chain payment by its transaction hash, and we stamp
--     their chat_id onto that payment row.
--
-- text, not bigint: chat_id is stored as text to match provider /
-- external_ref (also text) and to sidestep any 64-bit edge, and it's
-- compared as text everywhere. Nullable because most payment rows never
-- get one (a pending invoice, a completed payment nobody has run /mykey
-- or /link for), same as external_ref being null on a pending invoice.
--
-- Partial index (WHERE ... is not null) mirrors 0004's reasoning: the
-- only lookup is "which completed payment belongs to this chat_id", the
-- nulls are the common case and don't need indexing.
alter table payments add column if not exists telegram_chat_id text;

create index if not exists payments_telegram_chat_id_idx
    on payments (telegram_chat_id)
    where telegram_chat_id is not null;

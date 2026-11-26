from __future__ import annotations

import datetime
import logging
import uuid
from typing import Any

from app.accounts import TIER_PRO, api_key_prefix, generate_api_key, hash_api_key
from app.monitor import MONITORING_INTERVAL_HOURS
from app.db._core import (
    _GRANT_LOCK_NAMESPACE,
    _grant_lock_key,
    _grant_lock_timeout_ms,
    DatabaseNotConfigured,
    ProGrantConflict,
    _expires_at_to_timestamptz,
    _resolve_get_pool,
    _row_to_account,
    _row_to_payment,
    _row_to_subscription,
)

logger = logging.getLogger("app.db")


class PaymentRepository:
    """Purchase records and atomic Pro settlement, with the repositories'
    usual None result when persistence is not configured."""

    async def grant_pro_account(
        self, *, provider: str, external_ref: str,
        amount: float | None, currency: str | None,
        invoice_payment_id: str | None = None,
    ) -> dict[str, Any] | None:
        """Create a Pro account and settle its payment in one transaction.

        A completed replay returns the same account without plaintext. A new
        account's key is returned only after commit and is never stored.
        Invalid invoice/charge associations return None before writing. SQL
        failures, lock timeouts and cancellation propagate, rolling back both
        writes; an unexpected settlement refusal raises ProGrantConflict.
        This operation owns its charge lock and must not be called while a
        separate connection holds the same advisory lock.
        """
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None

        def refuse(reason: str) -> None:
            logger.error(
                "Pro grant refused for %s/%s (invoice %s): %s",
                provider, external_ref, invoice_payment_id, reason,
            )

        if not provider or not external_ref:
            return refuse("provider and charge reference are required")
        try:
            invoice_id = (
                uuid.UUID(invoice_payment_id)
                if invoice_payment_id is not None else None
            )
        except (ValueError, TypeError, AttributeError):
            return refuse("invalid invoice id")

        api_key = None
        async with pool.connection() as conn:
            async with conn.transaction():
                await conn.execute(
                    f"set local lock_timeout = {_grant_lock_timeout_ms()}"
                )
                # Reuse the old session lock's namespace so an older worker
                # still finishing a grant serializes with this transaction.
                # Unlike that implementation, this uses just one connection
                # and never proceeds without the lock on timeout.
                await conn.execute(
                    "select pg_advisory_xact_lock(%s, %s)",
                    (_GRANT_LOCK_NAMESPACE, _grant_lock_key(provider, external_ref)),
                )
                invoice = None
                if invoice_id is not None:
                    cur = await conn.execute(
                        """
                        select id, account_id, provider, external_ref,
                               status, product
                          from payments where id = %s for update
                        """, (invoice_id,),
                    )
                    invoice = await cur.fetchone()
                    if invoice is None:
                        return refuse("invoice does not exist")
                    if (invoice["provider"] != provider
                            or invoice["product"] != "pro_tier"):
                        return refuse("invoice provider or product does not match")
                    if invoice["external_ref"] not in (None, external_ref):
                        return refuse("invoice belongs to another charge")

                cur = await conn.execute(
                    """
                    select id, account_id, provider, external_ref, status, product
                      from payments
                     where provider = %s and external_ref = %s for update
                    """, (provider, external_ref),
                )
                existing = await cur.fetchone()
                if (invoice_id is not None and existing is not None
                        and existing["id"] != invoice_id):
                    return refuse("charge belongs to another invoice")

                payment = invoice if invoice is not None else existing
                if payment is not None:
                    if (payment["provider"] != provider
                            or payment["product"] != "pro_tier"):
                        return refuse("charge provider or product does not match")
                    if payment["status"] == "completed":
                        if (not payment["account_id"]
                                or payment["external_ref"] != external_ref):
                            return refuse("completed payment has no matching grant")
                        cur = await conn.execute(
                            """
                            select id, key_prefix, key_hash, tier, created_at
                              from accounts where id = %s
                            """, (payment["account_id"],),
                        )
                        row = await cur.fetchone()
                        if row is None or row["tier"] != TIER_PRO:
                            return refuse("completed payment has no Pro account")
                        account = _row_to_account(row)
                    elif (payment["status"] != "pending"
                          or payment["account_id"] is not None
                          or invoice_id is None):
                        return refuse("payment is not an ungranted pending invoice")
                    else:
                        account = None
                else:
                    account = None

                if account is None:
                    api_key = generate_api_key()
                    cur = await conn.execute(
                        """
                        insert into accounts (key_prefix, key_hash, tier)
                        values (%s, %s, %s)
                        returning id, key_prefix, key_hash, tier, created_at
                        """,
                        (api_key_prefix(api_key), hash_api_key(api_key), TIER_PRO),
                    )
                    row = await cur.fetchone()
                    if row is None:
                        raise ProGrantConflict("Pro account insertion was refused")
                    account = _row_to_account(row)
                    if invoice_id is not None:
                        cur = await conn.execute(
                            """
                            update payments
                               set status = 'completed', account_id = %s,
                                   external_ref = %s, tier_granted = %s
                             where id = %s and provider = %s
                               and product = 'pro_tier' and status = 'pending'
                               and account_id is null
                               and (external_ref is null or external_ref = %s)
                            returning id
                            """,
                            (uuid.UUID(account["id"]), external_ref, TIER_PRO,
                             invoice_id, provider, external_ref),
                        )
                    else:
                        cur = await conn.execute(
                            """
                            insert into payments
                                (account_id, provider, external_ref, amount,
                                 currency, status, tier_granted, product)
                            values (%s, %s, %s, %s, %s, 'completed', %s, 'pro_tier')
                            returning id
                            """,
                            (uuid.UUID(account["id"]), provider, external_ref,
                             amount, currency, TIER_PRO),
                        )
                    if await cur.fetchone() is None:
                        raise ProGrantConflict("Pro payment settlement was refused")

        if api_key is not None:
            account["api_key"] = api_key
        return account

    async def create(
        self, *, account_id: str | None, provider: str,
        external_ref: str | None, amount: float | None, currency: str | None,
        status: str, tier_granted: str | None,
        product: str = "pro_tier", audit_id: str | None = None,
        payer_name: str | None = None, payer_email: str | None = None,
        payer_x: str | None = None, payer_locale: str | None = None,
        provider_payment_id: str | None = None,
        fixpack_job_id: str | None = None,
        delivery_grant: str | None = None,
    ) -> dict[str, Any] | None:
        """payer_name/payer_email (migration 0026) and payer_x (0032) are what
        the payer said about themselves before paying. The name is for the
        operator's books; the other two are how the customer is told what
        happened to their money -- see app/notify/router.py. Only bank_transfer
        supplies them; a Stars charge carries an identity of its own.

        `paypal_order_id` (migration 0018) is still SELECTed and still holds
        the rows PayPal wrote, but nothing sets it any more: PayPal was removed
        as a way to pay. Reading the books is not the same as keeping the till
        open, and the column is the books.

        `fixpack_job_id` (migration 0035) is which job this order paid for, and
        it goes in with this INSERT rather than in a later UPDATE because
        grant_fixpack already holds the job by the time it gets here. audit_id
        cannot stand in for it: one audit can hold several jobs and several
        orders, and picking among them by time misdirects the message that
        tells a buyer what happened to their money."""
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        parsed_account_id = uuid.UUID(account_id) if account_id else None
        parsed_audit_id = uuid.UUID(audit_id) if audit_id else None
        parsed_job_id = uuid.UUID(fixpack_job_id) if fixpack_job_id else None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                insert into payments
                    (account_id, provider, external_ref, amount, currency,
                     status, tier_granted, product, audit_id,
                     payer_name, payer_email, payer_x, payer_locale,
                     provider_payment_id, fixpack_job_id)
                values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s)
                returning id, account_id, provider, external_ref, amount,
                          currency, status, tier_granted, telegram_chat_id,
                          product, audit_id, paypal_order_id, payer_name,
                          payer_email, payer_x, payer_locale,
                          provider_payment_id, fixpack_job_id, created_at
                """,
                (parsed_account_id, provider, external_ref, amount, currency,
                 status, tier_granted, product, parsed_audit_id,
                 payer_name, payer_email, payer_x, payer_locale,
                 provider_payment_id, parsed_job_id),
            )
            row = await cur.fetchone()
            if delivery_grant is not None and row is not None:
                # The pool connection commits on clean exit, so the order and
                # its encrypted repository grant become visible together.
                # Keep this secret outside the public payment row mapper.
                await conn.execute(
                    "insert into fixpack_delivery_grants (payment_id, encrypted_grant) "
                    "values (%s, %s)", (row["id"], delivery_grant),
                )
        return _row_to_payment(row)

    async def get(self, payment_id: str) -> dict[str, Any] | None:
        """One payment by id.

        `refunded_at` is selected HERE and in none of the sibling queries
        below, which is a deliberate asymmetry rather than an oversight. This
        is the only read that can return a row in any status, so it is the only
        one where "refunded" is news: the others are filtered to `pending` or
        `completed`, or are looking a payment up in order to grant something.

        It was missing until 2026-08-21, and the endpoint that noticed is the
        one that most needed it. GET /internal/payments/{id}/fixpack-merit
        exists to be consulted BEFORE an operator decides a refund, and it
        renders `refunded_at` -- so it reported `null` for every payment ever
        refunded, including one refunded three weeks earlier. `status` said
        "refunded" in the same response. Of the two fields that contradicted
        each other, the wrong one was the one that looks precise.

        `refund_reason` is deliberately NOT here. It is the operator's own
        note, written to be true rather than to be read by the person it is
        about, and this row is passed around widely enough that adding it would
        be a decision about disclosure taken by accident. mark_refunded returns
        it to the caller that wrote it; that is the audience it has.
        """
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        try:
            parsed_id = uuid.UUID(payment_id)
        except ValueError:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select id, account_id, provider, external_ref, amount,
                       currency, status, tier_granted, telegram_chat_id,
                       product, audit_id, paypal_order_id, payer_name,
                       payer_email, payer_x, payer_locale, refunded_at,
                       provider_payment_id, fixpack_job_id, created_at
                from payments where id = %s
                """,
                (parsed_id,),
            )
            row = await cur.fetchone()
        return _row_to_payment(row) if row else None

    async def get_by_external_ref(
        self, provider: str, external_ref: str
    ) -> dict[str, Any] | None:
        """Idempotency lookup for Stage 2: a provider's charge/transaction
        id resolves to at most one payment (see migration 0004's partial
        unique index). Used to avoid double-granting on a retried Telegram
        webhook or a TRC20 transfer seen on more than one poll."""
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select id, account_id, provider, external_ref, amount,
                       currency, status, tier_granted, telegram_chat_id,
                       product, audit_id, paypal_order_id, payer_name,
                       payer_email, payer_x, payer_locale,
                       provider_payment_id, fixpack_job_id, created_at
                from payments where provider = %s and external_ref = %s
                """,
                (provider, external_ref),
            )
            row = await cur.fetchone()
        return _row_to_payment(row) if row else None

    async def get_completed_fixpack_for_job(
        self, fixpack_job_id: str
    ) -> dict[str, Any] | None:
        """Find the funding payment, never the newest additional payment.

        Legacy jobs without a key are usable only with one unambiguous linked
        completed payment. Missing/ambiguous ownership requires reconciliation.
        """
        from app.fixpack_funding import funding_key

        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select p.id, p.account_id, p.provider, p.external_ref, p.amount,
                       p.currency, p.status, p.tier_granted, p.telegram_chat_id,
                       p.product, p.audit_id, p.paypal_order_id, p.payer_name,
                       p.payer_email, p.payer_x, p.payer_locale,
                       p.provider_payment_id, p.fixpack_job_id, p.created_at,
                       j.funding_key
                from payments p join fixpack_jobs j on j.id = p.fixpack_job_id
                where p.fixpack_job_id = %s and p.product = 'fixpack'
                  and p.status = 'completed'
                """, (fixpack_job_id,),
            )
            rows = await cur.fetchall()
        for row in rows:
            if row.get("funding_key") and row.get("external_ref") and (
                funding_key(row["provider"], row["external_ref"]) == row["funding_key"]
            ):
                return _row_to_payment(row)
        if len(rows) == 1 and not rows[0].get("funding_key"):
            return _row_to_payment(rows[0])
        return None

    async def list_pending(
        self, provider: str, *, created_after: datetime.datetime | None = None
    ) -> list[dict[str, Any]]:
        """Open (unpaid) invoices for a provider, newest first. Written for
        the USDT poller, which matched incoming transfers against invoices it
        had not seen paid; that rail is gone and bank_transfer is the caller
        left. Returns [] when DATABASE_URL isn't set, same
        not-configured contract as create/get (an empty list, not None, so
        callers can iterate without a guard).

        `created_after` bounds the window. It exists for bank_transfer's
        kopeck-suffix reservation, which asks a different question from the
        poller: not "what might still get paid" (anything, forever -- a
        transfer can surface on day nine) but "what amount is currently in
        flight". Without a bound those two questions share an answer, and
        since nothing ever moves an abandoned invoice out of 'pending', the
        set only grows -- 99 abandoned checkouts and every later buyer is
        quoted the same amount.

        The default is unbounded so the poller keeps its old behaviour: a
        window there would silently stop matching a slow transfer.
        """
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return []
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select id, account_id, provider, external_ref, amount,
                       currency, status, tier_granted, telegram_chat_id,
                       product, audit_id, paypal_order_id, payer_name,
                       payer_email, payer_x, payer_locale,
                       provider_payment_id, created_at
                from payments
                where provider = %s and status = 'pending'
                  and (%s::timestamptz is null or created_at >= %s)
                order by created_at desc
                """,
                (provider, created_after, created_after),
            )
            rows = await cur.fetchall()
        return [_row_to_payment(r) for r in rows]

    async def mark_completed(
        self, payment_id: str, *, account_id: str, external_ref: str
    ) -> dict[str, Any] | None:
        """Transition a pending invoice to completed and link the account
        it granted. This low-level method links an existing account; payment
        providers use grant_pro_account to create and link one atomically.

        Compare-and-set, the same first-writer-wins shape as
        link_telegram_chat_id: the predicate is part of the UPDATE, so the
        decision and the write cannot be separated by another connection.
        Returns the row on success and None on refusal, and the caller MUST
        distinguish the two -- see below. No-op (None) when DATABASE_URL isn't
        set, matching mark_delivered.

        Three outcomes:
          * row was 'pending' -> completed here, row returned. This caller won.
          * row was already 'completed' under the SAME external_ref -> returned
            too, because that is this same payment arriving twice (a retried
            webhook, a transfer seen on a later poll). Idempotent: the caller
            learns "already done" and must not repeat side effects.
          * row was already 'completed' under a DIFFERENT external_ref -> None.
            Not an earlier copy of this payment but a second, distinct charge
            against one invoice, which is a money anomaly a human has to
            reconcile. Returning None rather than overwriting is the point: the
            older unconditional UPDATE clobbered the first charge's account_id,
            so the key the first payer was handed pointed at an orphaned
            account.

        `account_id is null or account_id = %s` is in the predicate for the
        same reason, one level deeper. Two concurrent confirmations of the SAME
        charge both read a payment with no account, both minted one, and the
        second was admitted by the same-external_ref branch above -- overwriting
        the first's account_id and orphaning an account whose key had already
        gone out. Atomic Pro grants now serialize those confirmations, while
        this predicate also protects callers of the low-level method.

        Note the `or account_id = %s`: re-linking the SAME account is still
        allowed, so a replay that reaches here with the account it already
        granted gets the idempotent row back. Only reassignment to a DIFFERENT
        account is refused, which is the actual anomaly. Writing this as a bare
        `account_id is null` looked equivalent -- grant_pro_account returns before
        the UPDATE once it sees an account_id -- but this method's contract is
        the repository's, not grant_pro_account's, and CI's real-Postgres suite
        asserts the replay directly."""
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                update payments
                set status = 'completed', account_id = %s, external_ref = %s
                where id = %s
                  and (account_id is null or account_id = %s)
                  and (status = 'pending'
                       or (status = 'completed'
                           and external_ref = %s))
                returning id, status, account_id, external_ref
                """,
                (uuid.UUID(account_id), external_ref, uuid.UUID(payment_id),
                 uuid.UUID(account_id), external_ref),
            )
            row = await cur.fetchone()
        return _row_to_payment(row) if row else None

    async def mark_refunded(
        self, payment_id: str, *, reason: str,
    ) -> dict[str, Any] | None:
        """Record that a completed payment was given back. Returns the row, or
        None if there was nothing to refund.

        This moves no money and cannot. A bank transfer lands on a private
        individual's account and goes back the same way, by hand; Stars and
        USDT have no refund call we hold a credential for. What the software
        owes is an honest record: before this column existed, a refunded
        payment stayed `completed` forever, and a month later nothing
        distinguished money kept from money returned.

        `status = 'completed'` is inside the UPDATE, not checked before it, for
        the same reason as mark_completed: the decision and the write cannot be
        separated by another connection. That also makes a second refund of the
        same payment a no-op rather than a second entry -- an operator who runs
        the command twice, or a retried request, must not turn one refund into
        two in the books.

        Refusing `pending` is not pedantry. DRY-XZCNTN sat at 10.60 pending
        while DRY-UPRQKH at 10.79 was the charge that actually happened;
        refunding the invoice nobody paid would have recorded a payout that
        never occurred and left the real one looking clean.
        """
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                update payments
                   set status = 'refunded',
                       refunded_at = now(),
                       refund_reason = %s
                 where id = %s
                   and status = 'completed'
                returning *
                """,
                (reason, uuid.UUID(payment_id)),
            )
            row = await cur.fetchone()
        return _row_to_payment(row) if row else None

    async def mark_completed_fixpack(
        self, payment_id: str, *, external_ref: str,
        fixpack_job_id: str | None = None,
    ) -> dict[str, Any] | None:
        """Transition a pending Fix Pack invoice to completed, stamping the
        provider's charge id as its external_ref. The Fix Pack counterpart to
        mark_completed -- but a Fix Pack grants no account/tier, so this
        never sets account_id (it stays null).

        Identical compare-and-set gate, same three outcomes, same obligation on
        the caller to tell a returned row from None: see mark_completed. None
        when DATABASE_URL isn't set.

        `fixpack_job_id` (migration 0035) rides along on the same UPDATE that
        completes the order, so the link between an order and the job it bought
        is written by the statement that makes the order real -- never by a
        later write that a crash could skip. This is the branch a card payment
        takes: the pending row exists from checkout, and grant_fixpack has the
        job in hand when it calls this.

        COALESCE, so a retry cannot blank a link an earlier attempt already
        wrote. The CAS gate lets a second call through when it carries the same
        external_ref -- that is what makes the grant retry-safe -- and a retry
        that reached here with no job id would otherwise erase the pairing."""
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        parsed_job_id = uuid.UUID(fixpack_job_id) if fixpack_job_id else None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                update payments
                set status = 'completed', external_ref = %s,
                    fixpack_job_id = coalesce(%s, fixpack_job_id)
                where id = %s and (status = 'pending'
                                   or (status = 'completed'
                                       and external_ref = %s))
                returning id, status, account_id, external_ref, fixpack_job_id
                """,
                (external_ref, parsed_job_id, uuid.UUID(payment_id),
                 external_ref),
            )
            row = await cur.fetchone()
        return _row_to_payment(row) if row else None

    async def get_completed_by_telegram_chat_id(
        self, telegram_chat_id: str
    ) -> dict[str, Any] | None:
        """The completed payment linked to this Telegram chat_id that granted
        an account, if any (newest first). Backs /mykey and /rotatekey: a
        chat_id has an account -- and thus a recoverable key -- exactly when a
        completed payment carries it (Stars stamps it at purchase, USDT and
        bank transfer via /link). Returns None when DATABASE_URL isn't set,
        same not-configured contract as get.

        `account_id is not null` is load-bearing, not tidiness. A Fix Pack
        payment is completed and can carry a telegram_chat_id, but grants no
        account by design -- mark_completed_fixpack leaves account_id null,
        because a Fix Pack is delivered as a pull request and has no key. It is
        also, being a later purchase, the NEWEST row for that chat. Without
        this predicate a Pro customer who ran /link with a Fix Pack reference
        had /mykey and /rotatekey answer "no account" from then on, with no way
        back: nothing unlinks a chat.

        The predicate cannot hide a payment that has a key. A completed Pro
        payment always has an account -- mark_completed takes account_id as a
        required argument, so the state cannot exist."""
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select id, account_id, provider, external_ref, amount,
                       currency, status, tier_granted, telegram_chat_id,
                       product, audit_id, paypal_order_id, payer_name,
                       payer_email, payer_x, payer_locale,
                       provider_payment_id, created_at
                from payments
                where telegram_chat_id = %s and status = 'completed'
                  and account_id is not null
                order by created_at desc
                limit 1
                """,
                (telegram_chat_id,),
            )
            row = await cur.fetchone()
        return _row_to_payment(row) if row else None

    async def set_provider_payment_id(
        self, payment_id: str, provider_payment_id: str
    ) -> bool:
        """Record the payment's identity in the system that took the money.

        Written AFTER the payment exists at the provider, which is the only
        order available: we cannot know their id before asking them to make
        one. So the window is real -- an order can be recorded here with the
        column still null if this update fails -- and it is survivable, because
        nothing in the confirmation path reads this column. The notification
        finds our row through the metadata we set on the payment; this is for
        the refund that has to address ЮKassa by their id, and for an operator
        reconciling two sets of books.

        `where provider_payment_id is null` so a second call cannot overwrite
        an id already recorded. Migration 0034's unique index stops one charge
        completing two orders; this stops one order claiming two charges.

        Returns whether the row was updated. False is not an error worth
        raising on a path where a customer is mid-payment.
        """
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return False
        try:
            parsed_id = uuid.UUID(payment_id)
        except ValueError:
            return False
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                update payments
                   set provider_payment_id = %s
                 where id = %s
                   and provider_payment_id is null
                """,
                (provider_payment_id, parsed_id),
            )
            return cur.rowcount > 0

    async def link_telegram_chat_id(
        self, payment_id: str, telegram_chat_id: str
    ) -> dict[str, Any] | None:
        """First-successful-link-wins: stamp telegram_chat_id onto a payment
        ONLY if it has none yet (WHERE telegram_chat_id is null). This is the
        atomic guard behind /link's anti-hijack rule -- two racing callers
        can't both claim the same on-chain payment, the second's update
        touches zero rows. Idempotent for the same claimer via the OR clause.
        Always returns the row's CURRENT state (whoever owns it now), so the
        caller can tell whether it won the claim or lost to an earlier one.
        No-op-safe when DATABASE_URL isn't set (returns None)."""
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        pid = uuid.UUID(payment_id)
        async with pool.connection() as conn:
            await conn.execute(
                """
                update payments set telegram_chat_id = %s
                where id = %s
                  and (telegram_chat_id is null or telegram_chat_id = %s)
                """,
                (telegram_chat_id, pid, telegram_chat_id),
            )
            cur = await conn.execute(
                """
                select id, account_id, provider, external_ref, amount,
                       currency, status, tier_granted, telegram_chat_id,
                       product, audit_id, paypal_order_id, payer_name,
                       payer_email, payer_x, payer_locale,
                       provider_payment_id, created_at
                from payments where id = %s
                """,
                (pid,),
            )
            row = await cur.fetchone()
        return _row_to_payment(row) if row else None

    async def claim_key_delivery(self, payment_id: str) -> bool:
        """First-asker-wins the right to be handed this payment's API key:
        True for exactly one caller, False for every later one (migration
        0024's key_delivered_at). Same conditional-update shape as
        link_telegram_chat_id -- the second caller's update matches zero rows.

        Only a completed payment can be claimed, so a pending invoice can
        never have its key delivered. False when DATABASE_URL isn't set: no
        claim was recorded, so no key may be handed out.

        The winner is expected to mint the key with rotate_key (the plaintext
        from the original create() was discarded by the poller/webhook that
        granted, and is not stored -- see migration 0019). If that fails, call
        release_key_delivery so the payer can try again.
        """
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return False
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                update payments set key_delivered_at = now()
                where id = %s and status = 'completed'
                  and key_delivered_at is null
                returning id
                """,
                (uuid.UUID(payment_id),),
            )
            return await cur.fetchone() is not None

    async def release_key_delivery(self, payment_id: str) -> None:
        """Undo a won claim_key_delivery because the key could not actually be
        minted. Without this, a transient failure between claiming and rotating
        would burn the payer's only delivery attempt and leave them with a paid
        account they can never get a key for. No-op when DATABASE_URL isn't
        set, matching mark_completed."""
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return
        async with pool.connection() as conn:
            await conn.execute(
                "update payments set key_delivered_at = null where id = %s",
                (uuid.UUID(payment_id),),
            )


class SubscriptionRepository:
    """Recurring Stars subscriptions (migration 0015). Same real/fake split
    and not-configured contract as the other repositories: when DATABASE_URL
    isn't set every method no-ops (returns None) instead of failing, so the
    Telegram webhook still answers even on a deployment without a database.

    The natural key is (telegram_user_id, invoice_payload): a
    BotSubscriptionUpdated update (Bot API `subscription` field) carries only
    those two fields, never a charge id, so they are the only stable way to
    resolve a state change back to a row. upsert_first / renew / set_status
    all pivot on it. See migration 0015 for the full rationale."""

    async def get_by_user_and_payload(
        self, telegram_user_id: str, invoice_payload: str
    ) -> dict[str, Any] | None:
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select id, account_id, telegram_user_id, telegram_chat_id,
                       tier, invoice_payload, telegram_payment_charge_id,
                       status, expires_at, payment_provider,
                       paypal_subscription_id, created_at, updated_at
                from subscriptions
                where telegram_user_id = %s and invoice_payload = %s
                """,
                (telegram_user_id, invoice_payload),
            )
            row = await cur.fetchone()
        return _row_to_subscription(row) if row else None

    async def get_active_by_user(
        self, telegram_user_id: str
    ) -> dict[str, Any] | None:
        """The most recent still-charging subscription for a user (status
        'active'), newest first. Backs /unsubscribe, which needs the stored
        telegram_payment_charge_id to call editUserStarSubscription."""
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select id, account_id, telegram_user_id, telegram_chat_id,
                       tier, invoice_payload, telegram_payment_charge_id,
                       status, expires_at, payment_provider,
                       paypal_subscription_id, created_at, updated_at
                from subscriptions
                where telegram_user_id = %s and status = 'active'
                order by created_at desc
                limit 1
                """,
                (telegram_user_id,),
            )
            row = await cur.fetchone()
        return _row_to_subscription(row) if row else None

    async def upsert_first(
        self, *, telegram_user_id: str, invoice_payload: str, tier: str,
        telegram_chat_id: str | None, telegram_payment_charge_id: str | None,
        expires_at: Any, repo_full_name: str | None = None,
    ) -> dict[str, Any] | None:
        """Record the first payment of a subscription (is_first_recurring).
        Upsert on the natural key so a retried first-payment webhook lands on
        the same row (idempotent) and re-enabling a previously canceled/expired
        subscription reactivates its row rather than colliding. Sets status
        back to 'active'.

        repo_full_name (Phase C) is the canonical 'owner/repo' this subscription
        monitors, or None for the legacy no-repo tier. It rides the natural key
        via the invoice_payload ('sub:monitor:<owner/repo>'), so a re-upsert for
        the same payload always carries the same repo."""
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        expires_dt = _expires_at_to_timestamptz(expires_at)
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                insert into subscriptions
                    (telegram_user_id, invoice_payload, tier, telegram_chat_id,
                     telegram_payment_charge_id, status, repo_full_name,
                     expires_at)
                values (%s, %s, %s, %s, %s, 'active', %s, %s)
                on conflict (telegram_user_id, invoice_payload) do update
                   set tier = excluded.tier,
                       telegram_chat_id = excluded.telegram_chat_id,
                       telegram_payment_charge_id =
                           excluded.telegram_payment_charge_id,
                       status = 'active',
                       expires_at = excluded.expires_at,
                       repo_full_name = excluded.repo_full_name,
                       updated_at = now()
                returning id, account_id, telegram_user_id, telegram_chat_id,
                          tier, invoice_payload, telegram_payment_charge_id,
                          status, expires_at, repo_full_name, last_monitored_at,
                          payment_provider, paypal_subscription_id,
                          created_at, updated_at
                """,
                (telegram_user_id, invoice_payload, tier, telegram_chat_id,
                 telegram_payment_charge_id, repo_full_name, expires_dt),
            )
            row = await cur.fetchone()
        return _row_to_subscription(row) if row else None

    async def list_active_for_repo(
        self, repo_full_name: str
    ) -> list[dict[str, Any]]:
        """Monitoring subscriptions with live access for a repo: expires_at in
        the future (the access boundary from 0015, which honors a
        canceled-but-still-in-period subscription). Matched on the canonical
        repo_full_name (app/monitor.normalize_repo_full_name), stored
        already-normalized, so this is an exact-equality lookup. Empty list when
        DATABASE_URL isn't set."""
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return []
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select id, account_id, telegram_user_id, telegram_chat_id,
                       tier, invoice_payload, telegram_payment_charge_id,
                       status, expires_at, repo_full_name, last_monitored_at,
                       payment_provider, paypal_subscription_id,
                       created_at, updated_at
                from subscriptions
                where repo_full_name = %s
                      and expires_at is not null and expires_at > now()
                order by created_at asc
                """,
                (repo_full_name,),
            )
            rows = await cur.fetchall()
        return [_row_to_subscription(r) for r in rows]

    async def claim_for_monitoring(
        self, repo_full_name: str, at: datetime.datetime
    ) -> bool:
        """Atomically claim this repo for a monitoring run and report whether the
        claim was won. In one write it stamps last_monitored_at = `at` on the
        repo's subscription rows IFF none has been monitored within
        MONITORING_INTERVAL_HOURS -- so this is BOTH the per-repo cost cap AND
        the concurrency guard.

        The interval is a parameter read from app/monitor, not a literal in this
        SQL. It was `interval '24 hours'` here and 24 again in the test fake, so
        the two agreed only by coincidence and a change to one would have left
        the other passing. See MONITORING_INTERVAL_HOURS for what a run costs
        and why the number is what it is.

        Two near-simultaneous default-branch pushes race on this UPDATE: the
        first commits and stamps the rows; the second, under READ COMMITTED,
        re-checks its WHERE against the freshly-committed rows, finds them no
        longer eligible, updates nothing, and returns an empty set -- so exactly
        one push re-audits and notifies. Same idea as the Fix Pack processor's
        FOR UPDATE SKIP LOCKED job claim, expressed as a conditional UPDATE.

        Returns False (nothing claimed) when DATABASE_URL isn't set. Callers must
        claim BEFORE the audit, not after, so the stamp also throttles retries of
        a dead/unfetchable repo."""
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return False
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                update subscriptions
                   set last_monitored_at = %s, updated_at = now()
                 where repo_full_name = %s
                   and (last_monitored_at is null
                        or last_monitored_at
                           < %s - make_interval(hours => %s))
                returning id
                """,
                (at, repo_full_name, at, MONITORING_INTERVAL_HOURS),
            )
            rows = await cur.fetchall()
        return len(rows) > 0

    async def renew(
        self, subscription_id: str, *, expires_at: Any,
        telegram_payment_charge_id: str | None,
    ) -> dict[str, Any] | None:
        """A recurring renewal (is_recurring, not first): push expires_at out
        and rotate telegram_payment_charge_id to this period's charge (the id
        editUserStarSubscription needs is the latest one). Never creates a row.
        Also clears any failed/canceled status back to active, since a
        successful charge means the subscription is charging again."""
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        expires_dt = _expires_at_to_timestamptz(expires_at)
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                update subscriptions
                   set expires_at = %s,
                       telegram_payment_charge_id = %s,
                       status = 'active',
                       updated_at = now()
                 where id = %s
                returning id, account_id, telegram_user_id, telegram_chat_id,
                          tier, invoice_payload, telegram_payment_charge_id,
                          status, expires_at, payment_provider,
                          paypal_subscription_id, created_at, updated_at
                """,
                (expires_dt, telegram_payment_charge_id,
                 uuid.UUID(subscription_id)),
            )
            row = await cur.fetchone()
        return _row_to_subscription(row) if row else None

    async def set_status(
        self, subscription_id: str, status: str
    ) -> dict[str, Any] | None:
        """Update only the renewal status (canceled/active/failed/expired).
        expires_at is deliberately untouched -- access is expires_at-based, and
        a canceled or failed-renewal subscription keeps the period it paid
        for. See migration 0015."""
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                update subscriptions
                   set status = %s, updated_at = now()
                 where id = %s
                returning id, account_id, telegram_user_id, telegram_chat_id,
                          tier, invoice_payload, telegram_payment_charge_id,
                          status, expires_at, payment_provider,
                          paypal_subscription_id, created_at, updated_at
                """,
                (status, uuid.UUID(subscription_id)),
            )
            row = await cur.fetchone()
        return _row_to_subscription(row) if row else None

    # PayPal keyed its monitoring subscriptions on paypal_subscription_id
    # (migration 0018) rather than the Stars natural key, and had its own
    # create/upsert/renew trio here. It is no longer a way to pay, so those are
    # gone. The COLUMN and its rows stay, and every read above still selects
    # it: nothing may write it, and nothing may lose it.

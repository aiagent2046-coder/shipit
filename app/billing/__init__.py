"""The one step every way of paying shares.

Four providers were built -- Telegram Stars, USDT/TRC20, PayPal and a manually
confirmed bank transfer -- and they took completely different paths to the same
outcome: a completed `payments` row plus an `accounts` row with tier='pro', and
the account's opaque API key handed back to whoever paid. That converging step
-- "a confirmed payment becomes a pro account with a key" -- lives here, once,
so no provider reimplements it.

Three of the four were removed on 2026-08-20 and bank transfer is the rail
left, with Robokassa to follow. This file barely changed, which is the point of
its shape: a provider is a way of reaching the step below, and the step below
never knew which one had called it.

Everything stays anonymous by default (see app/accounts.py): paying is
the only way to get a key, there is no email/password and no public
create-account endpoint. Missing configuration degrades gracefully the
same way the rest of the codebase does -- an unconfigured provider's
endpoint returns 503, and if DATABASE_URL isn't set the grant simply
can't persist (returns None) rather than raising.
"""

from __future__ import annotations

import logging
from typing import Any, Protocol

from app.accounts import TIER_PRO, generate_api_key

logger = logging.getLogger(__name__)


class _AccountStore(Protocol):
    async def create(self, *, api_key: str, tier: str) -> dict[str, Any] | None: ...
    async def get_by_id(self, account_id: str) -> dict[str, Any] | None: ...
    async def rotate_key(self, account_id: str) -> dict[str, Any] | None: ...


class _PaymentStore(Protocol):
    async def get_by_external_ref(
        self, provider: str, external_ref: str
    ) -> dict[str, Any] | None: ...
    async def create(self, **kwargs: Any) -> dict[str, Any] | None: ...
    async def mark_completed(
        self, payment_id: str, *, account_id: str, external_ref: str
    ) -> dict[str, Any] | None: ...
    async def mark_completed_fixpack(
        self, payment_id: str, *, external_ref: str
    ) -> dict[str, Any] | None: ...
    async def claim_key_delivery(self, payment_id: str) -> bool: ...
    async def release_key_delivery(self, payment_id: str) -> None: ...


async def deliver_key_once(
    *,
    account_repo: _AccountStore,
    payment_repo: _PaymentStore,
    payment: dict[str, Any],
) -> str | None:
    """The plaintext API key for a completed payment, for the first caller to
    ask and no one after -- or None if it has already been delivered.

    This exists because the plaintext key is not stored anywhere (migration
    0019). A grant can happen while nobody is connected -- the operator
    confirming a bank transfer from their phone, and, before they were removed,
    the USDT poller and the PayPal capture webhook -- so the key that grant
    receives is discarded; the payer's browser then polls a separate endpoint
    for it. There is nothing to look up at that point, so the key is *minted*
    here instead: winning migration
    0024's key_delivered_at claim earns one rotate_key, whose fresh plaintext is
    what gets handed back. Nothing is ever written to disk in plaintext.

    None means "not yours to receive" and callers must say so plainly rather
    than imply the payment failed: either it was already delivered (the common
    case -- a duplicate poll, or /link after the browser already showed it), or
    the payment has no account. Recovery from there is /rotatekey, the same
    lost-key path /mykey points at.
    """
    if not payment.get("account_id"):
        return None
    if not await payment_repo.claim_key_delivery(payment["id"]):
        return None
    try:
        rotated = await account_repo.rotate_key(payment["account_id"])
    except Exception:
        await payment_repo.release_key_delivery(payment["id"])
        raise
    if rotated is None:
        await payment_repo.release_key_delivery(payment["id"])
        return None
    return rotated.get("api_key")


async def grant_pro_tier(
    *,
    account_repo: _AccountStore,
    payment_repo: _PaymentStore,
    provider: str,
    external_ref: str,
    amount: float | None,
    currency: str | None,
    invoice_payment_id: str | None = None,
) -> dict[str, Any] | None:
    """Idempotently turn a confirmed payment into a pro account, and
    return that account.

    The returned dict carries `api_key` ONLY when this call is what created
    the account -- that plaintext exists in memory and nowhere else (migration
    0019), so it is the caller's one chance to deliver it. On a replay of an
    already-granted charge the account is re-read from the database, which by
    design cannot produce the key text again, so `api_key` is absent. Read it
    with `.get("api_key")` and handle None: for an in-handler delivery (a
    Stars charge that still arrives) that means telling the payer the key
    already went out and pointing at /rotatekey; for a grant that happens while
    nobody is connected (the operator confirming a transfer) it means going
    through deliver_key_once instead of this function's return value.

    `external_ref` is the provider's own charge/transaction id
    (telegram_payment_charge_id for Stars, the reference for a bank
    transfer) and is the idempotency key: calling this twice with the same
    one -- a retried Telegram webhook, an operator tapping Confirm twice --
    returns the original account, mints no second key, and records no
    second payment. (Migration 0004's partial unique index is the
    database-level backstop for the check-then-write race here.)

    `invoice_payment_id` distinguishes the two bookkeeping shapes, which is
    the only thing that ever differed between the providers:
      * An INVOICE flow passes it -- a pending `payments` row already exists
        (the invoice the payer was shown), so we transition that row to
        completed and link the account. Bank transfer works this way; USDT and
        PayPal did.
      * A charge with no invoice behind it omits it -- there is no
        pre-existing row (a Stars invoice lived in Telegram, not our DB), so
        we insert a completed one.

    Returns None only when DATABASE_URL isn't configured (account_repo
    can't create): callers surface that as "couldn't persist", not a
    crash.
    """
    # Imported here, not at module scope, on purpose. This module talks to
    # storage only through the Protocols above so it can be tested with fakes,
    # and serialization is not a repository operation -- it belongs to the
    # database. Importing it locally keeps the module-level boundary intact
    # while making the lock impossible to forget: the alternative was passing
    # it in from every provider, and a call site that forgot would silently
    # lose the protection.
    #
    # With no DATABASE_URL the lock yields without locking, which is exactly
    # what keeps the fake-backed tests unchanged.
    from app.db import grant_lock

    async with grant_lock(provider, external_ref):
        return await _grant_pro_tier_locked(
            account_repo=account_repo, payment_repo=payment_repo,
            provider=provider, external_ref=external_ref, amount=amount,
            currency=currency, invoice_payment_id=invoice_payment_id,
        )


async def _grant_pro_tier_locked(
    *,
    account_repo: _AccountStore,
    payment_repo: _PaymentStore,
    provider: str,
    external_ref: str,
    amount: float | None,
    currency: str | None,
    invoice_payment_id: str | None,
) -> dict[str, Any] | None:
    """grant_pro_tier's body, with the per-charge lock already held.

    Split out only so the lock wraps every return path including the early
    ones; there is no reason to call this directly.
    """
    existing = await payment_repo.get_by_external_ref(provider, external_ref)
    if existing is not None and existing.get("account_id"):
        # Already granted for this charge/tx -- re-return the same account so
        # the retry mints no second key. This account dict has no `api_key`:
        # the key was minted once, in the branch below, and is not stored.
        account = await account_repo.get_by_id(existing["account_id"])
        if account is not None:
            return account

    account = await account_repo.create(api_key=generate_api_key(), tier=TIER_PRO)
    if account is None:
        return None  # DATABASE_URL not configured -- nothing was persisted.

    if invoice_payment_id is not None:
        completed = await payment_repo.mark_completed(
            invoice_payment_id, account_id=account["id"], external_ref=external_ref
        )
        if completed is None:
            # The CAS gate refused, and the two reasons it can refuse mean
            # opposite things, so they must not share an outcome.
            current = await payment_repo.get_by_external_ref(
                provider, external_ref
            )
            linked = (current or {}).get("account_id")

            if linked and linked != account["id"]:
                # Same charge, someone else got there first: a concurrent
                # confirmation of this very payment. The grant DID happen, so
                # reporting failure would be a lie that makes an operator press
                # Confirm again. Return the account that won, without an
                # api_key -- the key was minted by the winner and delivered by
                # it, and this path must not hand out a second one.
                #
                # The account minted a few lines above is now unreferenced. It
                # is inert (nobody holds its key) but it is junk, so it is
                # logged rather than swept: with grant_lock in place this should
                # not happen at all, and a silent cleanup would hide the fact
                # that it did.
                logger.warning(
                    "concurrent grant for %s/%s: payment %s was linked to "
                    "account %s first; account %s minted here is unreferenced "
                    "and its key was never delivered",
                    provider, external_ref, invoice_payment_id, linked,
                    account["id"],
                )
                winner = await account_repo.get_by_id(linked)
                if winner is not None:
                    return winner
                return None

            # This invoice is already completed under a DIFFERENT external_ref,
            # so a distinct charge got here first. Say so rather than report a
            # grant -- the older unconditional UPDATE would have overwritten
            # that charge's account_id and orphaned the account whose key its
            # payer already holds. A human has to reconcile this one.
            logger.error(
                "payment %s already completed under another charge; refusing to "
                "re-complete it for %s/%s (account %s was minted and is now "
                "unreferenced)",
                invoice_payment_id, provider, external_ref, account["id"],
            )
            return None
    else:
        await payment_repo.create(
            account_id=account["id"], provider=provider, external_ref=external_ref,
            amount=amount, currency=currency, status="completed",
            tier_granted=TIER_PRO, product=PRODUCT_PRO,
        )
    return account


# Product labels for the `payments.product` column (migration 0007). Kept
# here alongside grant_pro_tier / grant_fixpack -- the two converging steps
# that write them -- so both providers use the exact same strings.
PRODUCT_PRO = "pro_tier"
PRODUCT_FIXPACK = "fixpack"


async def grant_fixpack(
    *,
    fixpack_repo: Any,
    payment_repo: _PaymentStore,
    audit_repo: Any,
    provider: str,
    external_ref: str,
    amount: float | None,
    currency: str | None,
    audit_id: str | None,
    invoice_payment_id: str | None = None,
) -> dict[str, Any] | None:
    """The Fix Pack counterpart to grant_pro_tier: idempotently turn a
    confirmed Fix Pack payment into a paid `fixpack_jobs` row for its
    audit, and return that row. Deliberately does NOT touch accounts or
    tiers -- a Fix Pack is a one-off per-audit product, not an account
    upgrade -- so it never calls grant_pro_tier and mints no API key.

    Idempotency mirrors grant_pro_tier: `external_ref` (the Stars charge id,
    or the reference on a bank transfer) is the key. A retried Telegram webhook
    or an operator tapping Confirm twice finds the already-completed payment
    and returns without creating a second job (migration 0004's partial unique
    index is the DB-level backstop for the check-then-write race).

    `invoice_payment_id` distinguishes the two bookkeeping shapes, same as in
    grant_pro_tier: an invoice flow passes it (a pending row already exists ->
    transition it to completed), a charge with no invoice behind it omits it
    (no pre-existing row -> insert a completed one).

    THE JOB IS CREATED BEFORE THE PAYMENT IS COMPLETED, and the order is the
    whole point rather than an accident. There is no transaction around the two
    writes -- nothing in app/db.py uses one -- so a crash, a lost connection or
    a redeploy can always land between them, and the order decides which
    half-done state that leaves:

      * payment completed, no job (the OLD order) is unrecoverable. The retry
        hits the early-return above, because the payment is already 'completed',
        and never reaches the job creation. Money taken, no Fix Pack, forever.
      * job created, payment still 'pending' (THIS order) self-heals. The retry
        skips the early-return, calls create_paid again, gets the SAME job back
        (idempotent per audit via migration 0025), completes the payment, and
        finishes what the first attempt started.

    The cost of this order is the mirror-image window -- a job exists for a
    payment that never completed -- and it is the cheap one: nothing bills off
    fixpack_jobs, so an orphan job is at worst one fix PR generated for a
    payment that has to be reconciled by hand, never a paying customer left with
    nothing. Neither window closes without a real transaction.

    Returns None when nothing could be persisted (DATABASE_URL not configured);
    callers surface that as "couldn't queue", not a crash. Generation of the
    actual fix PR is a separate follow-up step that picks up the 'paid' row this
    creates.
    """
    existing = await payment_repo.get_by_external_ref(provider, external_ref)
    if existing is not None and existing.get("status") == "completed":
        # Already processed this charge/tx -- don't create a second job.
        return existing

    audit = await audit_repo.get(audit_id) if (audit_repo and audit_id) else None
    stack = (audit or {}).get("stack") or "unknown"

    job = await fixpack_repo.create_paid(audit_id=audit_id, stack=stack)
    if job is None:
        return None  # DATABASE_URL not configured -- nothing persisted.

    if invoice_payment_id is not None:
        completed = await payment_repo.mark_completed_fixpack(
            invoice_payment_id, external_ref=external_ref
        )
        if completed is None:
            # The CAS gate refused: the invoice is already completed under a
            # DIFFERENT charge. A second distinct payment against one invoice is
            # a bookkeeping anomaly for a human, but the delivery outcome is
            # still correct and complete -- create_paid is idempotent per audit,
            # so `job` is the one job that audit has, and the earlier charge's
            # row is left untouched. Report it loudly and return the job, since
            # the caller's only question is whether the Fix Pack is queued.
            logger.error(
                "fixpack invoice %s already completed under another charge; "
                "leaving it as is and not recording %s/%s against it (job %s "
                "stands)",
                invoice_payment_id, provider, external_ref, job["id"],
            )
    else:
        created = await payment_repo.create(
            account_id=None, provider=provider, external_ref=external_ref,
            amount=amount, currency=currency, status="completed",
            tier_granted=None, product=PRODUCT_FIXPACK, audit_id=audit_id,
        )
        if created is None:
            return None  # DATABASE_URL not configured -- nothing persisted.

    return job


# Product label for the `payments.product` column on a subscription charge --
# distinct from PRODUCT_PRO / PRODUCT_FIXPACK so revenue bookkeeping can tell a
# recurring subscription charge apart from the one-shot products.
PRODUCT_SUBSCRIPTION = "subscription"

async def grant_subscription(
    *,
    subscription_repo: Any,
    payment_repo: _PaymentStore,
    provider: str,
    external_ref: str | None,
    amount: float | None,
    currency: str | None,
    telegram_user_id: str | None = None,
    telegram_chat_id: str | None = None,
    invoice_payload: str | None = None,
    tier: str,
    expires_at: Any,
    is_first_recurring: bool,
    repo_full_name: str | None = None,
) -> dict[str, Any] | None:
    """The subscription counterpart to grant_pro_tier / grant_fixpack:
    idempotently turn a confirmed recurring charge into an up-to-date
    `subscriptions` row, and return that row.

    Deliberately mints NO account and NO API key: the throwaway
    'monitoring' tier unlocks nothing today (the Phase C monitoring
    feature that will consume it doesn't exist yet), so a key would be dead
    plumbing. The subscription is keyed off the provider's natural key; the
    nullable subscriptions.account_id is left for Phase C to link.

    Keyed on the natural key of the provider that wrote the row: Stars on
    (telegram_user_id, invoice_payload) -- migration 0015. PayPal, which keyed
    on paypal_subscription_id (migration 0018), was removed as a way to pay;
    the column and its rows stay, and nothing writes them any more.

    Two paths, chosen by the successful_payment / webhook flags:
      * is_first_recurring -> upsert_first on the natural key: a new
        subscription, or the reactivation of a previously canceled/expired
        one. Idempotent -- a retried first-payment event lands on the same row.
      * otherwise (renewal) -> renew the existing row: push expires_at out
        (Stars also rotates telegram_payment_charge_id to this period's charge).

    Each charge is also recorded as a completed `payments` row (each renewal
    is a real charge), idempotent on (provider, external_ref) via migration
    0004's partial unique index -- same revenue bookkeeping as the other
    products. A retried event whose charge is already recorded skips the
    second payment insert. `external_ref=None` writes no payment row at all.

    Returns None only when nothing could be persisted (DATABASE_URL not
    configured -- subscription_repo can't write); callers surface that as
    "couldn't persist", not a crash.
    """
    # Record the charge for revenue bookkeeping, idempotently. A retried
    # event finds the charge already recorded and does not double-insert.
    # external_ref may be None (an activation with no charge id) -> skip.
    if external_ref is not None:
        existing_payment = await payment_repo.get_by_external_ref(
            provider, external_ref
        )
        if existing_payment is None:
            await payment_repo.create(
                account_id=None, provider=provider, external_ref=external_ref,
                amount=amount, currency=currency, status="completed",
                tier_granted=None, product=PRODUCT_SUBSCRIPTION,
            )

    if is_first_recurring:
        return await subscription_repo.upsert_first(
            telegram_user_id=telegram_user_id, invoice_payload=invoice_payload,
            tier=tier, telegram_chat_id=telegram_chat_id,
            telegram_payment_charge_id=external_ref, expires_at=expires_at,
            repo_full_name=repo_full_name,
        )

    existing = await subscription_repo.get_by_user_and_payload(
        telegram_user_id, invoice_payload
    )
    if existing is None:
        # A renewal for a subscription we never recorded the first payment of
        # (e.g. rows predating this feature, or a missed first webhook). Treat
        # it as a first payment so the row exists and stays correct, rather
        # than dropping the renewal on the floor.
        return await subscription_repo.upsert_first(
            telegram_user_id=telegram_user_id, invoice_payload=invoice_payload,
            tier=tier, telegram_chat_id=telegram_chat_id,
            telegram_payment_charge_id=external_ref, expires_at=expires_at,
            repo_full_name=repo_full_name,
        )
    return await subscription_repo.renew(
        existing["id"], expires_at=expires_at,
        telegram_payment_charge_id=external_ref,
    )

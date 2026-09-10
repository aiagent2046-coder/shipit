"""The one step every way of paying shares.

Four providers were built -- Telegram Stars, USDT/TRC20, PayPal and a manually
confirmed bank transfer -- and they took completely different paths to the same
outcome: a completed `payments` row plus an `accounts` row with tier='pro', and
the account's opaque API key handed back to whoever paid. That converging step
-- "a confirmed payment becomes a pro account with a key" -- lives here, once,
so no provider reimplements it.

Three of the four were removed on 2026-08-20 and bank transfer is the rail
left, with an aggregator to follow. This file barely changed, which is the point of
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

logger = logging.getLogger(__name__)


class _AccountStore(Protocol):
    async def rotate_key(self, account_id: str) -> dict[str, Any] | None: ...


class _PaymentStore(Protocol):
    async def get_by_external_ref(
        self, provider: str, external_ref: str
    ) -> dict[str, Any] | None: ...
    async def create(self, **kwargs: Any) -> dict[str, Any] | None: ...
    async def mark_completed_fixpack(
        self, payment_id: str, *, external_ref: str, fixpack_job_id: str | None = None
    ) -> dict[str, Any] | None: ...
    async def claim_key_delivery(self, payment_id: str) -> bool: ...
    async def release_key_delivery(self, payment_id: str) -> None: ...


class _ProGrantStore(Protocol):
    async def grant_pro_account(
        self, *, provider: str, external_ref: str,
        amount: float | None, currency: str | None,
        invoice_payment_id: str | None = None,
    ) -> dict[str, Any] | None: ...


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
    payment_repo: _ProGrantStore,
    provider: str,
    external_ref: str,
    amount: float | None,
    currency: str | None,
    invoice_payment_id: str | None = None,
) -> dict[str, Any] | None:
    """Atomically settle a confirmed payment and grant its Pro account.

    The provider's external_ref identifies the charge. An invoice flow also
    names the existing pending payment; a charge without an invoice inserts
    its completed payment in the same transaction as the new account.

    Only the caller that creates the account receives its plaintext api_key,
    after commit. A replay returns the existing account without that key:
    direct Stars delivery points at /rotatekey, while bank-transfer polling
    uses deliver_key_once. Plaintext is never stored (migration 0019).

    None means storage is unconfigured or the invoice/charge association was
    refused. Database errors propagate so a failed transaction is retried,
    rather than reported as an entitlement that was successfully granted.
    """
    return await payment_repo.grant_pro_account(
        provider=provider, external_ref=external_ref, amount=amount,
        currency=currency, invoice_payment_id=invoice_payment_id,
    )


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
    """Record a confirmed payment and reserve its work before completing it.

    The immutable funding key distinguishes a crash retry from another payment
    joining the same live job. A completed replay retains that distinction.
    Review-required means money was recorded but no additional work was funded;
    it is not a refund and must not be announced as a new queued Fix Pack.
    """
    from app.fixpack_funding import funding_key

    key = funding_key(provider, external_ref)
    existing = await payment_repo.get_by_external_ref(provider, external_ref)
    if existing is not None and existing.get("status") == "completed":
        job_id = existing.get("fixpack_job_id")
        job = await fixpack_repo.get(job_id) if job_id else None
        return {**existing, "funding_review_required": (
            job is None or job.get("funding_key") != key
        )}

    audit = await audit_repo.get(audit_id) if (audit_repo and audit_id) else None
    stack = (audit or {}).get("stack") or "unknown"

    job = await fixpack_repo.create_paid(audit_id=audit_id, stack=stack, funding_key=key)
    if job is None:
        return None  # DATABASE_URL not configured -- nothing persisted.

    if invoice_payment_id is not None:
        completed = await payment_repo.mark_completed_fixpack(
            invoice_payment_id, external_ref=external_ref,
            fixpack_job_id=str(job["id"]),
        )
        if completed is None:
            logger.error("Fix Pack invoice completion refused for job %s", job["id"])
            return None
    else:
        created = await payment_repo.create(
            account_id=None, provider=provider, external_ref=external_ref,
            amount=amount, currency=currency, status="completed",
            tier_granted=None, product=PRODUCT_FIXPACK, audit_id=audit_id,
            fixpack_job_id=str(job["id"]),
        )
        if created is None:
            return None  # DATABASE_URL not configured -- nothing persisted.

    return {**job, "funding_review_required": job.get("funding_key") != key}


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

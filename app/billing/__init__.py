"""Paywall Stage 2: payment providers, and the one step they share.

Two providers (app/billing/telegram_stars.py, app/billing/usdt_trc20.py)
take completely different paths to the same outcome: a completed
`payments` row plus an `accounts` row with tier='pro', and the account's
opaque API key handed back to whoever paid. That converging step --
"a confirmed payment becomes a pro account with a key" -- lives here,
once, so neither provider reimplements it.

Everything stays anonymous by default (see app/accounts.py): paying is
the only way to get a key, there is no email/password and no public
create-account endpoint. Missing configuration degrades gracefully the
same way the rest of the codebase does -- an unconfigured provider's
endpoint returns 503, and if DATABASE_URL isn't set the grant simply
can't persist (returns None) rather than raising.
"""

from __future__ import annotations

from typing import Any, Protocol

from app.accounts import TIER_PRO, generate_api_key


class _AccountStore(Protocol):
    async def create(self, *, api_key: str, tier: str) -> dict[str, Any] | None: ...
    async def get_by_id(self, account_id: str) -> dict[str, Any] | None: ...


class _PaymentStore(Protocol):
    async def get_by_external_ref(
        self, provider: str, external_ref: str
    ) -> dict[str, Any] | None: ...
    async def create(self, **kwargs: Any) -> dict[str, Any] | None: ...
    async def mark_completed(
        self, payment_id: str, *, account_id: str, external_ref: str
    ) -> None: ...
    async def mark_completed_fixpack(
        self, payment_id: str, *, external_ref: str
    ) -> None: ...


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
    return that account (including its `api_key`) for delivery.

    `external_ref` is the provider's own charge/transaction id
    (telegram_payment_charge_id for Stars, the TRC20 transaction_id for
    USDT) and is the idempotency key: calling this twice with the same
    one -- a retried Telegram webhook, a transfer seen on two polls --
    returns the original account, mints no second key, and records no
    second payment. (Migration 0004's partial unique index is the
    database-level backstop for the check-then-write race here.)

    `invoice_payment_id` distinguishes the two providers' bookkeeping,
    which is the only thing that differs between them:
      * USDT passes it -- a pending `payments` row already exists (the
        invoice the payer was shown), so we transition that row to
        completed and link the account.
      * Telegram omits it -- there is no pre-existing row (the invoice
        lived in Telegram, not our DB), so we insert a completed one.

    Returns None only when DATABASE_URL isn't configured (account_repo
    can't create): callers surface that as "couldn't persist", not a
    crash. When configured, the returned dict always carries `api_key`.
    """
    existing = await payment_repo.get_by_external_ref(provider, external_ref)
    if existing is not None and existing.get("account_id"):
        # Already granted for this charge/tx -- re-fetch and re-return the
        # same account so a retry re-delivers the original key, unchanged.
        account = await account_repo.get_by_id(existing["account_id"])
        if account is not None:
            return account

    account = await account_repo.create(api_key=generate_api_key(), tier=TIER_PRO)
    if account is None:
        return None  # DATABASE_URL not configured -- nothing was persisted.

    if invoice_payment_id is not None:
        await payment_repo.mark_completed(
            invoice_payment_id, account_id=account["id"], external_ref=external_ref
        )
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

    Idempotency mirrors grant_pro_tier: `external_ref` (the Stars charge id
    or the TRC20 transaction id) is the key. A retried Telegram webhook or
    a transfer seen on two polls finds the already-completed payment and
    returns without creating a second job (migration 0004's partial unique
    index is the DB-level backstop for the check-then-write race).

    `invoice_payment_id` distinguishes the two providers' bookkeeping, same
    as in grant_pro_tier: USDT passes it (a pending invoice row already
    exists -> transition it to completed), Telegram omits it (no pre-
    existing row -> insert a completed one).

    Returns None only when nothing could be persisted (DATABASE_URL not
    configured); callers surface that as "couldn't queue", not a crash.
    Generation of the actual fix PR is a separate follow-up step that picks
    up the 'paid' row this creates.
    """
    existing = await payment_repo.get_by_external_ref(provider, external_ref)
    if existing is not None and existing.get("status") == "completed":
        # Already processed this charge/tx -- don't create a second job.
        return existing

    audit = await audit_repo.get(audit_id) if (audit_repo and audit_id) else None
    stack = (audit or {}).get("stack") or "unknown"

    if invoice_payment_id is not None:
        await payment_repo.mark_completed_fixpack(
            invoice_payment_id, external_ref=external_ref
        )
    else:
        created = await payment_repo.create(
            account_id=None, provider=provider, external_ref=external_ref,
            amount=amount, currency=currency, status="completed",
            tier_granted=None, product=PRODUCT_FIXPACK, audit_id=audit_id,
        )
        if created is None:
            return None  # DATABASE_URL not configured -- nothing persisted.

    return await fixpack_repo.create_paid(audit_id=audit_id, stack=stack)


# Product label for the `payments.product` column on a subscription charge --
# distinct from PRODUCT_PRO / PRODUCT_FIXPACK so revenue bookkeeping can tell a
# recurring subscription charge apart from the one-shot products.
PRODUCT_SUBSCRIPTION = "subscription"

# The provider string for PayPal, matching app.billing.paypal.PROVIDER. Named
# here so grant_subscription can branch on it without importing that module
# (paypal.py imports the grant_* functions from here, not vice versa).
PROVIDER_PAYPAL = "paypal"


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
    paypal_subscription_id: str | None = None,
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

    Provider branches on the natural key, additively:
      * Stars keys on (telegram_user_id, invoice_payload) -- migration 0015.
      * PayPal keys on paypal_subscription_id -- migration 0018. PayPal rows
        have no telegram_user_id/invoice_payload, so those go unset.

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
    second payment insert. PayPal's first-period ACTIVATED event carries no
    charge id (external_ref is None); no payment row is written for it -- the
    recurring PAYMENT.SALE.COMPLETED events carry the sale ids.

    Returns None only when nothing could be persisted (DATABASE_URL not
    configured -- subscription_repo can't write); callers surface that as
    "couldn't persist", not a crash.
    """
    # Record the charge for revenue bookkeeping, idempotently. A retried
    # event finds the charge already recorded and does not double-insert.
    # external_ref may be None (PayPal ACTIVATED has no charge id) -> skip.
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

    if provider == PROVIDER_PAYPAL:
        return await _grant_subscription_paypal(
            subscription_repo=subscription_repo,
            paypal_subscription_id=paypal_subscription_id, tier=tier,
            expires_at=expires_at, is_first_recurring=is_first_recurring,
            repo_full_name=repo_full_name,
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


async def _grant_subscription_paypal(
    *,
    subscription_repo: Any,
    paypal_subscription_id: str | None,
    tier: str,
    expires_at: Any,
    is_first_recurring: bool,
    repo_full_name: str | None,
) -> dict[str, Any] | None:
    """PayPal's branch of grant_subscription, keyed on paypal_subscription_id
    (migration 0018) instead of Stars' (telegram_user_id, invoice_payload).

    The subscriptions row is normally pre-inserted at create time (status
    'approval_pending', repo bound) by create_monitor_subscription, so the
    common path is an update-by-id. But the row is keyed on the PayPal id here
    so the webhook path never depends on that pre-insert having happened:
      * ACTIVATED (is_first_recurring) -> upsert_first_paypal: create the row
        if a pre-insert was skipped, else move it to active with the new
        expires_at. Idempotent -- a retried ACTIVATED lands on the same row.
      * SALE renewal -> renew_paypal on the existing row; if none exists (a
        renewal arriving before we saw ACTIVATED), fall back to upsert_first
        so the row exists and stays correct rather than dropping the renewal.
    """
    if not paypal_subscription_id:
        return None
    if is_first_recurring:
        return await subscription_repo.upsert_first_paypal(
            paypal_subscription_id=paypal_subscription_id, tier=tier,
            expires_at=expires_at, repo_full_name=repo_full_name,
        )
    existing = await subscription_repo.get_by_paypal_subscription_id(
        paypal_subscription_id
    )
    if existing is None:
        return await subscription_repo.upsert_first_paypal(
            paypal_subscription_id=paypal_subscription_id, tier=tier,
            expires_at=expires_at, repo_full_name=repo_full_name,
        )
    return await subscription_repo.renew_paypal(
        existing["id"], expires_at=expires_at,
    )

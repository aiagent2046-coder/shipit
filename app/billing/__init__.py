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
            tier_granted=TIER_PRO,
        )
    return account

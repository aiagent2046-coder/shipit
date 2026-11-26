"""Bank-transfer invoice lookup.

This module was "USDT invoices and bank-transfer invoice lookup" until USDT was
removed as a way to pay. What is left is the poll endpoint a payer's browser
sits on between pressing "I've paid" and the operator tapping Confirm.

Extracted from app/main.py verbatim -- handler bodies are unchanged, only the
decorators moved from ``@app.<verb>`` to ``@router.<verb>``.

Only the endpoints whose rate limiting is not driven by a module-level limit
constant live here. The bank-transfer invoice creators and the paid-report
endpoint are still in main.py: they read ``BANK_TRANSFER_INVOICE_LIMIT`` /
``BANK_TRANSFER_PAID_LIMIT``, which the suite monkeypatches on the ``app.main``
module object. Moving those without also teaching the tests about the new
binding would leave the patch pointing at a name nothing reads -- the
``MONITORING_FOR_SALE`` failure mode. They move in a later commit, with the
test-side change made deliberately rather than as collateral.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.billing import bank_transfer, telegram_stars, yookassa
from app.db import (
    AccountRepository,
    AuditRepository,
    FixpackJobRepository,
    PaymentRepository,
    SubscriptionRepository,
)
from app.deploypack.delivery_auth import DeliveryAuthorizationError
from app.deploypack.paid_delivery_auth import (
    authorize_paid_checkout,
    get_paid_delivery_store,
    repository_name,
    seal_paid_grant,
)
from app.ratelimit import RateLimiter
from app.routes._shared import _json_object_body, _secret_equals
from app.routes.bank_transfer import _check_invoice_rate_limit
from app.routes.dependencies import (
    get_account_repo,
    get_audit_repo,
    get_billing_transport,
    get_fixpack_repo,
    get_payment_repo,
    get_rate_limiter,
    get_subscription_repo,
)

router = APIRouter()


@router.get("/v1/billing/bank-transfer/{reference}")
async def get_bank_transfer_invoice(
    reference: str,
    payment_repo: PaymentRepository = Depends(get_payment_repo),
    account_repo: AccountRepository = Depends(get_account_repo),
) -> dict:
    """Poll one bank-transfer invoice. Reveals the API key only once the
    operator has confirmed the transfer arrived (status 'completed'); a
    pending or expired invoice never leaks a key. 404 if no such invoice.

    An 'expired' status here is cosmetic: it tells a payer the quote is stale,
    but the operator can still confirm a transfer that surfaces later, because
    a slow bank must never become lost money."""
    status = await bank_transfer.invoice_status(
        payment_repo, account_repo, reference,
        details=bank_transfer.bank_details_from_env(),
    )
    if status is None:
        raise HTTPException(
            status_code=404,
            detail={"reason": "not_found",
                    "detail": "no bank transfer invoice with this reference, or "
                              "persistence isn't configured on this deployment"},
        )
    return status


class RenewDelivery(BaseModel):
    reference: str = Field(min_length=1, max_length=128)
    audit_token: str


@router.post("/v1/audits/{audit_id}/fixpack/delivery-authorization")
async def renew_delivery_authorization(
    audit_id: str, body: RenewDelivery, request: Request,
    audit_repo: AuditRepository = Depends(get_audit_repo),
    payment_repo: PaymentRepository = Depends(get_payment_repo),
    limiter: RateLimiter = Depends(get_rate_limiter),
    grant_store=Depends(get_paid_delivery_store),
) -> dict:
    _check_invoice_rate_limit(request, limiter)
    audit = await audit_repo.get_authorized(audit_id, body.audit_token)
    if audit is None:
        raise HTTPException(404, detail={"reason": "not_found"})
    candidates = []
    for provider in (bank_transfer.PROVIDER, yookassa.PROVIDER):
        row = await payment_repo.get_by_external_ref(provider, body.reference)
        if (row and row.get("provider") == provider
                and str(row.get("audit_id")) == audit_id
                and row.get("product") == "fixpack" and row.get("status") == "completed"):
            candidates.append(row)
    if len(candidates) != 1:
        raise HTTPException(404, detail={"reason": "not_found"})
    payment = candidates[0]
    try:
        token = await authorize_paid_checkout(audit, request.headers.get("x-github-token"))
        encrypted = seal_paid_grant(
            token, provider=payment["provider"], external_ref=payment["external_ref"],
            audit_id=audit_id, repo_full_name=repository_name(audit),
        )
    except DeliveryAuthorizationError as exc:
        raise HTTPException(exc.status_code, detail={"reason": exc.reason}) from None
    if not await grant_store.replace_for_payment(str(payment["id"]), encrypted):
        raise HTTPException(409, detail={"reason": "delivery_authorization_not_waiting"})
    return {"status": "paid"}


telegram_router = APIRouter()


@telegram_router.post("/v1/webhooks/telegram")
async def telegram_webhook(
    request: Request,
    account_repo: AccountRepository = Depends(get_account_repo),
    payment_repo: PaymentRepository = Depends(get_payment_repo),
    audit_repo: AuditRepository = Depends(get_audit_repo),
    fixpack_repo: FixpackJobRepository = Depends(get_fixpack_repo),
    subscription_repo: SubscriptionRepository = Depends(get_subscription_repo),
    transport=Depends(get_billing_transport),
) -> dict:
    """The Telegram bot webhook. Stars is no longer a way to pay; the bot is
    still the operator's bank-transfer confirm button, the key-recovery
    commands, and the only outward notification channel. Handles the
    pre_checkout_query (approve within 10s), successful_payment (grant pro /
    Fix Pack / subscription), subscription (BotSubscriptionUpdated renewal
    state changes) and callback_query (the operator's bank-transfer confirm
    button) update types; ignores everything else.

    Authenticity is Telegram's secret_token: setWebhook is called with a
    secret, echoed back in X-Telegram-Bot-Api-Secret-Token on every
    delivery. Constant-time compared here, same posture as the reap
    endpoint's bearer token. 503 if the bot token or webhook secret
    isn't configured — an unconfigured payment webhook is an operational
    gap to notice, not a silent no-op. See app/billing/telegram_stars.py.

    Note this header proves the update came from TELEGRAM, not from any
    particular person: it is shared by every user who can message the bot.
    The callback_query branch therefore does its own owner check against
    TELEGRAM_ADMIN_CHAT_ID before acting (telegram_stars._is_operator).
    """
    token = telegram_stars.bot_token_from_env()
    secret = telegram_stars.webhook_secret_from_env()
    if not token or not secret:
        raise HTTPException(
            status_code=503,
            detail={"reason": "telegram_not_configured",
                    "detail": "TELEGRAM_BOT_TOKEN and TELEGRAM_WEBHOOK_SECRET "
                              "must both be set on this deployment"},
        )
    provided = request.headers.get("x-telegram-bot-api-secret-token", "")
    if not _secret_equals(provided, secret):
        raise HTTPException(status_code=401, detail={"reason": "unauthorized"})

    update = await _json_object_body(request)
    return await telegram_stars.handle_update(
        update, account_repo=account_repo, payment_repo=payment_repo,
        audit_repo=audit_repo, fixpack_repo=fixpack_repo,
        subscription_repo=subscription_repo,
        token=token, transport=transport,
    )

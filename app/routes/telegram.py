"""The Telegram bot webhook.

Extracted from app/main.py verbatim -- the handler body is unchanged, only the
decorator moved from ``@app.post`` to ``@router.post``.

The webhook secret is compared with a constant-time helper and the endpoint
503s when it is unset, matching the GitHub webhook next door: an unconfigured
deployment must refuse the call, not accept it unverified.

``telegram_stars`` is imported as a module, which is also what the test suite
patches attributes on (``main_mod.telegram_stars.send_message`` resolved to
this same module object). Keeping the import shape means those patches continue
to work from here unchanged.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from app.billing import telegram_stars
from app.db import (
    AccountRepository,
    AuditRepository,
    FixpackJobRepository,
    PaymentRepository,
    SubscriptionRepository,
)
from app.routes._shared import _json_object_body, _secret_equals
from app.routes.dependencies import (
    get_account_repo,
    get_audit_repo,
    get_billing_transport,
    get_fixpack_repo,
    get_payment_repo,
    get_subscription_repo,
)

router = APIRouter()


@router.post("/v1/webhooks/telegram")
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

"""PayPal checkout: orders, subscriptions, and the webhook that grants on capture.

Extracted from app/main.py verbatim -- handler bodies are unchanged, only the
decorators moved from ``@app.<verb>`` to ``@router.<verb>``.

``logger`` is this module's own logger rather than main's. It is used for one
upstream-failure warning; the record's module field changes from ``app.main``
to ``app.routes.paypal``, which is more accurate about where the failure was
observed.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request

from app.billing import paypal
from app.db import (
    AccountRepository,
    AuditRepository,
    FixpackJobRepository,
    PaymentRepository,
    SubscriptionRepository,
    database_url_from_env,
)
from app import monitor
from app.monitor import normalize_repo_full_name
from app.routes._shared import (
    _json_object_body,
    _reject_if_fixpack_already_live,
    _reject_if_nothing_to_fix,
)
from app.routes.dependencies import (
    get_account_repo,
    get_audit_repo,
    get_fixpack_repo,
    get_payment_repo,
    get_paypal_transport,
    get_subscription_repo,
)

logger = logging.getLogger(__name__)

router = APIRouter()


def _paypal_not_configured_error() -> HTTPException:
    return HTTPException(
        status_code=503,
        detail={"reason": "paypal_not_configured",
                "detail": "PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET must both "
                          "be set on this deployment"},
    )


def _paypal_not_persisted_error() -> HTTPException:
    return HTTPException(
        status_code=503,
        detail={"reason": "not_persisted",
                "detail": "PayPal checkout requires DATABASE_URL (a pending row "
                          "is created so the webhook capture can grant against "
                          "it, and the browser can poll the key back)"},
    )


@router.post("/v1/paypal/orders", status_code=201)
async def create_paypal_order(
    request: Request,
    payment_repo: PaymentRepository = Depends(get_payment_repo),
    audit_repo: AuditRepository = Depends(get_audit_repo),
    fixpack_repo: FixpackJobRepository = Depends(get_fixpack_repo),
    transport=Depends(get_paypal_transport),
) -> dict:
    """Open a PayPal order for a ONE-TIME product (Pro or a Fix Pack), the
    PayPal counterpart to POST /v1/billing/usdt/invoice. Returns the PayPal
    order id the browser JS SDK approves + captures against; the capture then
    arrives as a PAYMENT.CAPTURE.COMPLETED webhook that grants. Poll
    GET /v1/paypal/orders/{id} to collect the Pro key once captured.

    Body: {"product": "pro"} or {"product": "fixpack", "audit_id": "<id>"}.

    503 if PayPal isn't configured, or if DATABASE_URL isn't set -- the latter
    is checked BEFORE creating the PayPal order, so an unpersistable order is
    never opened at PayPal and left orphaned. Fix Pack: 404 unknown audit, 422
    if the audit has no GitHub repo to open a fix PR against (same gate as the
    USDT Fix Pack invoice)."""
    if not paypal.is_configured():
        raise _paypal_not_configured_error()
    if not database_url_from_env():
        raise _paypal_not_persisted_error()

    body = await _json_object_body(request)
    product = (body.get("product") or "").strip().lower()

    if product == "fixpack":
        audit_id = body.get("audit_id")
        if not audit_id:
            raise HTTPException(
                status_code=422,
                detail={"reason": "missing_audit_id",
                        "detail": "product 'fixpack' requires an audit_id"},
            )
        audit = await audit_repo.get(audit_id)
        if audit is None:
            raise HTTPException(
                status_code=404,
                detail={"reason": "audit_not_found",
                        "detail": "no audit with this id, or persistence isn't "
                                  "configured on this deployment"},
            )
        if not audit.get("repo_url"):
            raise HTTPException(
                status_code=422,
                detail={"reason": "not_github_audit",
                        "detail": "Fix Pack currently only supports audits run "
                                  "from a public GitHub URL. This audit was "
                                  "created from an uploaded zip, so there's no "
                                  "repository to open a fix PR against."},
            )
        await _reject_if_fixpack_already_live(fixpack_repo, audit_id)
        _reject_if_nothing_to_fix(audit)
        try:
            order = await paypal.create_fixpack_order(
                payment_repo, audit_id=audit_id, transport=transport
            )
        except paypal.PayPalError as exc:
            raise _paypal_upstream_error(exc) from exc
        if order is None:
            raise _paypal_not_persisted_error()
        return order

    if product == "pro":
        try:
            order = await paypal.create_pro_order(payment_repo, transport=transport)
        except paypal.PayPalError as exc:
            raise _paypal_upstream_error(exc) from exc
        if order is None:
            raise _paypal_not_persisted_error()
        return order

    raise HTTPException(
        status_code=422,
        detail={"reason": "unknown_product",
                "detail": "product must be 'pro' or 'fixpack'"},
    )


@router.get("/v1/paypal/orders/{order_id}")
async def get_paypal_order(
    order_id: str,
    payment_repo: PaymentRepository = Depends(get_payment_repo),
    account_repo: AccountRepository = Depends(get_account_repo),
) -> dict:
    """Poll one PayPal Pro order, the counterpart to GET
    /v1/billing/usdt/invoice/{id}. Reveals the API key only once the webhook
    has captured and granted (status 'completed'); a pending order never leaks
    a key. 404 if there's no such order (or persistence isn't configured)."""
    status = await paypal.order_status(payment_repo, account_repo, order_id)
    if status is None:
        raise HTTPException(
            status_code=404,
            detail={"reason": "not_found",
                    "detail": "no PayPal order with this id, or persistence "
                              "isn't configured on this deployment"},
        )
    return status


def _monitoring_not_for_sale_error() -> HTTPException:
    """503 rather than 404: the route exists and works, the product is
    withdrawn. 404 would read as a client mistake and send someone hunting for
    a typo in a URL that is correct."""
    return HTTPException(
        status_code=503,
        detail={"reason": "monitoring_not_for_sale",
                "detail": "continuous monitoring is not on sale right now. Its "
                          "price, its spend attribution and its spend cap are "
                          "unresolved, so it was withdrawn rather than sold at "
                          "a placeholder price. Nothing was charged."},
    )


@router.post("/v1/paypal/subscriptions", status_code=201)
async def create_paypal_subscription(
    request: Request,
    subscription_repo: SubscriptionRepository = Depends(get_subscription_repo),
    transport=Depends(get_paypal_transport),
) -> dict:
    """Open a PayPal monitoring subscription (RECURRING), the PayPal
    counterpart to the Telegram /monitor flow. Returns the subscription id and
    the `approve` URL the browser sends the buyer to; PayPal then delivers
    BILLING.SUBSCRIPTION.ACTIVATED and recurring PAYMENT.SALE.COMPLETED
    webhooks. The subscriptions row is pre-inserted here (repo bound) so every
    later webhook resolves by paypal_subscription_id.

    Body: {"repo_url": "https://github.com/<owner>/<repo>"}.

    503 if PayPal isn't configured, if PAYPAL_MONITOR_PLAN_ID (the billing plan)
    isn't set, or if DATABASE_URL isn't set (checked before creating the
    subscription at PayPal). 422 on a repo_url that isn't a clean github.com
    owner/repo.

    503 before any of those when monitoring is withdrawn from sale, which it
    currently is -- see MONITORING_FOR_SALE. Checked first so a withdrawn
    product and an unconfigured deployment never report each other's reason."""
    if not monitor.MONITORING_FOR_SALE:
        raise _monitoring_not_for_sale_error()
    if not paypal.is_configured():
        raise _paypal_not_configured_error()
    plan_id = paypal.monitor_plan_id_from_env()
    if not plan_id:
        raise HTTPException(
            status_code=503,
            detail={"reason": "paypal_plan_not_configured",
                    "detail": "PAYPAL_MONITOR_PLAN_ID (the PayPal billing plan "
                              "id for the monitoring subscription) is not set on "
                              "this deployment"},
        )
    if not database_url_from_env():
        raise _paypal_not_persisted_error()

    body = await _json_object_body(request)
    repo_full_name = normalize_repo_full_name(body.get("repo_url"))
    if repo_full_name is None:
        raise HTTPException(
            status_code=422,
            detail={"reason": "bad_repo_url",
                    "detail": "repo_url must be "
                              "https://github.com/<owner>/<repo> "
                              "(public GitHub repos only)"},
        )
    try:
        sub = await paypal.create_monitor_subscription(
            subscription_repo, repo_full_name=repo_full_name, plan_id=plan_id,
            transport=transport,
        )
    except paypal.PayPalError as exc:
        raise _paypal_upstream_error(exc) from exc
    if sub is None:
        raise _paypal_not_persisted_error()
    return sub


@router.post("/v1/webhooks/paypal")
async def paypal_webhook(
    request: Request,
    account_repo: AccountRepository = Depends(get_account_repo),
    payment_repo: PaymentRepository = Depends(get_payment_repo),
    audit_repo: AuditRepository = Depends(get_audit_repo),
    fixpack_repo: FixpackJobRepository = Depends(get_fixpack_repo),
    subscription_repo: SubscriptionRepository = Depends(get_subscription_repo),
    transport=Depends(get_paypal_transport),
) -> dict:
    """PayPal webhook. Authenticity is verified the way PayPal requires -- an
    outbound POST to /v1/notifications/verify-webhook-signature carrying the
    transmission headers and the raw event (NOT a local HMAC like Telegram or
    GitHub) -- so this needs PAYPAL_WEBHOOK_ID plus the OAuth credentials.

    Handles PAYMENT.CAPTURE.COMPLETED (one-time Pro/Fix Pack),
    BILLING.SUBSCRIPTION.ACTIVATED / PAYMENT.SALE.COMPLETED (recurring
    monitoring), and BILLING.SUBSCRIPTION.CANCELLED/SUSPENDED/EXPIRED; anything
    else is a 200 ack so PayPal stops retrying. See app/billing/paypal.py.

    503 if PayPal or the webhook id isn't configured -- an unverifiable webhook
    must never be trusted (same posture as the Telegram/GitHub webhooks). 401 on
    a failed signature verification."""
    if not paypal.is_configured():
        raise _paypal_not_configured_error()
    webhook_id = paypal.webhook_id_from_env()
    if not webhook_id:
        raise HTTPException(
            status_code=503,
            detail={"reason": "paypal_webhook_not_configured",
                    "detail": "PAYPAL_WEBHOOK_ID is not set on this deployment"},
        )

    event = await _json_object_body(request)
    try:
        verified = await paypal.verify_webhook_signature(
            headers=request.headers, event=event, webhook_id=webhook_id,
            transport=transport,
        )
    except paypal.PayPalError as exc:
        raise _paypal_upstream_error(exc) from exc
    if not verified:
        raise HTTPException(status_code=401, detail={"reason": "unauthorized"})

    return await paypal.handle_webhook_event(
        event, account_repo=account_repo, payment_repo=payment_repo,
        audit_repo=audit_repo, fixpack_repo=fixpack_repo,
        subscription_repo=subscription_repo, transport=transport,
    )


def _paypal_upstream_error(exc: Exception) -> HTTPException:
    """A PayPal REST call failed (non-2xx / unusable body). Surface as 502 --
    upstream's fault, not the caller's -- same split the LLM client and the
    GitHub fetcher draw between a bad request and a bad upstream."""
    logger.warning("paypal upstream call failed: %s", exc)
    return HTTPException(
        status_code=502,
        detail={"reason": "paypal_upstream_error",
                "detail": "PayPal did not accept the request; try again later"},
    )

"""PayPal Checkout payment provider -- an ALTERNATIVE to Telegram Stars.

Additive, never a replacement: the Stars and USDT providers are untouched.
PayPal is offered side by side for the same three products, routed by billing
type exactly as Stars is:

  * Pro (`/upgrade` equivalent)  -> ONE-TIME  -> Orders API (capture)
  * Fix Pack (`/fixpack`)        -> ONE-TIME  -> Orders API (capture)
  * Continuous Monitoring        -> RECURRING -> Subscriptions API (plan + sub)

Shape mirrors app/billing/telegram_stars.py deliberately: env-readers that
return None when unset (so an unconfigured endpoint 503s rather than
half-works), pure body-builders, an injectable `transport=` seam so tests fake
every outbound call with httpx.MockTransport, and a `handle_webhook_event`
dispatcher. No PayPal SDK -- pure httpx, same as the hand-rolled Telegram/USDT
clients (httpx is already pinned; the REST surface we need is tiny).

Product/routing context travels the same way Stars carries it in the invoice
payload: encoded in the PayPal Order `purchase_units[].custom_id` / Subscription
`custom_id` ("pro" / "fixpack:<audit_id>" / "monitor:<owner/repo>"), and read
back off the webhook event -- so a webhook routes with NO database round trip.

Webhook authenticity is verified the way PayPal requires and NOT the local-HMAC
way Telegram/GitHub use: an outbound POST to
/v1/notifications/verify-webhook-signature (needs an OAuth2 token). That call is
isolated here behind the same injectable transport seam.

Not exercised against real PayPal: this sandbox has no credentials. Outbound
calls are injectable for tests, and scripts/verify_paypal_sandbox_locally.py
lets the operator drive a real sandbox order/subscription once keys are wired.
See the README.
"""

from __future__ import annotations

import datetime
import logging
import os
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)

PROVIDER = "paypal"
CURRENCY = "USD"

_SANDBOX_API = "https://api-m.sandbox.paypal.com"
_LIVE_API = "https://api-m.paypal.com"

# Product labels for payments.product / subscriptions.tier. Defined locally
# (same as usdt_trc20.py) so this module doesn't import app.billing at import
# time; the grant functions are imported lazily inside the handlers.
PRODUCT_PRO = "pro_tier"
PRODUCT_FIXPACK = "fixpack"
PRODUCT_SUBSCRIPTION = "subscription"

# Routing context, encoded in the Order/Subscription custom_id -- the PayPal
# equivalent of Telegram's invoice payload. Read back off the webhook event.
PRO_CUSTOM_ID = "pro"
FIXPACK_CUSTOM_ID_PREFIX = "fixpack:"
MONITOR_CUSTOM_ID_PREFIX = "monitor:"

# The monitoring subscription's tier label on the subscriptions row -- matches
# telegram_stars.MONITOR_TIER so both providers' monitoring rows read the same.
MONITOR_TIER = "monitoring"

# Renewal period fallback. A PAYMENT.SALE.COMPLETED renewal event does not carry
# next_billing_time, so expires_at is pushed out this far from the charge. The
# real cadence is defined by the PayPal billing plan; 30 days matches the Stars
# subscription period and is the sane default for the monitoring product.
MONITOR_PERIOD_DAYS = 30

PRO_DESCRIPTION = "Drydock Pro — higher audit limits and more."


def _fixpack_description(audit_id: str) -> str:
    return (
        f"Drydock Fix Pack for audit {audit_id[:8]} — a generated pull "
        "request fixing this audit's findings."
    )


# Prices are fiat USD (PayPal charges fiat), env-overridable-with-default, the
# same pattern as TELEGRAM_PRO_STARS / FIXPACK_USDT_PRICE. The monitoring price
# lives in the PayPal billing plan (PAYPAL_MONITOR_PLAN_ID), not here.
_DEFAULT_PRO_PRICE_USD = "5.00"
_DEFAULT_FIXPACK_PRICE_USD = "10.00"


def client_id_from_env() -> str | None:
    return os.environ.get("PAYPAL_CLIENT_ID") or None


def client_secret_from_env() -> str | None:
    return os.environ.get("PAYPAL_CLIENT_SECRET") or None


def webhook_id_from_env() -> str | None:
    """The webhook id from the PayPal app config, sent to
    verify-webhook-signature. Unset -> the webhook endpoint 503s (an
    unverifiable webhook must never be trusted)."""
    return os.environ.get("PAYPAL_WEBHOOK_ID") or None


def monitor_plan_id_from_env() -> str | None:
    """The PayPal billing plan id for the monitoring subscription, created once
    out-of-band by the operator (see README / the plan doc). Unset -> the
    subscription endpoint 503s."""
    return os.environ.get("PAYPAL_MONITOR_PLAN_ID") or None


def is_configured() -> bool:
    """Both credentials present. Endpoints 503 when this is False, same posture
    as telegram_not_configured / usdt_not_configured."""
    return bool(client_id_from_env() and client_secret_from_env())


def api_base() -> str:
    """Select the sandbox vs live REST host from PAYPAL_ENV. Unset or anything
    other than 'live' means sandbox -- fail safe toward the test environment."""
    env = (os.environ.get("PAYPAL_ENV") or "sandbox").strip().lower()
    return _LIVE_API if env == "live" else _SANDBOX_API


def _price_from_env(var: str, default: str) -> str:
    """A fiat amount as a string (PayPal wants amount.value as a string). An
    unparseable override falls back to the default rather than sending garbage
    to PayPal."""
    raw = os.environ.get(var) or default
    try:
        return f"{float(raw):.2f}"
    except ValueError:
        return f"{float(default):.2f}"


def pro_price_usd() -> str:
    return _price_from_env("PAYPAL_PRO_PRICE_USD", _DEFAULT_PRO_PRICE_USD)


def fixpack_price_usd() -> str:
    return _price_from_env("PAYPAL_FIXPACK_PRICE_USD", _DEFAULT_FIXPACK_PRICE_USD)


def fixpack_custom_id(audit_id: str) -> str:
    return f"{FIXPACK_CUSTOM_ID_PREFIX}{audit_id}"


def monitor_custom_id(repo_full_name: str) -> str:
    return f"{MONITOR_CUSTOM_ID_PREFIX}{repo_full_name}"


class PayPalError(Exception):
    """A PayPal REST call returned a non-2xx response or an unusable body."""


# Bounded like telegram_stars.PRE_CHECKOUT_TIMEOUT_S: a slow token/verify call
# should fail fast and surface, not hang a request or a webhook ack.
OAUTH_TIMEOUT_S = 10.0
_CALL_TIMEOUT_S = 30.0

# In-process OAuth token cache. Client-credentials tokens are valid for ~9h;
# we refresh a minute early. monotonic() so a wall-clock jump can't extend it.
_token_cache: dict[str, Any] = {"token": None, "expires_at": 0.0}


def reset_token_cache() -> None:
    """Drop the cached OAuth token. For tests, which swap transports between
    cases and must not reuse a token minted through a previous case's mock."""
    _token_cache["token"] = None
    _token_cache["expires_at"] = 0.0


async def _access_token(*, transport: httpx.BaseTransport | None = None) -> str:
    now = time.monotonic()
    cached = _token_cache["token"]
    if cached and now < _token_cache["expires_at"]:
        return cached
    cid = client_id_from_env()
    secret = client_secret_from_env()
    if not cid or not secret:
        raise PayPalError("PayPal is not configured (PAYPAL_CLIENT_ID/SECRET)")
    async with httpx.AsyncClient(
        base_url=api_base(), timeout=OAUTH_TIMEOUT_S, transport=transport
    ) as client:
        resp = await client.post(
            "/v1/oauth2/token",
            data={"grant_type": "client_credentials"},
            auth=(cid, secret),
            headers={"Accept": "application/json"},
        )
        data = resp.json() if resp.content else {}
    if resp.status_code >= 300 or not data.get("access_token"):
        raise PayPalError(
            f"oauth token failed: {resp.status_code} {str(data)[:200]}"
        )
    token = data["access_token"]
    try:
        expires_in = float(data.get("expires_in", 300))
    except (TypeError, ValueError):
        expires_in = 300.0
    _token_cache["token"] = token
    _token_cache["expires_at"] = now + max(0.0, expires_in - 60)
    return token


async def _call(
    method: str, path: str, *, token: str, json: dict[str, Any] | None = None,
    transport: httpx.BaseTransport | None = None, timeout: float = _CALL_TIMEOUT_S,
) -> dict[str, Any]:
    async with httpx.AsyncClient(
        base_url=api_base(), timeout=timeout, transport=transport
    ) as client:
        resp = await client.request(
            method, path, json=json,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
        )
        data = resp.json() if resp.content else {}
    if resp.status_code >= 300:
        raise PayPalError(f"{method} {path} failed: {resp.status_code} {str(data)[:300]}")
    return data


# --- Orders API (one-time: Pro + Fix Pack) ---

async def create_order(
    *, custom_id: str, amount_usd: str, description: str,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    """Create a CAPTURE-intent order carrying the routing custom_id, and return
    PayPal's response ({"id", "status", "links": [...]}). The browser JS SDK
    approves + captures against PayPal directly; the capture then arrives here
    as a PAYMENT.CAPTURE.COMPLETED webhook (we never grant on an un-captured
    order)."""
    token = await _access_token(transport=transport)
    body = {
        "intent": "CAPTURE",
        "purchase_units": [
            {
                "custom_id": custom_id,
                "description": description,
                "amount": {"currency_code": CURRENCY, "value": amount_usd},
            }
        ],
    }
    return await _call(
        "POST", "/v2/checkout/orders", token=token, json=body, transport=transport
    )


async def create_pro_order(
    payment_repo: Any, *, transport: httpx.BaseTransport | None = None,
) -> dict[str, Any] | None:
    """Open a PayPal order for the Pro tier and persist a pending payments row
    keyed by the order id, so GET /v1/paypal/orders/{id} can poll the key back
    once the webhook captures. Mirrors usdt_trc20.create_invoice. Returns None
    when the pending row can't be persisted (DATABASE_URL unset)."""
    price = pro_price_usd()
    order = await create_order(
        custom_id=PRO_CUSTOM_ID, amount_usd=price, description=PRO_DESCRIPTION,
        transport=transport,
    )
    order_id = order.get("id")
    row = await payment_repo.create(
        account_id=None, provider=PROVIDER, external_ref=None,
        amount=float(price), currency=CURRENCY, status="pending",
        tier_granted="pro", product=PRODUCT_PRO, paypal_order_id=order_id,
    )
    if row is None:
        return None
    return {"order_id": order_id, "status": order.get("status"),
            "amount": price, "currency": CURRENCY, "product": "pro"}


async def create_fixpack_order(
    payment_repo: Any, *, audit_id: str,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any] | None:
    """Open a PayPal order for a Fix Pack scoped to one audit. Same pattern as
    create_pro_order, at the Fix Pack price, tagged product='fixpack' + audit_id
    so the webhook creates the paid fixpack_jobs row (not a tier). Returns None
    when the pending row can't be persisted."""
    price = fixpack_price_usd()
    order = await create_order(
        custom_id=fixpack_custom_id(audit_id), amount_usd=price,
        description=_fixpack_description(audit_id), transport=transport,
    )
    order_id = order.get("id")
    row = await payment_repo.create(
        account_id=None, provider=PROVIDER, external_ref=None,
        amount=float(price), currency=CURRENCY, status="pending",
        tier_granted=None, product=PRODUCT_FIXPACK, audit_id=audit_id,
        paypal_order_id=order_id,
    )
    if row is None:
        return None
    return {"order_id": order_id, "status": order.get("status"),
            "amount": price, "currency": CURRENCY, "product": "fixpack",
            "audit_id": audit_id}


async def order_status(
    payment_repo: Any, account_repo: Any, order_id: str,
) -> dict[str, Any] | None:
    """State of one Pro order for the browser widget to poll, mirroring
    usdt_trc20.invoice_status. Reveals the API key ONLY once the webhook has
    captured and granted (status 'completed', account linked); a pending order
    never leaks a key. Returns None if there's no such order (endpoint -> 404)."""
    row = await payment_repo.get_by_paypal_order_id(order_id)
    if row is None or row.get("provider") != PROVIDER:
        return None
    if row.get("status") == "completed":
        account = (
            await account_repo.get_by_id(row["account_id"])
            if row.get("account_id") else None
        )
        return {
            "order_id": order_id,
            "status": "completed",
            "tier": "pro",
            "api_key": account["api_key"] if account else None,
        }
    return {"order_id": order_id, "status": "pending"}


# --- Subscriptions API (recurring: Monitoring) ---

async def create_subscription(
    *, plan_id: str, custom_id: str,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    """Create a subscription against a billing plan, carrying the routing
    custom_id, and return PayPal's response ({"id": "I-...", "status", "links"}).
    The browser sends the buyer to the `approve` link; PayPal then delivers
    BILLING.SUBSCRIPTION.ACTIVATED and recurring PAYMENT.SALE.COMPLETED webhooks."""
    token = await _access_token(transport=transport)
    body = {"plan_id": plan_id, "custom_id": custom_id}
    return await _call(
        "POST", "/v1/billing/subscriptions", token=token, json=body,
        transport=transport,
    )


def approve_url_from_subscription(subscription: dict[str, Any]) -> str | None:
    for link in subscription.get("links") or []:
        if link.get("rel") == "approve":
            return link.get("href")
    return None


async def create_monitor_subscription(
    subscription_repo: Any, *, repo_full_name: str, plan_id: str,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any] | None:
    """Open a PayPal monitoring subscription for a repo and pre-insert its
    subscriptions row (status 'approval_pending', repo bound). Pre-inserting at
    creation -- when we still know the repo -- means every later webhook
    (ACTIVATED / SALE / CANCELLED) just updates the row by paypal_subscription_id
    and never has to reconstruct the repo binding, even if a SALE event arrives
    before ACTIVATED. Returns {subscription_id, approve_url, status}, or None if
    the row can't be persisted (DATABASE_URL unset)."""
    sub = await create_subscription(
        plan_id=plan_id, custom_id=monitor_custom_id(repo_full_name),
        transport=transport,
    )
    sub_id = sub.get("id")
    row = await subscription_repo.create_paypal(
        paypal_subscription_id=sub_id, tier=MONITOR_TIER,
        repo_full_name=repo_full_name,
    )
    if row is None:
        return None
    return {
        "subscription_id": sub_id,
        "approve_url": approve_url_from_subscription(sub),
        "status": sub.get("status"),
    }


# --- Webhook verification + dispatch ---

async def verify_webhook_signature(
    *, headers: Any, event: dict[str, Any], webhook_id: str,
    transport: httpx.BaseTransport | None = None,
) -> bool:
    """Verify a webhook via PayPal's verify-webhook-signature API (the option
    the founder specified over offline cert verification). Returns True only on
    verification_status == "SUCCESS"; any non-SUCCESS body, a missing header, or
    a transport error is a hard False -- we never grant on an unverified event.
    `headers` is the request's case-insensitive header mapping."""
    token = await _access_token(transport=transport)
    verify_body = {
        "auth_algo": headers.get("paypal-auth-algo"),
        "cert_url": headers.get("paypal-cert-url"),
        "transmission_id": headers.get("paypal-transmission-id"),
        "transmission_sig": headers.get("paypal-transmission-sig"),
        "transmission_time": headers.get("paypal-transmission-time"),
        "webhook_id": webhook_id,
        "webhook_event": event,
    }
    data = await _call(
        "POST", "/v1/notifications/verify-webhook-signature",
        token=token, json=verify_body, transport=transport,
    )
    return data.get("verification_status") == "SUCCESS"


def _parse_paypal_time(value: Any) -> datetime.datetime | None:
    """PayPal RFC3339 timestamps ('2026-08-20T10:00:00Z') -> aware UTC
    datetime, or None if absent/unparseable (caller falls back to a period)."""
    if not value or not isinstance(value, str):
        return None
    try:
        return datetime.datetime.fromisoformat(value)
    except ValueError:
        return None


def _period_from_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC) + datetime.timedelta(
        days=MONITOR_PERIOD_DAYS
    )


def _amount_from(node: dict[str, Any]) -> float | None:
    """PayPal amounts appear as amount.value (orders/captures) or amount.total
    (sales). Return a float, or None if absent/unparseable."""
    raw = node.get("value")
    if raw is None:
        raw = node.get("total")
    if raw is None:
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


_SUBSCRIPTION_STATUS_EVENTS = {
    "BILLING.SUBSCRIPTION.CANCELLED": "canceled",
    "BILLING.SUBSCRIPTION.SUSPENDED": "suspended",
    "BILLING.SUBSCRIPTION.EXPIRED": "expired",
}


async def handle_webhook_event(
    event: dict[str, Any], *, account_repo: Any, payment_repo: Any,
    audit_repo: Any, fixpack_repo: Any, subscription_repo: Any,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    """Dispatch one VERIFIED webhook event (the endpoint verifies the signature
    before calling this, mirroring how the Telegram handler trusts a
    secret-token-checked update).

    Handled event types; anything else is acknowledged and ignored (PayPal, like
    Telegram, POSTs many event types to one URL):
      * PAYMENT.CAPTURE.COMPLETED -> the authoritative "money captured" event for
        a one-time order. Route by custom_id: "pro" grants Pro (key delivered by
        the browser poll, not a DM); "fixpack:<audit_id>" creates the paid
        fixpack_jobs row. Idempotent on the capture id via grant_*.
      * BILLING.SUBSCRIPTION.ACTIVATED -> first period: upsert the subscriptions
        row to active with expires_at = next_billing_time.
      * PAYMENT.SALE.COMPLETED -> a recurring charge (billing_agreement_id = the
        subscription id): record the charge and push expires_at out one period.
      * BILLING.SUBSCRIPTION.CANCELLED/SUSPENDED/EXPIRED -> set the row's status;
        access stays expires_at-based (a cancel keeps the paid period), matching
        the Stars semantics in migration 0015.
    """
    event_type = event.get("event_type", "") or ""
    resource = event.get("resource") or {}

    if event_type == "PAYMENT.CAPTURE.COMPLETED":
        return await _handle_capture_completed(
            resource, account_repo=account_repo, payment_repo=payment_repo,
            audit_repo=audit_repo, fixpack_repo=fixpack_repo,
        )
    if event_type == "BILLING.SUBSCRIPTION.ACTIVATED":
        return await _handle_subscription_activated(
            resource, subscription_repo=subscription_repo, payment_repo=payment_repo,
        )
    if event_type == "PAYMENT.SALE.COMPLETED":
        return await _handle_sale_completed(
            resource, subscription_repo=subscription_repo, payment_repo=payment_repo,
        )
    if event_type in _SUBSCRIPTION_STATUS_EVENTS:
        return await _handle_subscription_status(
            event_type, resource, subscription_repo=subscription_repo,
        )
    return {"ok": True, "handled": "ignored", "event_type": event_type}


async def _handle_capture_completed(
    resource: dict[str, Any], *, account_repo: Any, payment_repo: Any,
    audit_repo: Any, fixpack_repo: Any,
) -> dict[str, Any]:
    from app.billing import grant_fixpack, grant_pro_tier

    capture_id = resource.get("id")
    if not capture_id:
        return {"ok": True, "handled": "capture", "persisted": False,
                "reason": "no_capture_id"}
    custom_id = resource.get("custom_id") or ""
    order_id = (
        ((resource.get("supplementary_data") or {}).get("related_ids") or {})
        .get("order_id")
    )
    amount = _amount_from(resource.get("amount") or {})
    currency = (resource.get("amount") or {}).get("currency_code") or CURRENCY

    # The pending row created at order time -> transition it to completed via
    # invoice_payment_id (the exact path USDT uses). If it can't be found
    # (order id absent, or DB unconfigured), grant_* inserts a completed row
    # instead -- still idempotent on the capture id.
    pending = (
        await payment_repo.get_by_paypal_order_id(order_id) if order_id else None
    )
    invoice_payment_id = pending["id"] if pending else None

    if custom_id.startswith(FIXPACK_CUSTOM_ID_PREFIX):
        audit_id = custom_id[len(FIXPACK_CUSTOM_ID_PREFIX):]
        job = await grant_fixpack(
            fixpack_repo=fixpack_repo, payment_repo=payment_repo,
            audit_repo=audit_repo, provider=PROVIDER, external_ref=capture_id,
            amount=amount, currency=currency, audit_id=audit_id,
            invoice_payment_id=invoice_payment_id,
        )
        return {"ok": True, "handled": "capture", "product": "fixpack",
                "persisted": job is not None}

    account = await grant_pro_tier(
        account_repo=account_repo, payment_repo=payment_repo,
        provider=PROVIDER, external_ref=capture_id, amount=amount,
        currency=currency, invoice_payment_id=invoice_payment_id,
    )
    return {"ok": True, "handled": "capture", "product": "pro",
            "persisted": account is not None}


async def _handle_subscription_activated(
    resource: dict[str, Any], *, subscription_repo: Any, payment_repo: Any,
) -> dict[str, Any]:
    from app.billing import grant_subscription

    sub_id = resource.get("id")
    if not sub_id:
        return {"ok": True, "handled": "subscription_activated",
                "persisted": False, "reason": "no_subscription_id"}
    custom_id = resource.get("custom_id") or ""
    repo_full_name = (
        custom_id[len(MONITOR_CUSTOM_ID_PREFIX):]
        if custom_id.startswith(MONITOR_CUSTOM_ID_PREFIX) else None
    )
    next_billing = (
        (resource.get("billing_info") or {}).get("next_billing_time")
    )
    expires_at = _parse_paypal_time(next_billing) or _period_from_now()
    sub = await grant_subscription(
        subscription_repo=subscription_repo, payment_repo=payment_repo,
        provider=PROVIDER, external_ref=None, amount=None, currency=CURRENCY,
        paypal_subscription_id=sub_id, tier=MONITOR_TIER, expires_at=expires_at,
        is_first_recurring=True, repo_full_name=repo_full_name,
    )
    return {"ok": True, "handled": "subscription_activated",
            "persisted": sub is not None}


async def _handle_sale_completed(
    resource: dict[str, Any], *, subscription_repo: Any, payment_repo: Any,
) -> dict[str, Any]:
    from app.billing import grant_subscription

    sale_id = resource.get("id")
    sub_id = resource.get("billing_agreement_id")
    if not sub_id or not sale_id:
        # A one-off capture's sale (no subscription) or a malformed event --
        # nothing to renew. One-time money is handled via PAYMENT.CAPTURE.
        return {"ok": True, "handled": "sale", "persisted": False,
                "reason": "no_subscription"}
    amount = _amount_from(resource.get("amount") or {})
    currency = (resource.get("amount") or {}).get("currency") or CURRENCY
    sub = await grant_subscription(
        subscription_repo=subscription_repo, payment_repo=payment_repo,
        provider=PROVIDER, external_ref=sale_id, amount=amount, currency=currency,
        paypal_subscription_id=sub_id, tier=MONITOR_TIER,
        expires_at=_period_from_now(), is_first_recurring=False,
    )
    return {"ok": True, "handled": "sale", "persisted": sub is not None}


async def _handle_subscription_status(
    event_type: str, resource: dict[str, Any], *, subscription_repo: Any,
) -> dict[str, Any]:
    status = _SUBSCRIPTION_STATUS_EVENTS[event_type]
    sub_id = resource.get("id")
    if not sub_id or subscription_repo is None:
        return {"ok": True, "handled": "subscription_status", "state": status,
                "updated": False}
    row = await subscription_repo.get_by_paypal_subscription_id(sub_id)
    if row is None:
        return {"ok": True, "handled": "subscription_status", "state": status,
                "updated": False}
    await subscription_repo.set_status(row["id"], status)
    return {"ok": True, "handled": "subscription_status", "status": status,
            "updated": True}

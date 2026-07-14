"""Telegram Stars payment provider (Bot API).

Stars is the only way bots may charge for digital goods, and it's a
simpler flow than classic Telegram Payments: the invoice currency is the
literal "XTR" and `provider_token` is an empty string -- there is no
third-party payment provider to register or tokenize (confirmed at
https://core.telegram.org/bots/payments-stars).

The flow this module covers:
  1. sendInvoice(currency="XTR", prices=[LabeledPrice(...)]) -> the user
     sees a Pay button.
  2. Telegram POSTs a `pre_checkout_query` update to our webhook the
     instant they tap Pay; we must answerPreCheckoutQuery within 10s or
     the charge is cancelled. We approve (nothing to reserve/oversell --
     one pro tier, always available).
  3. On success Telegram POSTs a `message` carrying `successful_payment`
     with `telegram_payment_charge_id`; that id is the idempotency key
     (Telegram retries the webhook until it gets 200, so the same charge
     can arrive more than once). We grant pro and DM the api_key back.

Authenticity is Telegram's own `secret_token` mechanism: setWebhook is
called with a secret, and Telegram echoes it in the
`X-Telegram-Bot-Api-Secret-Token` header on every delivery. The webhook
endpoint (app/main.py) constant-time-compares it, same posture as the
reap endpoint's bearer token. This module never trusts an update it
wasn't handed after that check.

Not exercised against a real bot: this sandbox has no TELEGRAM_BOT_TOKEN
and can't receive a real Telegram webhook. Outbound calls are injectable
(`transport=`) so tests fake them with httpx.MockTransport, and
scripts/verify_telegram_stars_locally.py lets the operator prove the
real sendInvoice call with their own token. See the README.
"""

from __future__ import annotations

import os
from typing import Any

import httpx

TELEGRAM_API = "https://api.telegram.org"

PROVIDER = "telegram_stars"
CURRENCY = "XTR"

# Price of the pro tier, in Stars. Env-overridable so it can be tuned
# without a code change; a plain constant default keeps it configured-out
# of the box. Stars are whole units -- `amount` in a LabeledPrice is the
# integer star count for XTR (no minor-unit multiplier, unlike fiat).
_DEFAULT_PRO_STARS = 250


def bot_token_from_env() -> str | None:
    """Same env-var-or-None pattern as GITHUB_PR_TOKEN / PREVIEW_REAP_TOKEN.
    Unset -> the webhook endpoint refuses (503) rather than half-working."""
    return os.environ.get("TELEGRAM_BOT_TOKEN") or None


def webhook_secret_from_env() -> str | None:
    """The secret handed to setWebhook and echoed back in the
    X-Telegram-Bot-Api-Secret-Token header. Unset -> endpoint refuses."""
    return os.environ.get("TELEGRAM_WEBHOOK_SECRET") or None


def pro_stars_price() -> int:
    raw = os.environ.get("TELEGRAM_PRO_STARS")
    if raw:
        try:
            return int(raw)
        except ValueError:
            pass
    return _DEFAULT_PRO_STARS


def build_invoice_payload(
    *, chat_id: int | str, title: str, description: str,
    payload: str, stars: int,
) -> dict[str, Any]:
    """The JSON body for sendInvoice, for Stars specifically. Pure and
    separate from the HTTP call so the exact shape (XTR, empty
    provider_token, LabeledPrice) is unit-testable without a network."""
    return {
        "chat_id": chat_id,
        "title": title,
        "description": description,
        "payload": payload,
        # Empty provider_token + XTR currency is what makes this a Stars
        # invoice rather than a classic fiat one.
        "provider_token": "",
        "currency": CURRENCY,
        "prices": [{"label": title, "amount": stars}],
    }


def _base_url(token: str) -> str:
    return f"{TELEGRAM_API}/bot{token}"


async def _call(
    method: str, body: dict[str, Any], *, token: str,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    async with httpx.AsyncClient(
        base_url=_base_url(token), timeout=30, transport=transport
    ) as client:
        resp = await client.post(f"/{method}", json=body)
        data = resp.json()
        if resp.status_code >= 300 or not data.get("ok", False):
            raise TelegramError(
                f"{method} failed: {resp.status_code} {str(data)[:300]}"
            )
        return data


class TelegramError(Exception):
    """A Bot API call returned a non-2xx or ok=false response."""


async def send_invoice(
    *, chat_id: int | str, title: str, description: str, payload: str,
    stars: int, token: str, transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    return await _call(
        "sendInvoice",
        build_invoice_payload(
            chat_id=chat_id, title=title, description=description,
            payload=payload, stars=stars,
        ),
        token=token, transport=transport,
    )


async def answer_pre_checkout_query(
    query_id: str, *, ok: bool, token: str,
    error_message: str | None = None,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {"pre_checkout_query_id": query_id, "ok": ok}
    if not ok and error_message:
        body["error_message"] = error_message
    return await _call("answerPreCheckoutQuery", body, token=token, transport=transport)


async def send_message(
    chat_id: int | str, text: str, *, token: str,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    return await _call(
        "sendMessage", {"chat_id": chat_id, "text": text},
        token=token, transport=transport,
    )


def _delivery_text(api_key: str) -> str:
    return (
        "Payment received — your ShipIt pro access is active.\n\n"
        f"Your API key:\n{api_key}\n\n"
        "Send it as `Authorization: Bearer <key>` on API requests. "
        "Keep it secret; anyone with it has your pro access."
    )


async def handle_update(
    update: dict[str, Any], *, account_repo: Any, payment_repo: Any,
    token: str, transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    """Dispatch one webhook update. Caller (the endpoint) has already
    verified the secret-token header, so this trusts the update is really
    from Telegram.

    Two update types matter; anything else is acknowledged and ignored
    (Telegram sends many kinds to the same webhook URL):
      * pre_checkout_query -> approve it (10s deadline).
      * message.successful_payment -> grant pro, DM the key. Idempotent
        on telegram_payment_charge_id via grant_pro_tier.
    """
    from app.billing import grant_pro_tier

    pcq = update.get("pre_checkout_query")
    if pcq is not None:
        await answer_pre_checkout_query(
            pcq["id"], ok=True, token=token, transport=transport
        )
        return {"ok": True, "handled": "pre_checkout_query"}

    message = update.get("message") or {}
    sp = message.get("successful_payment")
    if sp is not None:
        chat_id = message["chat"]["id"]
        account = await grant_pro_tier(
            account_repo=account_repo, payment_repo=payment_repo,
            provider=PROVIDER, external_ref=sp["telegram_payment_charge_id"],
            amount=sp.get("total_amount"), currency=sp.get("currency", CURRENCY),
        )
        if account is None:
            # DATABASE_URL not configured -- we took the payment but can't
            # persist an account. Tell the payer plainly rather than go
            # silent; an operator misconfiguration, not the payer's fault.
            await send_message(
                chat_id,
                "Payment received, but pro access could not be provisioned "
                "(server misconfiguration). Please contact support with this "
                f"charge id: {sp['telegram_payment_charge_id']}",
                token=token, transport=transport,
            )
            return {"ok": True, "handled": "successful_payment", "persisted": False}
        await send_message(
            chat_id, _delivery_text(account["api_key"]),
            token=token, transport=transport,
        )
        return {"ok": True, "handled": "successful_payment", "persisted": True}

    return {"ok": True, "handled": "ignored"}

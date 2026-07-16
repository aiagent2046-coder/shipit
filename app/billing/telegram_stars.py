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
        "Payment received — your Drydock pro access is active.\n\n"
        f"Your API key:\n{api_key}\n\n"
        "Send it as `Authorization: Bearer <key>` on API requests. "
        "Keep it secret; anyone with it has your pro access.\n\n"
        "Open your report: https://drydock.co"
    )


async def handle_update(
    update: dict[str, Any], *, account_repo: Any, payment_repo: Any,
    token: str, transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    """Dispatch one webhook update. Caller (the endpoint) has already
    verified the secret-token header, so this trusts the update is really
    from Telegram.

    Update types that matter; anything else is acknowledged and ignored
    (Telegram sends many kinds to the same webhook URL):
      * pre_checkout_query -> approve it (10s deadline).
      * message.successful_payment -> grant pro, DM the key. Idempotent
        on telegram_payment_charge_id via grant_pro_tier.
      * message.text "/mykey" -> resend the delivery message for the
        account already linked to this chat_id (key recovery).
      * message.text "/link <tx_hash>" -> a USDT payer claims a credited
        on-chain payment by its tx hash, linking it to this chat_id so
        /mykey can recover it thereafter.
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
        # Stamp the payer's chat_id onto the just-granted payment so /mykey
        # can recover this key later. Additive to the Stars flow -- the
        # grant and delivery above are unchanged; this only records the
        # association that was previously used once and thrown away.
        paid = await payment_repo.get_by_external_ref(
            PROVIDER, sp["telegram_payment_charge_id"]
        )
        if paid is not None:
            await payment_repo.link_telegram_chat_id(paid["id"], str(chat_id))
        await send_message(
            chat_id, _delivery_text(account["api_key"]),
            token=token, transport=transport,
        )
        return {"ok": True, "handled": "successful_payment", "persisted": True}

    text = (message.get("text") or "").strip()
    if text.split(maxsplit=1)[:1] == ["/mykey"]:
        return await _handle_mykey(
            message, account_repo=account_repo, payment_repo=payment_repo,
            token=token, transport=transport,
        )
    if text.split(maxsplit=1)[:1] == ["/link"]:
        return await _handle_link(
            message, text, account_repo=account_repo, payment_repo=payment_repo,
            token=token, transport=transport,
        )

    return {"ok": True, "handled": "ignored"}


_NO_ACCOUNT_TEXT = (
    "No Drydock pro account is linked to this Telegram chat yet.\n\n"
    "If you paid with Telegram Stars, your key is linked automatically at "
    "purchase — if you don't see it, make sure you're messaging from the "
    "same Telegram account you paid with.\n\n"
    "If you paid with USDT (TRC20), send `/link <tx_hash>` with your "
    "payment's transaction hash to link it to this chat, then run /mykey "
    "again."
)


async def _handle_mykey(
    message: dict[str, Any], *, account_repo: Any, payment_repo: Any,
    token: str, transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    chat_id = message["chat"]["id"]
    paid = await payment_repo.get_completed_by_telegram_chat_id(str(chat_id))
    account = (
        await account_repo.get_by_id(paid["account_id"])
        if paid and paid.get("account_id") else None
    )
    if account is None:
        await send_message(
            chat_id, _NO_ACCOUNT_TEXT, token=token, transport=transport
        )
        return {"ok": True, "handled": "mykey", "found": False}
    await send_message(
        chat_id, _delivery_text(account["api_key"]),
        token=token, transport=transport,
    )
    return {"ok": True, "handled": "mykey", "found": True}


async def _handle_link(
    message: dict[str, Any], text: str, *, account_repo: Any, payment_repo: Any,
    token: str, transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    # Anti-hijacking, documented residual risk (honest note, same spirit as
    # app/db.py's "what is NOT proven" and README's "known gaps"): a TRC20
    # transaction hash and the receiving address are both PUBLIC on-chain
    # data, so anyone watching the wallet can see a legitimate payer's tx
    # hash and could race them to run /link first and claim the key. We do
    # NOT try to fully solve this (no time-window, no extra identity proof);
    # the only mitigation is first-successful-link-wins, then permanently
    # locked -- once a payment carries a chat_id it can never be re-linked to
    # a different one (enforced atomically in
    # PaymentRepository.link_telegram_chat_id's WHERE clause). This is an
    # accepted MVP-level residual risk, not a bug to eliminate here.
    from app.billing import usdt_trc20

    chat_id = message["chat"]["id"]
    parts = text.split(maxsplit=1)
    tx_hash = parts[1].strip() if len(parts) > 1 else ""
    if not tx_hash:
        await send_message(
            chat_id,
            "Usage: `/link <tx_hash>` — send the transaction hash of your "
            "USDT (TRC20) payment.",
            token=token, transport=transport,
        )
        return {"ok": True, "handled": "link", "result": "missing_hash"}

    row = await payment_repo.get_by_external_ref(usdt_trc20.PROVIDER, tx_hash)
    if row is None:
        await send_message(
            chat_id,
            "That transaction hash wasn't found. If you just sent the "
            "payment, the poller runs on an interval — wait a few minutes "
            "and try `/link` again.",
            token=token, transport=transport,
        )
        return {"ok": True, "handled": "link", "result": "not_found"}

    # "completed" is the credited/matched state the USDT poller sets (via
    # grant_pro_tier -> mark_completed); reuse it rather than invent a new
    # status. Anything else means the poller hasn't credited it yet.
    if row.get("status") != "completed":
        await send_message(
            chat_id,
            "That payment is still pending confirmation. The poller runs on "
            "an interval — please retry `/link` shortly.",
            token=token, transport=transport,
        )
        return {"ok": True, "handled": "link", "result": "pending"}

    existing = row.get("telegram_chat_id")
    if existing is not None and str(existing) != str(chat_id):
        # Already claimed by someone else. Do NOT reveal which chat_id owns
        # it (tx hashes are public; leaking the owner would help an attacker).
        await send_message(
            chat_id,
            "That payment has already been linked to another Telegram "
            "account and can't be re-linked.",
            token=token, transport=transport,
        )
        return {"ok": True, "handled": "link", "result": "already_claimed"}

    # Unlinked, or already linked to THIS chat (idempotent): claim it and
    # hand back the key. The conditional update is the first-wins guard.
    linked = await payment_repo.link_telegram_chat_id(row["id"], str(chat_id))
    if linked is not None and str(linked.get("telegram_chat_id")) != str(chat_id):
        # Lost a concurrent race between the status check and the claim.
        await send_message(
            chat_id,
            "That payment has already been linked to another Telegram "
            "account and can't be re-linked.",
            token=token, transport=transport,
        )
        return {"ok": True, "handled": "link", "result": "already_claimed"}

    account = await account_repo.get_by_id(row["account_id"]) if row.get("account_id") else None
    if account is None:
        await send_message(
            chat_id,
            "That payment is linked to this chat, but its account could not "
            "be loaded. Please contact support with your transaction hash.",
            token=token, transport=transport,
        )
        return {"ok": True, "handled": "link", "result": "no_account"}
    await send_message(
        chat_id, _delivery_text(account["api_key"]),
        token=token, transport=transport,
    )
    return {"ok": True, "handled": "link", "result": "linked"}

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

# Public site base. Audit reports live at {SITE_URL}/audit/{audit_id}
# (web/src/app/audit/[id]/page.tsx); the bare site root is the "run an
# audit" landing page.
SITE_URL = "https://drydock.co"

PROVIDER = "telegram_stars"
CURRENCY = "XTR"

# Price of the pro tier, in Stars. Env-overridable so it can be tuned
# without a code change; a plain constant default keeps it configured-out
# of the box. Stars are whole units -- `amount` in a LabeledPrice is the
# integer star count for XTR (no minor-unit multiplier, unlike fiat).
_DEFAULT_PRO_STARS = 250

# Invoice copy for the Pro tier. Kept as module constants so the /upgrade
# command and scripts/verify_telegram_stars_locally.py mint the exact same
# invoice the operator already verified against the live Bot API.
PRO_TITLE = "Drydock Pro"
PRO_DESCRIPTION = "Drydock pro tier — higher audit limits and more."
PRO_PAYLOAD = "pro"

# Price of a Fix Pack, in Stars. Same env-overridable-with-default pattern
# as _DEFAULT_PRO_STARS above -- a Fix Pack is a separate product (one
# generated fix PR for one audit), priced independently of the Pro tier.
_DEFAULT_FIXPACK_STARS = 600

# Invoice copy for a Fix Pack. Unlike the Pro invoice, a Fix Pack is tied
# to a specific audit, so the payload encodes that audit_id (see
# FIXPACK_PAYLOAD_PREFIX): the successful_payment handler reads it back to
# know which audit the purchase is for.
FIXPACK_TITLE = "Drydock Fix Pack"
FIXPACK_PAYLOAD_PREFIX = "fixpack:"


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


def fixpack_stars_price() -> int:
    raw = os.environ.get("FIXPACK_STARS_PRICE")
    if raw:
        try:
            return int(raw)
        except ValueError:
            pass
    return _DEFAULT_FIXPACK_STARS


def fixpack_payload(audit_id: str) -> str:
    """Invoice payload for a Fix Pack purchase: the prefix plus the audit
    it's for, so the successful_payment handler can recover the audit_id
    (the invoice itself lives in Telegram, not our DB)."""
    return f"{FIXPACK_PAYLOAD_PREFIX}{audit_id}"


def _fixpack_description(audit_id: str) -> str:
    return (
        f"Drydock Fix Pack for audit {audit_id[:8]} — a generated pull "
        "request fixing this audit's findings."
    )


_FIXPACK_ZIP_ONLY_TEXT = (
    "Fix Pack currently only supports audits run from a GitHub URL. This "
    "audit was created from an uploaded zip, so there's no repository to "
    "open a fix PR against. Re-run the audit with your public GitHub repo "
    "URL, then buy a Fix Pack for that audit."
)


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
        # Pro is a general subscription, not tied to any one audit (see
        # grant_pro_tier -- the payment carries no audit_id), so there is
        # no specific "report" to link. Point at the run-an-audit landing
        # page instead of a bare, report-less homepage link.
        f"Run an audit: {SITE_URL}"
    )


async def handle_update(
    update: dict[str, Any], *, account_repo: Any, payment_repo: Any,
    token: str, transport: httpx.BaseTransport | None = None,
    audit_repo: Any = None, fixpack_repo: Any = None,
) -> dict[str, Any]:
    """Dispatch one webhook update. Caller (the endpoint) has already
    verified the secret-token header, so this trusts the update is really
    from Telegram.

    Update types that matter; anything else is acknowledged and ignored
    (Telegram sends many kinds to the same webhook URL):
      * pre_checkout_query -> approve it (10s deadline).
      * message.successful_payment -> for a Pro purchase, grant pro and DM
        the key (idempotent on telegram_payment_charge_id via
        grant_pro_tier); for a Fix Pack purchase (payload prefixed
        "fixpack:"), create the paid fixpack_jobs row instead (via
        grant_fixpack) and DM a confirmation -- no tier change, no key.
      * message.text "/upgrade" -> send a Stars invoice for the pro tier
        (the Pay button that /pricing tells users to expect).
      * message.text "/fixpack <audit_id>" -> send a Stars invoice for a
        Fix Pack scoped to that audit (GitHub-URL audits only).
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
        payload = sp.get("invoice_payload", "") or ""
        if payload.startswith(FIXPACK_PAYLOAD_PREFIX):
            return await _handle_fixpack_payment(
                message, sp, payment_repo=payment_repo,
                audit_repo=audit_repo, fixpack_repo=fixpack_repo,
                token=token, transport=transport,
            )
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
    if text.split(maxsplit=1)[:1] == ["/upgrade"]:
        return await _handle_upgrade(
            message, token=token, transport=transport,
        )
    if text.split(maxsplit=1)[:1] == ["/fixpack"]:
        return await _handle_fixpack(
            message, text, audit_repo=audit_repo,
            token=token, transport=transport,
        )
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


async def _handle_upgrade(
    message: dict[str, Any], *, token: str,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    # The /pricing page tells users to run /upgrade to pay with Stars; this
    # sends the invoice that produces the Pay button. Reuses send_invoice and
    # the same PRO_* copy / pro_stars_price() the verify script proved live.
    chat_id = message["chat"]["id"]
    await send_invoice(
        chat_id=chat_id, title=PRO_TITLE, description=PRO_DESCRIPTION,
        payload=PRO_PAYLOAD, stars=pro_stars_price(),
        token=token, transport=transport,
    )
    return {"ok": True, "handled": "upgrade"}


async def _handle_fixpack(
    message: dict[str, Any], text: str, *, audit_repo: Any,
    token: str, transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    # "/fixpack <audit_id>": send a Stars invoice for a Fix Pack scoped to
    # that audit. Mirrors _handle_upgrade's shape (same send_invoice, same
    # env-driven price), but the payload encodes the audit_id and the
    # invoice is only offered for GitHub-URL audits (repo_url not null) --
    # a zip-upload audit has no repo to open a fix PR against (V1 scope).
    chat_id = message["chat"]["id"]
    parts = text.split(maxsplit=1)
    audit_id = parts[1].strip() if len(parts) > 1 else ""
    if not audit_id:
        await send_message(
            chat_id,
            "Usage: `/fixpack <audit_id>` — the id of a completed audit you "
            "ran from a public GitHub URL.",
            token=token, transport=transport,
        )
        return {"ok": True, "handled": "fixpack", "result": "missing_audit_id"}

    audit = await audit_repo.get(audit_id) if audit_repo is not None else None
    if audit is None:
        await send_message(
            chat_id,
            "No audit with that id was found. Double-check the audit id from "
            "your report.",
            token=token, transport=transport,
        )
        return {"ok": True, "handled": "fixpack", "result": "audit_not_found"}

    if not audit.get("repo_url"):
        await send_message(
            chat_id, _FIXPACK_ZIP_ONLY_TEXT, token=token, transport=transport
        )
        return {"ok": True, "handled": "fixpack", "result": "not_github_audit"}

    await send_invoice(
        chat_id=chat_id, title=FIXPACK_TITLE,
        description=_fixpack_description(audit_id),
        payload=fixpack_payload(audit_id), stars=fixpack_stars_price(),
        token=token, transport=transport,
    )
    return {"ok": True, "handled": "fixpack", "result": "invoice_sent"}


async def _handle_fixpack_payment(
    message: dict[str, Any], sp: dict[str, Any], *, payment_repo: Any,
    audit_repo: Any, fixpack_repo: Any, token: str,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    # A completed Fix Pack Stars payment. Unlike the Pro flow this grants
    # NO tier and mints NO key: it records the payment and creates the paid
    # fixpack_jobs row (generation is a separate follow-up). Idempotent on
    # telegram_payment_charge_id via grant_fixpack.
    from app.billing import grant_fixpack

    chat_id = message["chat"]["id"]
    audit_id = sp["invoice_payload"][len(FIXPACK_PAYLOAD_PREFIX):]
    job = await grant_fixpack(
        fixpack_repo=fixpack_repo, payment_repo=payment_repo,
        audit_repo=audit_repo, provider=PROVIDER,
        external_ref=sp["telegram_payment_charge_id"],
        amount=sp.get("total_amount"), currency=sp.get("currency", CURRENCY),
        audit_id=audit_id,
    )
    if job is None:
        # DATABASE_URL not configured -- payment taken but nothing persisted.
        await send_message(
            chat_id,
            "Payment received, but your Fix Pack could not be queued "
            "(server misconfiguration). Please contact support with this "
            f"charge id: {sp['telegram_payment_charge_id']}",
            token=token, transport=transport,
        )
        return {"ok": True, "handled": "fixpack_payment", "persisted": False}
    await send_message(
        chat_id,
        f"Payment received — your Drydock Fix Pack for audit {audit_id[:8]} "
        "is queued. You'll get the pull request once it's generated.\n\n"
        # A Fix Pack IS bought for one specific audit, so link that audit's
        # report directly (the /audit/{id} route), not the bare site root.
        f"View this audit: {SITE_URL}/audit/{audit_id}",
        token=token, transport=transport,
    )
    return {"ok": True, "handled": "fixpack_payment", "persisted": True}


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

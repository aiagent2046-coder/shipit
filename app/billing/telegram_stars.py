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

import hmac
import logging
import os
from typing import Any

import httpx

# Module level, unlike this file's other app.monitor use (a local import inside
# _handle_monitor): tests patch the name in the consuming module, and having
# both call sites read one binding keeps the patch target the same everywhere.
# app.monitor imports nothing from app, so there is no cycle.
from app import monitor
from app.notify import telegram as tg

logger = logging.getLogger(__name__)

# The Bot API client lives in app/notify/telegram.py -- it is a way of reaching
# a person, not a way of charging one, and it has to outlive this module. These
# names are re-exported because the bot's own handlers below call them, and
# because the test suite patches them on THIS module object.
TELEGRAM_API = tg.TELEGRAM_API
SITE_URL = tg.SITE_URL
TelegramError = tg.TelegramError
bot_token_from_env = tg.bot_token_from_env
webhook_secret_from_env = tg.webhook_secret_from_env
send_message = tg.send_message
answer_callback_query = tg.answer_callback_query
edit_message_reply_markup = tg.edit_message_reply_markup
edit_message_text = tg.edit_message_text

PROVIDER = "telegram_stars"
CURRENCY = "XTR"

# The provider string USDT/TRC20 rows carry. That rail is gone, but /link still
# reads the books under this name: a completed invoice is a payment someone
# made, and the key it bought is still theirs to collect.
RETIRED_USDT_PROVIDER = "usdt_trc20"

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

# --- Recurring subscriptions (Telegram Stars) ---
# The Bot API allows exactly ONE subscription period: 30 days, expressed in
# seconds. createInvoiceLink/sendInvoice reject any other value
# (https://core.telegram.org/bots/api#createinvoicelink). Not env-overridable
# -- it is a fixed protocol constant, not a tuning knob.
SUBSCRIPTION_PERIOD_SECONDS = 2592000

# Throwaway tier that exists only to prove the subscription plumbing end to
# end (a real Stars charge that renews and can be canceled). It is NOT the
# Phase C monitoring price; 1 Star keeps the live test cheap. The invoice
# payload is prefixed "sub:" so the successful_payment handler routes it the
# same way "fixpack:" routes a Fix Pack purchase.
SUBSCRIPTION_PAYLOAD_PREFIX = "sub:"
SUBSCRIPTION_TIER = "test-monitoring"
SUBSCRIPTION_PAYLOAD = f"{SUBSCRIPTION_PAYLOAD_PREFIX}{SUBSCRIPTION_TIER}"
SUBSCRIPTION_TITLE = "Drydock Monitoring (test)"
SUBSCRIPTION_DESCRIPTION = (
    "Test subscription for Drydock continuous monitoring — billing "
    "verification only, not the final product price."
)
_DEFAULT_SUBSCRIPTION_STARS = 1


def subscription_stars_price() -> int:
    raw = os.environ.get("SUBSCRIPTION_STARS")
    if raw:
        try:
            return int(raw)
        except ValueError:
            pass
    return _DEFAULT_SUBSCRIPTION_STARS


# --- Continuous Monitoring subscription (Phase C) ---
# A recurring Stars subscription bound to a specific repository. Same "sub:"
# family as the test tier -- so successful_payment still routes it through
# _handle_subscription_payment -- but the payload carries the canonical
# owner/repo after a second "monitor:" segment: "sub:monitor:<owner/repo>".
# That makes the natural key (telegram_user_id, invoice_payload) distinct per
# repo per user, so one user can monitor several repos without a schema change.
MONITOR_PAYLOAD_PREFIX = f"{SUBSCRIPTION_PAYLOAD_PREFIX}monitor:"
MONITOR_TIER = "monitoring"
MONITOR_TITLE = "Drydock Continuous Monitoring"


def monitor_payload(repo_full_name: str) -> str:
    return f"{MONITOR_PAYLOAD_PREFIX}{repo_full_name}"


def _monitor_description(repo_full_name: str) -> str:
    return (
        f"Continuous monitoring for {repo_full_name} — re-audits on each push "
        "to the default branch and alerts you here on new critical/high "
        "findings. Renews every 30 days; cancel any time with /unsubscribe."
    )


def _monitor_confirmation_text(repo_full_name: str, expires_at: Any) -> str:
    when = str(expires_at) if expires_at is not None else "the next billing date"
    return (
        f"Continuous monitoring is active for {repo_full_name}.\n\n"
        "On each push to the repository's default branch we re-audit it (at "
        "most once a day) and message you here if new critical or high findings "
        "appear that weren't in the previous audit.\n\n"
        f"Next renewal / access through: {when}\n\n"
        "Renews automatically every 30 days. Send /unsubscribe to stop "
        "auto-renewal; you keep access until the current period ends."
    )


def build_invoice_payload(
    *, chat_id: int | str, title: str, description: str,
    payload: str, stars: int,
) -> dict[str, Any]:
    """The JSON body for sendInvoice, for Stars specifically. Pure and
    separate from the HTTP call so the exact shape (XTR, empty
    provider_token, LabeledPrice) is unit-testable without a network.

    Deliberately has NO subscription_period: sendInvoice CANNOT create a
    recurring subscription invoice. Telegram rejects that with
    SUBSCRIPTION_EXPORT_MISSING -- a subscription invoice "may not be sent
    using messages.sendMedia [= Bot API sendInvoice], only exported to
    invoice deep links using payments.exportInvoice [= createInvoiceLink]"
    (https://core.telegram.org/api/subscriptions). An earlier version passed
    subscription_period through here, which shipped a 400-looping /subscribe
    to prod; the parameter is removed so that footgun can't recur. Recurring
    invoices go through create_invoice_link below."""
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


async def create_invoice_link(
    *, title: str, description: str, payload: str, stars: int,
    subscription_period: int | None = None, token: str,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    """Create an invoice via createInvoiceLink and return the Bot API envelope
    ({"ok": True, "result": "<url>"}); `result` is a shareable invoice link,
    NOT tied to any chat (hence no chat_id, unlike build_invoice_payload).

    This is the ONLY way to mint a recurring Stars subscription invoice:
    subscription invoices cannot be sent with sendInvoice and must be exported
    as a deep link (https://core.telegram.org/api/subscriptions). Pass
    subscription_period=SUBSCRIPTION_PERIOD_SECONDS for a subscription; omit it
    for an ordinary one-shot link. Body is the same Stars shape as
    build_invoice_payload minus chat_id."""
    body: dict[str, Any] = {
        "title": title,
        "description": description,
        "payload": payload,
        "provider_token": "",
        "currency": CURRENCY,
        "prices": [{"label": title, "amount": stars}],
    }
    if subscription_period is not None:
        body["subscription_period"] = subscription_period
    return await _call(
        "createInvoiceLink", body, token=token, transport=transport,
    )


# Telegram cancels the charge if we don't answerPreCheckoutQuery within
# ~10s of the Pay tap ("within 10 seconds",
# https://core.telegram.org/bots/api#answerprecheckoutquery). Bound the
# outbound answer well under that: a slow Bot API response then fails fast
# and surfaces, instead of the generic 30s _call timeout silently sailing
# past the deadline and producing a BOT_PRECHECKOUT_TIMEOUT on Telegram's
# side. The pre_checkout branch (see handle_update) does NO DB work, so
# this single outbound call is the only thing that can spend the budget --
# keep its ceiling short.
PRE_CHECKOUT_TIMEOUT_S = 8.0

_call = tg.call


async def send_invoice(
    *, chat_id: int | str, title: str, description: str, payload: str,
    stars: int, token: str, transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    # One-shot invoices only (/upgrade, /fixpack). Subscriptions must NOT use
    # this -- see build_invoice_payload and create_invoice_link.
    return await _call(
        "sendInvoice",
        build_invoice_payload(
            chat_id=chat_id, title=title, description=description,
            payload=payload, stars=stars,
        ),
        token=token, transport=transport,
    )


async def edit_user_star_subscription(
    *, user_id: int | str, telegram_payment_charge_id: str, is_canceled: bool,
    token: str, transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    """Cancel (is_canceled=True) or re-enable (False) the auto-renewal of a
    Stars subscription. Cancellation does NOT revoke access immediately -- the
    payer keeps access until the current paid period ends
    (https://core.telegram.org/bots/api#edituserstarsubscription). Returns the
    Bot API envelope ({"ok": True, "result": true} on success)."""
    return await _call(
        "editUserStarSubscription",
        {
            "user_id": user_id,
            "telegram_payment_charge_id": telegram_payment_charge_id,
            "is_canceled": is_canceled,
        },
        token=token, transport=transport,
    )


async def answer_pre_checkout_query(
    query_id: str, *, ok: bool, token: str,
    error_message: str | None = None,
    transport: httpx.BaseTransport | None = None,
    timeout: float = PRE_CHECKOUT_TIMEOUT_S,
) -> dict[str, Any]:
    body: dict[str, Any] = {"pre_checkout_query_id": query_id, "ok": ok}
    if not ok and error_message:
        body["error_message"] = error_message
    return await _call(
        "answerPreCheckoutQuery", body, token=token,
        transport=transport, timeout=timeout,
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


def _no_key_for_this_payment_text(payment: dict[str, Any]) -> str:
    """A real, completed payment that simply has no key to hand over.

    In practice always a Fix Pack, which is delivered as a pull request. The
    text this replaced said the account "could not be loaded" and told the
    payer to contact support -- describing a failure to someone whose payment
    worked perfectly, about a key that was never supposed to exist.

    The last line matters as much as the first: a payer who just typed a
    command and got an unexpected answer will assume they broke something, and
    the honest reassurance is cheaper than the support message it prevents.
    """
    from app.billing import PRODUCT_FIXPACK

    what = ("Fix Pack" if payment.get("product") == PRODUCT_FIXPACK
            else "purchase")
    return (
        f"That reference is for a {what}, which doesn't come with an API "
        "key — it's delivered as a pull request on your repository, and "
        "you'll get a message here when it's opened.\n\n"
        "Nothing went wrong and nothing changed: if you also have Drydock "
        "pro on this chat, /mykey and /rotatekey still work as before."
    )


def _already_delivered_text() -> str:
    # A retried webhook / a second /link for a payment whose key already went
    # out. The key text is not stored (migration 0019), so there is nothing to
    # re-send -- say that plainly and point at the same recovery path /mykey
    # does, rather than going silent or implying the payment failed.
    return (
        "Your payment is confirmed and your Drydock pro access is active — "
        "this key was already delivered once.\n\n"
        "For security the full key is shown only once and is never stored, so "
        "it can't be re-sent. Lost it? Run /rotatekey to get a new key (the "
        "old one stops working immediately)."
    )


async def handle_update(
    update: dict[str, Any], *, account_repo: Any, payment_repo: Any,
    token: str, transport: httpx.BaseTransport | None = None,
    audit_repo: Any = None, fixpack_repo: Any = None,
    subscription_repo: Any = None,
) -> dict[str, Any]:
    """Dispatch one webhook update. Caller (the endpoint) has already
    verified the secret-token header, so this trusts the update is really
    from Telegram.

    Update types that matter; anything else is acknowledged and ignored
    (Telegram sends many kinds to the same webhook URL):
      * pre_checkout_query -> approve it (10s deadline). Product-agnostic: a
        subscription's first charge also emits one, approved unconditionally
        like every other product.
      * message.successful_payment -> for a Pro purchase, grant pro and DM
        the key (idempotent on telegram_payment_charge_id via
        grant_pro_tier); for a Fix Pack purchase (payload prefixed
        "fixpack:"), create the paid fixpack_jobs row instead (via
        grant_fixpack) and DM a confirmation -- no tier change, no key; for a
        subscription (payload prefixed "sub:"), upsert/renew the subscriptions
        row (via grant_subscription) -- no account, no key.
      * callback_query -> an inline button was tapped. Only the operator's
        bank-transfer Confirm button produces one; owner-only, fail-closed.
      * subscription (BotSubscriptionUpdated) -> a renewal state change
        (canceled/active/failed); update the subscriptions row's status. This
        is the field key the Bot API uses for BotSubscriptionUpdated.
      * message.text "/upgrade" -> send a Stars invoice for the pro tier
        (the Pay button that /pricing tells users to expect).
      * message.text "/subscribe" -> send a recurring Stars invoice for the
        test-monitoring subscription tier.
      * message.text "/unsubscribe" -> cancel the caller's active
        subscription's auto-renewal (editUserStarSubscription); access
        continues until the current period ends.
      * message.text "/fixpack <audit_id>" -> send a Stars invoice for a
        Fix Pack scoped to that audit (GitHub-URL audits only).
      * message.text "/mykey" -> resend the delivery message for the
        account already linked to this chat_id (key recovery).
      * message.text "/link <reference>" -> a payer claims a credited
        on-chain payment by its tx hash, linking it to this chat_id so
        /mykey can recover it thereafter.
    """
    from app.billing import grant_pro_tier

    pcq = update.get("pre_checkout_query")
    if pcq is not None:
        # Answer FIRST, before any repo is consulted, and identically for
        # every product (Pro and Fix Pack alike -- the payload is not even
        # read here): there is nothing to reserve or oversell, so approving
        # is unconditional. Doing a DB round-trip (e.g. re-checking the audit
        # or an existing fixpack_job) before answering is exactly what would
        # blow Telegram's ~10s deadline under Supabase latency and cancel the
        # charge -- real state validation belongs in the successful_payment
        # handlers below, never on this path. The short PRE_CHECKOUT_TIMEOUT_S
        # bounds the one outbound call so even Bot API slowness fails fast.
        await answer_pre_checkout_query(
            pcq["id"], ok=True, token=token, transport=transport
        )
        return {"ok": True, "handled": "pre_checkout_query"}

    # An inline button was tapped. Today the only one that produces a callback
    # is the operator's bank-transfer confirm button (every other keyboard in
    # this module is a `url` button, which produces no update at all), and it
    # moves money, so this branch is owner-only -- see _handle_callback_query.
    cbq = update.get("callback_query")
    if cbq is not None:
        return await _handle_callback_query(
            cbq, account_repo=account_repo, payment_repo=payment_repo,
            audit_repo=audit_repo, fixpack_repo=fixpack_repo,
            token=token, transport=transport,
        )

    # BotSubscriptionUpdated: a renewal state change (canceled/active/failed).
    # The Bot API delivers it under the `subscription` field of an Update. It
    # carries only the user + invoice_payload + state -- no charge id -- so it
    # is matched on the (telegram_user_id, invoice_payload) natural key.
    bsu = update.get("subscription")
    if bsu is not None:
        return await _handle_subscription_updated(
            bsu, subscription_repo=subscription_repo,
        )

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
        if payload.startswith(SUBSCRIPTION_PAYLOAD_PREFIX):
            return await _handle_subscription_payment(
                message, sp, payment_repo=payment_repo,
                subscription_repo=subscription_repo,
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
        # The key is delivered straight from the grant that minted it, in this
        # same handler -- it is never re-read from the database, because it
        # isn't stored there (migration 0019). A retried webhook therefore has
        # no key to re-send: grant_pro_tier's replay path returns the account
        # without one, and the payer is pointed at /rotatekey (usable because
        # the chat_id was just stamped above).
        api_key = account.get("api_key")
        await send_message(
            chat_id,
            _delivery_text(api_key) if api_key else _already_delivered_text(),
            token=token, transport=transport,
        )
        return {
            "ok": True, "handled": "successful_payment", "persisted": True,
            "key_delivered": api_key is not None,
        }

    text = (message.get("text") or "").strip()
    if text.split(maxsplit=1)[:1] == ["/upgrade"]:
        return await _handle_upgrade(
            message, token=token, transport=transport,
        )
    if text.split(maxsplit=1)[:1] == ["/subscribe"]:
        return await _handle_subscribe(
            message, token=token, transport=transport,
        )
    if text.split(maxsplit=1)[:1] == ["/unsubscribe"]:
        return await _handle_unsubscribe(
            message, subscription_repo=subscription_repo,
            token=token, transport=transport,
        )
    if text.split(maxsplit=1)[:1] == ["/fixpack"]:
        return await _handle_fixpack(
            message, text, audit_repo=audit_repo,
            token=token, transport=transport,
        )
    if text.split(maxsplit=1)[:1] == ["/monitor"]:
        return await _handle_monitor(
            message, text, audit_repo=audit_repo,
            token=token, transport=transport,
        )
    if text.split(maxsplit=1)[:1] == ["/mykey"]:
        return await _handle_mykey(
            message, account_repo=account_repo, payment_repo=payment_repo,
            token=token, transport=transport,
        )
    if text.split(maxsplit=1)[:1] == ["/rotatekey"]:
        return await _handle_rotatekey(
            message, account_repo=account_repo, payment_repo=payment_repo,
            token=token, transport=transport,
        )
    if text.split(maxsplit=1)[:1] == ["/link"]:
        return await _handle_link(
            message, text, account_repo=account_repo, payment_repo=payment_repo,
            token=token, transport=transport,
        )

    return {"ok": True, "handled": "ignored"}


def _is_operator(user_id: Any) -> bool:
    """True only if `user_id` is the configured operator's Telegram id.

    FAILS CLOSED, and that is the whole point of the function: with
    TELEGRAM_ADMIN_CHAT_ID unset there is nobody to compare against, so the
    answer is False for everyone. The opposite reading -- "no allowlist
    configured, so allow all" -- would turn any deployment that merely forgot
    one env var into a stranger-operated Confirm button handing out pro
    access, which is the single worst failure this module can have."""
    from app.alerts import admin_chat_id_from_env

    expected = admin_chat_id_from_env()
    if not expected or user_id is None:
        return False
    # compare_digest over the string forms: the env var is a string and the
    # Bot API sends an int, so both are normalised before comparing.
    return hmac.compare_digest(str(expected).strip(), str(user_id))


async def _handle_callback_query(
    cbq: dict[str, Any], *, account_repo: Any, payment_repo: Any,
    audit_repo: Any = None, fixpack_repo: Any = None,
    token: str, transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    """The operator tapped Confirm on a bank-transfer notification.

    The webhook's secret-token check proves the update came from Telegram; it
    says nothing about WHO tapped the button, and anyone who learns the bot's
    username can send it a callback. So the sender is checked against the
    operator allowlist here, and an unrecognised sender is treated exactly
    like an unknown button -- acknowledged so their client stops spinning,
    but nothing is granted and nothing is disclosed about what the button
    would have done.

    Confirmation itself is idempotent (bank_transfer.confirm goes through the
    CAS-gated grant path), so the button being tapped twice -- by a retried
    webhook, or by an operator who did not see the first edit land -- grants
    once and reports success both times."""
    from app.billing import bank_transfer

    data = cbq.get("data") or ""
    query_id = cbq.get("id")

    if not data.startswith(bank_transfer.CONFIRM_CALLBACK_PREFIX):
        if query_id:
            await answer_callback_query(query_id, token=token, transport=transport)
        return {"ok": True, "handled": "callback_query", "result": "ignored"}

    sender = (cbq.get("from") or {}).get("id")
    if not _is_operator(sender):
        logger.warning(
            "rejected bank-transfer confirm callback from non-operator %s", sender
        )
        if query_id:
            await answer_callback_query(query_id, token=token, transport=transport)
        return {"ok": True, "handled": "callback_query", "result": "forbidden"}

    payment_id = data[len(bank_transfer.CONFIRM_CALLBACK_PREFIX):]
    result = await bank_transfer.confirm(
        payment_repo=payment_repo, account_repo=account_repo,
        payment_id=payment_id, fixpack_repo=fixpack_repo, audit_repo=audit_repo,
    )
    if result is None:
        if query_id:
            await answer_callback_query(
                query_id, token=token, transport=transport,
                text="No such bank transfer.",
            )
        return {"ok": True, "handled": "callback_query", "result": "not_found"}

    granted = result["granted"]
    if query_id:
        await answer_callback_query(
            query_id, token=token, transport=transport,
            text="Confirmed." if granted else "Could not record the confirmation.",
        )
    if granted:
        # Take the button off the notification so the operator can see at a
        # glance which transfers are still outstanding. Cosmetic and
        # best-effort -- a stale button is harmless, since a second press
        # replays through the same CAS gate and grants nothing new.
        message = cbq.get("message") or {}
        chat = message.get("chat") or {}
        if chat.get("id") is not None and message.get("message_id") is not None:
            await edit_message_text(
                chat_id=chat["id"], message_id=message["message_id"],
                text=_confirmed_text(result), token=token, transport=transport,
            )
    return {
        "ok": True, "handled": "callback_query",
        "result": "confirmed" if granted else "not_persisted",
        "payment_id": result["payment_id"], "product": result["product"],
    }


def _confirmed_text(result: dict[str, Any]) -> str:
    from app.billing import bank_transfer

    what = (
        "Fix Pack" if result.get("product") == bank_transfer.PRODUCT_FIXPACK
        else "Pro tier"
    )
    lines = [
        f"Bank transfer CONFIRMED — {what}",
        "",
        f"Reference: {result.get('reference')}",
    ]
    if result.get("audit_id"):
        lines.append(f"Audit: {result['audit_id']}")
    if result.get("joined_existing_job"):
        # The one case where "CONFIRMED" alone would be a lie by omission: the
        # money is taken and no extra work was funded, because this audit
        # already had a live Fix Pack job and create_paid is idempotent per
        # audit. Nothing downstream can undo that -- only the operator can.
        lines += [
            "",
            "WARNING: this audit already had a Fix Pack job in progress, so "
            "this payment funded no additional work. One pull request will be "
            "opened, not two. Reconcile by hand — a refund is likely owed.",
        ]
    return "\n".join(lines)


_NO_ACCOUNT_TEXT = (
    "No Drydock pro account is linked to this Telegram chat yet.\n\n"
    "If you paid with Telegram Stars, your key is linked automatically at "
    "purchase — if you don't see it, make sure you're messaging from the "
    "same Telegram account you paid with.\n\n"
    "If you paid by bank transfer, send `/link DRY-XXXXXX` with the "
    "reference code from the payment page to link it to this chat, then run "
    "/mykey again."
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


def _subscribe_prompt_text(url: str) -> str:
    return (
        "Drydock Monitoring (test) — a recurring Telegram Stars subscription "
        "that renews every 30 days.\n\n"
        f"Tap to subscribe:\n{url}\n\n"
        "You can cancel auto-renewal any time with /unsubscribe."
    )


# What both subscription commands say instead of minting an invoice. States the
# reason and that no money moved, because "unavailable" alone reads as a bug.
_MONITORING_WITHDRAWN_TEXT = (
    "Continuous monitoring isn't on sale right now.\n\n"
    "It was priced as a placeholder and its audit spend wasn't capped or "
    "attributed to the subscriber, so we withdrew it instead of charging for "
    "something we hadn't finished costing. You haven't been charged.\n\n"
    "A Fix Pack is still available per audit \u2014 that one we can price "
    "honestly."
)


async def _reject_monitoring_sale(
    chat_id: int, handled: str, *, token: str,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    await send_message(
        chat_id, _MONITORING_WITHDRAWN_TEXT, token=token, transport=transport,
    )
    return {"ok": True, "handled": handled, "result": "not_for_sale"}


async def _handle_subscribe(
    message: dict[str, Any], *, token: str,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    # Withdrawn from sale -- see monitor.MONITORING_FOR_SALE. Checked before
    # createInvoiceLink so no payable link is ever minted.
    if not monitor.MONITORING_FOR_SALE:
        return await _reject_monitoring_sale(
            message["chat"]["id"], "subscribe",
            token=token, transport=transport,
        )
    # A recurring Stars invoice CANNOT be sent with sendInvoice -- Telegram
    # returns 400 SUBSCRIPTION_EXPORT_MISSING (see build_invoice_payload). A
    # subscription invoice must be exported as a deep link via createInvoiceLink
    # and then handed to the user, who taps it to open the Pay flow. So: mint
    # the link, then DM it (with an inline URL button for one-tap UX).
    chat_id = message["chat"]["id"]
    resp = await create_invoice_link(
        title=SUBSCRIPTION_TITLE, description=SUBSCRIPTION_DESCRIPTION,
        payload=SUBSCRIPTION_PAYLOAD, stars=subscription_stars_price(),
        subscription_period=SUBSCRIPTION_PERIOD_SECONDS,
        token=token, transport=transport,
    )
    url = resp["result"]
    reply_markup = {
        "inline_keyboard": [[{"text": "Subscribe with Stars", "url": url}]]
    }
    await send_message(
        chat_id, _subscribe_prompt_text(url),
        token=token, transport=transport, reply_markup=reply_markup,
    )
    return {"ok": True, "handled": "subscribe"}


def _subscription_confirmation_text(expires_at: Any) -> str:
    when = str(expires_at) if expires_at is not None else "the next billing date"
    return (
        "Subscription active — thanks! This is a billing test of Drydock "
        "continuous monitoring (not the final price).\n\n"
        f"Next renewal / access through: {when}\n\n"
        "It renews automatically every 30 days. Send /unsubscribe to stop "
        "auto-renewal; you keep access until the current period ends."
    )


async def _handle_subscription_payment(
    message: dict[str, Any], sp: dict[str, Any], *, payment_repo: Any,
    subscription_repo: Any, token: str,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    # A completed subscription Stars charge (first or renewal). Grants NO
    # account and mints NO key (the test-monitoring tier unlocks nothing yet):
    # it upserts/renews the subscriptions row and records the charge. Which
    # path is taken is decided by is_first_recurring / is_recurring.
    from app.billing import grant_subscription

    chat_id = message["chat"]["id"]
    # message.from carries the payer; fall back to chat id for private chats
    # where they coincide.
    user_id = str((message.get("from") or {}).get("id") or chat_id)
    is_first = bool(sp.get("is_first_recurring"))
    payload = sp.get("invoice_payload", "") or ""
    # A monitoring subscription (sub:monitor:<owner/repo>) binds a repo and uses
    # the 'monitoring' tier; the legacy sub:test-monitoring payload binds nothing.
    repo_full_name: str | None = None
    tier = SUBSCRIPTION_TIER
    if payload.startswith(MONITOR_PAYLOAD_PREFIX):
        repo_full_name = payload[len(MONITOR_PAYLOAD_PREFIX):] or None
        tier = MONITOR_TIER
    subscription = await grant_subscription(
        subscription_repo=subscription_repo, payment_repo=payment_repo,
        provider=PROVIDER, external_ref=sp["telegram_payment_charge_id"],
        amount=sp.get("total_amount"), currency=sp.get("currency", CURRENCY),
        telegram_user_id=user_id, telegram_chat_id=str(chat_id),
        invoice_payload=payload,
        tier=tier,
        expires_at=sp.get("subscription_expiration_date"),
        is_first_recurring=is_first,
        repo_full_name=repo_full_name,
    )
    if subscription is None:
        # DATABASE_URL not configured -- charge taken but nothing persisted.
        await send_message(
            chat_id,
            "Payment received, but your subscription could not be recorded "
            "(server misconfiguration). Please contact support with this "
            f"charge id: {sp['telegram_payment_charge_id']}",
            token=token, transport=transport,
        )
        return {"ok": True, "handled": "subscription_payment", "persisted": False}
    # DM only on the first charge -- silent auto-renewals shouldn't spam the
    # payer every 30 days (Telegram already shows its own receipt).
    if is_first:
        confirmation = (
            _monitor_confirmation_text(repo_full_name, subscription.get("expires_at"))
            if repo_full_name
            else _subscription_confirmation_text(subscription.get("expires_at"))
        )
        await send_message(
            chat_id, confirmation, token=token, transport=transport,
        )
    return {
        "ok": True, "handled": "subscription_payment", "persisted": True,
        "first": is_first,
    }


# BotSubscriptionUpdated.state -> our plain-text subscriptions.status. Only
# these three states arrive; any other is ignored (acknowledged, no update).
_SUBSCRIPTION_STATE_TO_STATUS = {
    "canceled": "canceled",
    "active": "active",
    "failed": "failed",
}


async def _handle_subscription_updated(
    bsu: dict[str, Any], *, subscription_repo: Any,
) -> dict[str, Any]:
    # A renewal state change. Match the row on (telegram_user_id,
    # invoice_payload) -- the only identifiers BotSubscriptionUpdated carries
    # -- and update status only. expires_at is deliberately NOT touched:
    # access is expires_at-based, and a canceled/failed subscription keeps the
    # period it already paid for (see migration 0015). 'failed' therefore does
    # NOT revoke access immediately; the paid period is honored to its end.
    state = bsu.get("state", "")
    status = _SUBSCRIPTION_STATE_TO_STATUS.get(state)
    if status is None:
        return {"ok": True, "handled": "subscription_updated", "state": state,
                "updated": False}
    user_id = str((bsu.get("user") or {}).get("id") or "")
    invoice_payload = bsu.get("invoice_payload", "") or ""
    if subscription_repo is None or not user_id:
        return {"ok": True, "handled": "subscription_updated", "state": state,
                "updated": False}
    row = await subscription_repo.get_by_user_and_payload(user_id, invoice_payload)
    if row is None:
        return {"ok": True, "handled": "subscription_updated", "state": state,
                "updated": False}
    await subscription_repo.set_status(row["id"], status)
    return {"ok": True, "handled": "subscription_updated", "state": state,
            "status": status, "updated": True}


async def _handle_unsubscribe(
    message: dict[str, Any], *, subscription_repo: Any, token: str,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    # Cancel the caller's active subscription's auto-renewal. Needs the payer's
    # user_id (which the message carries) and the subscription's latest
    # telegram_payment_charge_id (which we stored). editUserStarSubscription
    # does NOT revoke access -- the payer keeps it until the period ends -- so
    # we set status='canceled' but leave expires_at as the access boundary.
    chat_id = message["chat"]["id"]
    user_id = str((message.get("from") or {}).get("id") or chat_id)
    row = (
        await subscription_repo.get_active_by_user(user_id)
        if subscription_repo is not None else None
    )
    if row is None or not row.get("telegram_payment_charge_id"):
        await send_message(
            chat_id,
            "No active subscription is linked to this Telegram account.",
            token=token, transport=transport,
        )
        return {"ok": True, "handled": "unsubscribe", "found": False}
    await edit_user_star_subscription(
        user_id=user_id,
        telegram_payment_charge_id=row["telegram_payment_charge_id"],
        is_canceled=True, token=token, transport=transport,
    )
    await subscription_repo.set_status(row["id"], "canceled")
    await send_message(
        chat_id,
        "Auto-renewal canceled. You keep access until the end of the current "
        f"paid period ({row.get('expires_at') or 'the current period'}).",
        token=token, transport=transport,
    )
    return {"ok": True, "handled": "unsubscribe", "found": True}


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


_MONITOR_ZIP_ONLY_TEXT = (
    "Continuous monitoring watches a GitHub repository for new issues on each "
    "push, so it only works for audits run from a public GitHub URL. This audit "
    "was created from an uploaded zip (no repository to watch). Re-run the audit "
    "with your public GitHub repo URL, then enable monitoring for that audit."
)


def _monitor_prompt_text(repo_full_name: str, url: str) -> str:
    return (
        f"Continuous monitoring for {repo_full_name} — a recurring Telegram "
        "Stars subscription that renews every 30 days. We re-audit on each push "
        "to the default branch (at most once a day) and alert you here on new "
        "critical/high findings.\n\n"
        f"Tap to enable:\n{url}\n\n"
        "You can cancel auto-renewal any time with /unsubscribe."
    )


async def _handle_monitor(
    message: dict[str, Any], text: str, *, audit_repo: Any,
    token: str, transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    # "/monitor <audit_id>": subscribe to continuous monitoring of the repo the
    # audit ran against. Mirrors _handle_fixpack's audit lookup + repo_url gate,
    # but sends a RECURRING subscription invoice (createInvoiceLink, like
    # /subscribe -- a subscription invoice cannot be sent with sendInvoice, see
    # build_invoice_payload) whose payload binds the repo:
    # sub:monitor:<owner/repo>. _handle_subscription_payment records that repo on
    # the subscriptions row.
    from app.monitor import normalize_repo_full_name

    chat_id = message["chat"]["id"]
    # Withdrawn from sale -- see monitor.MONITORING_FOR_SALE. Before the audit
    # lookup: there is nothing to validate for a product we will not sell.
    if not monitor.MONITORING_FOR_SALE:
        return await _reject_monitoring_sale(
            chat_id, "monitor", token=token, transport=transport,
        )
    parts = text.split(maxsplit=1)
    audit_id = parts[1].strip() if len(parts) > 1 else ""
    if not audit_id:
        await send_message(
            chat_id,
            "Usage: `/monitor <audit_id>` — the id of a completed audit you ran "
            "from a public GitHub URL. Enables continuous monitoring of that "
            "repository.",
            token=token, transport=transport,
        )
        return {"ok": True, "handled": "monitor", "result": "missing_audit_id"}

    audit = await audit_repo.get(audit_id) if audit_repo is not None else None
    if audit is None:
        await send_message(
            chat_id,
            "No audit with that id was found. Double-check the audit id from "
            "your report.",
            token=token, transport=transport,
        )
        return {"ok": True, "handled": "monitor", "result": "audit_not_found"}

    repo_full_name = normalize_repo_full_name(audit.get("repo_url"))
    if not repo_full_name:
        await send_message(
            chat_id, _MONITOR_ZIP_ONLY_TEXT, token=token, transport=transport
        )
        return {"ok": True, "handled": "monitor", "result": "not_github_audit"}

    resp = await create_invoice_link(
        title=MONITOR_TITLE, description=_monitor_description(repo_full_name),
        payload=monitor_payload(repo_full_name), stars=subscription_stars_price(),
        subscription_period=SUBSCRIPTION_PERIOD_SECONDS,
        token=token, transport=transport,
    )
    url = resp["result"]
    reply_markup = {
        "inline_keyboard": [[{"text": "Enable monitoring with Stars", "url": url}]]
    }
    await send_message(
        chat_id, _monitor_prompt_text(repo_full_name, url),
        token=token, transport=transport, reply_markup=reply_markup,
    )
    return {"ok": True, "handled": "monitor", "result": "invoice_sent",
            "repo_full_name": repo_full_name}


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
    # A Fix Pack IS bought for one specific audit, so link that audit's report
    # directly (the /audit/{id} route), not the bare site root. The token is
    # NOT optional: GET /v1/audits/{id} authorises on the row's own token, so
    # a bare link is a flat 404 for the person who just paid. Named
    # audit_token, not token -- `token` in this scope is the bot's.
    audit_token = await audit_repo.get_access_token(audit_id)
    lines = [
        f"Payment received — your Drydock Fix Pack for audit {audit_id[:8]} "
        "is queued. You'll get the pull request once it's generated.",
    ]
    if audit_token:
        lines.append(f"View this audit: {SITE_URL}/audit/{audit_id}"
                     f"?token={audit_token}")
    # No token found (row gone, or persistence off): send no link at all
    # rather than one that 404s. A missing line asks nothing of the buyer; a
    # dead link tells them their paid order does not exist.
    await send_message(
        chat_id, "\n\n".join(lines),
        token=token, transport=transport,
    )
    return {"ok": True, "handled": "fixpack_payment", "persisted": True}


def _mykey_status_text(key_prefix: str | None, tier: str) -> str:
    # The key text is shown exactly once, at purchase, and is never stored,
    # so /mykey cannot re-send it. Confirm the account exists (by its safe
    # prefix) and point at /rotatekey for a lost key -- rotation mints a new
    # key rather than recovering the old one.
    shown = f"{key_prefix}…" if key_prefix else "sk_live_…"
    return (
        f"Your Drydock account is active ({tier}).\n\n"
        f"API key: {shown}\n\n"
        "For security the full key is shown only once, at purchase, and is "
        "never stored — so it can't be shown again here. Lost it? Run "
        "/rotatekey to get a new key (the old one stops working immediately)."
    )


def _rotate_text(api_key: str) -> str:
    return (
        "Done — here is your NEW Drydock API key. Your previous key no longer "
        f"works.\n\nYour API key:\n{api_key}\n\n"
        "Send it as `Authorization: Bearer <key>` on API requests. Update it "
        "anywhere you stored the old one. Keep it secret; anyone with it has "
        "your pro access."
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
        chat_id,
        _mykey_status_text(account.get("key_prefix"), account.get("tier", "pro")),
        token=token, transport=transport,
    )
    return {"ok": True, "handled": "mykey", "found": True}


async def _handle_rotatekey(
    message: dict[str, Any], *, account_repo: Any, payment_repo: Any,
    token: str, transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    # Identify the account the same way /mykey does: the chat that paid owns
    # the account. Holding this chat is the proof of ownership -- no old key
    # is required, which is exactly what makes this a lost-key recovery path.
    chat_id = message["chat"]["id"]
    paid = await payment_repo.get_completed_by_telegram_chat_id(str(chat_id))
    account_id = paid.get("account_id") if paid else None
    if not account_id:
        await send_message(
            chat_id, _NO_ACCOUNT_TEXT, token=token, transport=transport
        )
        return {"ok": True, "handled": "rotatekey", "found": False}
    rotated = await account_repo.rotate_key(account_id)
    if rotated is None:
        await send_message(
            chat_id, _NO_ACCOUNT_TEXT, token=token, transport=transport
        )
        return {"ok": True, "handled": "rotatekey", "found": False}
    await send_message(
        chat_id, _rotate_text(rotated["api_key"]),
        token=token, transport=transport,
    )
    return {"ok": True, "handled": "rotatekey", "found": True}


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
    from app.billing import bank_transfer

    chat_id = message["chat"]["id"]
    parts = text.split(maxsplit=1)
    claim = parts[1].strip() if len(parts) > 1 else ""
    if not claim:
        await send_message(
            chat_id,
            "Usage: `/link DRY-XXXXXX` — the reference code of your bank "
            "transfer.",
            token=token, transport=transport,
        )
        return {"ok": True, "handled": "link", "result": "missing_hash"}

    # Which provider to look the claim up under is read off its shape: a bank
    # reference is DRY- plus six characters, a TRC20 hash is 64 hex, so the
    # payer never has to say which method they used. Uppercased first because
    # the code is shown uppercase but typed by hand.
    if bank_transfer.REFERENCE_RE.match(claim.upper()):
        provider, claim = bank_transfer.PROVIDER, claim.upper()
        not_found_text = (
            "That reference code wasn't found. Check it against the one shown "
            "on the payment page — it looks like `DRY-XXXXXX`."
        )
        pending_text = (
            "That transfer hasn't been confirmed yet. Bank transfers are "
            "checked by hand and can take a few business days to arrive — "
            "please retry `/link` later."
        )
    else:
        # USDT/TRC20 was removed as a way to pay, and its poller with it. A
        # completed invoice from before the removal is still a payment someone
        # made, and /link is how they collect the key it bought -- so the
        # LOOKUP stays. What changes is that nothing can move an invoice to
        # completed any more, so a pending one will stay pending forever and
        # must be told to ask a human rather than to wait for a poller.
        provider = RETIRED_USDT_PROVIDER
        not_found_text = (
            "That transaction hash wasn't found. USDT (TRC20) is no longer a "
            "way to pay here. If you paid before it was withdrawn and your "
            "key never arrived, email support with the hash."
        )
        pending_text = (
            "That payment was never confirmed, and USDT (TRC20) has since "
            "been withdrawn — nothing will confirm it now. Email support with "
            "the transaction hash and we will sort it out by hand."
        )

    row = await payment_repo.get_by_external_ref(provider, claim)
    if row is None:
        await send_message(
            chat_id, not_found_text, token=token, transport=transport,
        )
        return {"ok": True, "handled": "link", "result": "not_found"}

    # "completed" is the credited state both providers converge on (via
    # grant_pro_tier -> mark_completed); reuse it rather than invent a new
    # status. Anything else means it hasn't been credited yet.
    if row.get("status") != "completed":
        await send_message(
            chat_id, pending_text, token=token, transport=transport,
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

    # Before claiming anything: does this payment grant an account at all?
    #
    # A Fix Pack payment is completed and matches a DRY- reference like any
    # other, but grants no account by design -- it is delivered as a pull
    # request and has no key. Stamping this chat onto it used to happen first
    # and be discovered second, which broke the payer's Pro access: /mykey and
    # /rotatekey read the NEWEST completed payment carrying the chat, that was
    # now the Fix Pack row, and it has no account. Permanently, because nothing
    # unlinks a chat.
    #
    # get_completed_by_telegram_chat_id now ignores account-less payments, so
    # the damage is undone for anyone already in that state. This stops it
    # being done in the first place -- and lets us say something true instead
    # of sending the payer to support over a failure that never happened.
    if not row.get("account_id"):
        await send_message(
            chat_id, _no_key_for_this_payment_text(row),
            token=token, transport=transport,
        )
        return {"ok": True, "handled": "link", "result": "no_account"}

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

    # /link and the web checkout's invoice poll are two doors to the same
    # payment, and the key it grants exists in neither place: the poller that
    # granted it discarded the plaintext. So both doors go through the one
    # delivery claim -- whichever the payer reaches first mints and hands over
    # the key, and the other reports it already went out. Re-running /link is
    # then a no-op that costs no key, and /rotatekey works from here on because
    # the claim above stamped this chat_id.
    from app.billing import deliver_key_once

    api_key = await deliver_key_once(
        account_repo=account_repo, payment_repo=payment_repo, payment=row,
    )
    await send_message(
        chat_id,
        _delivery_text(api_key) if api_key else _already_delivered_text(),
        token=token, transport=transport,
    )
    return {
        "ok": True, "handled": "link",
        "result": "linked" if api_key else "already_delivered",
    }

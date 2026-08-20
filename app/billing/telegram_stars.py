"""The Telegram bot: what it still does, now that it does not sell.

STARS WAS THE REASON THIS FILE EXISTS, and Stars is no longer a way to pay
here. What survives is everything the bot does that is not a sale, and the
file keeps its name because the payment history it reads is still filed under
provider='telegram_stars' -- renaming the module would not rename the rows.

WHAT IT STILL DOES:

  The operator's Confirm button. A bank transfer is confirmed by a human
  looking at their banking app, and this is where the tap lands. Owner-only
  and fail-closed (_is_operator): with TELEGRAM_ADMIN_CHAT_ID unset the answer
  is False for everyone, because "no allowlist, so allow all" would turn one
  missing environment variable into a stranger-operated grant button.

  Key recovery. /mykey, /rotatekey and /link, for a payer who has already paid
  and has nothing in their hands. /link reads payments under both the
  bank-transfer and the retired usdt_trc20 provider: a completed invoice is
  someone's money whatever rail took it.

  Receiving a charge we can no longer prevent. Telegram, not this database,
  holds an invoice once minted -- an exported deep link sits in a chat until
  someone taps it, and a subscription sold before the withdrawal renews on
  Telegram's schedule. See handle_update for why every one of those is still
  honoured, and pages the operator.

  Cancelling. /unsubscribe still calls editUserStarSubscription. It is the one
  Stars API call left, and it stops money rather than taking it.

WHAT IT CANNOT DO: mint an invoice. sendInvoice, createInvoiceLink,
build_invoice_payload and all three price readers are gone, and
tests/test_billing_telegram.py asserts their absence rather than trusting the
diff that removed them.

Authenticity of an inbound update is Telegram's own `secret_token` mechanism:
setWebhook is called with a secret, and Telegram echoes it in the
`X-Telegram-Bot-Api-Secret-Token` header on every delivery. The webhook route
constant-time-compares it, same posture as the reap endpoint's bearer token.
This module never trusts an update it wasn't handed after that check.

Not exercised against a real bot: this sandbox has no TELEGRAM_BOT_TOKEN and
can't receive a real Telegram webhook. Outbound calls are injectable
(`transport=`) so tests fake them with httpx.MockTransport. The script that
proved the live sendInvoice call went with sendInvoice.
"""

from __future__ import annotations

import hmac
import logging
from typing import Any

import httpx

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

# THE INVOICE COPY AND THE PRICES ARE GONE, and with them every function
# that could mint a Stars invoice: send_invoice, create_invoice_link,
# build_invoice_payload, pro_stars_price, fixpack_stars_price,
# subscription_stars_price. Stars is no longer a way to pay here.
#
# The PAYLOAD PREFIXES stay. Telegram, not this database, holds an invoice
# once it is minted, so a link exported before the withdrawal can still be
# tapped, and a recurring subscription still renews on Telegram's schedule.
# When one of those arrives the payload is how we know what it was for.
FIXPACK_PAYLOAD_PREFIX = "fixpack:"

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

SUBSCRIPTION_PAYLOAD_PREFIX = "sub:"
SUBSCRIPTION_TIER = "test-monitoring"
SUBSCRIPTION_PAYLOAD = f"{SUBSCRIPTION_PAYLOAD_PREFIX}{SUBSCRIPTION_TIER}"

# --- Continuous Monitoring subscription (Phase C) ---
# A recurring Stars subscription bound to a specific repository. Same "sub:"
# family as the test tier -- so successful_payment still routes it through
# _handle_subscription_payment -- but the payload carries the canonical
# owner/repo after a second "monitor:" segment: "sub:monitor:<owner/repo>".
# Nothing mints one of these any more; the prefix is here to READ a renewal
# that Telegram is still charging on a subscription sold before the
# withdrawal.
MONITOR_PAYLOAD_PREFIX = f"{SUBSCRIPTION_PAYLOAD_PREFIX}monitor:"
MONITOR_TIER = "monitoring"


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


# What a payer sees if they tap Pay on an invoice minted before the
# withdrawal. Telegram shows this string verbatim and cancels the charge, so
# it has to say why and where to go, in the ~255 characters the Bot API allows.
PRE_CHECKOUT_WITHDRAWN = (
    "Telegram Stars is no longer accepted here. You have not been charged. "
    "Open your audit report at drydock.co and pay there instead."
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

    STARS IS NO LONGER A WAY TO PAY, and the asymmetry that follows is the
    whole shape of this function. Nothing here can MINT an invoice. Everything
    here can still RECEIVE one, because refusing an update does not refund
    anybody -- by the time a successful_payment arrives, Telegram has already
    moved the money, and the only thing declining to handle it accomplishes is
    that the payer gets nothing for it.

    The one place refusal is not merely rude is pre_checkout_query: that is
    the last moment before the charge, so it is declined with a reason. The
    invoices that can still reach it are ones minted before the withdrawal --
    Telegram, not this database, holds an invoice once it exists, and an
    exported deep link lives in a chat until someone taps it.

    Update types that matter; anything else is acknowledged and ignored
    (Telegram sends many kinds to the same webhook URL):
      * pre_checkout_query -> DECLINE, with PRE_CHECKOUT_WITHDRAWN as the
        reason Telegram shows the payer. No charge is made.
      * message.successful_payment -> honour it. For a Pro purchase, grant pro
        and DM the key (idempotent on telegram_payment_charge_id via
        grant_pro_tier); for a Fix Pack purchase (payload prefixed
        "fixpack:"), create the paid fixpack_jobs row instead (via
        grant_fixpack) and DM a confirmation -- no tier change, no key; for a
        subscription (payload prefixed "sub:"), upsert/renew the subscriptions
        row (via grant_subscription) -- no account, no key. Every one of these
        also pages the operator: a Stars charge arriving after the rail was
        withdrawn is an anomaly a human should look at, even though the
        software handled it correctly.
      * callback_query -> an inline button was tapped. Only the operator's
        bank-transfer Confirm button produces one; owner-only, fail-closed.
      * subscription (BotSubscriptionUpdated) -> a renewal state change
        (canceled/active/failed); update the subscriptions row's status. This
        is the field key the Bot API uses for BotSubscriptionUpdated.
      * message.text "/upgrade", "/subscribe", "/monitor", "/fixpack" -> say
        where to pay instead. None of them mints anything.
      * message.text "/unsubscribe" -> cancel the caller's active
        subscription's auto-renewal (editUserStarSubscription); access
        continues until the current period ends. KEPT, and it is the one
        Stars API call that survived: it STOPS money rather than taking it,
        and a subscriber left unable to cancel would keep being charged for a
        product we withdrew.
      * message.text "/mykey" -> resend the delivery message for the
        account already linked to this chat_id (key recovery).
      * message.text "/link <reference>" -> a payer claims a credited
        payment by its reference, linking it to this chat_id so /mykey can
        recover it thereafter.
    """
    from app.billing import grant_pro_tier

    pcq = update.get("pre_checkout_query")
    if pcq is not None:
        # Answer FIRST, before any repo is consulted, and identically for
        # every product -- the payload is not even read. Doing a DB round-trip
        # before answering is what would blow Telegram's ~10s deadline under
        # Supabase latency; the short PRE_CHECKOUT_TIMEOUT_S bounds the one
        # outbound call so even Bot API slowness fails fast.
        #
        # ok=False, where this used to approve unconditionally. This is the
        # last moment before the charge and the only point in the whole flow
        # where refusing actually spares the payer money rather than merely
        # withholding what they bought. An invoice can only reach here if it
        # was minted before the withdrawal, so the reason has to say that and
        # point somewhere that still works.
        await answer_pre_checkout_query(
            pcq["id"], ok=False, error_message=PRE_CHECKOUT_WITHDRAWN,
            token=token, transport=transport,
        )
        return {"ok": True, "handled": "pre_checkout_query",
                "result": "declined_withdrawn"}

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
        # A Stars charge after the rail was withdrawn. The handlers below still
        # do the right thing with it -- the money has already moved and the
        # payer must get what they paid for -- but a human should know it
        # happened, because it means an invoice minted before the withdrawal is
        # still out there, or a subscription is still renewing.
        #
        # Best-effort and BEFORE the grant: notify_operator never raises and
        # never blocks (app/alerts.py), and an alert that only fires on the
        # success path would go missing in exactly the case worth hearing about.
        await _alert_charge_on_a_withdrawn_rail(sp, payload)
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
        # The same transport the operator's own reply goes out on. confirm()
        # tells the PAYER their transfer landed, and that send has to be
        # injectable for the same reason every other outbound call here is: a
        # test must not reach api.telegram.org.
        transport=transport,
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


# WHERE TO PAY NOW. One string, because four commands used to mint four
# invoices and all four now have the same answer: the site. Naming the reason
# matters more than it looks -- "not available" reads as an outage, and a payer
# who thinks the bot is broken tries again instead of going where the money is
# actually taken.
_PAY_ON_THE_SITE = (
    "Telegram Stars is no longer accepted here.\n\n"
    "Payment moved to the site, where the price is shown in full before you "
    "pay and the receipt has an address on it. Open your audit report at "
    f"{SITE_URL} and buy from there.\n\n"
    "Nothing you have already paid for is affected — /mykey still works, and "
    "/link still claims a payment you have made."
)


async def _pay_on_the_site(
    chat_id: int, handled: str, *, token: str,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    await send_message(
        chat_id, _PAY_ON_THE_SITE, token=token, transport=transport,
    )
    return {"ok": True, "handled": handled, "result": "not_for_sale"}


async def _handle_upgrade(
    message: dict[str, Any], *, token: str,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    """/pricing used to tell people to run this to get a Pay button. It mints
    nothing now; it says where the Pay button lives."""
    return await _pay_on_the_site(
        message["chat"]["id"], "upgrade", token=token, transport=transport,
    )


# What the subscription commands say. Monitoring was withdrawn from sale before
# Stars was (#184: the price was a placeholder and the audit spend was neither
# capped nor attributed), so this text has to carry BOTH facts -- a reader who
# is told only about the payment rail will reasonably ask to pay another way.
_MONITORING_WITHDRAWN_TEXT = (
    "Continuous monitoring isn't on sale.\n\n"
    "It was priced as a placeholder and its audit spend wasn't capped or "
    "attributed to the subscriber, so we withdrew it instead of charging for "
    "something we hadn't finished costing. Telegram Stars, which is how it "
    "used to be billed, is no longer accepted here either. You haven't been "
    "charged.\n\n"
    "A Fix Pack is still available per audit \u2014 that one we can price "
    "honestly. Buy it from your report at " + SITE_URL + ".\n\n"
    "If you have a monitoring subscription from before this, send "
    "/unsubscribe to stop it renewing."
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
    """Unconditional now, where it used to consult monitor.MONITORING_FOR_SALE.

    The flag still gates the monitoring RUNNER, and turning it back on is the
    right way to resume that work. What it can no longer do is put this
    command back into business, because the code that minted a subscription
    invoice is gone with the Stars rail. A branch that reads a flag it cannot
    act on is worse than no branch: it claims a capability the module does not
    have."""
    return await _reject_monitoring_sale(
        message["chat"]["id"], "subscribe", token=token, transport=transport,
    )


def _subscription_confirmation_text(expires_at: Any) -> str:
    when = str(expires_at) if expires_at is not None else "the next billing date"
    return (
        "Subscription active — thanks! This is a billing test of Drydock "
        "continuous monitoring (not the final price).\n\n"
        f"Next renewal / access through: {when}\n\n"
        "It renews automatically every 30 days. Send /unsubscribe to stop "
        "auto-renewal; you keep access until the current period ends."
    )


async def _alert_charge_on_a_withdrawn_rail(
    sp: dict[str, Any], payload: str,
) -> None:
    """Page the operator that Telegram Stars took money we no longer sell for.

    Deduped on the charge id, so a retried webhook -- which Telegram sends
    until it gets a 200 -- pages once rather than once per retry.

    NEVER RAISES, and the try/except is not redundant with
    notify_operator's own promise never to. This runs after the payer has been
    charged and before they are granted anything: if an exception could escape
    here, an outage on OUR alert channel would turn a paid charge into a 5xx,
    Telegram would retry it, and the payer would still have nothing. That
    "notify_operator swallows everything" is true today is exactly the kind of
    fact a caller on this path must not depend on another module keeping.
    """
    from app.alerts import notify_operator

    charge = sp.get("telegram_payment_charge_id") or "unknown"
    try:
        await notify_operator(
            "Telegram Stars charge on a WITHDRAWN rail.\n\n"
            f"charge: {charge}\n"
            f"payload: {payload or '(none)'}\n"
            f"amount: {sp.get('total_amount')} {sp.get('currency', CURRENCY)}"
            "\n\n"
            "The payer has been granted what they bought. Someone still holds "
            "an invoice minted before the withdrawal, or a subscription is "
            "still renewing — check whether it should be refunded or "
            "cancelled.",
            dedupe_key=f"stars-withdrawn:{charge}",
        )
    except Exception:
        logger.warning(
            "withdrawn-rail alert failed for charge %s", charge, exc_info=True
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
    """"/fixpack <audit_id>" used to send a Stars invoice for that audit.

    The audit lookup and the zip-upload gate are KEPT even though nothing is
    sold here any more. Sending someone to the site to buy a Fix Pack for an
    audit that does not exist, or for a zip upload that has no repository to
    open a pull request against, wastes their time at the site instead of
    here -- and the second refusal is the one they would not understand."""
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

    await send_message(
        chat_id,
        "Telegram Stars is no longer accepted here. Buy the Fix Pack for this "
        f"audit from its report:\n{SITE_URL}/audit/{audit_id}",
        token=token, transport=transport,
    )
    return {"ok": True, "handled": "fixpack", "result": "not_for_sale"}


async def _handle_monitor(
    message: dict[str, Any], text: str, *, audit_repo: Any,
    token: str, transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    """Refuses before the audit lookup, and unconditionally -- see
    _handle_subscribe. There is nothing to validate for a product we will not
    sell, and no rail left to sell it on."""
    return await _reject_monitoring_sale(
        message["chat"]["id"], "monitor", token=token, transport=transport,
    )


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

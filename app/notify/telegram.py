"""The Telegram Bot API client, and nothing about money.

Lifted verbatim out of app/billing/telegram_stars.py, which is where it grew
because the bot's first job was selling Stars. Function bodies are unchanged;
what changed is who owns them, and therefore what can be deleted without
taking the outward channel down with it.

Authenticity of INBOUND updates is Telegram's own `secret_token` mechanism:
setWebhook is called with a secret and Telegram echoes it in the
`X-Telegram-Bot-Api-Secret-Token` header on every delivery. The webhook route
constant-time-compares it before anything here is called; this module never
verifies an update and must never be asked to.

Outbound calls are injectable (`transport=`) so tests fake them with
httpx.MockTransport rather than reaching api.telegram.org.

TWO CALL CONTRACTS, and the difference is deliberate:

  call()             raises TelegramError. For a call whose failure changes
                     the outcome -- answering a pre-checkout query inside
                     Telegram's 10-second window was the original example.

  best_effort_call()  logs and returns False. For a cosmetic call made AFTER
                     the state change it decorates has been committed: taking
                     a spent button off a message must never be able to turn a
                     completed grant into a 5xx.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any

import httpx

logger = logging.getLogger(__name__)

TELEGRAM_API = "https://api.telegram.org"

# Public site base. Audit reports live at {SITE_URL}/audit/{audit_id}
# (web/src/app/audit/[id]/page.tsx); the bare site root is the "run an
# audit" landing page. Here rather than in a billing module because every
# remaining caller uses it to build a link INTO a message.
SITE_URL = "https://drydock.co"


class TelegramError(Exception):
    """A Bot API call returned a non-2xx or ok=false response."""


def bot_token_from_env() -> str | None:
    """Same env-var-or-None pattern as GITHUB_PR_TOKEN / PREVIEW_REAP_TOKEN.
    Unset -> the webhook endpoint refuses (503) rather than half-working."""
    return os.environ.get("TELEGRAM_BOT_TOKEN") or None


_USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{5,32}$")


def bot_username_from_env() -> str | None:
    """The bot's @name, for building a deep link, or None if unusable.

    NOT read from the token, and not fetched with getMe. A page needs this to
    render an href, and neither an outbound API call per request nor a second
    literal typed into the frontend is the right way to get one. Telegram's own
    username rules are the validation, because this value ends up inside a URL
    a customer is invited to tap: anything not matching is treated as absent, so
    a typo removes the button rather than producing a link to nowhere.

    A leading @ is accepted and stripped -- it is how the name is written
    everywhere else, and rejecting the natural form would be a trap.
    """
    raw = (os.environ.get("TELEGRAM_BOT_USERNAME") or "").strip().lstrip("@")
    return raw if _USERNAME_RE.match(raw) else None


def webhook_secret_from_env() -> str | None:
    """The secret handed to setWebhook and echoed back in the
    X-Telegram-Bot-Api-Secret-Token header. Unset -> endpoint refuses."""
    return os.environ.get("TELEGRAM_WEBHOOK_SECRET") or None


def _base_url(token: str) -> str:
    return f"{TELEGRAM_API}/bot{token}"


async def call(
    method: str, body: dict[str, Any], *, token: str,
    transport: httpx.BaseTransport | None = None,
    timeout: float = 30,
) -> dict[str, Any]:
    async with httpx.AsyncClient(
        base_url=_base_url(token), timeout=timeout, transport=transport
    ) as client:
        resp = await client.post(f"/{method}", json=body)
        data = resp.json()
        if resp.status_code >= 300 or not data.get("ok", False):
            raise TelegramError(
                f"{method} failed: {resp.status_code} {str(data)[:300]}"
            )
        return data


async def best_effort_call(
    method: str, body: dict[str, Any], *, token: str,
    transport: httpx.BaseTransport | None = None,
) -> bool:
    """call() with the exception swallowed, in the style of
    app.alerts.notify_operator. For cosmetic post-grant calls only: every
    caller has already committed the state change the user paid for, so the
    only thing a raise could accomplish is to turn a successful payment into
    a 5xx."""
    try:
        await call(method, body, token=token, transport=transport)
        return True
    except Exception:
        logger.warning("%s failed (best-effort)", method, exc_info=True)
        return False


async def send_message(
    chat_id: int | str, text: str, *, token: str,
    transport: httpx.BaseTransport | None = None,
    reply_markup: dict[str, Any] | None = None,
) -> dict[str, Any]:
    # reply_markup is optional and defaults to None, so every existing caller
    # (key delivery, error notices, alerts) is unchanged. The operator's
    # bank-transfer confirm button is the one caller that passes it.
    body: dict[str, Any] = {"chat_id": chat_id, "text": text}
    if reply_markup is not None:
        body["reply_markup"] = reply_markup
    return await call("sendMessage", body, token=token, transport=transport)


async def answer_callback_query(
    query_id: str, *, token: str, text: str | None = None,
    transport: httpx.BaseTransport | None = None,
) -> bool:
    """Dismiss the spinner on a tapped inline button, optionally with a toast.

    Best-effort: this runs AFTER the operator's confirmation has already been
    persisted and the money already granted, so a Telegram hiccup here must not
    unwind a completed grant. Returns whether the call went through."""
    body: dict[str, Any] = {"callback_query_id": query_id}
    if text:
        body["text"] = text
    return await best_effort_call("answerCallbackQuery", body, token=token,
                                  transport=transport)


async def edit_message_reply_markup(
    *, chat_id: int | str, message_id: int | str, token: str,
    reply_markup: dict[str, Any] | None = None,
    transport: httpx.BaseTransport | None = None,
) -> bool:
    """Replace (or, with reply_markup=None, strip) a message's inline keyboard.

    Used to take the confirm button off an already-actioned notification. That
    is a UI-level guard only -- pressing a stale button twice is already safe
    at the database level via the CAS gate -- so like answer_callback_query it
    is best-effort and never raises."""
    body: dict[str, Any] = {"chat_id": chat_id, "message_id": message_id}
    if reply_markup is not None:
        body["reply_markup"] = reply_markup
    return await best_effort_call("editMessageReplyMarkup", body, token=token,
                                  transport=transport)


async def edit_message_text(
    *, chat_id: int | str, message_id: int | str, text: str, token: str,
    transport: httpx.BaseTransport | None = None,
) -> bool:
    """Rewrite a message's text, dropping any inline keyboard with it. Same
    best-effort contract as edit_message_reply_markup."""
    return await best_effort_call(
        "editMessageText",
        {"chat_id": chat_id, "message_id": message_id, "text": text},
        token=token, transport=transport,
    )

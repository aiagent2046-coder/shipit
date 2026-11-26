"""Best-effort operator alerts over the Telegram bot we already run.

No new integration and no new dependency: this reuses
`app.notify.telegram.send_message` to push a short message to a single
operator chat. The channel is opt-in via env — `TELEGRAM_BOT_TOKEN` (also
read by the bot webhook) plus `TELEGRAM_ADMIN_CHAT_ID` for the operator's own
chat. With either unset, alerting is a silent no-op, exactly like every other
"unconfigured -> degrade quietly" contract in this codebase.

Two invariants make this safe to sprinkle into failure paths:

  * **It never raises.** A Telegram outage, a bad chat id, or any other
    error is logged and swallowed — an alert must never turn a handled
    failure (a `failed` job, a caught 5xx) into a NEW unhandled one, and
    must never recurse into the 5xx handler that called it.
  * **It self-throttles — but only within one long-lived process.** A
    crash-loop firing the same alert every few seconds would spam the
    operator and hit Telegram's rate limits, so a tiny in-process, per-key
    time window suppresses duplicates. In-memory only (single VPS, single
    uvicorn process) — no external store. The CLI entry
    (`python -m app.alerts`) is a fresh process per invocation with an
    empty `_last_sent`, so the throttle cannot dedupe across invocations;
    that path is rate-limited by systemd itself (`RestartSec` plus
    `StartLimitBurst`/`StartLimitIntervalSec` on `shipit.service`). See
    the README for the recommended values.

Moved here from `app.alerts` during the import-cycles fix phase: the
notification layering is telegram (transport) <- this workflow <-
router/selfcheck (what to send). `app.alerts` stays as the systemd CLI
entry point and re-exports these names.
"""
from __future__ import annotations

import logging
import os
import time

import httpx

from app.notify import telegram

logger = logging.getLogger(__name__)

ADMIN_CHAT_ID_ENV = "TELEGRAM_ADMIN_CHAT_ID"

# Default suppression window for a repeated alert with the same dedupe key.
# Long enough that a tight crash-loop can't spam the operator, short enough
# that a genuinely recurring-but-spaced problem still re-notifies.
DEFAULT_THROTTLE_SECONDS = 60.0

# key -> monotonic timestamp of the last time we decided to send it.
_last_sent: dict[str, float] = {}


def admin_chat_id_from_env() -> str | None:
    """Operator chat id for alerts, or None. Same env-or-None pattern as
    telegram.bot_token_from_env — unset means alerting is off."""
    return os.environ.get(ADMIN_CHAT_ID_ENV) or None


def _should_send(dedupe_key: str, *, now: float, throttle_seconds: float) -> bool:
    """True if this key is outside its suppression window. Records `now` as
    the last-decided time whenever it returns True, so the window is measured
    from the last attempt regardless of whether the send itself succeeds
    (best-effort: a failing send must not defeat the crash-loop throttle)."""
    last = _last_sent.get(dedupe_key)
    if last is not None and (now - last) < throttle_seconds:
        return False
    _last_sent[dedupe_key] = now
    return True


async def notify_operator(
    text: str,
    *,
    dedupe_key: str | None = None,
    throttle_seconds: float = DEFAULT_THROTTLE_SECONDS,
    transport: httpx.BaseTransport | None = None,
    now: float | None = None,
    reply_markup: dict | None = None,
) -> bool:
    """Push one short alert to the operator chat. Returns True only if a
    message was actually sent; False for every quiet outcome (not
    configured, throttled, or send failed). Never raises.

    `dedupe_key` groups alerts for throttling (defaults to the text itself);
    give a stable key like "fixpack-failed:<job_id>" so distinct events
    don't share a window. `transport`/`now` are injection points for tests.

    `reply_markup` attaches an inline keyboard, which turns an alert into
    something the operator can act on in one tap (bank_transfer's confirm
    button). Still best-effort: a keyboard that fails to send is a lost
    notification, not a lost payment — the same invoice can be re-notified."""
    token = telegram.bot_token_from_env()
    chat_id = admin_chat_id_from_env()
    if not token or not chat_id:
        # Alerting isn't configured on this deployment — quiet no-op.
        return False

    key = dedupe_key or text
    if not _should_send(
        key, now=now if now is not None else time.monotonic(),
        throttle_seconds=throttle_seconds,
    ):
        return False

    try:
        await telegram.send_message(
            chat_id, text, token=token, transport=transport,
            reply_markup=reply_markup,
        )
        return True
    except Exception:
        # Best-effort: a Telegram failure must never propagate into the
        # caller's failure path (or the 5xx handler that invoked us).
        logger.warning(
            "operator alert failed to send (dedupe_key=%s)", key, exc_info=True
        )
        return False

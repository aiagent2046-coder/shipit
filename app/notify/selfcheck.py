"""Ask the notification channels whether they still work, before a customer does.

WHY THIS EXISTS. On 2026-08-25 this deployment sent no customer email at all.
Every send failed with SMTPAuthenticationError -- the mailbox password had
changed at the provider -- and nothing anywhere went red. That channel is a
deliberate no-op on failure: `send_email` returns False and raises nothing, so
a refund is still recorded and the customer is simply never told. The outage
was found by reading the journal by hand while testing something unrelated.

WHY THE EXISTING ALERT WAS NOT ENOUGH. app/notify/router.py already pages the
operator when nothing reached a customer, and it did, every time. But that
message says "could not reach a customer on any channel they gave", which reads
as one person with a bad address. Nothing in it distinguishes a typo in one
customer's email from a channel that is down for everybody, and the difference
between those two is the difference between an inconvenience and an outage.

WHAT IT CHECKS, AND WHAT THAT PROVES. Each configured channel is exercised the
way the product exercises it -- SMTP connect, STARTTLS, LOGIN through the same
`_open` a real send uses, and getMe for the bot token -- and then stops. It
proves the credentials are accepted. It does not prove a message will be
delivered or read: a mailbox at capacity, a spam filter, a bot blocked by its
chat are all invisible here. Those need a real send to a real address, which is
scripts/verify_smtp_locally.py, run by hand.

AN UNCONFIGURED CHANNEL IS NOT A BROKEN ONE. A deployment with no SMTP_HOST has
decided not to have mail, and paging somebody hourly about a decision they made
is how an alert gets muted, taking the real ones with it. Only a channel that
is configured and unusable is a failure.

Nothing here sends a message to anybody. A probe that delivered mail on a timer
is a probe someone switches off.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

import httpx

from app.notify import email as mail
from app.notify import telegram

logger = logging.getLogger(__name__)

EMAIL = "email"
TELEGRAM = "telegram"

# What the operator is told, per channel, when it stops working. Long enough to
# act on without opening a terminal: the failure is almost always a credential
# that changed somewhere else, and the fix is not in this repository.
_WHAT_IT_MEANS = {
    EMAIL: (
        "No customer is being told anything by email: not a payment "
        "confirmation, not a refund. The send fails silently by design, so "
        "nothing else will report this."
    ),
    TELEGRAM: (
        "The bot cannot reach Telegram, which is also how THIS alert travels "
        "-- if you are reading it, it recovered, or it arrived another way."
    ),
}


@dataclass(frozen=True)
class Result:
    """One channel's verdict.

    `detail` carries the exception type and, for SMTP, the server's own refusal
    text -- `(535, b'Incorrect authentication data')` is what turns "mail is
    broken" into "the password is wrong", and the two lead to different days.
    It never carries a credential: smtplib quotes the server's answer, not the
    request, and the username is a published support address rather than a
    secret. Same rule as scripts/verify_smtp_locally.py, which prints the same
    thing.
    """

    channel: str
    configured: bool
    ok: bool
    detail: str = ""

    @property
    def failed(self) -> bool:
        return self.configured and not self.ok


async def check_email(*, verify=None) -> Result:
    """`verify` is the injection point: the suite must not open a socket."""
    settings = mail.settings_from_env()
    if settings is None:
        return Result(EMAIL, configured=False, ok=True)

    verify = mail._verify if verify is None else verify
    try:
        await asyncio.to_thread(verify, settings)
    except Exception as exc:  # noqa: BLE001
        return Result(EMAIL, configured=True, ok=False,
                      detail=f"{type(exc).__name__}: {str(exc)[:200]}")
    return Result(EMAIL, configured=True, ok=True)


async def check_telegram(
    *, transport: httpx.BaseTransport | None = None, call=None,
) -> Result:
    token = telegram.bot_token_from_env()
    if not token:
        return Result(TELEGRAM, configured=False, ok=True)

    call = telegram.call if call is None else call
    try:
        await call("getMe", {}, token=token, transport=transport)
    except Exception as exc:  # noqa: BLE001
        return Result(TELEGRAM, configured=True, ok=False,
                      detail=f"{type(exc).__name__}: {str(exc)[:200]}")
    return Result(TELEGRAM, configured=True, ok=True)


def describe(results: list[Result]) -> str:
    """The alert text. One channel per line, worst first."""
    broken = [r for r in results if r.failed]
    lines = ["Drydock: a notification channel has stopped working.", ""]
    for result in broken:
        lines.append(f"{result.channel}: {result.detail}")
        lines.append(_WHAT_IT_MEANS.get(result.channel, ""))
        lines.append("")
    working = [r.channel for r in results if r.configured and r.ok]
    lines.append(f"still working: {', '.join(working) or 'nothing'}")
    return "\n".join(line for line in lines if line is not None).strip()


async def run(*, alert=None, transport=None, verify=None, call=None) -> list:
    """Check everything, page the operator about what is broken, return it all.

    The alert is deduplicated on the CHANNEL, not on the text, so an outage
    that lasts a week is one message a throttle-window rather than one an hour
    -- and a second channel failing is still its own message.
    """
    results = [
        await check_email(verify=verify),
        await check_telegram(transport=transport, call=call),
    ]

    broken = [r for r in results if r.failed]
    if not broken:
        return results

    for result in broken:
        # ERROR before the alert, and unconditionally: the alert travels over
        # Telegram, so a Telegram outage cannot announce itself. The journal
        # and the unit's own failed state are what remain in that case.
        logger.error("notification channel %s is not usable: %s",
                     result.channel, result.detail)

    if alert is None:
        from app.alerts import notify_operator as alert  # noqa: N813
    try:
        await alert(describe(results),
                    dedupe_key=f"channel-down:{','.join(r.channel for r in broken)}",
                    transport=transport)
    except Exception:  # noqa: BLE001
        logger.warning("could not page the operator about a dead channel",
                       exc_info=True)
    return results


def main(argv: list[str] | None = None) -> int:
    """Non-zero when a configured channel is unusable.

    That exit code is the second line of defence and the reason this is a unit
    rather than a cron line: shipit-notify-check.service carries
    `OnFailure=shipit-alert@%n.service`, and systemd holds the unit in `failed`
    afterwards. So a dead channel is visible in `systemctl status` even when
    the channel that carries alerts is the dead one.
    """
    logging.basicConfig(level=logging.INFO)
    results = asyncio.run(run())
    for result in results:
        state = ("not configured" if not result.configured
                 else "ok" if result.ok else f"FAILED {result.detail}")
        print(f"{result.channel:10} {state}")
    return 1 if any(r.failed for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())

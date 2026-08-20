"""Telling a customer something, on whatever channel they gave us.

THE PROBLEM THIS SOLVES IS NOT "SEND A MESSAGE". Three transports already do
that. The problem is that a customer can be UNREACHABLE and nobody finds out:
they paid by bank transfer with an email address that bounces, or an X handle
that does not take DMs from strangers, and the refund notice we believe we sent
went nowhere. From here that looks identical to a successful send, and the
customer's next move is a chargeback or a fraud accusation.

So this module's real output is not "sent". It is a `Delivery` that says what
was tried, what landed, and -- when nothing landed -- pages the operator, who
is the only party who can pick up a phone.

EVERY CHANNEL THE CUSTOMER GAVE, not the first that works. Somebody who wrote
down both an email address and a Telegram chat gave us both on purpose. For a
refund, hearing twice is not spam; hearing zero times is the thing that ends in
a dispute. The one place that would be wrong is a high-frequency notification,
and there isn't one -- these are the two or three moments in a whole
transaction that a person actually wants to know about.

NEVER RAISES, and never returns a False that a caller should act on by
unwinding. Every caller is announcing something that has ALREADY happened:
money moved, a pull request opened, a refund was issued. A notification that
fails is a customer who has to ask; a refund that fails because the
notification did is a much worse day.

THE OPERATOR PAGE IS THE POINT. It fires in two cases, and the second is the
one that is easy to miss:

  * The customer has channels and none of them worked. Something is broken or
    their details are wrong, and a human has to try another way.
  * The customer has NO channels at all. That is not a delivery failure, it is
    a record that we took money from somebody we have no way to contact -- and
    it should be visible at the moment it matters rather than discovered later.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx

from app.notify import email as mail
from app.notify import telegram, x

logger = logging.getLogger(__name__)

EMAIL = "email"
TELEGRAM = "telegram"
X = "x"


@dataclass(frozen=True)
class Contact:
    """Where one customer can be reached. Every field optional, because in
    practice most customers give exactly one."""

    email: str | None = None
    telegram_chat_id: str | None = None
    x_handle: str | None = None

    @classmethod
    def from_payment(cls, payment: dict) -> "Contact":
        """The contact details recorded against a `payments` row.

        Reads with `.get`, because a row from an older migration, or a fake in
        a test, may not carry every column -- and a missing key means "we do
        not have that channel", which is exactly what None means here."""
        return cls(
            email=payment.get("payer_email"),
            telegram_chat_id=payment.get("telegram_chat_id"),
            x_handle=payment.get("payer_x"),
        )

    def channels(self) -> tuple[str, ...]:
        """Which channels this customer actually has, in the order they are
        tried. Email first because it is the one that leaves the customer a
        record they can find again a month later."""
        found = []
        if (self.email or "").strip():
            found.append(EMAIL)
        if str(self.telegram_chat_id or "").strip():
            found.append(TELEGRAM)
        if x.normalize_handle(self.x_handle):
            found.append(X)
        return tuple(found)


@dataclass(frozen=True)
class Delivery:
    """What was tried and what landed.

    `attempted` and `delivered` are separate on purpose. "Nothing was tried"
    (we have no way to reach this person) and "everything was tried and
    everything failed" are different problems with different fixes, and a
    single boolean would collapse them.
    """

    attempted: tuple[str, ...] = ()
    delivered: tuple[str, ...] = ()

    @property
    def reached(self) -> bool:
        return bool(self.delivered)


async def notify_customer(
    *,
    contact: Contact,
    subject: str,
    body: str,
    reference: str = "",
    email_sender=None,
    transport: httpx.BaseTransport | None = None,
    alert=None,
) -> Delivery:
    """Tell one customer one thing, on every channel they gave us.

    `subject` is used as the email subject and is NOT prepended to the other
    two -- a DM that opens with its own subject line reads like a form letter,
    and Telegram and X both show the first line as the preview anyway.

    `reference` identifies the transaction in the operator page, so a "nobody
    could be reached" alert names something the operator can look up. It is
    never shown to the customer.

    The injection points (`email_sender`, `transport`, `alert`) exist so the
    suite can prove the routing without a mail server, an X account or a
    Telegram bot.
    """
    channels = contact.channels()
    if not channels:
        await _page_operator(
            "A customer has no contact channel at all.\n\n"
            f"reference: {reference or '(none)'}\n"
            f"about: {subject}\n\n"
            "Money was taken from somebody we have no way to reach. Nothing "
            "was sent because there was nowhere to send it.",
            dedupe_key=f"unreachable:{reference or subject}",
            alert=alert, transport=transport,
        )
        return Delivery()

    delivered: list[str] = []

    if EMAIL in channels:
        if await mail.send_email(
            to=(contact.email or "").strip(), subject=subject, body=body,
            sender=email_sender,
        ):
            delivered.append(EMAIL)

    if TELEGRAM in channels:
        token = telegram.bot_token_from_env()
        if token:
            try:
                await telegram.send_message(
                    str(contact.telegram_chat_id).strip(), body,
                    token=token, transport=transport,
                )
                delivered.append(TELEGRAM)
            except Exception as exc:  # noqa: BLE001
                # telegram.send_message raises on ok=false -- that contract is
                # right for a pre-checkout answer and wrong here, where the
                # thing being announced is already done.
                logger.warning(
                    "customer telegram notice failed (%s)", type(exc).__name__)

    if X in channels:
        if await x.send_dm(contact.x_handle or "", body, transport=transport):
            delivered.append(X)

    if not delivered:
        await _page_operator(
            "Could not reach a customer on any channel they gave.\n\n"
            f"reference: {reference or '(none)'}\n"
            f"about: {subject}\n"
            f"tried: {', '.join(channels)}\n\n"
            "Their details may be wrong, or a channel may be misconfigured on "
            "our side. Either way they have not been told, and only a person "
            "can find another way.",
            dedupe_key=f"unreachable:{reference or subject}",
            alert=alert, transport=transport,
        )

    return Delivery(attempted=channels, delivered=tuple(delivered))


async def _page_operator(
    text: str, *, dedupe_key: str, alert=None,
    transport: httpx.BaseTransport | None = None,
) -> None:
    """Best-effort, and wrapped rather than trusting notify_operator's own
    promise never to raise. This is the last thing on a path that has already
    succeeded at what mattered; an exception escaping here would report a
    completed refund as a failed request.

    `transport` is threaded in rather than left to default, and it is not
    cosmetic. MEASURED while writing this: without it the operator page reached
    api.telegram.org for real from the test suite -- 0.37s of DNS and a
    ProxyError per call -- because every OTHER outbound call here is injected
    and this one was not. A suite that touches the network is a suite that
    fails for reasons that have nothing to do with the code."""
    if alert is None:
        from app.alerts import notify_operator as alert  # noqa: N813
    try:
        await alert(text, dedupe_key=dedupe_key, transport=transport)
    except Exception:  # noqa: BLE001
        logger.warning("unreachable-customer alert failed", exc_info=True)

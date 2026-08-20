"""Sending an email, which this product has never been able to do.

WHAT THIS CHANGES. `payments.payer_email` has existed since migration 0026,
and that migration says in its own words: "This is a note-to-self for the
operator, not an authentication or delivery channel -- nothing is ever sent to
this address." That was true and it was a gap. A buyer who is not on Telegram
paid, went quiet, and had no way to be told anything: not that their transfer
was confirmed, not that their Fix Pack was delivered, not that they were
refunded. Their only channel was to email us first.

SMTP, NOT AN API. Resend, Postmark and SendGrid would each be a nicer client
and none of them is reliably reachable from where this runs or signable-up-for
by who runs it. SMTP is the one protocol every mail provider offers, including
the VPS host this already pays for, so the operator can point it at whatever
they can actually get an account with. The cost is that `smtplib` is blocking
and stdlib-only, so a send runs on a worker thread.

UNCONFIGURED IS A QUIET NO-OP, the same contract as app/alerts.py and every
other outward thing here: with SMTP_HOST unset, `send_email` returns False and
raises nothing. A deployment that has not set up mail must not fail a refund
because it could not announce one.

NEVER RAISES, for the same reason app.alerts.notify_operator does not. Every
caller is on a path where something has already happened -- money moved, a
pull request opened -- and an exception here would turn a completed action into
a failed request. The return value says whether it went out; it is never a
reason to unwind.

WHAT IT REFUSES TO SEND. A header value carrying CR or LF is an injection: the
address comes off a checkout form, and a `To:` with a newline in it can append
`Bcc:` recipients of the sender's choosing. 0026 deliberately did not validate
the address at INPUT time -- refusing a sale over an unusual TLD was not worth
it -- and that is a different question from what may be handed to an SMTP
server. Validation belongs here, at the boundary where it matters.

THE PASSWORD IS NEVER LOGGED, and neither is the body. A failed send logs the
exception type and the recipient's domain, which is enough to tell a wrong
password from a bad address from a network problem, and none of which is the
customer's message.
"""

from __future__ import annotations

import asyncio
import logging
import os
import smtplib
from dataclasses import dataclass, field
from email.message import EmailMessage
from typing import Callable

logger = logging.getLogger(__name__)

# Bounded well below any request timeout. A mail server that is not answering
# must not hold a worker thread for minutes on a path that has already
# succeeded at the thing the caller actually cared about.
_TIMEOUT_S = 20.0

# Implicit TLS from the first byte. Every other port is assumed to be plain
# SMTP upgraded with STARTTLS, which is what 587 and 25 do.
_IMPLICIT_TLS_PORT = 465


@dataclass(frozen=True)
class SmtpSettings:
    host: str
    port: int
    username: str
    # repr=False, and it is not decoration. A dataclass prints its fields, and
    # settings end up in a traceback or a debug line the moment anything goes
    # wrong at startup -- which is exactly when someone pastes the output into
    # a chat window.
    password: str = field(repr=False)
    sender: str

    @property
    def implicit_tls(self) -> bool:
        return self.port == _IMPLICIT_TLS_PORT


def settings_from_env() -> SmtpSettings | None:
    """The mail account, or None when this deployment has no mail.

    SMTP_HOST and SMTP_FROM are the two that must be present: without a server
    there is nowhere to send, and without a From address most providers reject
    the message anyway. Username and password default to empty because a relay
    on localhost, or one that authenticates by IP, needs neither -- and
    refusing to send in that case would be inventing a requirement.
    """
    host = (os.environ.get("SMTP_HOST") or "").strip()
    sender = (os.environ.get("SMTP_FROM") or "").strip()
    if not host or not sender:
        return None
    raw_port = (os.environ.get("SMTP_PORT") or "").strip()
    try:
        port = int(raw_port) if raw_port else 587
    except ValueError:
        # A typo in the port must not silently become a different port. 587 is
        # the submission default and the one an operator who set only HOST and
        # FROM meant; a non-numeric value is a mistake worth saying out loud.
        logger.warning("SMTP_PORT is not a number (%r); using 587", raw_port)
        port = 587
    return SmtpSettings(
        host=host,
        port=port,
        username=(os.environ.get("SMTP_USERNAME") or "").strip(),
        password=os.environ.get("SMTP_PASSWORD") or "",
        sender=sender,
    )


def is_sendable_address(address: str) -> bool:
    """Whether this string may be put in a `To:` header and handed to SMTP.

    Deliberately weak on what an address may LOOK like -- one `@`, something
    either side, no whitespace -- and absolute about what it may CONTAIN. The
    weakness is 0026's argument, unchanged: a real buyer with an unusual TLD
    must not lose their notification to our idea of a valid address. The
    absoluteness is the injection: a newline in a header value ends the header,
    and the next line is whatever the sender wrote.
    """
    if not address or any(c in address for c in "\r\n\t "):
        return False
    local, _, domain = address.partition("@")
    return bool(local) and bool(domain) and "@" not in domain


def _deliver(settings: SmtpSettings, message: EmailMessage) -> None:
    """The blocking half. Replaced wholesale in tests -- see `sender=`."""
    if settings.implicit_tls:
        client: smtplib.SMTP = smtplib.SMTP_SSL(
            settings.host, settings.port, timeout=_TIMEOUT_S)
    else:
        client = smtplib.SMTP(settings.host, settings.port, timeout=_TIMEOUT_S)
    try:
        if not settings.implicit_tls:
            # A server that cannot upgrade gets no credentials and no message:
            # the alternative is sending a customer's details, and possibly a
            # password, over a plaintext connection because a certificate was
            # missing.
            client.starttls()
        if settings.username:
            client.login(settings.username, settings.password)
        # The envelope is given explicitly, from the raw strings, rather than
        # letting send_message re-parse the headers. A non-ASCII local part is
        # RFC 2047 encoded in a header -- `=?utf-8?b?...?=@example.invalid` --
        # and that encoded form is not an address any server can route to.
        # Passing the real string means smtplib negotiates SMTPUTF8 when the
        # server offers it and raises SMTPNotSupportedError when it does not,
        # which send_email turns into a False rather than a message that
        # silently goes nowhere.
        client.send_message(
            message,
            from_addr=settings.sender,
            to_addrs=[message["To"]],
        )
    finally:
        try:
            client.quit()
        except Exception:  # noqa: BLE001
            # QUIT failing after the message was accepted is not a failed send,
            # and letting it raise here would report one.
            client.close()


def build_message(
    *, to: str, subject: str, body: str, sender: str,
) -> EmailMessage:
    """A plain-text UTF-8 message. Separate from the send so the shape can be
    asserted without a server, the way build_invoice_payload once was."""
    message = EmailMessage()
    message["From"] = sender
    message["To"] = to
    message["Subject"] = subject
    message.set_content(body)
    return message


async def send_email(
    *,
    to: str,
    subject: str,
    body: str,
    settings: SmtpSettings | None = None,
    sender: Callable[[SmtpSettings, EmailMessage], None] | None = None,
) -> bool:
    """Send one message. True only if it was actually handed to a server.

    False for every quiet outcome -- mail not configured, a recipient we will
    not put in a header, a send that failed -- and never an exception. See the
    module docstring for why a caller may not treat a False as a reason to
    unwind whatever it was announcing.

    `settings` and `sender` are injection points. Tests pass a `sender` and
    never open a socket.
    """
    resolved = settings if settings is not None else settings_from_env()
    if resolved is None:
        return False

    if not is_sendable_address(to):
        logger.warning("refusing to send to an unusable address")
        return False
    if any(c in subject for c in "\r\n"):
        logger.warning("refusing to send a subject containing a line break")
        return False

    message = build_message(
        to=to, subject=subject, body=body, sender=resolved.sender)
    deliver = sender if sender is not None else _deliver
    try:
        await asyncio.to_thread(deliver, resolved, message)
        return True
    except Exception as exc:  # noqa: BLE001
        # The domain, not the address: enough to tell a wrong password from a
        # bad host from a rejected recipient, without putting a customer's
        # email address in the journal on every failure.
        logger.warning(
            "email send failed (%s) to domain %s",
            type(exc).__name__, to.rpartition("@")[2] or "?",
        )
        return False

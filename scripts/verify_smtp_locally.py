"""Prove this deployment can actually send an email, before a customer needs it.

WHY A SCRIPT AND NOT A TEST. tests/test_notify_email.py proves the code is
right; it hands `send_email` a fake sender and never opens a socket, because a
suite that needs a mail server is a suite that gets skipped. What it cannot
prove is that THIS HOST, with THESE credentials, against THAT provider, gets a
message delivered. Only a real send does, and only the operator holds the
password.

This is the same shape the retired payment providers each had -- a
`verify_*_locally.py` the operator ran once with their own credentials to turn
"the code looks right" into "I have seen it work". Those scripts went with
their rails. This one exists because the channel it checks fails SILENTLY, and
is the one channel whose failure a customer feels.

WHAT SILENT MEANS HERE, precisely. app/notify/email.py returns False and raises
nothing on every unhappy path: no configuration, a bad password, a host that
does not resolve, a recipient the server refuses. That contract is right --
a refund must not fail because it could not be announced -- and it is exactly
why a misconfiguration can sit unnoticed for weeks. Nothing goes red. A
customer is simply never told their money came back, and the only trace is an
operator alert saying nobody could be reached.

    python3 scripts/verify_smtp_locally.py you@example.com

Reads the same SMTP_* variables the application reads, through the same
`settings_from_env`, and sends through the same `send_email`. Nothing here is
a reimplementation: if this script delivers, the product delivers, and if it
does not, the product would not have either.

THE PASSWORD IS NEVER PRINTED. Neither is the message body. The failure output
names the exception type and what to check, which is what tells a wrong
password from a wrong port from a blocked outbound 587.
"""

from __future__ import annotations

import asyncio
import os
import smtplib
import ssl
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.notify import email as mail  # noqa: E402

# What each failure most often means, in the order an operator should check.
# Deliberately specific: "check your settings" is what a person reads when they
# have already checked their settings.
_ADVICE: tuple[tuple[type[Exception], str], ...] = (
    (smtplib.SMTPAuthenticationError,
     "The server rejected the credentials. On a hosted mailbox the username "
     "is usually the FULL address (support@example.com), not the part before "
     "the @. If the provider has app passwords, an account password will be "
     "refused here."),
    (smtplib.SMTPSenderRefused,
     "The server refused the From address. It normally has to be a mailbox "
     "that account actually owns -- SMTP_FROM and SMTP_USERNAME usually match."),
    (smtplib.SMTPRecipientsRefused,
     "The server accepted us and refused the recipient. Try a different "
     "address before suspecting the configuration."),
    (smtplib.SMTPNotSupportedError,
     "The server does not support something the send needed -- most often "
     "SMTPUTF8, for a non-ASCII address. Try an ASCII recipient."),
    (ssl.SSLError,
     "TLS failed. Port 465 is TLS from the first byte; 587 and 25 start "
     "plain and upgrade with STARTTLS. Using the wrong one for the port "
     "fails exactly here."),
    (TimeoutError,
     "Nothing answered in 20 seconds. Outbound 587 and 465 are blocked by "
     "default at some hosts; check from the box with "
     "`nc -vz <host> <port>`."),
    (OSError,
     "The connection could not be made at all: the host did not resolve, or "
     "the port is closed or filtered from this machine."),
)


def _explain(exc: BaseException) -> str:
    for kind, advice in _ADVICE:
        if isinstance(exc, kind):
            return advice
    return ("Unrecognised failure. The exception type above is the thing to "
            "search for; the message may name the provider's own error code.")


def _fail(message: str) -> int:
    print(f"\nFAILED: {message}", file=sys.stderr)
    return 1


async def _run(recipient: str) -> int:
    settings = mail.settings_from_env()
    if settings is None:
        return _fail(
            "SMTP is not configured on this deployment.\n\n"
            "  SMTP_HOST and SMTP_FROM must BOTH be set. With either missing, "
            "app/notify/email.py is a deliberate no-op: it returns False and "
            "raises nothing, so a refund is still recorded and the customer is "
            "simply never told.\n\n"
            "  Reading /opt/shipit/.env? This script reads the ENVIRONMENT, "
            "not that file. Run it as:\n"
            "    set -a; . /opt/shipit/.env; set +a; "
            "python3 scripts/verify_smtp_locally.py <address>"
        )

    # Everything except the password, which is never printed and is repr=False
    # on the settings object for the same reason.
    print(f"host     : {settings.host}:{settings.port}"
          f" ({'implicit TLS' if settings.implicit_tls else 'STARTTLS'})")
    print(f"from     : {settings.sender}")
    print(f"username : {settings.username or '(none — unauthenticated relay)'}")
    print(f"password : {'set' if settings.password else 'NOT SET'}")
    print(f"to       : {recipient}")
    print()

    if not mail.is_sendable_address(recipient):
        return _fail(
            f"{recipient!r} is not an address this will put in a header. "
            "One @, something either side, no whitespace and no line break."
        )

    # The failure is caught HERE rather than read off send_email's False,
    # because False is all the product ever gets and it does not say why. A
    # script whose whole job is diagnosis has to see the exception.
    message = mail.build_message(
        to=recipient,
        subject="Drydock: SMTP verification",
        body=(
            "This is the verification message from "
            "scripts/verify_smtp_locally.py.\n\n"
            "If you are reading it, this deployment can tell a customer that "
            "their transfer was confirmed and that their refund was sent.\n"
        ),
        sender=settings.sender,
    )
    try:
        await asyncio.to_thread(mail._deliver, settings, message)
    except Exception as exc:  # noqa: BLE001
        print(f"{type(exc).__name__}: {str(exc)[:300]}", file=sys.stderr)
        return _fail(_explain(exc))

    print("Sent. Check the inbox, and check the spam folder before "
          "believing it worked.")
    print()
    print("A message that lands in spam is a message the customer does not "
          "read, which for a refund notice is the same as not sending it. If "
          "it is filtered, the domain needs SPF and DKIM at the provider "
          "before this channel is worth relying on.")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        print(f"usage: {argv[0]} <recipient-address>", file=sys.stderr)
        return 2
    # Belt and braces: this script exists to be run by hand on a production
    # host, and a stray argument must not become a message to a customer.
    if os.environ.get("SHIPIT_SMTP_VERIFY_CONFIRM") == "no":
        return _fail("refused by SHIPIT_SMTP_VERIFY_CONFIRM=no")
    return asyncio.run(_run(argv[1].strip()))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

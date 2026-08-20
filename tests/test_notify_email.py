"""The first thing in this codebase that can send an email.

Migration 0026 said of `payments.payer_email`: "nothing is ever sent to this
address." These tests are what make that sentence false on purpose, and what
keep the ways it could go wrong from coming back.

NO SOCKET IS OPENED. `send_email` takes a `sender=` callable and the tests pass
one, the same seam `transport=` gives the Bot API client. A test suite that
needs a mail server is a test suite that gets skipped.
"""

from __future__ import annotations

from email.message import EmailMessage

import pytest

from app.notify import email as mail

SETTINGS = mail.SmtpSettings(
    host="smtp.example.invalid", port=587, username="u", password="p",
    sender="Drydock <noreply@drydock.co>",
)


class Recorder:
    """Stands in for the blocking SMTP conversation."""

    def __init__(self, *, fail: Exception | None = None) -> None:
        self.sent: list[EmailMessage] = []
        self.fail = fail

    def __call__(self, settings: mail.SmtpSettings, message: EmailMessage) -> None:
        if self.fail is not None:
            raise self.fail
        self.sent.append(message)


# --- it sends ---------------------------------------------------------------

@pytest.mark.anyio
async def test_a_message_reaches_the_server() -> None:
    recorder = Recorder()

    sent = await mail.send_email(
        to="buyer@example.invalid", subject="Your Fix Pack is ready",
        body="The pull request is open.", settings=SETTINGS, sender=recorder,
    )

    assert sent is True
    assert len(recorder.sent) == 1
    message = recorder.sent[0]
    assert message["To"] == "buyer@example.invalid"
    assert message["From"] == SETTINGS.sender
    assert message["Subject"] == "Your Fix Pack is ready"
    assert "The pull request is open." in message.get_content()


@pytest.mark.anyio
async def test_a_non_ascii_body_survives() -> None:
    """The buyers this was built for read Russian. A message that arrives as
    mojibake is worse than one that does not arrive: it looks like we sent it
    and did not care."""
    recorder = Recorder()

    await mail.send_email(
        to="buyer@example.invalid", subject="Возврат средств",
        body="Мы вернули 10.79 USD.", settings=SETTINGS, sender=recorder,
    )

    message = recorder.sent[0]
    assert message["Subject"] == "Возврат средств"
    assert "10.79" in message.get_content()
    assert "Мы вернули" in message.get_content()


# --- it refuses ------------------------------------------------------------

@pytest.mark.parametrize("address", [
    "buyer@example.invalid\nBcc: attacker@evil.invalid",
    "buyer@example.invalid\r\nBcc: attacker@evil.invalid",
    "buyer with space@example.invalid",
    "buyer@@example.invalid",
    "no-at-sign",
    "@example.invalid",
    "buyer@",
    "",
])
@pytest.mark.anyio
async def test_a_header_injection_is_not_sent(address: str) -> None:
    """The address comes off a checkout form. A newline in it ends the `To:`
    header, and the next line is whatever the payer typed -- a `Bcc:` of their
    choosing, sent from our domain and our reputation.

    Refused rather than sanitised: stripping the newline would deliver a
    message to an address nobody meant, and this is a notification, not
    something whose absence hurts anybody but the person who forged it."""
    recorder = Recorder()

    sent = await mail.send_email(
        to=address, subject="hello", body="hi",
        settings=SETTINGS, sender=recorder,
    )

    assert sent is False
    assert recorder.sent == []


@pytest.mark.anyio
async def test_a_subject_with_a_line_break_is_not_sent() -> None:
    """The other header a caller composes. A refund reason typed by an
    operator, or an audit title taken from a repository, both end up here."""
    recorder = Recorder()

    sent = await mail.send_email(
        to="buyer@example.invalid", subject="Refund\nBcc: attacker@evil.invalid",
        body="hi", settings=SETTINGS, sender=recorder,
    )

    assert sent is False
    assert recorder.sent == []


@pytest.mark.anyio
async def test_an_ordinary_unusual_address_is_still_sent() -> None:
    """The boundary, and migration 0026's argument unchanged: the check is
    absolute about what an address may CONTAIN and deliberately weak about what
    it may look like. A real buyer with a long TLD, a plus tag or a subdomain
    must not lose their notification to our idea of a valid address."""
    recorder = Recorder()

    for address in ("buyer+fixpack@mail.example.technology",
                    "b@x.y",
                    "UPPER.Case@Example.Invalid"):
        assert await mail.send_email(
            to=address, subject="hi", body="hi",
            settings=SETTINGS, sender=recorder,
        ) is True

    assert len(recorder.sent) == 3


def test_a_non_ascii_address_is_not_quietly_mangled() -> None:
    """MEASURED while writing these tests, and it changed the code.

    `почта@example.invalid` in a `To:` header serialises to
    `=?utf-8?b?0L/QvtGH0YLQsA==?=@example.invalid` -- an RFC 2047 encoded-word
    in the local part, which is not an address any server can route to. Letting
    smtplib re-parse the header for the envelope would have handed that string
    to RCPT TO, and the message would have gone nowhere while `send_email`
    returned True.

    So `_deliver` passes the envelope explicitly, from the raw string. smtplib
    then negotiates SMTPUTF8 when the server offers it and raises
    SMTPNotSupportedError when it does not -- which becomes a False. Not
    sending is a fair outcome; claiming to have sent is not."""
    message = mail.build_message(
        to="почта@example.invalid", subject="hi", body="hi",
        sender="noreply@drydock.co",
    )

    # The header is encoded, and this is the trap.
    assert "=?utf-8?" in message.as_string()
    # The value read back off the message is the real address, which is what
    # _deliver hands to to_addrs.
    assert message["To"] == "почта@example.invalid"


@pytest.mark.anyio
async def test_a_server_without_smtputf8_reports_a_failure_not_a_success() -> None:
    """The other half of the paragraph above. A message that cannot be
    delivered must not be reported as delivered -- the caller writes that into
    a delivery record, and a lie there is worse than a gap."""
    import smtplib as smtplib_module

    recorder = Recorder(
        fail=smtplib_module.SMTPNotSupportedError("SMTPUTF8 not supported"))

    assert await mail.send_email(
        to="почта@example.invalid", subject="hi", body="hi",
        settings=SETTINGS, sender=recorder,
    ) is False


# --- it never raises -------------------------------------------------------

@pytest.mark.anyio
async def test_a_failed_send_is_false_not_an_exception() -> None:
    """Every caller is on a path where something already happened: money moved,
    a pull request opened. An exception here would turn a completed action into
    a failed request, and the customer would be no better informed."""
    recorder = Recorder(fail=OSError("connection refused"))

    assert await mail.send_email(
        to="buyer@example.invalid", subject="hi", body="hi",
        settings=SETTINGS, sender=recorder,
    ) is False


@pytest.mark.anyio
async def test_a_failed_send_does_not_log_the_address_or_the_body(caplog) -> None:
    """A failing mail server logs on every attempt. What ends up in the journal
    should be enough to tell a wrong password from a bad host from a rejected
    recipient -- and not a customer's email address, and not the message."""
    recorder = Recorder(fail=OSError("connection refused"))

    with caplog.at_level("WARNING"):
        await mail.send_email(
            to="private.person@example.invalid", subject="Your refund",
            body="We returned 10.79 USD to your card.",
            settings=SETTINGS, sender=recorder,
        )

    logged = caplog.text
    assert "private.person" not in logged
    assert "10.79" not in logged
    # But it still says enough to act on.
    assert "example.invalid" in logged
    assert "OSError" in logged


@pytest.mark.anyio
async def test_no_mail_configured_is_a_quiet_false(monkeypatch) -> None:
    """A deployment with no mail account must not fail a refund because it
    could not announce one. Same contract as app/alerts.py."""
    monkeypatch.delenv("SMTP_HOST", raising=False)
    monkeypatch.delenv("SMTP_FROM", raising=False)

    assert await mail.send_email(
        to="buyer@example.invalid", subject="hi", body="hi") is False


# --- configuration ---------------------------------------------------------

def test_settings_need_a_server_and_a_from_address(monkeypatch) -> None:
    monkeypatch.setenv("SMTP_HOST", "smtp.example.invalid")
    monkeypatch.delenv("SMTP_FROM", raising=False)
    assert mail.settings_from_env() is None

    monkeypatch.delenv("SMTP_HOST", raising=False)
    monkeypatch.setenv("SMTP_FROM", "noreply@drydock.co")
    assert mail.settings_from_env() is None


def test_credentials_are_optional(monkeypatch) -> None:
    """A relay on localhost, or one that authenticates by IP, needs neither.
    Refusing to send without a password would invent a requirement."""
    monkeypatch.setenv("SMTP_HOST", "localhost")
    monkeypatch.setenv("SMTP_FROM", "noreply@drydock.co")
    monkeypatch.delenv("SMTP_USERNAME", raising=False)
    monkeypatch.delenv("SMTP_PASSWORD", raising=False)

    settings = mail.settings_from_env()
    assert settings is not None
    assert settings.username == "" and settings.password == ""


def test_the_port_defaults_to_submission(monkeypatch) -> None:
    monkeypatch.setenv("SMTP_HOST", "smtp.example.invalid")
    monkeypatch.setenv("SMTP_FROM", "noreply@drydock.co")
    monkeypatch.delenv("SMTP_PORT", raising=False)

    settings = mail.settings_from_env()
    assert settings.port == 587
    assert settings.implicit_tls is False


def test_a_typo_in_the_port_does_not_become_a_different_port(
    monkeypatch, caplog,
) -> None:
    """"587 " with a stray character is a mistake, and silently connecting to
    some other port would be a confusing way to fail."""
    monkeypatch.setenv("SMTP_HOST", "smtp.example.invalid")
    monkeypatch.setenv("SMTP_FROM", "noreply@drydock.co")
    monkeypatch.setenv("SMTP_PORT", "587a")

    with caplog.at_level("WARNING"):
        settings = mail.settings_from_env()

    assert settings.port == 587
    assert "SMTP_PORT" in caplog.text


def test_465_means_implicit_tls(monkeypatch) -> None:
    """The one port where the connection is encrypted from the first byte.
    Every other port is upgraded with STARTTLS, and _deliver refuses to
    continue if that upgrade fails."""
    monkeypatch.setenv("SMTP_HOST", "smtp.example.invalid")
    monkeypatch.setenv("SMTP_FROM", "noreply@drydock.co")
    monkeypatch.setenv("SMTP_PORT", "465")

    assert mail.settings_from_env().implicit_tls is True


def test_the_password_is_not_in_the_settings_repr() -> None:
    """A dataclass prints its fields, and settings end up in a traceback or a
    debug line the moment anything goes wrong at startup -- which is exactly
    when someone pastes the output into a chat window."""
    secret = "hunter2-not-a-real-password"
    settings = mail.SmtpSettings(
        host="smtp.example.invalid", port=587, username="u",
        password=secret, sender="noreply@drydock.co",
    )

    assert secret not in repr(settings)
    # The rest is still there, or the repr would be useless for debugging.
    assert "smtp.example.invalid" in repr(settings)
    # And the value itself is not lost, only hidden from printing.
    assert settings.password == secret

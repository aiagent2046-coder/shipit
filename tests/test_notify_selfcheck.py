"""The check that would have caught a day of silently undelivered email.

On 2026-08-25 every customer email failed with SMTPAuthenticationError and
nothing went red. `send_email` returns False and raises nothing by design --
a refund must not fail because it could not be announced -- so the outage had
no symptom except a line in the journal that nobody was reading.

The properties below are the ones that decide whether this is worth having:
an unconfigured channel must stay quiet (an alert that cries wolf gets muted,
taking the real ones with it), a broken one must be both logged and announced,
and the exit code must fail so the unit is left in `failed` for the case where
the channel that carries alerts is the broken one.

Nothing here opens a socket. The SMTP probe and the Telegram call are both
injected.
"""

from __future__ import annotations

import logging
import smtplib

import pytest

from app.notify import selfcheck


@pytest.fixture(autouse=True)
def _no_channels(monkeypatch):
    """Start from a deployment with nothing configured, so each test says out
    loud which channels it is about."""
    for name in ("SMTP_HOST", "SMTP_FROM", "SMTP_USERNAME", "SMTP_PASSWORD",
                 "SMTP_PORT", "TELEGRAM_BOT_TOKEN"):
        monkeypatch.delenv(name, raising=False)


def _mail(monkeypatch):
    monkeypatch.setenv("SMTP_HOST", "smtp.example.invalid")
    monkeypatch.setenv("SMTP_FROM", "support@example.invalid")
    monkeypatch.setenv("SMTP_USERNAME", "support@example.invalid")
    monkeypatch.setenv("SMTP_PASSWORD", "hunter2")  # scan-allow: fixture


def _bot(monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123:fake")  # scan-allow: fixture


def _refuses(exc):
    def verify(settings):
        raise exc
    return verify


def _accepts(record=None):
    def verify(settings):
        if record is not None:
            record.append(settings)
    return verify


async def _bot_ok(method, body, *, token, transport=None, timeout=None):
    return {"ok": True, "result": {"username": "drydock_bot"}}


async def _bot_broken(method, body, *, token, transport=None, timeout=None):
    raise RuntimeError("getMe failed: 401 unauthorized")


async def _no_sleep(seconds: float) -> None:
    """The retry's backoff, made free. A suite that waits eleven seconds to
    prove a retry happened is a suite people stop running."""


def _collect(into):
    async def alert(text, *, dedupe_key=None, transport=None):
        into.append((text, dedupe_key))
        return True
    return alert


# --------------------------------------------------- an unconfigured channel

@pytest.mark.anyio
async def test_a_deployment_with_no_mail_is_not_broken(anyio_backend) -> None:
    """Having no SMTP_HOST is a decision, not a fault. Paging somebody hourly
    about a decision they made is how an alert gets muted."""
    result = await selfcheck.check_email(sleep=_no_sleep, verify=_refuses(AssertionError()))

    assert result.configured is False
    assert result.failed is False


@pytest.mark.anyio
async def test_an_unconfigured_channel_is_never_even_probed(
    anyio_backend, monkeypatch,
) -> None:
    probed: list = []
    await selfcheck.check_email(sleep=_no_sleep, verify=_accepts(probed))
    assert probed == []


@pytest.mark.anyio
async def test_nothing_configured_pages_nobody(anyio_backend) -> None:
    paged: list = []
    results = await selfcheck.run(alert=_collect(paged), verify=_accepts(),
                                  call=_bot_ok, sleep=_no_sleep)

    assert paged == []
    assert [r.failed for r in results] == [False, False]


# ------------------------------------------------------- a working channel

@pytest.mark.anyio
async def test_a_working_mailbox_is_quiet(anyio_backend, monkeypatch) -> None:
    _mail(monkeypatch)
    paged: list = []

    results = await selfcheck.run(alert=_collect(paged), verify=_accepts(),
                                  call=_bot_ok, sleep=_no_sleep)

    assert paged == []
    assert results[0].configured and results[0].ok


@pytest.mark.anyio
async def test_the_probe_is_handed_the_settings_the_product_would_use(
    anyio_backend, monkeypatch,
) -> None:
    """A probe that connects on its own terms proves its own terms work."""
    _mail(monkeypatch)
    monkeypatch.setenv("SMTP_PORT", "465")
    seen: list = []

    await selfcheck.check_email(sleep=_no_sleep, verify=_accepts(seen))

    assert seen[0].host == "smtp.example.invalid"
    assert seen[0].port == 465
    assert seen[0].implicit_tls is True
    assert seen[0].username == "support@example.invalid"


# --------------------------------------------------------- a broken channel

@pytest.mark.anyio
async def test_a_rejected_password_is_reported_with_what_the_server_said(
    anyio_backend, monkeypatch,
) -> None:
    """`(535, b'Incorrect authentication data')` is the difference between
    "mail is broken" and "the password is wrong", and those are different
    days. The server's refusal quotes its own answer, never our request."""
    _mail(monkeypatch)
    refusal = smtplib.SMTPAuthenticationError(
        535, b"Incorrect authentication data")

    result = await selfcheck.check_email(sleep=_no_sleep, verify=_refuses(refusal))

    assert result.failed
    assert "SMTPAuthenticationError" in result.detail
    assert "Incorrect authentication data" in result.detail


@pytest.mark.anyio
async def test_a_broken_mailbox_pages_the_operator(
    anyio_backend, monkeypatch,
) -> None:
    _mail(monkeypatch)
    paged: list = []

    await selfcheck.run(
        alert=_collect(paged),
        verify=_refuses(smtplib.SMTPAuthenticationError(535, b"nope")),
        call=_bot_ok, sleep=_no_sleep,
    )

    assert len(paged) == 1
    text, dedupe_key = paged[0]
    assert "email" in text
    assert "SMTPAuthenticationError" in text
    # The consequence, not just the symptom: someone reading this at speed
    # needs to know no customer is being told anything.
    assert "No customer is being told" in text
    assert dedupe_key == "channel-down:email"


@pytest.mark.anyio
async def test_the_alert_is_deduplicated_on_the_channel_not_the_text(
    anyio_backend, monkeypatch,
) -> None:
    """An outage lasting a week must be one message per throttle window, not
    one per hour -- and a SECOND channel failing must still be its own."""
    _mail(monkeypatch)
    _bot(monkeypatch)
    paged: list = []

    await selfcheck.run(
        alert=_collect(paged),
        verify=_refuses(smtplib.SMTPAuthenticationError(535, b"nope")),
        call=_bot_broken, sleep=_no_sleep,
    )

    assert paged[0][1] == "channel-down:email,telegram"


@pytest.mark.anyio
async def test_a_broken_channel_is_logged_before_it_is_announced(
    anyio_backend, monkeypatch, caplog,
) -> None:
    """The alert travels over Telegram, so a Telegram outage cannot announce
    itself. The journal is what is left, and it is written unconditionally --
    before the alert, not after it succeeds."""
    _bot(monkeypatch)

    async def alert_that_never_arrives(text, *, dedupe_key=None, transport=None):
        raise RuntimeError("telegram is the thing that is down")

    with caplog.at_level(logging.ERROR):
        results = await selfcheck.run(
            alert=alert_that_never_arrives, verify=_accepts(),
            call=_bot_broken, sleep=_no_sleep,
        )

    assert any("telegram" in r.getMessage() and r.levelno == logging.ERROR
               for r in caplog.records)
    assert [r.failed for r in results] == [False, True]


# ------------------------------------------------------------- one blip

def _fails_then(times: int, exc, record=None):
    """Raise `exc` for the first `times` calls, succeed afterwards."""
    state = {"calls": 0}

    def verify(settings):
        state["calls"] += 1
        if record is not None:
            record.append(state["calls"])
        if state["calls"] <= times:
            raise exc

    return verify


@pytest.mark.anyio
async def test_a_single_timeout_does_not_condemn_a_channel(
    anyio_backend, monkeypatch,
) -> None:
    """WHAT THIS COST IN PRODUCTION. Two hours after the check first ran, the
    Telegram probe timed out once -- four minutes after an identical probe
    answered 200, with the link healthy either side of it. From a host in
    Russia, reaching api.telegram.org is routinely uneven, and a check that
    condemns a channel on one timeout is the alert that cries wolf: exactly
    what this file avoids for an unconfigured channel and did not avoid here.
    """
    _mail(monkeypatch)
    paged: list = []

    result = await selfcheck.check_email(
        verify=_fails_then(1, TimeoutError("connect timed out")),
        sleep=_no_sleep)

    assert result.ok, "one blip was treated as an outage"
    assert result.failed is False
    assert paged == []


@pytest.mark.anyio
async def test_a_channel_that_never_answers_is_still_reported(
    anyio_backend, monkeypatch,
) -> None:
    """The retry must not turn the check into one that never fires."""
    _mail(monkeypatch)
    attempts: list = []

    result = await selfcheck.check_email(
        verify=_fails_then(99, TimeoutError("connect timed out"), attempts),
        sleep=_no_sleep)

    assert result.failed
    assert "TimeoutError" in result.detail
    assert len(attempts) == selfcheck.ATTEMPTS


@pytest.mark.anyio
async def test_a_refused_password_is_never_retried(
    anyio_backend, monkeypatch,
) -> None:
    """Not politeness. It will refuse again -- nothing about a password
    changes in three seconds -- and providers count failed logins towards
    locking the account, so retrying would make the check cause the outage it
    is watching for."""
    _mail(monkeypatch)
    attempts: list = []

    result = await selfcheck.check_email(
        verify=_fails_then(
            99, smtplib.SMTPAuthenticationError(535, b"nope"), attempts),
        sleep=_no_sleep)

    assert result.failed
    assert len(attempts) == 1, f"a rejected password was tried {len(attempts)} times"


@pytest.mark.anyio
async def test_a_recovered_probe_still_leaves_a_line_in_the_log(
    anyio_backend, monkeypatch, caplog,
) -> None:
    """A link that needs a retry every hour is on its way to needing more than
    three, and the only place that is visible is the journal -- the alert
    stays silent, correctly, because the channel works."""
    _mail(monkeypatch)

    with caplog.at_level(logging.WARNING):
        result = await selfcheck.check_email(
            verify=_fails_then(1, TimeoutError("connect timed out")),
            sleep=_no_sleep)

    assert result.ok
    assert any("retrying" in r.getMessage() for r in caplog.records)


@pytest.mark.anyio
async def test_the_telegram_probe_asks_for_a_bounded_timeout(
    anyio_backend, monkeypatch,
) -> None:
    """Three attempts at the transport's default thirty seconds, plus the
    backoff, outlives the unit's own TimeoutStartSec -- systemd would kill the
    check mid-probe and report a failure it did not measure."""
    _bot(monkeypatch)
    seen: list = []

    async def call(method, body, *, token, transport=None, timeout=None):
        seen.append(timeout)
        return {"ok": True, "result": {}}

    await selfcheck.check_telegram(call=call, sleep=_no_sleep)

    assert seen == [10]


@pytest.mark.anyio
async def test_the_backoff_grows_between_attempts(
    anyio_backend, monkeypatch,
) -> None:
    """Three attempts three seconds apart is one blip sampled three times; the
    gap has to widen enough to outlast a short outage."""
    _mail(monkeypatch)
    waited: list = []

    async def sleep(seconds):
        waited.append(seconds)

    await selfcheck.check_email(
        verify=_fails_then(99, TimeoutError("nope")), sleep=sleep)

    # Not `== BACKOFF_S`: a test that reads the constant it is checking cannot
    # fail when the constant changes. These are the properties that matter.
    assert len(waited) == selfcheck.ATTEMPTS - 1, (
        "one wait per gap, and none after the last attempt -- sleeping there "
        "spends the unit's time budget on a verdict already reached")
    assert all(seconds > 0 for seconds in waited)
    assert waited == sorted(waited), "the backoff must not shrink"


# ------------------------------------------------------------- the exit code

def test_the_exit_code_fails_so_systemd_holds_the_unit_in_failed(
    monkeypatch, capsys,
) -> None:
    """The second line of defence, and the reason this is a unit rather than a
    cron line: shipit-notify-check.service carries OnFailure=, and a failed
    unit is still visible in `systemctl status` long after a chat message has
    scrolled away -- or when it never arrived at all."""
    _mail(monkeypatch)

    async def run_reporting_a_dead_mailbox(**kwargs):
        return [selfcheck.Result("email", configured=True, ok=False,
                                 detail="SMTPAuthenticationError: 535"),
                selfcheck.Result("telegram", configured=False, ok=True)]

    monkeypatch.setattr(selfcheck, "run", run_reporting_a_dead_mailbox)

    assert selfcheck.main([]) == 1
    printed = capsys.readouterr().out
    assert "FAILED" in printed
    assert "not configured" in printed


def test_the_exit_code_is_zero_when_everything_works(monkeypatch) -> None:
    async def run_reporting_health(**kwargs):
        return [selfcheck.Result("email", configured=True, ok=True),
                selfcheck.Result("telegram", configured=True, ok=True)]

    monkeypatch.setattr(selfcheck, "run", run_reporting_health)

    assert selfcheck.main([]) == 0


def test_an_entirely_unconfigured_deployment_still_exits_zero(
    monkeypatch,
) -> None:
    """A developer's laptop has no channels and is not broken."""
    async def run_reporting_nothing(**kwargs):
        return [selfcheck.Result("email", configured=False, ok=True),
                selfcheck.Result("telegram", configured=False, ok=True)]

    monkeypatch.setattr(selfcheck, "run", run_reporting_nothing)

    assert selfcheck.main([]) == 0


# --------------------------------------------------------------- no sending

def test_the_probe_cannot_send_a_message() -> None:
    """A probe that delivered mail on a timer is a probe someone switches off.

    Read off the source: _verify's whole body is a connect and a close, and
    the names that put a message on the wire are not in it.
    """
    import inspect

    from app.notify import email as mail

    body = inspect.getsource(mail._verify)
    assert "send_message" not in body
    assert "sendmail" not in body
    assert "build_message" not in body

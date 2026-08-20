"""Whether a customer was actually told, and what happens when they were not.

THE FAILURE THIS EXISTS FOR is not a crash. It is silence: a refund notice sent
to an address that bounces, or an X handle that does not accept DMs from
strangers, looks from our side exactly like one that arrived. The customer's
next move is a chargeback or an accusation of fraud, and the first anyone here
hears of it is that.

So most of what is asserted below is about the UNHAPPY paths -- that a failure
is recorded as a failure, that a customer with no channel at all is a separate
and louder problem than a customer whose channels failed, and that neither can
take down the thing being announced.
"""

from __future__ import annotations

import httpx
import pytest

from app.notify import router
from app.notify.router import EMAIL, TELEGRAM, X, Contact, notify_customer


class Alerts:
    def __init__(self) -> None:
        self.pages: list[tuple[str, str]] = []

    async def __call__(self, text: str, *, dedupe_key: str, **kwargs) -> bool:
        self.pages.append((text, dedupe_key))
        return True


async def _exploding(text, **kwargs):
    raise RuntimeError("alert channel down")


class Mail:
    def __init__(self, *, fail: bool = False) -> None:
        self.sent: list = []
        self.fail = fail

    def __call__(self, settings, message) -> None:
        if self.fail:
            raise OSError("connection refused")
        self.sent.append(message)


def _http(handler) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


def _telegram_ok(calls: list):
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(200, json={"ok": True, "result": {"message_id": 1}})
    return _http(handler)


def _everything_refuses(calls: list):
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(403, json={"ok": False, "title": "Forbidden"})
    return _http(handler)


@pytest.fixture(autouse=True)
def _mail_configured(monkeypatch):
    """A mail account, so the email branch is exercised rather than skipped as
    unconfigured. Nothing here opens a socket -- the sender is injected."""
    monkeypatch.setenv("SMTP_HOST", "smtp.example.invalid")
    monkeypatch.setenv("SMTP_FROM", "noreply@drydock.co")


# --- which channels a customer has -----------------------------------------

def test_channels_are_the_ones_actually_filled_in() -> None:
    assert Contact().channels() == ()
    assert Contact(email="b@example.invalid").channels() == (EMAIL,)
    assert Contact(telegram_chat_id="555").channels() == (TELEGRAM,)
    assert Contact(x_handle="@drydock").channels() == (X,)
    assert Contact(
        email="b@example.invalid", telegram_chat_id="555", x_handle="drydock",
    ).channels() == (EMAIL, TELEGRAM, X)


def test_blank_is_not_a_channel() -> None:
    """A checkout form submits empty strings, not nulls, and a database column
    can hold either. Whitespace counts as absent: trying to email "  " is a
    guaranteed failure that would then page the operator about a customer who
    simply did not give an address."""
    assert Contact(email="   ", telegram_chat_id="", x_handle="  ").channels() == ()


def test_something_that_is_not_a_handle_is_not_an_x_channel() -> None:
    """The field is free text on a form. A URL or an email address in it means
    the customer misunderstood, not that they have an X account -- and counting
    it as a channel would turn one confused entry into a guaranteed page."""
    for value in ("https://x.com/drydock", "buyer@example.invalid",
                  "way too long to be a handle", "@"):
        assert Contact(x_handle=value).channels() == ()


def test_a_payment_row_missing_the_column_is_read_as_no_channel() -> None:
    """payer_x arrives in a later migration than the rows already in the table,
    and a fake repository in another test file will not carry it either. A
    missing key means "we do not have that channel"."""
    contact = Contact.from_payment({"payer_email": "b@example.invalid"})
    assert contact.channels() == (EMAIL,)


# --- it sends on every channel, not the first that works --------------------

@pytest.mark.anyio
async def test_a_customer_who_gave_two_channels_hears_on_both(monkeypatch) -> None:
    """They wrote down both on purpose. For a refund, hearing twice is not
    spam; hearing zero times is what ends in a dispute."""
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "t")
    sender, calls, alerts = Mail(), [], Alerts()

    result = await notify_customer(
        contact=Contact(email="b@example.invalid", telegram_chat_id="555"),
        subject="Refund issued", body="We returned 10.79 USD.",
        reference="DRY-ABC123",
        email_sender=sender, transport=_telegram_ok(calls), alert=alerts,
    )

    assert result.attempted == (EMAIL, TELEGRAM)
    assert result.delivered == (EMAIL, TELEGRAM)
    assert result.reached is True
    assert len(sender.sent) == 1
    assert any(path.endswith("/sendMessage") for path in calls)
    assert alerts.pages == []


@pytest.mark.anyio
async def test_the_subject_is_not_repeated_into_the_direct_messages(
    monkeypatch,
) -> None:
    """A DM that opens with its own subject line reads like a form letter, and
    both Telegram and X show the first line as the preview anyway."""
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "t")
    bodies: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        import json
        bodies.append(json.loads(request.content)["text"])
        return httpx.Response(200, json={"ok": True, "result": {"message_id": 1}})

    await notify_customer(
        contact=Contact(telegram_chat_id="555"),
        subject="Refund issued", body="We returned 10.79 USD.",
        transport=_http(handler), alert=Alerts(),
    )

    assert bodies == ["We returned 10.79 USD."]


# --- a partial failure is not a success ------------------------------------

@pytest.mark.anyio
async def test_one_channel_landing_is_enough_and_the_other_is_recorded(
    monkeypatch,
) -> None:
    """The customer was reached, so no page. But `delivered` says which one
    worked, because "email is bouncing" is worth knowing before the next
    customer has only email."""
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "t")
    alerts = Alerts()

    result = await notify_customer(
        contact=Contact(email="b@example.invalid", telegram_chat_id="555"),
        subject="Refund issued", body="We returned 10.79 USD.",
        email_sender=Mail(fail=True), transport=_telegram_ok([]), alert=alerts,
    )

    assert result.attempted == (EMAIL, TELEGRAM)
    assert result.delivered == (TELEGRAM,)
    assert result.reached is True
    assert alerts.pages == []


@pytest.mark.anyio
async def test_a_telegram_refusal_does_not_escape(monkeypatch) -> None:
    """telegram.send_message raises on ok=false. That contract is right where
    it came from -- an unanswered pre-checkout cancels a charge -- and wrong
    here, where the thing being announced is already done."""
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "t")
    alerts = Alerts()

    result = await notify_customer(
        contact=Contact(telegram_chat_id="555"),
        subject="Refund issued", body="body",
        transport=_everything_refuses([]), alert=alerts,
    )

    assert result.delivered == ()
    assert len(alerts.pages) == 1


# --- nobody was reached ----------------------------------------------------

@pytest.mark.anyio
async def test_every_channel_failing_pages_the_operator(monkeypatch) -> None:
    """Their details may be wrong, or a channel may be broken on our side.
    Either way the customer has not been told, and only a person can find
    another way."""
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "t")
    monkeypatch.setenv("X_DM_TOKEN", "x")
    alerts = Alerts()

    result = await notify_customer(
        contact=Contact(email="b@example.invalid", telegram_chat_id="555",
                        x_handle="@buyer"),
        subject="Refund issued", body="body", reference="DRY-ABC123",
        email_sender=Mail(fail=True), transport=_everything_refuses([]),
        alert=alerts,
    )

    assert result.attempted == (EMAIL, TELEGRAM, X)
    assert result.delivered == ()
    assert result.reached is False

    assert len(alerts.pages) == 1
    text, dedupe = alerts.pages[0]
    assert "Could not reach a customer" in text
    # The page has to name something the operator can look up, and list what
    # was tried, or it is just a notification that something is wrong.
    assert "DRY-ABC123" in text
    assert "email, telegram, x" in text
    assert dedupe == "unreachable:DRY-ABC123"


@pytest.mark.anyio
async def test_no_channel_at_all_is_its_own_alarm() -> None:
    """NOT the same problem as a delivery failure, and the distinction is why
    Delivery keeps `attempted` and `delivered` apart. This is a record that we
    took money from somebody we have no way to contact, and it should be
    visible at the moment it matters rather than found out later."""
    alerts = Alerts()

    result = await notify_customer(
        contact=Contact(), subject="Refund issued", body="body",
        reference="DRY-NOBODY", alert=alerts,
    )

    assert result.attempted == ()
    assert result.delivered == ()
    assert len(alerts.pages) == 1
    text, _ = alerts.pages[0]
    assert "no contact channel at all" in text
    assert "DRY-NOBODY" in text


@pytest.mark.anyio
async def test_a_broken_alert_channel_cannot_take_the_notification_down(
    monkeypatch,
) -> None:
    """The page is the LAST thing on a path that already succeeded at what
    mattered. An exception escaping here would report a completed refund as a
    failed request."""
    result = await notify_customer(
        contact=Contact(), subject="Refund issued", body="body",
        alert=_exploding,
    )

    assert result.reached is False


@pytest.mark.anyio
async def test_the_operator_page_goes_out_on_the_injected_transport(
    monkeypatch,
) -> None:
    """MEASURED, and it is why _page_operator takes a transport at all.

    Without one the page reached api.telegram.org for real from the test
    suite -- 0.37s of DNS and a ProxyError on every unreachable-customer test
    -- because every other outbound call here is injected and this one was
    not. Asserted on the REQUEST rather than the timing: a suite that is merely
    fast today can start touching the network tomorrow without anything
    failing."""
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "t")
    monkeypatch.setenv("TELEGRAM_ADMIN_CHAT_ID", "9")
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return httpx.Response(200, json={"ok": True, "result": {"message_id": 1}})

    # No `alert=`: the real app.alerts.notify_operator runs, and the only thing
    # standing between it and the network is the transport being threaded.
    result = await notify_customer(
        contact=Contact(email="b@example.invalid"),
        subject="Refund issued", body="body", reference="DRY-XYZ",
        email_sender=Mail(fail=True), transport=_http(handler),
    )

    assert result.reached is False
    assert seen == ["/bott/sendMessage"]


# --- the module boundary ---------------------------------------------------

def test_the_router_still_does_not_import_billing() -> None:
    """Same rule as the transports it drives, and worth restating here because
    this is the module most tempted to break it: it takes a `payments` row as
    input. It takes the ROW, not the provider."""
    import ast
    import pathlib

    source = pathlib.Path(router.__file__).read_text()
    reached = {
        node.module for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.ImportFrom) and node.module
    }
    assert not any(name.startswith("app.billing") for name in reached)

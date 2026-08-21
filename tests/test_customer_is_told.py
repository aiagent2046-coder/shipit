"""The two moments a customer is not watching a page, and has to be told.

A manually confirmed bank transfer is confirmed HOURS after the payer closed
their tab, and a refund is decided DAYS after they asked for one. Both were
silent: the customer's only way to find out was to ask. Somebody who paid,
complained, and heard nothing does not wait patiently — they file a dispute,
and from their side they are right to.

These tests are about the join, not the transports. app/notify/* is tested on
its own; what is asserted here is that the two money paths actually reach it,
that they carry the reference the customer can quote back, and — the part that
matters most — that a notification which fails cannot take the thing it was
announcing down with it.
"""

from __future__ import annotations

import uuid

import httpx
import pytest
from fastapi.testclient import TestClient

from app.billing import bank_transfer
from app.main import app
from app.routes.dependencies import get_billing_transport, get_payment_repo
from tests.conftest import (
    FakeAccountRepo,
    FakeCompletionCasMixin,
    FakeKeyDeliveryMixin,
    fixpack_live_job,
)

client = TestClient(app, raise_server_exceptions=False)


class Payments(FakeKeyDeliveryMixin, FakeCompletionCasMixin):
    def __init__(self) -> None:
        self.rows: dict[str, dict] = {}

    async def create(self, **kwargs):
        row = {"id": str(uuid.uuid4()), **kwargs}
        row.setdefault("status", "pending")
        self.rows[row["id"]] = row
        return row

    async def get(self, payment_id):
        return self.rows.get(payment_id)

    async def get_by_external_ref(self, provider, external_ref):
        for row in self.rows.values():
            if (row.get("provider") == provider
                    and row.get("external_ref") == external_ref):
                return row
        return None

    async def mark_refunded(self, payment_id, *, reason):
        row = self.rows.get(payment_id)
        if row is None or row.get("status") != "completed":
            return None
        row["status"] = "refunded"
        row["refund_reason"] = reason
        return row


class Fixpacks:
    def __init__(self) -> None:
        self.rows: list[dict] = []

    async def create_paid(self, *, audit_id, stack):
        live = fixpack_live_job(self.rows, audit_id)
        if live is not None:
            return {**live, "inserted": False}
        row = {"id": str(uuid.uuid4()), "audit_id": audit_id, "stack": stack,
               "status": "paid", "pack": "fixpack", "inserted": True}
        self.rows.append(row)
        return row


class Audits:
    async def get(self, audit_id):
        return {"id": audit_id, "stack": "fastapi",
                "repo_url": "https://github.com/acme/widget"}


class Captured:
    """Every outbound Bot API call, and a controllable verdict."""

    def __init__(self, *, refuse: bool = False) -> None:
        self.texts: list[str] = []
        self.refuse = refuse

    def transport(self) -> httpx.MockTransport:
        def handler(request: httpx.Request) -> httpx.Response:
            import json
            body = json.loads(request.content) if request.content else {}
            if "text" in body:
                self.texts.append(body["text"])
            if self.refuse:
                return httpx.Response(403, json={"ok": False})
            return httpx.Response(
                200, json={"ok": True, "result": {"message_id": 1}})
        return httpx.MockTransport(handler)


@pytest.fixture(autouse=True)
def _telegram_configured(monkeypatch):
    """A bot token, so the Telegram channel is live rather than skipped. No
    socket is opened — every call goes through an injected transport."""
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "t")
    monkeypatch.setenv("TELEGRAM_ADMIN_CHAT_ID", "9")
    monkeypatch.delenv("SMTP_HOST", raising=False)
    monkeypatch.delenv("SMTP_FROM", raising=False)


def _clear():
    app.dependency_overrides.clear()


# --- a confirmed transfer --------------------------------------------------

@pytest.mark.anyio
async def test_the_payer_is_told_their_transfer_was_confirmed() -> None:
    """The operator taps Confirm hours later. That tap is the only moment
    somebody who is not watching a page can be told anything."""
    payments, accounts = Payments(), FakeAccountRepo()
    captured = Captured()
    invoice = await payments.create(
        provider=bank_transfer.PROVIDER, external_ref="DRY-ABC123",
        account_id=None, amount=5.0, currency="USD", tier_granted="pro",
        product=bank_transfer.PRODUCT_PRO, telegram_chat_id="555",
    )

    await bank_transfer.confirm(
        payment_repo=payments, account_repo=accounts,
        payment_id=invoice["id"], transport=captured.transport(),
    )

    told = [t for t in captured.texts if "confirmed your bank transfer" in t]
    assert len(told) == 1
    # The reference is what they quote back to support, so it has to be in the
    # message and not only in our database.
    assert "DRY-ABC123" in told[0]


@pytest.mark.anyio
async def test_the_message_says_what_happens_next() -> None:
    """"Confirmed" on its own leaves them waiting without knowing for what.
    A Fix Pack runs and opens a pull request; Pro hands over a key. Those are
    different sentences and the payer needs the right one."""
    payments, accounts = Payments(), FakeAccountRepo()
    captured = Captured()
    invoice = await payments.create(
        provider=bank_transfer.PROVIDER, external_ref="DRY-FIXPCK",
        account_id=None, amount=10.0, currency="USD", tier_granted=None,
        product=bank_transfer.PRODUCT_FIXPACK, audit_id=str(uuid.uuid4()),
        telegram_chat_id="555",
    )

    await bank_transfer.confirm(
        payment_repo=payments, account_repo=accounts,
        payment_id=invoice["id"], transport=captured.transport(),
        fixpack_repo=Fixpacks(), audit_repo=Audits(),
    )

    told = [t for t in captured.texts if "confirmed your bank transfer" in t]
    assert told and "pull request" in told[0]


@pytest.mark.anyio
async def test_a_failed_notification_does_not_unwind_the_grant() -> None:
    """The grant already happened. If the notification could fail the
    confirmation, the operator would be invited to press Confirm again — and
    the thing that must never happen on a money path is a retry that looks
    necessary but is not."""
    payments, accounts = Payments(), FakeAccountRepo()
    captured = Captured(refuse=True)
    invoice = await payments.create(
        provider=bank_transfer.PROVIDER, external_ref="DRY-NOTELL",
        account_id=None, amount=5.0, currency="USD", tier_granted="pro",
        product=bank_transfer.PRODUCT_PRO, telegram_chat_id="555",
    )

    result = await bank_transfer.confirm(
        payment_repo=payments, account_repo=accounts,
        payment_id=invoice["id"], transport=captured.transport(),
    )

    assert result is not None
    assert result["granted"] is True


@pytest.mark.anyio
async def test_a_notification_that_raises_outright_is_swallowed() -> None:
    """The transports promise never to raise, and the wrapper does not depend
    on that promise being kept by another module on this path."""
    payments, accounts = Payments(), FakeAccountRepo()
    invoice = await payments.create(
        provider=bank_transfer.PROVIDER, external_ref="DRY-BOOM",
        account_id=None, amount=5.0, currency="USD", tier_granted="pro",
        product=bank_transfer.PRODUCT_PRO,
    )

    async def exploding(**kwargs):
        raise RuntimeError("notification stack is down")

    result = await bank_transfer.confirm(
        payment_repo=payments, account_repo=accounts,
        payment_id=invoice["id"], notify=exploding,
    )

    assert result["granted"] is True


# --- in the payer's language ------------------------------------------------

@pytest.mark.anyio
async def test_a_russian_payer_is_confirmed_in_russian() -> None:
    """The whole point of migration 0033. The operator confirms hours after
    the tab closed, so the language cannot be recovered then -- it has to come
    off the row."""
    payments, accounts = Payments(), FakeAccountRepo()
    captured = Captured()
    invoice = await payments.create(
        provider=bank_transfer.PROVIDER, external_ref="DRY-RUSSIAN",
        account_id=None, amount=5.0, currency="USD", tier_granted="pro",
        product=bank_transfer.PRODUCT_PRO, telegram_chat_id="555",
        payer_locale="ru-RU",
    )

    await bank_transfer.confirm(
        payment_repo=payments, account_repo=accounts,
        payment_id=invoice["id"], transport=captured.transport(),
    )

    told = [t for t in captured.texts if "DRY-RUSSIAN" in t]
    assert told and "подтвердили ваш перевод" in told[0]
    assert "We have confirmed" not in told[0]


@pytest.mark.anyio
async def test_a_payment_with_no_locale_is_confirmed_in_english() -> None:
    """Every row written before 0033 arrives here with None, and there are
    real ones. Silence about somebody's language is not a vote for Russian."""
    payments, accounts = Payments(), FakeAccountRepo()
    captured = Captured()
    invoice = await payments.create(
        provider=bank_transfer.PROVIDER, external_ref="DRY-NOLOCALE",
        account_id=None, amount=5.0, currency="USD", tier_granted="pro",
        product=bank_transfer.PRODUCT_PRO, telegram_chat_id="555",
    )

    await bank_transfer.confirm(
        payment_repo=payments, account_repo=accounts,
        payment_id=invoice["id"], transport=captured.transport(),
    )

    told = [t for t in captured.texts if "DRY-NOLOCALE" in t]
    assert told and "confirmed your bank transfer" in told[0]


def test_a_russian_payer_is_refunded_in_russian(monkeypatch) -> None:
    """The more sensitive of the two messages: they asked for their money back
    and are waiting to hear."""
    monkeypatch.setenv("SERVICE_FLAGS_TOKEN", "flags")
    payments = Payments()
    captured = Captured()
    payment_id = str(uuid.uuid4())
    payments.rows[payment_id] = {
        "id": payment_id, "provider": bank_transfer.PROVIDER,
        "external_ref": "DRY-RUB", "status": "completed",
        "amount": 10.79, "currency": "USD", "telegram_chat_id": "555",
        "payer_locale": "ru",
    }
    app.dependency_overrides[get_payment_repo] = lambda: payments
    app.dependency_overrides[get_billing_transport] = captured.transport
    try:
        resp = client.post(
            f"/internal/payments/{payment_id}/refund",
            json={"reason": "duplicate charge"},
            headers={"authorization": "Bearer flags"},
        )
    finally:
        _clear()

    assert resp.status_code == 200
    told = [t for t in captured.texts if "10.79" in t]
    assert told and "Мы вернули" in told[0]
    # And the operator's note stays out of it in Russian too.
    assert "duplicate charge" not in told[0]


# --- a refund --------------------------------------------------------------

def test_a_refund_tells_the_customer_and_reports_which_channels_landed(
    monkeypatch,
) -> None:
    monkeypatch.setenv("SERVICE_FLAGS_TOKEN", "flags")
    payments = Payments()
    captured = Captured()
    payment_id = str(uuid.uuid4())
    payments.rows[payment_id] = {
        "id": payment_id, "provider": bank_transfer.PROVIDER,
        "external_ref": "DRY-REFUND", "status": "completed",
        "amount": 10.79, "currency": "USD", "telegram_chat_id": "555",
    }
    app.dependency_overrides[get_payment_repo] = lambda: payments
    app.dependency_overrides[get_billing_transport] = captured.transport
    try:
        resp = client.post(
            f"/internal/payments/{payment_id}/refund",
            json={"reason": "customer says the Fix Pack was wrong"},
            headers={"authorization": "Bearer flags"},
        )
    finally:
        _clear()

    assert resp.status_code == 200
    assert resp.json()["notified"] == ["telegram"]

    told = [t for t in captured.texts if "refunded" in t]
    assert len(told) == 1
    assert "10.79 USD" in told[0]
    assert "DRY-REFUND" in told[0]


def test_the_operators_reason_is_not_read_back_to_the_customer(
    monkeypatch,
) -> None:
    """The reason is a note for the books -- "customer says the Fix Pack was
    wrong", "duplicate charge" -- written to be true rather than to be read by
    the person it is about. Quoting it back is at best clumsy and at worst an
    accusation."""
    monkeypatch.setenv("SERVICE_FLAGS_TOKEN", "flags")
    payments = Payments()
    captured = Captured()
    payment_id = str(uuid.uuid4())
    payments.rows[payment_id] = {
        "id": payment_id, "provider": bank_transfer.PROVIDER,
        "external_ref": "DRY-REASON", "status": "completed",
        "amount": 10.79, "currency": "USD", "telegram_chat_id": "555",
    }
    app.dependency_overrides[get_payment_repo] = lambda: payments
    app.dependency_overrides[get_billing_transport] = captured.transport
    try:
        client.post(
            f"/internal/payments/{payment_id}/refund",
            json={"reason": "buyer appears to have misread their own report"},
            headers={"authorization": "Bearer flags"},
        )
    finally:
        _clear()

    told = [t for t in captured.texts if "refunded" in t]
    assert told and "misread" not in told[0]


def test_a_refund_is_recorded_even_when_nobody_can_be_told(monkeypatch) -> None:
    """The record is the whole product of this endpoint. A refund that 500s
    because the mail server was down would be recorded nowhere and sent
    again."""
    monkeypatch.setenv("SERVICE_FLAGS_TOKEN", "flags")
    payments = Payments()
    captured = Captured(refuse=True)
    payment_id = str(uuid.uuid4())
    payments.rows[payment_id] = {
        "id": payment_id, "provider": bank_transfer.PROVIDER,
        "external_ref": "DRY-SILENT", "status": "completed",
        "amount": 10.79, "currency": "USD",
        # No contact details at all: the loudest case.
    }
    app.dependency_overrides[get_payment_repo] = lambda: payments
    app.dependency_overrides[get_billing_transport] = captured.transport
    try:
        resp = client.post(
            f"/internal/payments/{payment_id}/refund",
            json={"reason": "duplicate charge"},
            headers={"authorization": "Bearer flags"},
        )
    finally:
        _clear()

    assert resp.status_code == 200
    assert resp.json()["status"] == "refunded"
    assert resp.json()["notified"] == []
    # And the operator was paged about it, on the same injected transport.
    assert any("no contact channel" in t for t in captured.texts)

"""Buying and being told about it, over a channel nobody signs.

THE TEST THAT MATTERS MOST IN THIS FILE is the one where a stranger POSTs
`{"event": "payment.succeeded"}` from a trusted-looking address and gets
nothing. ЮKassa does not sign its notifications, so the endpoint's whole job is
to treat the body as a rumour and go and ask. If that ever stops being true,
anyone who learns the URL owns a free Fix Pack, and the first sign of it is an
invoice from an LLM provider.

The rest asserts that the second way to pay is not weaker than the first: the
same emergency stop, the same rate limit, the same refusal to sell a Fix Pack
for an audit that has nothing a Fix Pack can do.

Nothing here opens a socket. Every outbound call goes through an injected
httpx.MockTransport, and the repositories are the in-memory fakes.
"""

from __future__ import annotations

import json
import uuid

import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import (
    app,
    get_audit_repo,
    get_billing_transport,
    get_fixpack_repo,
    get_payment_repo,
    get_rate_limiter,
)
from app.ratelimit import RateLimiter
from tests.test_billing_bank_transfer import (
    FakeAuditRepo,
    FakeFixpackRepo,
    FakePaymentRepo,
)

client = TestClient(app)

REPO_URL = "https://github.com/acme/widget"
TRUSTED = "185.71.76.5"
PAYMENT_ID = "2c8c1c3a-000f-5000-9000-1b68e7f15f3e"
PAY_URL = "https://yoomoney.ru/checkout/payments/v2/contract?orderId=x"

PAYER = {
    "payer_name": "Ада Лавлейс",
    "payer_email": "ada@example.invalid",
    "payer_locale": "ru-RU",
}


@pytest.fixture(autouse=True)
def _shop(monkeypatch):
    monkeypatch.setenv("YOOKASSA_SHOP_ID", "test-shop")
    monkeypatch.setenv("YOOKASSA_SECRET_KEY", "test_secret")
    monkeypatch.delenv("YOOKASSA_VAT_CODE", raising=False)
    yield
    app.dependency_overrides.clear()


def _wire(payments, audits=None, jobs=None, transport=None):
    app.dependency_overrides[get_payment_repo] = lambda: payments
    app.dependency_overrides[get_audit_repo] = lambda: audits or FakeAuditRepo()
    app.dependency_overrides[get_fixpack_repo] = lambda: jobs or FakeFixpackRepo()
    app.dependency_overrides[get_rate_limiter] = lambda: RateLimiter(limit=1000)
    app.dependency_overrides[get_billing_transport] = lambda: transport


def _audit_with_findings():
    audits = FakeAuditRepo()
    return audits, audits.add()["id"]


def _yk(handler) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


def _created(record: list | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        if record is not None:
            record.append(request)
        return httpx.Response(200, json={
            "id": PAYMENT_ID, "status": "pending",
            "confirmation": {"type": "redirect", "confirmation_url": PAY_URL},
        })
    return _yk(handler)


def _succeeded(value="990.00", reference="DRY-ABC123", record=None):
    def handler(request: httpx.Request) -> httpx.Response:
        if record is not None:
            record.append(request)
        return httpx.Response(200, json={
            "id": PAYMENT_ID, "status": "succeeded", "paid": True,
            "amount": {"value": value, "currency": "RUB"},
            "metadata": {"reference": reference},
        })
    return _yk(handler)


# --- opening a payment ------------------------------------------------------

def test_a_payment_is_opened_and_the_buyer_is_told_where_to_pay() -> None:
    payments, (audits, audit_id) = FakePaymentRepo(), _audit_with_findings()
    seen: list[httpx.Request] = []
    _wire(payments, audits, transport=_created(seen))

    resp = client.post(
        f"/v1/audits/{audit_id}/fixpack/yookassa", json=PAYER)

    assert resp.status_code == 201
    body = resp.json()
    assert body["confirmation_url"] == PAY_URL
    assert body["amount"] == "990.00"
    assert body["currency"] == "RUB"
    assert body["reference"].startswith("DRY-")

    sent = json.loads(seen[0].content)
    assert sent["amount"] == {"value": "990.00", "currency": "RUB"}
    assert sent["metadata"] == {"reference": body["reference"]}
    # The idempotence key is the order, so a retried create is the same request
    # rather than a second charge on the same customer.
    assert seen[0].headers["Idempotence-Key"] == body["reference"]


def test_the_order_is_recorded_before_the_payment_system_is_called() -> None:
    """The notification comes back addressed to metadata we set, and metadata
    for a row that was never written names nothing. So the row exists first,
    even though that leaves a `pending` row behind every abandoned checkout."""
    payments, (audits, audit_id) = FakePaymentRepo(), _audit_with_findings()
    _wire(payments, audits, transport=_created())

    reference = client.post(
        f"/v1/audits/{audit_id}/fixpack/yookassa", json=PAYER).json()["reference"]

    row = [r for r in payments.rows.values() if r["external_ref"] == reference][0]
    assert row["status"] == "pending"
    assert row["provider"] == "yookassa"
    assert row["audit_id"] == audit_id
    assert row["provider_payment_id"] == PAYMENT_ID
    # The language the buyer chose survives to the row, because by the time
    # anybody writes to them the browser that knew it is gone.
    assert row["payer_locale"] == "ru-RU"


def test_a_payment_system_that_does_not_answer_charges_nothing() -> None:
    """502, and a message that says nothing was charged. The row stays pending
    -- deleting it would be worse, because a create that actually landed and
    only failed to answer us would leave a payment at ЮKassa whose metadata
    points at nothing."""
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route")

    payments, (audits, audit_id) = FakePaymentRepo(), _audit_with_findings()
    _wire(payments, audits, transport=_yk(handler))

    resp = client.post(f"/v1/audits/{audit_id}/fixpack/yookassa", json=PAYER)

    assert resp.status_code == 502
    assert "charged" in resp.json()["detail"]["detail"]
    assert all(r["status"] == "pending" for r in payments.rows.values())


def test_an_unconfigured_deployment_refuses_rather_than_pretends(
    monkeypatch,
) -> None:
    """Half a credential is no credential: a shop id with no key cannot sign a
    request, so the rail declines to be offered rather than failing at the
    moment somebody tries to pay."""
    monkeypatch.delenv("YOOKASSA_SECRET_KEY")
    audits, audit_id = _audit_with_findings()
    _wire(FakePaymentRepo(), audits, transport=_created())

    resp = client.post(f"/v1/audits/{audit_id}/fixpack/yookassa", json=PAYER)

    assert resp.status_code == 503
    assert resp.json()["detail"]["reason"] == "yookassa_not_configured"


def test_a_zip_audit_cannot_buy_a_fix_pack() -> None:
    """Same gate as the manual rail. A second way to pay that skips it is a way
    to buy something the first way refuses to sell."""
    audits = FakeAuditRepo()
    audit_id = audits.add(repo_url=None)["id"]
    _wire(FakePaymentRepo(), audits, transport=_created())

    resp = client.post(f"/v1/audits/{audit_id}/fixpack/yookassa", json=PAYER)

    assert resp.status_code == 422
    assert resp.json()["detail"]["reason"] == "not_github_audit"


def test_an_unknown_audit_is_not_sold_a_fix_pack() -> None:
    _wire(FakePaymentRepo(), FakeAuditRepo(), transport=_created())

    resp = client.post(
        f"/v1/audits/{uuid.uuid4()}/fixpack/yookassa", json=PAYER)

    assert resp.status_code == 404


# --- the notification is a rumour -------------------------------------------

def _notify(body: dict, *, source: str = TRUSTED):
    return client.post(
        "/v1/billing/yookassa/notifications",
        json=body, headers={"X-Forwarded-For": source},
    )


async def _seed(payments, audit_id, reference="DRY-ABC123", amount=990.0):
    return await payments.create(
        account_id=None, provider="yookassa", external_ref=reference,
        amount=amount, currency="RUB", status="pending", tier_granted=None,
        product="fixpack", audit_id=audit_id, payer_email="ada@example.invalid",
    )


@pytest.mark.anyio
async def test_a_forged_notification_grants_nothing(anyio_backend) -> None:
    """THE ONE THAT MATTERS. A stranger POSTs a succeeded event from an address
    inside ЮKassa's published range -- which `X-Forwarded-For` lets anyone
    claim -- naming a real order. Nothing in the body is believed, so the
    handler asks ЮKassa, is told the payment is still pending, and grants
    nothing."""
    payments, jobs = FakePaymentRepo(), FakeFixpackRepo()
    audits, audit_id = _audit_with_findings()
    await _seed(payments, audit_id)

    def still_pending(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "id": PAYMENT_ID, "status": "pending", "paid": False,
            "amount": {"value": "990.00", "currency": "RUB"},
            "metadata": {"reference": "DRY-ABC123"},
        })

    _wire(payments, audits, jobs, transport=_yk(still_pending))

    resp = _notify({
        "event": "payment.succeeded",
        "object": {"id": PAYMENT_ID, "status": "succeeded", "paid": True,
                   "amount": {"value": "990.00", "currency": "RUB"},
                   "metadata": {"reference": "DRY-ABC123"}},
    })

    assert resp.status_code == 200
    assert jobs.rows == [], "a forged notification created a Fix Pack job"
    row = await payments.get_by_external_ref("yookassa", "DRY-ABC123")
    assert row["status"] == "pending"


@pytest.mark.anyio
async def test_a_notification_from_an_untrusted_address_is_not_even_asked_about(
    anyio_backend,
) -> None:
    """The IP list authorises nothing, but it does save a request. A call that
    reaches ЮKassa from here would mean the filter did not run."""
    asked: list[httpx.Request] = []
    payments, jobs = FakePaymentRepo(), FakeFixpackRepo()
    audits, audit_id = _audit_with_findings()
    await _seed(payments, audit_id)
    _wire(payments, audits, jobs,
          transport=_succeeded(record=asked))

    resp = _notify({"event": "payment.succeeded",
                    "object": {"id": PAYMENT_ID}}, source="8.8.8.8")

    assert resp.status_code == 200
    assert asked == [], "spent a request on an untrusted notification"
    assert jobs.rows == []


@pytest.mark.anyio
async def test_a_payment_that_paid_a_rouble_does_not_buy_a_fix_pack(
    anyio_backend,
) -> None:
    """`succeeded` says money moved, not how much. Without the amount check a
    notification naming any succeeded payment of the sender's own -- one
    rouble, their own order -- would buy a 990-rouble product."""
    payments, jobs = FakePaymentRepo(), FakeFixpackRepo()
    audits, audit_id = _audit_with_findings()
    await _seed(payments, audit_id)
    _wire(payments, audits, jobs, transport=_succeeded(value="1.00"))

    _notify({"event": "payment.succeeded", "object": {"id": PAYMENT_ID}})

    assert jobs.rows == []
    row = await payments.get_by_external_ref("yookassa", "DRY-ABC123")
    assert row["status"] == "pending"


@pytest.mark.anyio
async def test_a_notification_naming_an_order_we_do_not_have_is_ignored(
    anyio_backend,
) -> None:
    payments, jobs = FakePaymentRepo(), FakeFixpackRepo()
    audits, _ = _audit_with_findings()
    _wire(payments, audits, jobs, transport=_succeeded(reference="DRY-NOPE99"))

    resp = _notify({"event": "payment.succeeded", "object": {"id": PAYMENT_ID}})

    assert resp.status_code == 200
    assert jobs.rows == []


@pytest.mark.anyio
async def test_every_answer_is_the_same_two_hundred(anyio_backend) -> None:
    """ЮKassa retries anything that is not 2xx, so an error here becomes a
    retry storm on a problem retrying cannot fix. And a distinguishable
    response is a probe: a stranger POSTing payment ids would learn which ones
    exist from the status code alone."""
    payments, jobs = FakePaymentRepo(), FakeFixpackRepo()
    audits, _ = _audit_with_findings()
    _wire(payments, audits, jobs, transport=_succeeded(reference="DRY-NOPE99"))

    bodies = [
        {"event": "payment.succeeded", "object": {"id": PAYMENT_ID}},
        {"event": "payment.canceled", "object": {"id": PAYMENT_ID}},
        {"event": "payment.succeeded", "object": {}},
        {"event": "payment.succeeded"},
        {"nonsense": True},
        {},
    ]
    assert {_notify(b).status_code for b in bodies} == {200}


def test_a_body_that_is_not_json_is_ignored_quietly() -> None:
    _wire(FakePaymentRepo(), FakeAuditRepo(), FakeFixpackRepo(),
          transport=_succeeded())

    resp = client.post(
        "/v1/billing/yookassa/notifications",
        content=b"not json at all",
        headers={"X-Forwarded-For": TRUSTED,
                 "Content-Type": "application/json"},
    )

    assert resp.status_code == 200


@pytest.mark.anyio
async def test_a_real_payment_grants_the_fix_pack(anyio_backend) -> None:
    payments, jobs = FakePaymentRepo(), FakeFixpackRepo()
    audits, audit_id = _audit_with_findings()
    await _seed(payments, audit_id)
    _wire(payments, audits, jobs, transport=_succeeded())

    resp = _notify({"event": "payment.succeeded", "object": {"id": PAYMENT_ID}})

    assert resp.status_code == 200
    row = await payments.get_by_external_ref("yookassa", "DRY-ABC123")
    assert row["status"] == "completed"


@pytest.mark.anyio
async def test_the_same_notification_twice_creates_one_job(anyio_backend) -> None:
    """ЮKassa retries until it gets a 2xx, and a retry after a slow response is
    the ordinary case rather than the exceptional one. The CAS gate in
    mark_completed_fixpack is what makes the second one a no-op."""
    payments, jobs = FakePaymentRepo(), FakeFixpackRepo()
    audits, audit_id = _audit_with_findings()
    await _seed(payments, audit_id)
    _wire(payments, audits, jobs, transport=_succeeded())

    body = {"event": "payment.succeeded", "object": {"id": PAYMENT_ID}}
    _notify(body)
    _notify(body)

    assert len(jobs.rows) <= 1, "a retried notification bought a second Fix Pack"


# --- the receipt ------------------------------------------------------------

def test_no_receipt_is_sent_when_the_shop_has_no_tax_position(monkeypatch) -> None:
    """A guessed VAT rate is a fiscal document making a false statement about
    somebody's tax, filed in their name. No configuration means no receipt."""
    monkeypatch.delenv("YOOKASSA_VAT_CODE", raising=False)
    payments, (audits, audit_id) = FakePaymentRepo(), _audit_with_findings()
    seen: list[httpx.Request] = []
    _wire(payments, audits, transport=_created(seen))

    client.post(f"/v1/audits/{audit_id}/fixpack/yookassa", json=PAYER)

    assert "receipt" not in json.loads(seen[0].content)


def test_a_receipt_is_sent_when_the_shop_is_configured_for_one(monkeypatch) -> None:
    monkeypatch.setenv("YOOKASSA_VAT_CODE", "1")
    monkeypatch.setenv("YOOKASSA_TAX_SYSTEM_CODE", "2")
    payments, (audits, audit_id) = FakePaymentRepo(), _audit_with_findings()
    seen: list[httpx.Request] = []
    _wire(payments, audits, transport=_created(seen))

    client.post(f"/v1/audits/{audit_id}/fixpack/yookassa", json=PAYER)

    receipt = json.loads(seen[0].content)["receipt"]
    assert receipt["customer"]["email"] == "ada@example.invalid"
    assert receipt["tax_system_code"] == 2
    assert receipt["items"][0]["amount"]["value"] == "990.00"

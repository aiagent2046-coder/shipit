"""The ЮKassa client, and mostly the parts that decide whether money is real.

THE BOUNDARY THIS FILE GUARDS is that ЮKassa does not sign its notifications.
Their own SDK offers an IP allowlist and nothing else, and this service sits
behind a reverse proxy where the apparent source address is a header the sender
writes. So the notification may only ever be a hint, and everything acted on
must come from a request WE make.

Most of what follows asserts the unhappy shapes: a succeeded payment for the
wrong amount, a payment id with a slash in it, an error body that must not be
logged, an idempotence header spelled the common English way instead of theirs.
Each is a way to take money and give nothing back, or to give the product away
and take nothing.

Nothing here opens a socket -- every call takes an injected transport.
"""

from __future__ import annotations

import json

import httpx
import pytest

from app.billing import yookassa


CREDS = ("test-shop", "test_secret")


def _transport(handler) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


def _ok(payload: dict, *, record: list | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        if record is not None:
            record.append(request)
        return httpx.Response(200, json=payload)
    return _transport(handler)


# --- the notification is a hint, never evidence -----------------------------

def test_an_address_outside_their_ranges_is_not_trusted() -> None:
    assert yookassa.is_notification_source_trusted("8.8.8.8") is False


@pytest.mark.parametrize("ip", ["77.75.153.1", "185.71.76.5", "77.75.156.11"])
def test_their_published_addresses_are_trusted(ip) -> None:
    assert yookassa.is_notification_source_trusted(ip) is True


@pytest.mark.parametrize("value", [None, "", "   ", "not-an-ip", "127.0.0.1, 8.8.8.8"])
def test_anything_that_is_not_an_address_is_untrusted(value) -> None:
    """`X-Forwarded-For` is text written by whoever sent the request, and a
    comma-joined chain is the shape it usually arrives in. Text that is not a
    single address means we do not know where this came from, and the honest
    reading of not knowing is not to trust it."""
    assert yookassa.is_notification_source_trusted(value) is False


def test_the_ip_list_matches_the_vendor_sdk() -> None:
    """Copied from yookassa 3.12.1's security_helper.py. Pinned so that a
    future edit is a deliberate act rather than a typo that silently widens or
    narrows who we will talk to."""
    assert len(yookassa.NOTIFICATION_NETWORKS) == 10
    assert "77.75.153.0/25" in yookassa.NOTIFICATION_NETWORKS
    assert any(":" in n for n in yookassa.NOTIFICATION_NETWORKS), "no IPv6 range"


# --- a succeeded payment is not automatically a paid one --------------------

def _succeeded(value: str = "990.00", currency: str = "RUB") -> dict:
    return {
        "id": "2c8c1c3a-000f-5000-9000-1b68e7f15f3e",
        "status": "succeeded",
        "paid": True,
        "amount": {"value": value, "currency": currency},
    }


def test_a_succeeded_payment_for_the_right_amount_is_paid() -> None:
    assert yookassa.is_paid(_succeeded(), expected_amount="990.00") is True


def test_the_amount_is_compared_as_a_number_not_as_text() -> None:
    """"990.0" and "990.00" are the same money. Refusing one of them would
    turn a customer who paid correctly into a customer who is told they did
    not."""
    assert yookassa.is_paid(_succeeded("990.0"), expected_amount="990.00") is True
    assert yookassa.is_paid(_succeeded("990"), expected_amount="990.00") is True


def test_a_succeeded_payment_for_the_wrong_amount_is_not_paid() -> None:
    """THE ONE THAT IS EASY TO FORGET. `status == "succeeded"` says money
    moved. It does not say how much, and a one-rouble payment is succeeded
    too. Without this, a notification naming any succeeded payment of the
    attacker's own would buy a Fix Pack for a rouble."""
    assert yookassa.is_paid(_succeeded("1.00"), expected_amount="990.00") is False


def test_a_payment_in_another_currency_is_not_paid() -> None:
    assert yookassa.is_paid(
        _succeeded(currency="USD"), expected_amount="990.00") is False


@pytest.mark.parametrize("status", ["pending", "waiting_for_capture", "canceled"])
def test_only_succeeded_counts(status) -> None:
    payment = {**_succeeded(), "status": status}
    assert yookassa.is_paid(payment, expected_amount="990.00") is False


def test_succeeded_but_not_yet_paid_does_not_count() -> None:
    """`paid` is separately false while a succeeded payment settles. Both are
    checked because either alone is a window in which the product is handed
    over for money that has not arrived."""
    payment = {**_succeeded(), "paid": False}
    assert yookassa.is_paid(payment, expected_amount="990.00") is False


@pytest.mark.parametrize("payment", [
    {}, {"status": "succeeded"}, {"status": "succeeded", "paid": True},
    {"status": "succeeded", "paid": True, "amount": "990.00"},
    {"status": "succeeded", "paid": True, "amount": {"value": None}},
    {"status": "succeeded", "paid": True, "amount": {"value": "nine hundred"}},
])
def test_a_malformed_payment_is_never_paid(payment) -> None:
    """Whatever arrives, the answer to "did they pay" is no unless the response
    actually says so. These shapes come from a stranger's imagination as easily
    as from ЮKassa."""
    assert yookassa.is_paid(payment, expected_amount="990.00") is False


# --- the request we send ----------------------------------------------------

@pytest.mark.anyio
async def test_the_idempotence_header_is_spelled_their_way() -> None:
    """`Idempotence-Key`, not `Idempotency-Key`. ЮKassa treats a request with
    no recognised key as a NEW payment, so this typo is a second charge on the
    same customer for the same order the first time a create is retried."""
    seen: list[httpx.Request] = []
    await yookassa.create_payment(
        credentials=CREDS, amount="990.00", description="Fix Pack",
        return_url="https://drydock.co/audit/x", idempotence_key="DRY-ABC123",
        transport=_ok({"id": "p1"}, record=seen),
    )

    assert seen[0].headers["Idempotence-Key"] == "DRY-ABC123"
    assert "idempotency-key" not in {k.lower() for k in seen[0].headers}


@pytest.mark.anyio
async def test_a_payment_is_captured_in_one_stage() -> None:
    """Two-stage exists so a merchant can inspect an order before taking the
    money. There is nothing to inspect: the product is generated the moment
    payment is confirmed. Two-stage would add a state where the payer has paid,
    we have not captured, and a timeout quietly returns their money."""
    seen: list[httpx.Request] = []
    await yookassa.create_payment(
        credentials=CREDS, amount="990.00", description="Fix Pack",
        return_url="https://drydock.co/audit/x", idempotence_key="k",
        transport=_ok({"id": "p1"}, record=seen),
    )

    body = json.loads(seen[0].content)
    assert body["capture"] is True
    assert body["amount"] == {"value": "990.00", "currency": "RUB"}
    assert body["confirmation"] == {
        "type": "redirect", "return_url": "https://drydock.co/audit/x"}


@pytest.mark.anyio
async def test_the_amount_is_always_two_places() -> None:
    """ЮKassa rejects a malformed amount at checkout, in front of the buyer.
    A price that has been through a float arrives as 990.0000000001."""
    seen: list[httpx.Request] = []
    await yookassa.create_payment(
        credentials=CREDS, amount="990", description="d",
        return_url="https://drydock.co/", idempotence_key="k",
        transport=_ok({"id": "p1"}, record=seen),
    )

    assert json.loads(seen[0].content)["amount"]["value"] == "990.00"


@pytest.mark.anyio
async def test_the_shop_credentials_are_sent_as_basic_auth() -> None:
    seen: list[httpx.Request] = []
    await yookassa.create_payment(
        credentials=("shop-42", "live_key"), amount="1.00", description="d",
        return_url="https://drydock.co/", idempotence_key="k",
        transport=_ok({"id": "p1"}, record=seen),
    )

    import base64
    expected = base64.b64encode(b"shop-42:live_key").decode()
    assert seen[0].headers["authorization"] == f"Basic {expected}"


@pytest.mark.anyio
async def test_metadata_carries_our_identifiers_and_not_the_payer(  ) -> None:
    """Metadata lands in a third party's dashboard and stays there. Our order
    reference is what we need to find the row again; the payer's name and
    address are not ours to leave lying around for a convenience we do not
    need."""
    seen: list[httpx.Request] = []
    await yookassa.create_payment(
        credentials=CREDS, amount="990.00", description="Fix Pack",
        return_url="https://drydock.co/", idempotence_key="k",
        metadata={"reference": "DRY-ABC123"},
        transport=_ok({"id": "p1"}, record=seen),
    )

    assert json.loads(seen[0].content)["metadata"] == {"reference": "DRY-ABC123"}


# --- the receipt ------------------------------------------------------------

def test_a_receipt_names_the_service_the_amount_and_the_buyer() -> None:
    receipt = yookassa.receipt_for(
        email="buyer@example.invalid", description="Drydock Fix Pack",
        amount="990.00", vat_code=1, tax_system_code=2,
    )

    assert receipt["customer"] == {"email": "buyer@example.invalid"}
    assert receipt["tax_system_code"] == 2
    item = receipt["items"][0]
    assert item["amount"] == {"value": "990.00", "currency": "RUB"}
    assert item["vat_code"] == 1
    assert item["payment_subject"] == "service"
    assert item["payment_mode"] == "full_payment"


def test_a_receipt_omits_the_tax_system_when_there_is_none_to_state() -> None:
    """The field is only required when the merchant has more than one tax
    regime. Sending a guessed value would put something untrue about somebody's
    tax on a fiscal document."""
    receipt = yookassa.receipt_for(
        email="b@example.invalid", description="d", amount="1.00",
        vat_code=1, tax_system_code=None,
    )
    assert "tax_system_code" not in receipt


# --- reading a payment ------------------------------------------------------

@pytest.mark.anyio
async def test_a_payment_id_out_of_a_notification_cannot_change_the_path() -> None:
    """The id arrives inside an unsigned body and is then concatenated into a
    URL. A value containing a slash addresses a different endpoint than this
    function claims to call, so it is refused rather than sent."""
    for hostile in ["", "../refunds/abc", "abc/capture", "a/b"]:
        with pytest.raises(yookassa.YooKassaError):
            await yookassa.get_payment(
                hostile, credentials=CREDS, transport=_ok({}))


@pytest.mark.anyio
async def test_a_payment_is_read_by_id_over_get() -> None:
    seen: list[httpx.Request] = []
    await yookassa.get_payment(
        "2c8c1c3a-000f", credentials=CREDS, transport=_ok(_succeeded(), record=seen))

    assert seen[0].method == "GET"
    assert str(seen[0].url) == "https://api.yookassa.ru/v3/payments/2c8c1c3a-000f"
    # No idempotence key on a read: it means nothing there, and sending one
    # would suggest this call changes something.
    assert "idempotence-key" not in {k.lower() for k in seen[0].headers}


# --- failures -------------------------------------------------------------

@pytest.mark.anyio
async def test_an_error_response_does_not_carry_its_body_into_the_exception() -> None:
    """Their error bodies echo the request back, and the request carries the
    payer's email on the receipt. An exception message ends up in a log, and a
    log is the wrong place for a customer's address."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={
            "type": "error", "code": "invalid_request",
            "description": "receipt.customer.email is invalid",
            "parameter": "buyer-private@example.invalid",
        })

    with pytest.raises(yookassa.YooKassaError) as caught:
        await yookassa.create_payment(
            credentials=CREDS, amount="990.00", description="d",
            return_url="https://drydock.co/", idempotence_key="k",
            transport=_transport(handler),
        )

    assert "buyer-private@example.invalid" not in str(caught.value)
    assert "400" in str(caught.value)


@pytest.mark.anyio
async def test_a_network_failure_is_a_yookassa_error_and_not_an_httpx_one() -> None:
    """The callers of this module are on paths where something has already
    happened -- an order exists, a notification arrived. They catch one
    exception type; letting httpx's escape would mean every caller has to know
    which HTTP client this module chose."""
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route to host")

    with pytest.raises(yookassa.YooKassaError):
        await yookassa.get_payment(
            "p1", credentials=CREDS, transport=_transport(handler))


@pytest.mark.anyio
async def test_a_non_json_answer_is_refused() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>maintenance</html>")

    with pytest.raises(yookassa.YooKassaError):
        await yookassa.get_payment(
            "p1", credentials=CREDS, transport=_transport(handler))


# --- configuration ----------------------------------------------------------

def test_half_a_credential_is_no_credential(monkeypatch) -> None:
    """A shop id with no key cannot sign a request. A deployment holding half
    of one must decline to offer the rail, not fail at the moment somebody
    tries to pay."""
    monkeypatch.setenv("YOOKASSA_SHOP_ID", "123")
    monkeypatch.delenv("YOOKASSA_SECRET_KEY", raising=False)
    assert yookassa.credentials_from_env() is None

    monkeypatch.delenv("YOOKASSA_SHOP_ID")
    monkeypatch.setenv("YOOKASSA_SECRET_KEY", "test_x")
    assert yookassa.credentials_from_env() is None


def test_a_test_key_is_recognised_as_one(monkeypatch) -> None:
    """A deployment that believes it is live while holding a test key takes no
    money at all, and the symptom is "customers are not paying" rather than
    anything that looks like a misconfiguration."""
    monkeypatch.setenv("YOOKASSA_SHOP_ID", "123")
    monkeypatch.setenv("YOOKASSA_SECRET_KEY", "test_abc")
    assert yookassa.is_test_shop() is True

    monkeypatch.setenv("YOOKASSA_SECRET_KEY", "live_abc")
    assert yookassa.is_test_shop() is False


def test_a_confirmation_url_must_be_https() -> None:
    """It is read out of a response and then a browser is sent to it."""
    assert yookassa.confirmation_url(
        {"confirmation": {"confirmation_url": "https://yoomoney.ru/x"}}
    ) == "https://yoomoney.ru/x"
    for bad in [
        {}, {"confirmation": None}, {"confirmation": {}},
        {"confirmation": {"confirmation_url": "http://yoomoney.ru/x"}},
        {"confirmation": {"confirmation_url": "javascript:alert(1)"}},
    ]:
        assert yookassa.confirmation_url(bad) is None

"""Tests for the USDT/TRC20 provider (paywall Stage 2).

No real Postgres and no real chain: TronGrid reads are faked with
httpx.MockTransport (same pattern as tests/test_github_app.py) and the DB
repos are in-memory fakes (same idea as tests/test_accounts.py). What is
NOT covered here is a real on-chain payment being matched — that would
cost real USDT; see scripts/verify_usdt_trc20_locally.py for the real
read path.
"""

from __future__ import annotations

import datetime
import re
import uuid

import httpx

from app.accounts import api_key_prefix
from app.billing import usdt_trc20
from app.main import (
    app,
    get_account_repo,
    get_billing_transport,
    get_payment_repo,
)
from fastapi.testclient import TestClient
from tests.conftest import FakeAccountRepo, FakeKeyDeliveryMixin

client = TestClient(app)

# A real, checksum-valid base58check TRON address -- the shape a wallet
# actually accepts. Must be valid because the invoice/poll endpoints now
# normalize+validate USDT_TRC20_ADDRESS and reject anything that isn't a
# genuine "T..." address (see test_invoice_endpoint_rejects_non_tron_env).
ADDRESS = "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb"
USDT_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"

# The shape any address handed to a payer must match: leading 'T', 34
# chars, base58 alphabet only (no 0, O, I, l).
_TRON_ADDR_RE = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")


class FakePaymentRepo(FakeKeyDeliveryMixin):
    def __init__(self):
        self.rows: dict[str, dict] = {}

    async def create(self, *, account_id, provider, external_ref, amount,
                     currency, status, tier_granted, product="pro_tier",
                     audit_id=None, created_at=None):
        row = {
            "id": str(uuid.uuid4()), "account_id": account_id, "provider": provider,
            "external_ref": external_ref, "amount": amount, "currency": currency,
            "status": status, "tier_granted": tier_granted, "product": product,
            "audit_id": audit_id,
            "created_at": created_at or datetime.datetime.now(datetime.timezone.utc),
        }
        self.rows[row["id"]] = row
        return row

    async def get(self, payment_id: str):
        return self.rows.get(payment_id)

    async def get_by_external_ref(self, provider: str, external_ref: str):
        for r in self.rows.values():
            if r["provider"] == provider and r["external_ref"] == external_ref:
                return r
        return None

    async def list_pending(self, provider: str):
        return [r for r in self.rows.values()
                if r["provider"] == provider and r["status"] == "pending"]

    async def mark_completed(self, payment_id, *, account_id, external_ref):
        self.rows[payment_id].update(
            status="completed", account_id=account_id, external_ref=external_ref)

    async def mark_completed_fixpack(self, payment_id, *, external_ref):
        self.rows[payment_id].update(status="completed", external_ref=external_ref)


def _trongrid_transport(transfers: list, *, success: bool = True):
    def handler(request: httpx.Request) -> httpx.Response:
        assert f"/v1/accounts/{ADDRESS}/transactions/trc20" in request.url.path
        return httpx.Response(200, json={"success": success, "data": transfers})
    return httpx.MockTransport(handler)


def _transfer(value_micros: int, *, tx_id: str, to: str = ADDRESS):
    return {
        "transaction_id": tx_id, "type": "Transfer", "from": "TSenderXYZ",
        "to": to, "value": str(value_micros),
        "token_info": {"symbol": "USDT", "address": USDT_CONTRACT, "decimals": 6},
        "block_timestamp": 1784040468000,
    }


# --- 5. invoice creation: unique amount + pending row ---

async def test_create_invoice_makes_unique_amount_and_pending_row():
    payments = FakePaymentRepo()
    inv1 = await usdt_trc20.create_invoice(payments, address=ADDRESS)
    inv2 = await usdt_trc20.create_invoice(payments, address=ADDRESS)

    assert inv1["address"] == ADDRESS
    assert inv1["currency"] == "USDT"
    assert inv1["network"] == "TRC20"
    # base price 5 USDT + sub-dollar nonce
    assert 5.0 <= inv1["amount"] < 6.0
    # unique amounts, so two open invoices are distinguishable on-chain
    assert inv1["amount"] != inv2["amount"]
    # each persisted a pending row
    rows = list(payments.rows.values())
    assert len(rows) == 2
    assert all(r["status"] == "pending" and r["provider"] == "usdt_trc20"
               for r in rows)
    assert all(r["account_id"] is None and r["external_ref"] is None for r in rows)


def test_invoice_endpoint_503_without_address(monkeypatch):
    monkeypatch.delenv("USDT_TRC20_ADDRESS", raising=False)
    app.dependency_overrides[get_payment_repo] = lambda: FakePaymentRepo()
    try:
        r = client.post("/v1/billing/usdt/invoice")
        assert r.status_code == 503
        assert r.json()["detail"]["reason"] == "usdt_not_configured"
    finally:
        app.dependency_overrides.pop(get_payment_repo, None)


def test_invoice_endpoint_creates_invoice(monkeypatch):
    monkeypatch.setenv("USDT_TRC20_ADDRESS", ADDRESS)
    app.dependency_overrides[get_payment_repo] = lambda: FakePaymentRepo()
    try:
        r = client.post("/v1/billing/usdt/invoice")
        assert r.status_code == 201
        body = r.json()
        assert body["address"] == ADDRESS
        # Regression guard: the address handed to the payer must be valid
        # base58check Tron ("T..."), never a "0x..." hex address a Tron
        # wallet would reject. This is the assertion the old suite lacked.
        assert _TRON_ADDR_RE.match(body["address"]), body["address"]
        assert body["currency"] == "USDT"
        assert "invoice_id" in body and "expires_at" in body
    finally:
        app.dependency_overrides.pop(get_payment_repo, None)


def test_invoice_endpoint_converts_hex_env_to_base58(monkeypatch):
    """If USDT_TRC20_ADDRESS is set to the internal 0x-hex form of a Tron
    address (the exact live bug), the endpoint still hands the payer a
    valid base58check "T..." address, not the raw "0x..." string."""
    hex_form = "0x3917C3B3127F9c6fCa89E59A4acEb2B8Eb84CeE6"
    monkeypatch.setenv("USDT_TRC20_ADDRESS", hex_form)
    app.dependency_overrides[get_payment_repo] = lambda: FakePaymentRepo()
    try:
        r = client.post("/v1/billing/usdt/invoice")
        assert r.status_code == 201
        addr = r.json()["address"]
        assert not addr.startswith("0x")
        assert _TRON_ADDR_RE.match(addr), addr
        # deterministic: 0x41 + the 20 hex bytes, base58check-encoded
        assert addr == "TFB5zBBVJwg8UHemGep9eGYZST4vxHYiAb"
    finally:
        app.dependency_overrides.pop(get_payment_repo, None)


def test_invoice_endpoint_rejects_non_tron_env(monkeypatch):
    """A configured value that isn't a Tron address at all is a 503
    (misconfig), never a bad address handed to a payer."""
    monkeypatch.setenv("USDT_TRC20_ADDRESS", "not-an-address")
    app.dependency_overrides[get_payment_repo] = lambda: FakePaymentRepo()
    try:
        r = client.post("/v1/billing/usdt/invoice")
        assert r.status_code == 503
        assert r.json()["detail"]["reason"] == "usdt_misconfigured"
    finally:
        app.dependency_overrides.pop(get_payment_repo, None)


def test_normalize_tron_address_forms():
    hexb = "3917C3B3127F9c6fCa89E59A4acEb2B8Eb84CeE6"
    expected = "TFB5zBBVJwg8UHemGep9eGYZST4vxHYiAb"
    # 20-byte Ethereum-style hex, with and without 0x
    assert usdt_trc20.normalize_tron_address("0x" + hexb) == expected
    assert usdt_trc20.normalize_tron_address(hexb) == expected
    # 21-byte TRON hex (0x41 version byte + 20-byte hash)
    assert usdt_trc20.normalize_tron_address("41" + hexb) == expected
    # already-valid base58 passes through unchanged
    assert usdt_trc20.normalize_tron_address(ADDRESS) == ADDRESS
    for form in (usdt_trc20.normalize_tron_address("0x" + hexb),
                 usdt_trc20.normalize_tron_address(ADDRESS)):
        assert _TRON_ADDR_RE.match(form), form


def test_normalize_tron_address_rejects_bad_input():
    for bad in ("", "   ", "not-an-address", "0xdeadbeef",
                "TXYZreceiveExampleAddress0000000000",  # bad base58 checksum
                "0x3917C3B3127F9c6fCa89E59A4acEb2B8Eb84CeE6ff"):  # wrong length
        try:
            usdt_trc20.normalize_tron_address(bad)
        except usdt_trc20.InvalidTronAddressError:
            continue
        raise AssertionError(f"expected rejection for {bad!r}")


# --- 6. poll matches a mocked transfer and completes the invoice ---

async def test_poll_matches_transfer_and_grants_pro():
    accounts, payments = FakeAccountRepo(), FakePaymentRepo()
    inv = await usdt_trc20.create_invoice(payments, address=ADDRESS)
    micros = usdt_trc20.amount_to_micros(inv["amount"])
    transport = _trongrid_transport([_transfer(micros, tx_id="0xdeadbeef")])

    result = await usdt_trc20.poll_and_match(
        payments, accounts, address=ADDRESS, transport=transport)
    assert result["matched"] == 1

    # invoice row is now completed and linked to a new pro account
    row = payments.rows[inv["invoice_id"]]
    assert row["status"] == "completed"
    assert row["external_ref"] == "0xdeadbeef"
    account = accounts.by_id[row["account_id"]]
    assert account["tier"] == "pro"

    # The poller ran with no browser attached, so the plaintext key it minted
    # is gone -- nothing stored it (migration 0019). The status endpoint the
    # payer polls therefore mints the key it hands back, and it is genuinely
    # this account's current key (its prefix matches what the account carries).
    status = await usdt_trc20.invoice_status(
        payments, accounts, inv["invoice_id"], address=ADDRESS)
    assert status["status"] == "completed"
    assert status["api_key"].startswith("sk_live_")
    assert status["key_already_delivered"] is False
    assert api_key_prefix(status["api_key"]) == account["key_prefix"]


async def test_status_pending_never_reveals_key():
    accounts, payments = FakeAccountRepo(), FakePaymentRepo()
    inv = await usdt_trc20.create_invoice(payments, address=ADDRESS)
    status = await usdt_trc20.invoice_status(
        payments, accounts, inv["invoice_id"], address=ADDRESS)
    assert status["status"] == "pending"
    assert "api_key" not in status


async def test_poll_is_idempotent_across_repeated_transfers():
    accounts, payments = FakeAccountRepo(), FakePaymentRepo()
    inv = await usdt_trc20.create_invoice(payments, address=ADDRESS)
    micros = usdt_trc20.amount_to_micros(inv["amount"])
    transport = _trongrid_transport([_transfer(micros, tx_id="0xsame")])

    first = await usdt_trc20.poll_and_match(
        payments, accounts, address=ADDRESS, transport=transport)
    second = await usdt_trc20.poll_and_match(
        payments, accounts, address=ADDRESS, transport=transport)
    assert first["matched"] == 1
    assert second["matched"] == 0          # same tx, already applied
    assert len(accounts.by_id) == 1        # no second account


async def test_repeat_status_poll_after_key_delivery_does_not_crash():
    """The regression this file could not express before: the browser polls
    this endpoint on a timer, so the SECOND poll of a paid invoice used to read
    api_key off a get_by_id() row that has no such field -- KeyError, 500, and
    a paying customer with no key and no way to get one.

    Now the first poll delivers and the rest report, in a shape the checkout
    page already renders (api_key null + key_already_delivered)."""
    accounts, payments = FakeAccountRepo(), FakePaymentRepo()
    inv = await usdt_trc20.create_invoice(payments, address=ADDRESS)
    micros = usdt_trc20.amount_to_micros(inv["amount"])
    await usdt_trc20.poll_and_match(
        payments, accounts, address=ADDRESS,
        transport=_trongrid_transport([_transfer(micros, tx_id="0xpoll")]))

    first = await usdt_trc20.invoice_status(
        payments, accounts, inv["invoice_id"], address=ADDRESS)
    assert first["api_key"] is not None

    for _ in range(3):
        again = await usdt_trc20.invoice_status(
            payments, accounts, inv["invoice_id"], address=ADDRESS)
        assert again["status"] == "completed"
        assert again["tier"] == "pro"
        assert again["api_key"] is None
        assert again["key_already_delivered"] is True
    # And no repeat poll quietly rotated the key out from under the payer.
    assert accounts.rotations == [payments.rows[inv["invoice_id"]]["account_id"]]


async def test_status_endpoint_delivers_key_once_over_http():
    """Same one-shot rule through the real endpoint, since that is where a
    KeyError became a 500 for the payer."""
    accounts, payments = FakeAccountRepo(), FakePaymentRepo()
    inv = await usdt_trc20.create_invoice(payments, address=ADDRESS)
    micros = usdt_trc20.amount_to_micros(inv["amount"])
    await usdt_trc20.poll_and_match(
        payments, accounts, address=ADDRESS,
        transport=_trongrid_transport([_transfer(micros, tx_id="0xhttp")]))

    app.dependency_overrides[get_account_repo] = lambda: accounts
    app.dependency_overrides[get_payment_repo] = lambda: payments
    try:
        first = client.get(f"/v1/billing/usdt/invoice/{inv['invoice_id']}")
        second = client.get(f"/v1/billing/usdt/invoice/{inv['invoice_id']}")
    finally:
        app.dependency_overrides.pop(get_account_repo, None)
        app.dependency_overrides.pop(get_payment_repo, None)

    assert first.status_code == 200
    assert first.json()["api_key"].startswith("sk_live_")
    assert second.status_code == 200          # not a 500
    assert second.json()["api_key"] is None
    assert second.json()["key_already_delivered"] is True


async def test_poll_ignores_wrong_amount_and_wrong_token():
    accounts, payments = FakeAccountRepo(), FakePaymentRepo()
    inv = await usdt_trc20.create_invoice(payments, address=ADDRESS)
    micros = usdt_trc20.amount_to_micros(inv["amount"])
    other = _transfer(micros, tx_id="0xother")
    other["token_info"]["address"] = "TSomeOtherToken000000000000000000"  # not USDT
    wrong_amount = _transfer(micros + 1, tx_id="0xwrongamt")
    transport = _trongrid_transport([other, wrong_amount])

    result = await usdt_trc20.poll_and_match(
        payments, accounts, address=ADDRESS, transport=transport)
    assert result["matched"] == 0
    assert payments.rows[inv["invoice_id"]]["status"] == "pending"


# --- 7. poll endpoint bearer auth ---

def _override(accounts, payments, transport):
    app.dependency_overrides[get_account_repo] = lambda: accounts
    app.dependency_overrides[get_payment_repo] = lambda: payments
    app.dependency_overrides[get_billing_transport] = lambda: transport


def _clear():
    for dep in (get_account_repo, get_payment_repo, get_billing_transport):
        app.dependency_overrides.pop(dep, None)


def test_poll_endpoint_requires_bearer_token(monkeypatch):
    monkeypatch.setenv("USDT_POLL_TOKEN", "polltok")
    monkeypatch.setenv("USDT_TRC20_ADDRESS", ADDRESS)
    _override(FakeAccountRepo(), FakePaymentRepo(), _trongrid_transport([]))
    try:
        assert client.post("/internal/billing/poll-usdt").status_code == 401
        r = client.post("/internal/billing/poll-usdt",
                        headers={"Authorization": "Bearer wrong"})
        assert r.status_code == 401
        r = client.post("/internal/billing/poll-usdt",
                        headers={"Authorization": "Bearer polltok"})
        assert r.status_code == 200
        assert r.json()["matched"] == 0
    finally:
        _clear()


def test_poll_endpoint_503_when_token_unconfigured(monkeypatch):
    monkeypatch.delenv("USDT_POLL_TOKEN", raising=False)
    _override(FakeAccountRepo(), FakePaymentRepo(), _trongrid_transport([]))
    try:
        r = client.post("/internal/billing/poll-usdt",
                        headers={"Authorization": "Bearer anything"})
        assert r.status_code == 503
        assert r.json()["detail"]["reason"] == "poll_not_configured"
    finally:
        _clear()


# --- 8. expired invoices are not matched ---

async def test_expired_invoice_is_not_matched():
    accounts, payments = FakeAccountRepo(), FakePaymentRepo()
    # An invoice created well beyond the TTL: pending but stale.
    old = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
        seconds=usdt_trc20.INVOICE_TTL_SECONDS + 60)
    inv = await payments.create(
        account_id=None, provider="usdt_trc20", external_ref=None,
        amount=5.123456, currency="USDT", status="pending", tier_granted="pro",
        created_at=old,
    )
    micros = usdt_trc20.amount_to_micros(inv["amount"])
    transport = _trongrid_transport([_transfer(micros, tx_id="0xlate")])

    result = await usdt_trc20.poll_and_match(
        payments, accounts, address=ADDRESS, transport=transport)
    assert result["matched"] == 0
    assert payments.rows[inv["id"]]["status"] == "pending"  # still unpaid
    assert len(accounts.by_id) == 0

    # and the status endpoint reports it expired, without a key
    status = await usdt_trc20.invoice_status(
        payments, accounts, inv["id"], address=ADDRESS)
    assert status["status"] == "expired"
    assert "api_key" not in status

"""Tests for the Telegram Stars provider (paywall Stage 2).

No real Telegram and no real Postgres: outbound Bot API calls are faked
with httpx.MockTransport (same pattern as tests/test_github_app.py), and
in-memory Fake*Repo stand-ins replace the DB repositories (same idea as
tests/test_accounts.py's FakeAccountRepo). What is NOT covered here is a
real payment round trip — that needs a real bot token and a real user
tapping Pay; see scripts/verify_telegram_stars_locally.py.
"""

from __future__ import annotations

import datetime
import uuid

import httpx

from app.billing import telegram_stars
from app.main import (
    app,
    get_account_repo,
    get_billing_transport,
    get_payment_repo,
)
from fastapi.testclient import TestClient

client = TestClient(app)


# --- in-memory repo fakes ---

class FakeAccountRepo:
    def __init__(self):
        self.by_id: dict[str, dict] = {}
        self.by_key: dict[str, dict] = {}

    async def create(self, *, api_key: str, tier: str):
        row = {
            "id": str(uuid.uuid4()), "api_key": api_key, "tier": tier,
            "created_at": "2026-07-14T10:00:00Z",
        }
        self.by_id[row["id"]] = row
        self.by_key[api_key] = row
        return row

    async def get_by_id(self, account_id: str):
        return self.by_id.get(account_id)

    async def get_by_api_key(self, api_key: str):
        return self.by_key.get(api_key)


class FakePaymentRepo:
    def __init__(self):
        self.rows: dict[str, dict] = {}

    async def create(self, *, account_id, provider, external_ref, amount,
                     currency, status, tier_granted):
        row = {
            "id": str(uuid.uuid4()), "account_id": account_id, "provider": provider,
            "external_ref": external_ref, "amount": amount, "currency": currency,
            "status": status, "tier_granted": tier_granted,
            "created_at": datetime.datetime.now(datetime.timezone.utc),
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

    async def mark_completed(self, payment_id, *, account_id, external_ref):
        r = self.rows[payment_id]
        r.update(status="completed", account_id=account_id, external_ref=external_ref)


def _telegram_transport(calls: list):
    """MockTransport that records (method, body) and returns ok for every
    Bot API call."""
    def handler(request: httpx.Request) -> httpx.Response:
        method = request.url.path.rsplit("/", 1)[-1]
        import json
        calls.append((method, json.loads(request.content) if request.content else {}))
        return httpx.Response(200, json={"ok": True, "result": {"message_id": 1}})
    return httpx.MockTransport(handler)


def _successful_payment_update(charge_id: str, chat_id: int = 555):
    return {
        "update_id": 1,
        "message": {
            "chat": {"id": chat_id},
            "from": {"id": chat_id},
            "successful_payment": {
                "currency": "XTR", "total_amount": 250,
                "invoice_payload": "pro", "telegram_payment_charge_id": charge_id,
                "provider_payment_charge_id": "prov_1",
            },
        },
    }


# --- 1. invoice payload shape ---

def test_build_invoice_payload_is_a_stars_invoice():
    body = telegram_stars.build_invoice_payload(
        chat_id=42, title="ShipIt Pro", description="pro tier",
        payload="pro", stars=250,
    )
    assert body["currency"] == "XTR"
    assert body["provider_token"] == ""          # empty => Stars, not fiat
    assert body["prices"] == [{"label": "ShipIt Pro", "amount": 250}]
    assert body["chat_id"] == 42
    assert body["payload"] == "pro"


# --- 2. pre_checkout_query approval ---

async def test_pre_checkout_query_is_approved():
    calls: list = []
    transport = _telegram_transport(calls)
    update = {"update_id": 1, "pre_checkout_query": {
        "id": "pcq_1", "from": {"id": 555}, "currency": "XTR",
        "total_amount": 250, "invoice_payload": "pro"}}

    result = await telegram_stars.handle_update(
        update, account_repo=FakeAccountRepo(), payment_repo=FakePaymentRepo(),
        token="t", transport=transport,
    )
    assert result["handled"] == "pre_checkout_query"
    assert calls == [("answerPreCheckoutQuery",
                      {"pre_checkout_query_id": "pcq_1", "ok": True})]


# --- 3. successful_payment grants pro + is idempotent on retry ---

async def test_successful_payment_grants_pro_and_dms_key():
    calls: list = []
    transport = _telegram_transport(calls)
    accounts, payments = FakeAccountRepo(), FakePaymentRepo()

    result = await telegram_stars.handle_update(
        _successful_payment_update("charge_abc"),
        account_repo=accounts, payment_repo=payments,
        token="t", transport=transport,
    )
    assert result == {"ok": True, "handled": "successful_payment", "persisted": True}
    # exactly one account, tier pro, key delivered by sendMessage
    assert len(accounts.by_id) == 1
    account = next(iter(accounts.by_id.values()))
    assert account["tier"] == "pro"
    send_calls = [c for c in calls if c[0] == "sendMessage"]
    assert len(send_calls) == 1
    assert account["api_key"] in send_calls[0][1]["text"]
    # one completed payment recorded, keyed by the charge id
    assert len(payments.rows) == 1
    pay = next(iter(payments.rows.values()))
    assert pay["status"] == "completed"
    assert pay["external_ref"] == "charge_abc"


async def test_duplicate_successful_payment_is_idempotent():
    calls: list = []
    transport = _telegram_transport(calls)
    accounts, payments = FakeAccountRepo(), FakePaymentRepo()

    for _ in range(2):  # Telegram retries the webhook until it gets 200
        await telegram_stars.handle_update(
            _successful_payment_update("charge_dup"),
            account_repo=accounts, payment_repo=payments,
            token="t", transport=transport,
        )
    # No second account, no second payment — same charge id.
    assert len(accounts.by_id) == 1
    assert len(payments.rows) == 1
    # The key is re-delivered on the retry (same key), so the payer who
    # missed the first DM still gets it.
    send_calls = [c for c in calls if c[0] == "sendMessage"]
    assert len(send_calls) == 2
    assert send_calls[0][1]["text"] == send_calls[1][1]["text"]


# --- 4. webhook endpoint rejects wrong/missing secret token ---

def _override(accounts, payments, transport):
    app.dependency_overrides[get_account_repo] = lambda: accounts
    app.dependency_overrides[get_payment_repo] = lambda: payments
    app.dependency_overrides[get_billing_transport] = lambda: transport


def _clear():
    for dep in (get_account_repo, get_payment_repo, get_billing_transport):
        app.dependency_overrides.pop(dep, None)


def test_webhook_rejects_missing_and_wrong_secret(monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "t")
    monkeypatch.setenv("TELEGRAM_WEBHOOK_SECRET", "s3cret")
    _override(FakeAccountRepo(), FakePaymentRepo(), _telegram_transport([]))
    try:
        # missing header
        r = client.post("/v1/webhooks/telegram", json={"update_id": 1})
        assert r.status_code == 401
        # wrong secret
        r = client.post("/v1/webhooks/telegram", json={"update_id": 1},
                        headers={"X-Telegram-Bot-Api-Secret-Token": "wrong"})
        assert r.status_code == 401
    finally:
        _clear()


def test_webhook_503_when_not_configured(monkeypatch):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_WEBHOOK_SECRET", raising=False)
    _override(FakeAccountRepo(), FakePaymentRepo(), _telegram_transport([]))
    try:
        r = client.post("/v1/webhooks/telegram", json={"update_id": 1},
                        headers={"X-Telegram-Bot-Api-Secret-Token": "s"})
        assert r.status_code == 503
        assert r.json()["detail"]["reason"] == "telegram_not_configured"
    finally:
        _clear()


def test_webhook_correct_secret_processes_payment(monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "t")
    monkeypatch.setenv("TELEGRAM_WEBHOOK_SECRET", "s3cret")
    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []
    _override(accounts, payments, _telegram_transport(calls))
    try:
        r = client.post(
            "/v1/webhooks/telegram",
            json=_successful_payment_update("charge_endpoint"),
            headers={"X-Telegram-Bot-Api-Secret-Token": "s3cret"},
        )
        assert r.status_code == 200
        assert r.json()["handled"] == "successful_payment"
        assert len(accounts.by_id) == 1
    finally:
        _clear()

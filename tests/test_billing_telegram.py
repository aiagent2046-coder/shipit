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

from app.billing import telegram_stars, usdt_trc20
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

    async def get_completed_by_telegram_chat_id(self, telegram_chat_id: str):
        found = [
            r for r in self.rows.values()
            if r["status"] == "completed"
            and r.get("telegram_chat_id") == telegram_chat_id
        ]
        return found[-1] if found else None

    async def link_telegram_chat_id(self, payment_id: str, telegram_chat_id: str):
        r = self.rows[payment_id]
        # First-wins: only stamp if unset (or already the same chat) -- mirrors
        # the DB method's WHERE clause so tests exercise the real guard.
        if r.get("telegram_chat_id") in (None, telegram_chat_id):
            r["telegram_chat_id"] = telegram_chat_id
        return r


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
        chat_id=42, title="Drydock Pro", description="pro tier",
        payload="pro", stars=250,
    )
    assert body["currency"] == "XTR"
    assert body["provider_token"] == ""          # empty => Stars, not fiat
    assert body["prices"] == [{"label": "Drydock Pro", "amount": 250}]
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


# --- 5. /mykey key recovery ---

def _text_update(text: str, chat_id: int = 555):
    return {"update_id": 1, "message": {
        "chat": {"id": chat_id}, "from": {"id": chat_id}, "text": text}}


async def _send(update, accounts, payments, calls):
    return await telegram_stars.handle_update(
        update, account_repo=accounts, payment_repo=payments,
        token="t", transport=_telegram_transport(calls),
    )


def _last_text(calls):
    sends = [c for c in calls if c[0] == "sendMessage"]
    return sends[-1][1]["text"] if sends else None


async def test_mykey_returns_key_for_linked_account():
    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []
    # A Stars purchase links this chat_id (555) to the account automatically.
    await _send(_successful_payment_update("charge_mykey", 555),
                accounts, payments, calls)
    account = next(iter(accounts.by_id.values()))

    calls.clear()
    result = await _send(_text_update("/mykey", 555), accounts, payments, calls)
    assert result["handled"] == "mykey" and result["found"] is True
    # The delivery text (same copy as purchase) carrying the exact key.
    assert account["api_key"] in _last_text(calls)


async def test_mykey_no_account_returns_helpful_message():
    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []
    result = await _send(_text_update("/mykey", 999), accounts, payments, calls)
    assert result["handled"] == "mykey" and result["found"] is False
    msg = _last_text(calls)
    # Explains both recovery paths, leaks no key.
    assert "Stars" in msg and "/link" in msg
    assert "sk_live_" not in msg


# --- 6. /link USDT payment claiming ---

async def _completed_usdt_payment(payments, accounts, tx_hash, *, chat_id=None):
    """A credited USDT payment as the poller leaves it: status completed,
    external_ref = tx hash, linked to a real account."""
    acct = await accounts.create(api_key="sk_live_usdtkey", tier="pro")
    row = await payments.create(
        account_id=acct["id"], provider=usdt_trc20.PROVIDER,
        external_ref=tx_hash, amount=5.5, currency="USDT",
        status="completed", tier_granted="pro",
    )
    if chat_id is not None:
        row["telegram_chat_id"] = chat_id
    return acct, row


async def test_link_valid_unlinked_payment_links_and_returns_key():
    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []
    acct, row = await _completed_usdt_payment(payments, accounts, "0xabc")

    result = await _send(_text_update("/link 0xabc", 777),
                         accounts, payments, calls)
    assert result["result"] == "linked"
    assert acct["api_key"] in _last_text(calls)
    # Persisted the association so a later /mykey works.
    assert row["telegram_chat_id"] == "777"


async def test_link_is_idempotent_for_same_chat():
    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []
    acct, _ = await _completed_usdt_payment(payments, accounts, "0xdup")
    for _ in range(2):
        result = await _send(_text_update("/link 0xdup", 777),
                             accounts, payments, calls)
        assert result["result"] == "linked"
    assert acct["api_key"] in _last_text(calls)


async def test_link_already_claimed_by_other_chat_is_rejected():
    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []
    acct, _ = await _completed_usdt_payment(
        payments, accounts, "0xowned", chat_id="111")

    result = await _send(_text_update("/link 0xowned", 222),
                         accounts, payments, calls)
    assert result["result"] == "already_claimed"
    msg = _last_text(calls)
    # No key leaked, and crucially no leak of the owning chat_id ("111").
    assert acct["api_key"] not in msg
    assert "111" not in msg


async def test_link_unknown_hash_reports_not_found():
    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []
    result = await _send(_text_update("/link 0xnope", 333),
                         accounts, payments, calls)
    assert result["result"] == "not_found"
    assert "wasn't found" in _last_text(calls)


async def test_link_pending_payment_reports_pending():
    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []
    # A payment row that carries the tx hash but isn't credited yet.
    await payments.create(
        account_id=None, provider=usdt_trc20.PROVIDER, external_ref="0xpending",
        amount=5.5, currency="USDT", status="pending", tier_granted="pro",
    )
    result = await _send(_text_update("/link 0xpending", 444),
                         accounts, payments, calls)
    assert result["result"] == "pending"
    assert "pending" in _last_text(calls).lower()


async def test_link_without_hash_shows_usage():
    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []
    result = await _send(_text_update("/link", 555), accounts, payments, calls)
    assert result["result"] == "missing_hash"
    assert "Usage" in _last_text(calls)


# --- 7. /upgrade sends a Stars invoice ---

async def test_upgrade_sends_stars_invoice(monkeypatch):
    monkeypatch.delenv("TELEGRAM_PRO_STARS", raising=False)
    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []
    result = await _send(_text_update("/upgrade", 888), accounts, payments, calls)
    assert result == {"ok": True, "handled": "upgrade"}
    # Exactly one sendInvoice call, carrying the verified Pro invoice params.
    invoices = [c for c in calls if c[0] == "sendInvoice"]
    assert len(invoices) == 1
    body = invoices[0][1]
    assert body["chat_id"] == 888
    assert body["title"] == telegram_stars.PRO_TITLE
    assert body["description"] == telegram_stars.PRO_DESCRIPTION
    assert body["payload"] == telegram_stars.PRO_PAYLOAD
    assert body["currency"] == "XTR"
    assert body["provider_token"] == ""
    assert body["prices"] == [
        {"label": telegram_stars.PRO_TITLE,
         "amount": telegram_stars.pro_stars_price()}
    ]

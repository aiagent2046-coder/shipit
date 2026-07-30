"""Tests for the bank_transfer provider — the manually confirmed one.

No real Postgres and no real Telegram: outbound Bot API calls go through
httpx.MockTransport (same pattern as tests/test_billing_telegram.py) and the
repositories are the shared in-memory fakes from tests/conftest.py. What is
covered here is everything that decides whether money turns into access:
who may press Confirm, what an unconfigured deployment does, and what the
payer's "I've paid" button is and is not allowed to change.

The idempotency of a double confirmation is asserted here against the fake
CAS gate and again in tests/test_db_postgres_smoke.py against the real SQL,
because the fake can only prove the caller handles the contract, not that
Postgres implements it.
"""

from __future__ import annotations

import datetime
import uuid

import httpx

import app.main as main_mod
from app.billing import bank_transfer, telegram_stars
from app.main import (
    app,
    get_account_repo,
    get_audit_repo,
    get_billing_transport,
    get_fixpack_repo,
    get_payment_repo,
    get_rate_limiter,
)
from app.ratelimit import RateLimiter
from fastapi.testclient import TestClient
from tests.conftest import (
    FakeAccountRepo,
    FakeCompletionCasMixin,
    FakeKeyDeliveryMixin,
    fixpack_live_job,
)

client = TestClient(app)

REPO_URL = "https://github.com/acme/widget"

# Obviously-fake stand-ins for the operator's real banking details, which are
# one private individual's and live only in the deployment's environment.
BANK_ENV = {
    "BANK_TRANSFER_BANK_NAME": "Example Test Bank",
    "BANK_TRANSFER_SWIFT": "TESTKZKAXXX",
    "BANK_TRANSFER_BENEFICIARY": "Test Beneficiary",
    "BANK_TRANSFER_ACCOUNT": "KZ00TEST0000000000000000",
    "BANK_TRANSFER_ADDRESS": "1 Test Street, Testville",
}

# The same five fields as they reach the payer, keyed the way the module and
# the API response key them.
BANK_DETAILS = {
    "bank_name": BANK_ENV["BANK_TRANSFER_BANK_NAME"],
    "swift": BANK_ENV["BANK_TRANSFER_SWIFT"],
    "beneficiary": BANK_ENV["BANK_TRANSFER_BENEFICIARY"],
    "account": BANK_ENV["BANK_TRANSFER_ACCOUNT"],
    "address": BANK_ENV["BANK_TRANSFER_ADDRESS"],
}

ADMIN_CHAT_ID = "424242"
STRANGER_CHAT_ID = 999111


# --- in-memory repo fakes ---

class FakePaymentRepo(FakeKeyDeliveryMixin, FakeCompletionCasMixin):
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

    async def get(self, payment_id):
        return self.rows.get(payment_id)

    async def get_by_external_ref(self, provider, external_ref):
        for r in self.rows.values():
            if r["provider"] == provider and r["external_ref"] == external_ref:
                return r
        return None

    async def link_telegram_chat_id(self, payment_id, telegram_chat_id):
        # First-wins, mirroring the real method's WHERE clause.
        r = self.rows[payment_id]
        if r.get("telegram_chat_id") in (None, telegram_chat_id):
            r["telegram_chat_id"] = telegram_chat_id
        return r


class FakeAuditRepo:
    def __init__(self):
        self.by_id: dict[str, dict] = {}

    def add(self, *, stack="fastapi", repo_url=REPO_URL):
        row = {"id": str(uuid.uuid4()), "stack": stack, "repo_url": repo_url}
        self.by_id[row["id"]] = row
        return row

    async def get(self, audit_id):
        return self.by_id.get(audit_id)


class FakeFixpackRepo:
    def __init__(self):
        self.rows: list[dict] = []

    async def create_paid(self, *, audit_id, stack):
        live = fixpack_live_job(self.rows, audit_id)
        if live is not None:
            return {**live, "inserted": False}
        row = {
            "id": str(uuid.uuid4()), "audit_id": audit_id, "pack": "fixpack",
            "stack": stack, "status": "paid", "verified": None, "detail": None,
            "pr_url": None, "pr_delivered": False,
            "created_at": datetime.datetime.now(datetime.timezone.utc),
        }
        self.rows.append(row)
        return {**row, "inserted": True}

    async def get_by_audit(self, audit_id):
        matches = [r for r in self.rows if r["audit_id"] == audit_id]
        return max(matches, key=lambda r: r["created_at"]) if matches else None


def _telegram_transport(calls: list):
    """Records (method, body) for every Bot API call and answers ok."""
    def handler(request: httpx.Request) -> httpx.Response:
        import json
        method = request.url.path.rsplit("/", 1)[-1]
        calls.append((method, json.loads(request.content) if request.content else {}))
        return httpx.Response(200, json={"ok": True, "result": {"message_id": 1}})
    return httpx.MockTransport(handler)


def _configure_bank(monkeypatch):
    for var, value in BANK_ENV.items():
        monkeypatch.setenv(var, value)


def _configure_alerts(monkeypatch, chat_id=ADMIN_CHAT_ID):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "fake-test-bot-token")
    if chat_id is None:
        monkeypatch.delenv("TELEGRAM_ADMIN_CHAT_ID", raising=False)
    else:
        monkeypatch.setenv("TELEGRAM_ADMIN_CHAT_ID", chat_id)
    # notify_operator throttles per dedupe key in a module global that
    # outlives a test, so every test that asserts on a notification clears it.
    import app.alerts as alerts_mod
    alerts_mod._last_sent.clear()


def _confirm_update(payment_id: str, *, from_id):
    return {
        "update_id": 1,
        "callback_query": {
            "id": "cbq-1",
            "from": {"id": from_id},
            "message": {"chat": {"id": from_id}, "message_id": 77},
            "data": f"{bank_transfer.CONFIRM_CALLBACK_PREFIX}{payment_id}",
        },
    }


async def _tap_confirm(update, *, accounts, payments, calls,
                       audits=None, fixpacks=None):
    return await telegram_stars.handle_update(
        update, account_repo=accounts, payment_repo=payments,
        audit_repo=audits, fixpack_repo=fixpacks,
        token="fake-test-bot-token", transport=_telegram_transport(calls),
    )


def _override(deps: dict):
    for dep, value in deps.items():
        # A closure, not `lambda v=value: v`: FastAPI reads the signature of an
        # override and would turn that default argument into a query parameter,
        # silently handing the endpoint something other than the fake.
        app.dependency_overrides[dep] = _returns(value)


def _returns(value):
    def dependency():
        return value
    return dependency


def _clear():
    for dep in (get_account_repo, get_payment_repo, get_audit_repo,
                get_fixpack_repo, get_billing_transport):
        app.dependency_overrides.pop(dep, None)


# --- 1. reference codes ---

def test_reference_shape_avoids_confusable_characters():
    for _ in range(200):
        ref = bank_transfer.generate_reference()
        assert bank_transfer.REFERENCE_RE.match(ref), ref
        # O/0 and I/1 are excluded so a payer copying the code into a banking
        # app by hand cannot produce a code that matches a different invoice.
        assert not set(ref[len(bank_transfer.REFERENCE_PREFIX):]) & set("O0I1")


async def test_reference_collision_is_retried_not_raised(monkeypatch):
    """A taken code is re-rolled. The endpoint must never turn a collision --
    which is expected, if rare -- into a 500."""
    payments = FakePaymentRepo()
    taken = bank_transfer.generate_reference()
    free = bank_transfer.generate_reference()
    while free == taken:
        free = bank_transfer.generate_reference()
    await payments.create(
        account_id=None, provider=bank_transfer.PROVIDER, external_ref=taken,
        amount=5.0, currency="USD", status="pending", tier_granted="pro",
    )

    # First two candidates collide with the row above; the third is free.
    candidates = iter([taken, taken, free])
    monkeypatch.setattr(bank_transfer, "generate_reference", lambda: next(candidates))

    invoice = await bank_transfer.create_invoice(payments, details=dict(BANK_DETAILS))
    assert invoice is not None
    assert invoice["reference"] == free


async def test_reference_reservation_gives_up_rather_than_looping(monkeypatch):
    """Every candidate taken -> None, which the endpoint reports as 503. An
    unbounded retry loop would hang the request instead."""
    payments = FakePaymentRepo()
    ref = bank_transfer.generate_reference()
    await payments.create(
        account_id=None, provider=bank_transfer.PROVIDER, external_ref=ref,
        amount=5.0, currency="USD", status="pending", tier_granted="pro",
    )
    monkeypatch.setattr(bank_transfer, "generate_reference", lambda: ref)
    assert await bank_transfer.create_invoice(payments, details=dict(BANK_DETAILS)) is None


# --- 2. configuration is all-or-nothing, and missing config is 503 ---

def test_bank_details_require_every_field(monkeypatch):
    _configure_bank(monkeypatch)
    assert bank_transfer.bank_details_from_env() is not None
    # A payer given a SWIFT code but no account number cannot send anything,
    # so a half-configured deployment must read as unconfigured.
    monkeypatch.setenv("BANK_TRANSFER_ACCOUNT", "")
    assert bank_transfer.bank_details_from_env() is None


def test_pro_invoice_503_when_bank_details_unset():
    """conftest strips the BANK_TRANSFER_* vars, so this is the default state."""
    payments = FakePaymentRepo()
    _override({get_payment_repo: payments})
    try:
        r = client.post("/v1/billing/bank-transfer/pro")
        assert r.status_code == 503
        assert r.json()["detail"]["reason"] == "bank_transfer_not_configured"
    finally:
        _clear()


def test_fixpack_invoice_503_when_bank_details_unset():
    payments, audits = FakePaymentRepo(), FakeAuditRepo()
    audit = audits.add()
    _override({get_payment_repo: payments, get_audit_repo: audits})
    try:
        r = client.post(f"/v1/audits/{audit['id']}/fixpack/bank-transfer")
        assert r.status_code == 503
        assert r.json()["detail"]["reason"] == "bank_transfer_not_configured"
    finally:
        _clear()


def test_pro_invoice_returns_details_and_reference(monkeypatch):
    _configure_bank(monkeypatch)
    payments = FakePaymentRepo()
    _override({get_payment_repo: payments})
    try:
        body = client.post("/v1/billing/bank-transfer/pro").json()
    finally:
        _clear()

    assert bank_transfer.REFERENCE_RE.match(body["reference"])
    assert body["currency"] == "USD"
    assert body["amount"] == "5.00"
    # The details ride in the response body, never in NEXT_PUBLIC_* config:
    # this is the only place the frontend can learn them.
    assert body["bank"]["swift"] == BANK_ENV["BANK_TRANSFER_SWIFT"]
    assert body["bank"]["account"] == BANK_ENV["BANK_TRANSFER_ACCOUNT"]
    row = payments.rows[body["payment_id"]]
    assert row["status"] == "pending"
    assert row["provider"] == "bank_transfer"
    assert row["account_id"] is None


def test_two_open_invoices_get_distinct_references(monkeypatch):
    _configure_bank(monkeypatch)
    payments = FakePaymentRepo()
    _override({get_payment_repo: payments})
    try:
        first = client.post("/v1/billing/bank-transfer/pro").json()
        second = client.post("/v1/billing/bank-transfer/pro").json()
    finally:
        _clear()
    assert first["reference"] != second["reference"]
    assert len(payments.rows) == 2


def test_fixpack_invoice_rejects_a_zip_audit(monkeypatch):
    _configure_bank(monkeypatch)
    payments, audits = FakePaymentRepo(), FakeAuditRepo()
    audit = audits.add(repo_url=None)
    _override({get_payment_repo: payments, get_audit_repo: audits})
    try:
        r = client.post(f"/v1/audits/{audit['id']}/fixpack/bank-transfer")
        assert r.status_code == 422
        assert r.json()["detail"]["reason"] == "not_github_audit"
    finally:
        _clear()


# --- 3. "I've paid" grants nothing and only pages the operator ---

async def test_report_paid_writes_no_state(monkeypatch):
    """The row must stay 'pending'. Any third status would fall outside the
    CAS predicate in mark_completed and make the payment unconfirmable
    forever -- a slow bank must never become lost money."""
    _configure_bank(monkeypatch)
    _configure_alerts(monkeypatch)
    payments = FakePaymentRepo()
    invoice = await bank_transfer.create_invoice(payments, details=dict(BANK_DETAILS))
    calls: list = []

    result = await bank_transfer.mark_awaiting_confirmation(
        payments, invoice["reference"], transport=_telegram_transport(calls),
    )

    assert result["status"] == "pending"
    assert result["notified"] is True
    assert payments.rows[invoice["payment_id"]]["status"] == "pending"
    assert payments.rows[invoice["payment_id"]]["account_id"] is None
    method, body = calls[0]
    assert method == "sendMessage"
    assert invoice["reference"] in body["text"]
    button = body["reply_markup"]["inline_keyboard"][0][0]
    assert button["callback_data"] == (
        f"{bank_transfer.CONFIRM_CALLBACK_PREFIX}{invoice['payment_id']}"
    )


async def test_report_paid_unknown_reference_is_404(monkeypatch):
    _configure_bank(monkeypatch)
    _configure_alerts(monkeypatch)
    payments = FakePaymentRepo()
    _override({get_payment_repo: payments,
                 get_billing_transport: _telegram_transport([])})
    try:
        r = client.post("/v1/billing/bank-transfer/DRY-ZZZZZZ/paid")
        assert r.status_code == 404
        assert r.json()["detail"]["reason"] == "not_found"
    finally:
        _clear()


def test_report_paid_is_rate_limited(monkeypatch):
    """Unauthenticated, and its whole job is pushing a message to the
    operator's phone, so the number of DISTINCT invoices one client can page
    about per window is bounded. (A repeat press of the SAME invoice is
    already collapsed by notify_operator's dedupe key.)"""
    _configure_bank(monkeypatch)
    _configure_alerts(monkeypatch)
    payments = FakePaymentRepo()
    # The endpoint passes its own per-route budget to check(), so that is what
    # has to shrink; the limiter here only supplies a frozen clock.
    monkeypatch.setattr(main_mod, "BANK_TRANSFER_PAID_LIMIT", 2)
    limiter = RateLimiter(limit=100, window_seconds=100, clock=lambda: 0.0)
    app.dependency_overrides[get_rate_limiter] = lambda: limiter
    _override({get_payment_repo: payments,
                 get_billing_transport: _telegram_transport([])})
    try:
        references = [
            client.post("/v1/billing/bank-transfer/pro").json()["reference"]
            for _ in range(3)
        ]
        codes = [
            client.post(f"/v1/billing/bank-transfer/{ref}/paid").status_code
            for ref in references
        ]
        assert codes == [200, 200, 429]
        # ... and the client stays cut off, including for an invoice it already
        # notified about successfully.
        last = client.post(f"/v1/billing/bank-transfer/{references[0]}/paid")
        assert last.status_code == 429
        assert last.json()["detail"]["reason"] == "rate_limited"
        assert int(last.headers["Retry-After"]) > 0
    finally:
        app.dependency_overrides.pop(get_rate_limiter, None)
        _clear()


# --- 4. the Confirm button is owner-only, and fails closed ---

async def test_callback_from_stranger_is_rejected_and_grants_nothing(monkeypatch):
    _configure_bank(monkeypatch)
    _configure_alerts(monkeypatch)
    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []
    invoice = await bank_transfer.create_invoice(payments, details=dict(BANK_DETAILS))

    result = await _tap_confirm(
        _confirm_update(invoice["payment_id"], from_id=STRANGER_CHAT_ID),
        accounts=accounts, payments=payments, calls=calls,
    )

    assert result["result"] == "forbidden"
    assert payments.rows[invoice["payment_id"]]["status"] == "pending"
    assert accounts.by_id == {}
    # Acknowledged so the stranger's client stops spinning, but told nothing
    # about what the button would have done.
    assert [m for m, _ in calls] == ["answerCallbackQuery"]
    assert "text" not in calls[0][1]


async def test_callback_rejected_when_no_admin_chat_id_is_configured(monkeypatch):
    """THE fail-closed case. With TELEGRAM_ADMIN_CHAT_ID unset there is nobody
    to compare against, so nobody is the operator. Reading an absent allowlist
    as "allow everyone" would turn a deployment that merely forgot one env var
    into a stranger-operated Confirm button handing out pro access."""
    _configure_bank(monkeypatch)
    _configure_alerts(monkeypatch, chat_id=None)
    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []
    invoice = await bank_transfer.create_invoice(payments, details=dict(BANK_DETAILS))

    for sender in (STRANGER_CHAT_ID, int(ADMIN_CHAT_ID)):
        result = await _tap_confirm(
            _confirm_update(invoice["payment_id"], from_id=sender),
            accounts=accounts, payments=payments, calls=calls,
        )
        assert result["result"] == "forbidden", sender

    assert payments.rows[invoice["payment_id"]]["status"] == "pending"
    assert accounts.by_id == {}


def test_is_operator_is_false_for_every_sender_without_an_allowlist(monkeypatch):
    """The allowlist predicate itself, checked directly: no configuration means
    no operator, including for the empty-string and None senders that a
    malformed update could carry."""
    monkeypatch.delenv("TELEGRAM_ADMIN_CHAT_ID", raising=False)
    for sender in (STRANGER_CHAT_ID, int(ADMIN_CHAT_ID), "", None, 0):
        assert telegram_stars._is_operator(sender) is False

    monkeypatch.setenv("TELEGRAM_ADMIN_CHAT_ID", "")
    for sender in (STRANGER_CHAT_ID, int(ADMIN_CHAT_ID), None):
        assert telegram_stars._is_operator(sender) is False

    monkeypatch.setenv("TELEGRAM_ADMIN_CHAT_ID", ADMIN_CHAT_ID)
    assert telegram_stars._is_operator(int(ADMIN_CHAT_ID)) is True
    assert telegram_stars._is_operator(ADMIN_CHAT_ID) is True
    assert telegram_stars._is_operator(STRANGER_CHAT_ID) is False


async def test_webhook_secret_alone_does_not_authorize_a_confirm(monkeypatch):
    """The webhook's secret header proves the update came from Telegram, not
    that the owner sent it. A correctly-signed update from a stranger must
    still be refused."""
    _configure_bank(monkeypatch)
    _configure_alerts(monkeypatch)
    monkeypatch.setenv("TELEGRAM_WEBHOOK_SECRET", "fake-test-webhook-secret")
    accounts, payments = FakeAccountRepo(), FakePaymentRepo()
    invoice = await bank_transfer.create_invoice(payments, details=dict(BANK_DETAILS))
    _override({get_account_repo: accounts, get_payment_repo: payments,
                 get_billing_transport: _telegram_transport([])})
    try:
        r = client.post(
            "/v1/webhooks/telegram",
            json=_confirm_update(invoice["payment_id"], from_id=STRANGER_CHAT_ID),
            headers={"X-Telegram-Bot-Api-Secret-Token": "fake-test-webhook-secret"},
        )
        assert r.status_code == 200
        assert r.json()["result"] == "forbidden"
    finally:
        _clear()
    assert accounts.by_id == {}


async def test_unknown_callback_data_is_ignored(monkeypatch):
    _configure_alerts(monkeypatch)
    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []
    result = await _tap_confirm(
        {"update_id": 1, "callback_query": {
            "id": "cbq-1", "from": {"id": int(ADMIN_CHAT_ID)}, "data": "something-else"}},
        accounts=accounts, payments=payments, calls=calls,
    )
    assert result["result"] == "ignored"
    assert accounts.by_id == {}


# --- 5. confirmation grants, and grants exactly once ---

async def test_operator_confirm_grants_pro_and_reveals_key_once(monkeypatch):
    _configure_bank(monkeypatch)
    _configure_alerts(monkeypatch)
    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []
    invoice = await bank_transfer.create_invoice(payments, details=dict(BANK_DETAILS))

    result = await _tap_confirm(
        _confirm_update(invoice["payment_id"], from_id=int(ADMIN_CHAT_ID)),
        accounts=accounts, payments=payments, calls=calls,
    )

    assert result["result"] == "confirmed"
    assert result["product"] == "pro_tier"
    row = payments.rows[invoice["payment_id"]]
    assert row["status"] == "completed"
    # external_ref stays the invoice's own reference code: a second press then
    # replays the SAME ref, which is exactly what the CAS gate admits.
    assert row["external_ref"] == invoice["reference"]
    assert len(accounts.by_id) == 1
    # The button is taken off the notification once it has been acted on.
    assert "editMessageText" in [m for m, _ in calls]

    status = await bank_transfer.invoice_status(
        payments, accounts, invoice["reference"])
    assert status["status"] == "completed"
    assert status["api_key"].startswith("sk_")
    # One-shot delivery: the key exists nowhere at rest, so a second poll can
    # only say so rather than show it again.
    again = await bank_transfer.invoice_status(
        payments, accounts, invoice["reference"])
    assert again["api_key"] is None
    assert again["key_already_delivered"] is True


async def test_double_confirm_grants_once(monkeypatch):
    """A human will press the button twice. The second press must replay
    through the CAS gate: same account, no second key, no second payment row."""
    _configure_bank(monkeypatch)
    _configure_alerts(monkeypatch)
    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []
    invoice = await bank_transfer.create_invoice(payments, details=dict(BANK_DETAILS))
    update = _confirm_update(invoice["payment_id"], from_id=int(ADMIN_CHAT_ID))

    first = await _tap_confirm(update, accounts=accounts, payments=payments,
                               calls=calls)
    second = await _tap_confirm(update, accounts=accounts, payments=payments,
                                calls=calls)

    assert first["result"] == second["result"] == "confirmed"
    assert len(accounts.by_id) == 1
    assert len(payments.rows) == 1
    assert accounts.rotations == []


async def test_operator_confirm_creates_one_fixpack_job(monkeypatch):
    _configure_bank(monkeypatch)
    _configure_alerts(monkeypatch)
    accounts, payments = FakeAccountRepo(), FakePaymentRepo()
    audits, fixpacks, calls = FakeAuditRepo(), FakeFixpackRepo(), []
    audit = audits.add()
    invoice = await bank_transfer.create_fixpack_invoice(
        payments, details=dict(BANK_DETAILS), audit_id=audit["id"])
    update = _confirm_update(invoice["payment_id"], from_id=int(ADMIN_CHAT_ID))

    first = await _tap_confirm(update, accounts=accounts, payments=payments,
                               calls=calls, audits=audits, fixpacks=fixpacks)
    second = await _tap_confirm(update, accounts=accounts, payments=payments,
                                calls=calls, audits=audits, fixpacks=fixpacks)

    assert first["result"] == second["result"] == "confirmed"
    assert first["product"] == "fixpack"
    assert len(fixpacks.rows) == 1
    assert fixpacks.rows[0]["status"] == "paid"
    assert fixpacks.rows[0]["stack"] == "fastapi"
    # A Fix Pack is a per-audit product, not an account upgrade: no key minted.
    assert accounts.by_id == {}

    status = await bank_transfer.invoice_status(
        payments, accounts, invoice["reference"])
    assert status == {
        "reference": invoice["reference"], "status": "completed",
        "product": "fixpack", "audit_id": audit["id"],
    }


async def test_confirm_unknown_payment_reports_not_found(monkeypatch):
    _configure_alerts(monkeypatch)
    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []
    result = await _tap_confirm(
        _confirm_update(str(uuid.uuid4()), from_id=int(ADMIN_CHAT_ID)),
        accounts=accounts, payments=payments, calls=calls,
    )
    assert result["result"] == "not_found"
    assert accounts.by_id == {}


async def test_report_paid_after_confirmation_does_not_page_again(monkeypatch):
    _configure_bank(monkeypatch)
    _configure_alerts(monkeypatch)
    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []
    invoice = await bank_transfer.create_invoice(payments, details=dict(BANK_DETAILS))
    await _tap_confirm(
        _confirm_update(invoice["payment_id"], from_id=int(ADMIN_CHAT_ID)),
        accounts=accounts, payments=payments, calls=calls)

    after: list = []
    result = await bank_transfer.mark_awaiting_confirmation(
        payments, invoice["reference"], transport=_telegram_transport(after))
    assert result == {"reference": invoice["reference"],
                      "status": "completed", "notified": False}
    assert after == []


# --- 6. expiry is cosmetic, never a reason money is lost ---

async def test_expired_invoice_is_still_confirmable(monkeypatch):
    """A SWIFT transfer can surface on day nine. The payer is told the quote is
    stale, but the operator can still confirm it and the payer still gets what
    they paid for."""
    _configure_bank(monkeypatch)
    _configure_alerts(monkeypatch)
    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []
    invoice = await bank_transfer.create_invoice(payments, details=dict(BANK_DETAILS))
    row = payments.rows[invoice["payment_id"]]
    row["created_at"] = datetime.datetime.now(datetime.timezone.utc) - (
        datetime.timedelta(seconds=bank_transfer.INVOICE_TTL_SECONDS + 60))

    status = await bank_transfer.invoice_status(
        payments, accounts, invoice["reference"])
    assert status == {"reference": invoice["reference"], "status": "expired"}

    result = await _tap_confirm(
        _confirm_update(invoice["payment_id"], from_id=int(ADMIN_CHAT_ID)),
        accounts=accounts, payments=payments, calls=calls)
    assert result["result"] == "confirmed"
    assert len(accounts.by_id) == 1


async def test_pending_status_carries_what_the_page_needs(monkeypatch):
    _configure_bank(monkeypatch)
    payments, accounts = FakePaymentRepo(), FakeAccountRepo()
    invoice = await bank_transfer.create_invoice(payments, details=dict(BANK_DETAILS))
    status = await bank_transfer.invoice_status(
        payments, accounts, invoice["reference"], details=dict(BANK_DETAILS))
    assert status["status"] == "pending"
    assert status["amount"] == "5.00"
    assert status["currency"] == "USD"
    assert status["bank"]["bank_name"] == BANK_ENV["BANK_TRANSFER_BANK_NAME"]
    assert "api_key" not in status


# --- 7. /link recovers a Pro key from a reference code ---

def _link_update(text: str, chat_id: int = 555):
    return {"update_id": 1, "message": {
        "chat": {"id": chat_id}, "from": {"id": chat_id}, "text": text}}


async def _link(text, accounts, payments, calls, chat_id=555):
    await telegram_stars.handle_update(
        _link_update(text, chat_id), account_repo=accounts, payment_repo=payments,
        token="fake-test-bot-token", transport=_telegram_transport(calls),
    )
    return calls[-1][1]["text"]


async def test_link_with_reference_delivers_the_key(monkeypatch):
    """The recovery door for the tab that was closed days before the operator
    got round to the statement."""
    _configure_bank(monkeypatch)
    _configure_alerts(monkeypatch)
    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []
    invoice = await bank_transfer.create_invoice(payments, details=dict(BANK_DETAILS))
    await _tap_confirm(
        _confirm_update(invoice["payment_id"], from_id=int(ADMIN_CHAT_ID)),
        accounts=accounts, payments=payments, calls=calls)
    calls.clear()

    payments.rows[invoice["payment_id"]]["telegram_chat_id"] = None
    text = await _link(f"/link {invoice['reference']}", accounts, payments, calls)
    assert "sk_" in text


async def test_link_accepts_a_lowercased_reference(monkeypatch):
    _configure_bank(monkeypatch)
    _configure_alerts(monkeypatch)
    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []
    invoice = await bank_transfer.create_invoice(payments, details=dict(BANK_DETAILS))
    text = await _link(
        f"/link {invoice['reference'].lower()}", accounts, payments, calls)
    # Recognised as a bank reference (not "not found"), just not yet confirmed.
    assert "hasn't been confirmed yet" in text


async def test_link_pending_reference_explains_the_wait(monkeypatch):
    _configure_bank(monkeypatch)
    _configure_alerts(monkeypatch)
    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []
    invoice = await bank_transfer.create_invoice(payments, details=dict(BANK_DETAILS))
    text = await _link(f"/link {invoice['reference']}", accounts, payments, calls)
    assert "business days" in text


async def test_link_unknown_reference_says_so(monkeypatch):
    _configure_alerts(monkeypatch)
    accounts, payments, calls = FakeAccountRepo(), FakePaymentRepo(), []
    text = await _link("/link DRY-ZZZZZZ", accounts, payments, calls)
    assert "reference code wasn't found" in text

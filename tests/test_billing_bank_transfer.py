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
import pytest

import app.routes.bank_transfer as bank_transfer_routes
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
    "BANK_TRANSFER_CARD": "0000 0000 0000 0000",
    "BANK_TRANSFER_BANK_NAME": "Example Test Bank",
    "BANK_TRANSFER_SWIFT": "TESTKZKAXXX",
    "BANK_TRANSFER_BENEFICIARY": "Test Beneficiary",
    "BANK_TRANSFER_ACCOUNT": "KZ00TEST0000000000000000",
    "BANK_TRANSFER_ADDRESS": "1 Test Street, Testville",
}

# The same six fields as they reach the payer, keyed the way the module and
# the API response key them.
BANK_DETAILS = {
    "card": BANK_ENV["BANK_TRANSFER_CARD"],
    "bank_name": BANK_ENV["BANK_TRANSFER_BANK_NAME"],
    "swift": BANK_ENV["BANK_TRANSFER_SWIFT"],
    "beneficiary": BANK_ENV["BANK_TRANSFER_BENEFICIARY"],
    "account": BANK_ENV["BANK_TRANSFER_ACCOUNT"],
    "address": BANK_ENV["BANK_TRANSFER_ADDRESS"],
}

ADMIN_CHAT_ID = "424242"
STRANGER_CHAT_ID = 999111

# Obviously-fake payer details: these stand in for a member of the public, not
# for anyone real. Both fields are required by the endpoint (see section 8), so
# every invoice-creating request in this file carries them.
PAYER_NAME = "Test Payer"
PAYER_EMAIL = "test.payer@example.invalid"
PAYER = {"payer_name": PAYER_NAME, "payer_email": PAYER_EMAIL}


# --- in-memory repo fakes ---


# `confirm()` now tells the PAYER their transfer landed, and pages the operator
# when it cannot reach them. Both go out over httpx, so a direct call to
# confirm() in a test reaches api.telegram.org unless a transport is handed in
# -- which it did, at 0.4s of DNS per call, until this was noticed. The suite's
# rule is that nothing touches the network; this is how these call sites keep
# it. Tests that drive confirm through the webhook already pass one.
def _no_network() -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True, "result": {"message_id": 1}})
    return httpx.MockTransport(handler)


class FakePaymentRepo(FakeKeyDeliveryMixin, FakeCompletionCasMixin):
    def __init__(self):
        self.rows: dict[str, dict] = {}

    async def create(self, *, account_id, provider, external_ref, amount,
                     currency, status, tier_granted, product="pro_tier",
                     audit_id=None, created_at=None,
                     payer_name=None, payer_email=None, payer_x=None):
        row = {
            "id": str(uuid.uuid4()), "account_id": account_id, "provider": provider,
            "external_ref": external_ref, "amount": amount, "currency": currency,
            "status": status, "tier_granted": tier_granted, "product": product,
            "audit_id": audit_id,
            "payer_name": payer_name, "payer_email": payer_email,
            "payer_x": payer_x,
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

    # Read by _reserve_unique_amount to find which kopeck suffixes are already
    # in flight. `created_after` is honoured for real here, not accepted and
    # ignored: the window is the whole fix for the pool saturating, so a fake
    # that ignores it would let that regression back in silently.
    async def list_pending(self, provider, *, created_after=None):
        return [
            r for r in self.rows.values()
            if r["provider"] == provider and r["status"] == "pending"
            and (created_after is None or r["created_at"] >= created_after)
        ]

    async def link_telegram_chat_id(self, payment_id, telegram_chat_id):
        # First-wins, mirroring the real method's WHERE clause.
        r = self.rows[payment_id]
        if r.get("telegram_chat_id") in (None, telegram_chat_id):
            r["telegram_chat_id"] = telegram_chat_id
        return r


class FakeAuditRepo:
    def __init__(self):
        self.by_id: dict[str, dict] = {}

    # A finding the Fix Pack can actually rewrite. Default rather than opt-in
    # because these tests are about invoice mechanics, and since the sell
    # endpoints refuse an audit with nothing auto-fixable, an audit with no
    # findings at all is no longer a neutral fixture -- it is the refusal case.
    def add(self, *, stack="fastapi", repo_url=REPO_URL, findings=None):
        row = {"id": str(uuid.uuid4()), "stack": stack, "repo_url": repo_url,
               "findings_json": [{"rule_id": "aws-access-key-id",
                                  "file": "config.py", "line": 1,
                                  "title": "AWS Access Key ID",
                                  "context": None}]
               if findings is None else findings}
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
        r = client.post("/v1/billing/bank-transfer/pro", json=PAYER)
        assert r.status_code == 503
        assert r.json()["detail"]["reason"] == "bank_transfer_not_configured"
    finally:
        _clear()


def test_fixpack_invoice_503_when_bank_details_unset():
    payments, audits = FakePaymentRepo(), FakeAuditRepo()
    audit = audits.add()
    _override({get_payment_repo: payments, get_audit_repo: audits})
    try:
        r = client.post(f"/v1/audits/{audit['id']}/fixpack/bank-transfer",
                        json=PAYER)
        assert r.status_code == 503
        assert r.json()["detail"]["reason"] == "bank_transfer_not_configured"
    finally:
        _clear()


def test_pricing_publishes_the_fixpack_price(monkeypatch):
    """The storefront's only source for what anything costs. /pricing showed no
    price at all before this endpoint existed, so the figure was unknowable
    until a buyer had already started a checkout."""
    monkeypatch.delenv("BANK_TRANSFER_FIXPACK_PRICE_USD", raising=False)
    r = client.get("/v1/pricing")
    assert r.status_code == 200
    assert r.json() == {"fixpack": {"amount": "10.00", "currency": "USD"}}


def test_pricing_follows_the_configured_price(monkeypatch):
    """Read through the same accessor the invoice creator uses, so the page
    cannot advertise one figure while checkout charges another. A number typed
    into the frontend would drift the first time this env var moved."""
    monkeypatch.setenv("BANK_TRANSFER_FIXPACK_PRICE_USD", "14")
    assert client.get("/v1/pricing").json()["fixpack"]["amount"] == "14.00"


async def test_advertised_price_is_what_the_invoice_charges(monkeypatch):
    """The anti-drift assertion that matters: the advertised amount and the
    amount actually demanded must agree to the dollar. They differ in kopecks
    by design -- the suffix is the per-order matching key -- so compare the
    whole-dollar part and require the surcharge to stay under one unit."""
    monkeypatch.delenv("BANK_TRANSFER_FIXPACK_PRICE_USD", raising=False)
    advertised = client.get("/v1/pricing").json()["fixpack"]

    payments = FakePaymentRepo()
    invoice = await bank_transfer.create_fixpack_invoice(
        payments, details=BANK_DETAILS, audit_id=str(uuid.uuid4()),
        payer_name=PAYER["payer_name"], payer_email=PAYER["payer_email"],
    )

    assert invoice["currency"] == advertised["currency"]
    charged, quoted = float(invoice["amount"]), float(advertised["amount"])
    assert int(charged) == int(quoted)
    assert 0 <= charged - quoted < 1


def test_billing_details_publishes_the_requisites(monkeypatch):
    """The footer's source. Public and unauthenticated by the operator's own
    decision -- these requisites are published information, and this endpoint
    is the single place the frontend reads them from."""
    _configure_bank(monkeypatch)
    r = client.get("/v1/billing/details")
    assert r.status_code == 200
    assert r.json()["bank"] == BANK_DETAILS


def test_billing_details_is_200_with_null_when_unconfigured():
    """Not 503: a footer is not a checkout. An unconfigured deployment renders
    a footer without a requisites block, not an error on every page."""
    r = client.get("/v1/billing/details")
    assert r.status_code == 200
    assert r.json() == {"bank": None}


def test_pro_invoice_returns_details_and_reference(monkeypatch):
    _configure_bank(monkeypatch)
    payments = FakePaymentRepo()
    _override({get_payment_repo: payments})
    try:
        body = client.post("/v1/billing/bank-transfer/pro", json=PAYER).json()
    finally:
        _clear()

    assert bank_transfer.REFERENCE_RE.match(body["reference"])
    assert body["currency"] == "USD"
    # 5.00 plus a kopeck suffix, never the bare price and never a discount.
    # The quoted amount is the price exactly -- no kopeck nonce. The storefront
    # advertising one figure while checkout demanded another is what removed it.
    assert body["amount"] == bank_transfer.pro_price_usd()
    # The card is what the checkout page renders and the payer copies; the rest
    # ride along for the footer, and none of it is ever NEXT_PUBLIC_* config.
    assert body["bank"]["card"] == BANK_ENV["BANK_TRANSFER_CARD"]
    assert body["bank"]["swift"] == BANK_ENV["BANK_TRANSFER_SWIFT"]
    assert body["bank"]["account"] == BANK_ENV["BANK_TRANSFER_ACCOUNT"]
    row = payments.rows[body["payment_id"]]
    assert row["status"] == "pending"
    assert row["provider"] == "bank_transfer"
    assert row["account_id"] is None


async def test_saturation_falls_back_to_the_bare_price(monkeypatch):
    """With every suffix in flight the sale still goes through at the plain
    price. Refusing to sell because a hundred invoices are open would be a
    worse failure than two orders sharing an amount -- name and email still
    tell those apart."""
    _configure_bank(monkeypatch)
    payments = FakePaymentRepo()
    for _ in range(99):
        await bank_transfer.create_invoice(payments, details=dict(BANK_DETAILS))
    saturated = await bank_transfer.create_invoice(
        payments, details=dict(BANK_DETAILS))
    assert saturated["amount"] == "5.00"


def test_two_open_invoices_get_distinct_references(monkeypatch):
    _configure_bank(monkeypatch)
    payments = FakePaymentRepo()
    _override({get_payment_repo: payments})
    try:
        first = client.post("/v1/billing/bank-transfer/pro", json=PAYER).json()
        second = client.post("/v1/billing/bank-transfer/pro", json=PAYER).json()
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
        r = client.post(f"/v1/audits/{audit['id']}/fixpack/bank-transfer",
                        json=PAYER)
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
    monkeypatch.setattr(bank_transfer_routes, "BANK_TRANSFER_PAID_LIMIT", 2)
    limiter = RateLimiter(limit=100, window_seconds=100, clock=lambda: 0.0)
    app.dependency_overrides[get_rate_limiter] = lambda: limiter
    _override({get_payment_repo: payments,
                 get_billing_transport: _telegram_transport([])})
    try:
        references = [
            client.post("/v1/billing/bank-transfer/pro", json=PAYER).json()["reference"]
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
    # The amount the payer was quoted, suffix included -- not the catalogue
    # price, or the page would tell them to send the wrong figure.
    assert status["amount"] == f"{float(invoice['amount']):.2f}"
    # The quoted amount is the price exactly -- no kopeck nonce. The storefront
    # advertising one figure while checkout demanded another is what removed it.
    assert status["amount"] == bank_transfer.pro_price_usd()
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


# --- 8. required payer contact (migration 0026) ---
#
# Required, not decorative: a card transfer carries no reference field, so the
# payer's name on the statement plus their email is the only thing the operator
# can match an incoming payment against.


def test_pro_invoice_records_payer_contact(monkeypatch):
    _configure_bank(monkeypatch)
    payments = FakePaymentRepo()
    _override({get_payment_repo: payments})
    try:
        body = client.post(
            "/v1/billing/bank-transfer/pro",
            json={"payer_name": PAYER_NAME, "payer_email": PAYER_EMAIL},
        ).json()
    finally:
        _clear()

    row = payments.rows[body["payment_id"]]
    assert row["payer_name"] == PAYER_NAME
    assert row["payer_email"] == PAYER_EMAIL
    # Contact is for the operator's books only -- it must not leak back into
    # the payer-facing invoice, which is rendered on a shared checkout card.
    assert "payer_name" not in body
    assert "payer_email" not in body


@pytest.mark.parametrize("body", [
    None,                                                  # no body at all
    {},                                                    # neither field
    {"payer_name": PAYER_NAME},                            # no email
    {"payer_email": PAYER_EMAIL},                          # no name
    {"payer_name": "   ", "payer_email": PAYER_EMAIL},     # blank name
    {"payer_name": PAYER_NAME, "payer_email": "nope"},     # not an address
])
def test_pro_invoice_requires_both_contact_fields(monkeypatch, body):
    """422 and no payment row. Without a name the operator cannot tell whose
    card transfer arrived, so an invoice that can never be confirmed must not
    be created in the first place."""
    _configure_bank(monkeypatch)
    payments = FakePaymentRepo()
    _override({get_payment_repo: payments})
    try:
        r = client.post("/v1/billing/bank-transfer/pro", json=body)
    finally:
        _clear()

    assert r.status_code == 422
    assert payments.rows == {}


def test_payer_contact_is_stored_stripped(monkeypatch):
    """Surrounding whitespace is the payer's, not part of their name: the
    operator compares this string against a bank statement by eye."""
    _configure_bank(monkeypatch)
    payments = FakePaymentRepo()
    _override({get_payment_repo: payments})
    try:
        r = client.post(
            "/v1/billing/bank-transfer/pro",
            json={"payer_name": f"  {PAYER_NAME}  ",
                  "payer_email": f" {PAYER_EMAIL} "},
        )
    finally:
        _clear()

    assert r.status_code == 201
    row = payments.rows[r.json()["payment_id"]]
    assert row["payer_name"] == PAYER_NAME
    assert row["payer_email"] == PAYER_EMAIL


def test_payer_email_check_stays_weak(monkeypatch):
    """An "@" is the whole test. Nothing is ever sent to this address -- it is
    a tie-breaker between two payers of the same name -- so rejecting an
    unusual TLD would cost a sale to enforce a rule nothing depends on."""
    _configure_bank(monkeypatch)
    payments = FakePaymentRepo()
    _override({get_payment_repo: payments})
    try:
        r = client.post(
            "/v1/billing/bank-transfer/pro",
            json={"payer_name": PAYER_NAME, "payer_email": "a@b"},
        )
    finally:
        _clear()

    assert r.status_code == 201
    assert payments.rows[r.json()["payment_id"]]["payer_email"] == "a@b"


def test_payer_contact_is_length_capped(monkeypatch):
    """The one thing that IS rejected: a field long enough to be abuse rather
    than a name. 422 from the model, and no payment row written."""
    _configure_bank(monkeypatch)
    payments = FakePaymentRepo()
    _override({get_payment_repo: payments})
    try:
        r = client.post(
            "/v1/billing/bank-transfer/pro",
            json={"payer_name": "x" * 201, "payer_email": PAYER_EMAIL},
        )
    finally:
        _clear()

    assert r.status_code == 422
    assert payments.rows == {}


def test_fixpack_invoice_records_payer_contact(monkeypatch):
    _configure_bank(monkeypatch)
    payments, audits = FakePaymentRepo(), FakeAuditRepo()
    audit = audits.add()
    _override({get_payment_repo: payments, get_audit_repo: audits})
    try:
        body = client.post(
            f"/v1/audits/{audit['id']}/fixpack/bank-transfer",
            json={"payer_name": PAYER_NAME, "payer_email": PAYER_EMAIL},
        ).json()
    finally:
        _clear()

    row = payments.rows[body["payment_id"]]
    assert row["payer_name"] == PAYER_NAME
    assert row["payer_email"] == PAYER_EMAIL
    assert row["product"] == bank_transfer.PRODUCT_FIXPACK


async def test_notification_carries_the_payer_contact(monkeypatch):
    """The operator's Telegram message is the only consumer of these fields."""
    _configure_bank(monkeypatch)
    _configure_alerts(monkeypatch)
    payments, calls = FakePaymentRepo(), []
    invoice = await bank_transfer.create_invoice(
        payments, details=dict(BANK_DETAILS),
        payer_name=PAYER_NAME, payer_email=PAYER_EMAIL,
    )

    await bank_transfer.mark_awaiting_confirmation(
        payments, invoice["reference"], transport=_telegram_transport(calls),
    )

    text = calls[0][1]["text"]
    assert f"Payer: {PAYER_NAME}" in text
    assert f"Email: {PAYER_EMAIL}" in text


async def test_notification_omits_the_lines_when_no_contact_was_given(monkeypatch):
    """No empty "Payer:" line -- a label with nothing after it tells the
    operator less than no line at all."""
    _configure_bank(monkeypatch)
    _configure_alerts(monkeypatch)
    payments, calls = FakePaymentRepo(), []
    invoice = await bank_transfer.create_invoice(payments, details=dict(BANK_DETAILS))

    await bank_transfer.mark_awaiting_confirmation(
        payments, invoice["reference"], transport=_telegram_transport(calls),
    )

    text = calls[0][1]["text"]
    assert "Payer:" not in text
    assert "Email:" not in text
    assert invoice["reference"] in text


async def test_blank_payer_contact_is_treated_as_absent(monkeypatch):
    """A payer who tabs through the inputs leaves whitespace, not a name."""
    _configure_bank(monkeypatch)
    _configure_alerts(monkeypatch)
    payments, calls = FakePaymentRepo(), []
    invoice = await bank_transfer.create_invoice(
        payments, details=dict(BANK_DETAILS), payer_name="   ", payer_email="",
    )

    await bank_transfer.mark_awaiting_confirmation(
        payments, invoice["reference"], transport=_telegram_transport(calls),
    )

    text = calls[0][1]["text"]
    assert "Payer:" not in text
    assert "Email:" not in text


# --- a second Fix Pack for one audit ---
#
# create_paid is idempotent per audit: a second confirmed payment joins the
# live job instead of opening a second fix PR. That is correct for a retry and
# wrong for a second BUYER -- two payments, one pull request, and "completed"
# reported to both. Two defences, because neither covers the other's case.


def test_second_fixpack_invoice_is_refused_while_a_job_is_live(monkeypatch):
    """Defence one: don't sell. This is the last moment where refusing costs
    nothing, because no money has moved yet."""
    _configure_bank(monkeypatch)
    payments, audits, fixpacks = FakePaymentRepo(), FakeAuditRepo(), FakeFixpackRepo()
    audit = audits.add()
    _override({get_payment_repo: payments, get_audit_repo: audits,
               get_fixpack_repo: fixpacks})
    try:
        first = client.post(
            f"/v1/audits/{audit['id']}/fixpack/bank-transfer", json=PAYER)
        assert first.status_code == 201
        # The job appears when the operator CONFIRMS, not when the invoice is
        # opened, so put one there directly rather than driving the whole
        # Telegram callback -- the endpoint under test only reads the status.
        fixpacks.rows.append({
            "id": str(uuid.uuid4()), "audit_id": audit["id"], "pack": "fixpack",
            "stack": "fastapi", "status": "paid", "verified": None,
            "detail": None, "pr_url": None, "pr_delivered": False,
            "created_at": datetime.datetime.now(datetime.timezone.utc),
        })

        second = client.post(
            f"/v1/audits/{audit['id']}/fixpack/bank-transfer", json=PAYER)
        assert second.status_code == 409
        assert second.json()["detail"]["reason"] == "fixpack_already_in_progress"
        # Refused before anything was written: no second invoice to confirm.
        assert len(payments.rows) == 1
    finally:
        _clear()


def test_a_terminal_job_does_not_block_a_new_purchase(monkeypatch):
    """The boundary. The refusal mirrors create_paid's ON CONFLICT predicate --
    'paid' and 'running' only -- so re-buying after a failed Fix Pack, or after
    a delivered one on a re-run audit, still works. A stricter check here would
    refuse sales the database would have served."""
    _configure_bank(monkeypatch)
    payments, audits, fixpacks = FakePaymentRepo(), FakeAuditRepo(), FakeFixpackRepo()
    audit = audits.add()
    fixpacks.rows.append({
        "id": str(uuid.uuid4()), "audit_id": audit["id"], "pack": "fixpack",
        "stack": "fastapi", "status": "failed", "verified": None, "detail": None,
        "pr_url": None, "pr_delivered": False,
        "created_at": datetime.datetime.now(datetime.timezone.utc),
    })
    _override({get_payment_repo: payments, get_audit_repo: audits,
               get_fixpack_repo: fixpacks})
    try:
        r = client.post(
            f"/v1/audits/{audit['id']}/fixpack/bank-transfer", json=PAYER)
        assert r.status_code == 201
    finally:
        _clear()


async def test_confirming_a_second_payment_warns_the_operator(monkeypatch):
    """Defence two, for the case defence one cannot see.

    Both invoices are opened BEFORE either is confirmed, so no job exists yet
    and the 409 has nothing to refuse on. With a 7-day TTL and manual
    confirmation that window is a normal week. The money is then taken twice
    and nothing downstream can undo it -- only the operator can, and only if
    they are told.
    """
    _configure_bank(monkeypatch)
    _configure_alerts(monkeypatch)
    accounts, payments = FakeAccountRepo(), FakePaymentRepo()
    audits, fixpacks = FakeAuditRepo(), FakeFixpackRepo()
    audit = audits.add()

    first_invoice = await bank_transfer.create_fixpack_invoice(
        payments, details=dict(BANK_DETAILS), audit_id=audit["id"])
    second_invoice = await bank_transfer.create_fixpack_invoice(
        payments, details=dict(BANK_DETAILS), audit_id=audit["id"])
    assert first_invoice["reference"] != second_invoice["reference"]

    first = await bank_transfer.confirm(
        payment_repo=payments, account_repo=accounts, audit_repo=audits,
        fixpack_repo=fixpacks, payment_id=first_invoice["payment_id"],
        transport=_no_network())
    second = await bank_transfer.confirm(
        payment_repo=payments, account_repo=accounts, audit_repo=audits,
        fixpack_repo=fixpacks, payment_id=second_invoice["payment_id"],
        transport=_no_network())

    # Both payments went through and both report granted -- that part is
    # unchanged and correct, the Fix Pack IS queued.
    assert first["granted"] is True and second["granted"] is True
    assert len(fixpacks.rows) == 1

    # What changed: the second one no longer claims to have funded work.
    assert first["joined_existing_job"] is False
    assert second["joined_existing_job"] is True

    text = telegram_stars._confirmed_text(second)
    assert "WARNING" in text
    assert "funded no additional work" in text
    assert "refund" in text
    # The first confirmation stays clean; a warning on every Fix Pack would be
    # noise and would stop being read.
    assert "WARNING" not in telegram_stars._confirmed_text(first)


async def test_a_pro_confirmation_never_carries_the_warning(monkeypatch):
    """joined_existing_job is a Fix Pack concept. Pro grants an account, and
    grant_pro_tier's replay path returns a row with no `inserted` key at all --
    "we don't know" must not render as "we double-charged"."""
    _configure_bank(monkeypatch)
    accounts, payments = FakeAccountRepo(), FakePaymentRepo()
    audits, fixpacks = FakeAuditRepo(), FakeFixpackRepo()
    invoice = await bank_transfer.create_invoice(payments, details=dict(BANK_DETAILS))
    result = await bank_transfer.confirm(
        payment_repo=payments, account_repo=accounts, audit_repo=audits,
        fixpack_repo=fixpacks, payment_id=invoice["payment_id"],
        transport=_no_network())
    assert result["joined_existing_job"] is False
    assert "WARNING" not in telegram_stars._confirmed_text(result)
def test_invoice_creation_is_rate_limited(monkeypatch):
    """Opening an invoice is unauthenticated by necessity -- a buyer has no key
    until they have paid -- and each one takes a kopeck suffix for the length
    of the TTL window. Unbounded, that is a way for anyone to fill the pool and
    switch the operator's matching hint off for everybody."""
    _configure_bank(monkeypatch)
    payments = FakePaymentRepo()
    monkeypatch.setattr(bank_transfer_routes, "BANK_TRANSFER_INVOICE_LIMIT", 2)
    limiter = RateLimiter(limit=100, window_seconds=100, clock=lambda: 0.0)
    app.dependency_overrides[get_rate_limiter] = lambda: limiter
    _override({get_payment_repo: payments})
    try:
        codes = [
            client.post("/v1/billing/bank-transfer/pro", json=PAYER).status_code
            for _ in range(3)
        ]
        assert codes == [201, 201, 429]
        last = client.post("/v1/billing/bank-transfer/pro", json=PAYER)
        assert last.json()["detail"]["reason"] == "rate_limited"
        assert int(last.headers["Retry-After"]) > 0
        # Refused before anything was written: a 429 must not consume a suffix.
        assert len(payments.rows) == 2
    finally:
        app.dependency_overrides.pop(get_rate_limiter, None)
        _clear()


def test_pro_and_fixpack_share_one_invoice_budget(monkeypatch):
    """One limiter key across both creators, because they draw suffixes from
    one pool. Separate budgets would let the same client take twice as much
    of it."""
    _configure_bank(monkeypatch)
    payments = FakePaymentRepo()
    audits = FakeAuditRepo()
    audit = audits.add()
    monkeypatch.setattr(bank_transfer_routes, "BANK_TRANSFER_INVOICE_LIMIT", 2)
    limiter = RateLimiter(limit=100, window_seconds=100, clock=lambda: 0.0)
    app.dependency_overrides[get_rate_limiter] = lambda: limiter
    _override({get_payment_repo: payments, get_audit_repo: audits})
    try:
        assert client.post(
            "/v1/billing/bank-transfer/pro", json=PAYER).status_code == 201
        assert client.post(
            f"/v1/audits/{audit['id']}/fixpack/bank-transfer",
            json=PAYER).status_code == 201
        # Budget spent across the two routes, not per route.
        assert client.post(
            "/v1/billing/bank-transfer/pro", json=PAYER).status_code == 429
    finally:
        app.dependency_overrides.pop(get_rate_limiter, None)
        _clear()


def test_bank_transfer_refuses_when_nothing_is_auto_fixable(monkeypatch):
    """Same refusal on the card route. Three sell points grew independently
    and already duplicate the audit and repo_url gates, so the thing that
    breaks is one of them being missed -- see #128.

    THE OTHER TWO SELL POINTS ARE GONE. USDT and PayPal were removed as ways
    to pay, and the four cases below came with the USDT route: they were the
    only place each was checked. A gate is not tested because it is written
    down three times; it is tested because some test exercises it. Moved here
    rather than deleted with the endpoint that happened to host them."""
    _configure_bank(monkeypatch)
    payments, audits, fixpacks = FakePaymentRepo(), FakeAuditRepo(), FakeFixpackRepo()
    audit = audits.add(findings=[
        {"rule_id": "no-tests", "file": "", "line": 0, "title": "No tests",
         "context": None},
    ])
    _override({get_payment_repo: payments, get_audit_repo: audits,
               get_fixpack_repo: fixpacks})
    try:
        r = client.post(
            f"/v1/audits/{audit['id']}/fixpack/bank-transfer", json=PAYER)
        assert r.status_code == 409
        assert r.json()["detail"]["reason"] == "no_auto_fixable_findings"
        assert len(payments.rows) == 0
    finally:
        _clear()


def test_fixpack_invoice_for_an_unknown_audit_is_404(monkeypatch):
    """Nothing to sell against. A 404 rather than an invoice, because an
    invoice opened against an audit that does not exist can be paid and can
    never be fulfilled."""
    _configure_bank(monkeypatch)
    payments, audits = FakePaymentRepo(), FakeAuditRepo()
    _override({get_payment_repo: payments, get_audit_repo: audits})
    try:
        r = client.post(
            f"/v1/audits/{uuid.uuid4()}/fixpack/bank-transfer", json=PAYER)
        assert r.status_code == 404
        assert r.json()["detail"]["reason"] == "audit_not_found"
        assert len(payments.rows) == 0
    finally:
        _clear()


def test_a_finding_only_in_a_comment_is_not_something_to_sell(monkeypatch):
    """The seam with #132. That change stopped the Fix Pack from rewriting
    comments; this one stops us charging for the rewrite it will not do."""
    _configure_bank(monkeypatch)
    payments, audits, fixpacks = FakePaymentRepo(), FakeAuditRepo(), FakeFixpackRepo()
    audit = audits.add(findings=[
        {"rule_id": "aws-access-key-id", "file": "app.py", "line": 3,
         "title": "AWS Access Key ID", "context": "comment"},
    ])
    _override({get_payment_repo: payments, get_audit_repo: audits,
               get_fixpack_repo: fixpacks})
    try:
        r = client.post(
            f"/v1/audits/{audit['id']}/fixpack/bank-transfer", json=PAYER)
        assert r.status_code == 409
        assert len(payments.rows) == 0
    finally:
        _clear()


def test_an_audit_with_no_findings_at_all_is_refused(monkeypatch):
    """A clean repository. Nothing was found, so there is nothing to fix --
    and this is the state a customer is most likely to try to buy from,
    because a good score reads as 'everything is fine, but let me tidy up'."""
    _configure_bank(monkeypatch)
    payments, audits, fixpacks = FakePaymentRepo(), FakeAuditRepo(), FakeFixpackRepo()
    audit = audits.add(findings=[])
    _override({get_payment_repo: payments, get_audit_repo: audits,
               get_fixpack_repo: fixpacks})
    try:
        assert client.post(
            f"/v1/audits/{audit['id']}/fixpack/bank-transfer",
            json=PAYER).status_code == 409
        assert len(payments.rows) == 0
    finally:
        _clear()


def test_a_real_secret_is_still_sellable(monkeypatch):
    """The boundary, and the reason the three refusals above are safe. A check
    that refused everything would be worse than the bug it guards: it would
    stop the product selling at all, on the one rail that still sells."""
    _configure_bank(monkeypatch)
    payments, audits, fixpacks = FakePaymentRepo(), FakeAuditRepo(), FakeFixpackRepo()
    audit = audits.add()     # default fixture: a real secret
    _override({get_payment_repo: payments, get_audit_repo: audits,
               get_fixpack_repo: fixpacks})
    try:
        r = client.post(
            f"/v1/audits/{audit['id']}/fixpack/bank-transfer", json=PAYER)
        assert r.status_code == 201
        assert len(payments.rows) == 1
    finally:
        _clear()

"""Tests for the Fix Pack purchase flow (paywall Stage 2, second product).

A Fix Pack is bought per-audit and is entirely separate from the Pro tier:
it grants no account/tier and mints no API key -- a successful payment just
creates a paid `fixpack_jobs` row for the audit (generation is a separate
follow-up). V1 offers it only for audits run from a GitHub URL (repo_url
not null); a zip-upload audit has no repo to open a fix PR against.

Same no-real-Telegram / no-real-chain / no-real-Postgres posture as
tests/test_billing_telegram.py and tests/test_billing_usdt.py: Bot API and
TronGrid calls are faked with httpx.MockTransport and the repositories are
in-memory fakes.
"""

from __future__ import annotations

import datetime
import re
import uuid

import httpx
from fastapi.testclient import TestClient

from app.billing import telegram_stars, usdt_trc20
from app.db import STALE_LEASE_DETAIL_PREFIX
from app.main import (
    app,
    get_audit_repo,
    get_account_repo,
    get_billing_transport,
    get_fixpack_repo,
    get_payment_repo,
)
from tests.conftest import (
    FakeAccountRepo,
    FakeCompletionCasMixin,
    FakeKeyDeliveryMixin,
    fixpack_live_job,
)

client = TestClient(app)

ADDRESS = "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb"
USDT_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
REPO_URL = "https://github.com/acme/widget"


# --- in-memory repo fakes ---

class FakeAuditRepo:
    def __init__(self):
        self.by_id: dict[str, dict] = {}

    # A finding the Fix Pack can actually rewrite. Default rather than opt-in
    # because these tests are about invoice mechanics, and since the sell
    # endpoints refuse an audit with nothing auto-fixable, an audit with no
    # findings at all is no longer a neutral fixture -- it is the refusal case.
    def add(self, *, stack="fastapi", repo_url=REPO_URL, findings=None,
            access_token="tok-abc123"):
        row = {"id": str(uuid.uuid4()), "stack": stack, "repo_url": repo_url,
               "access_token": access_token,
               "findings_json": [{"rule_id": "aws-access-key-id",
                                  "file": "config.py", "line": 1,
                                  "title": "AWS Access Key ID",
                                  "context": None}]
               if findings is None else findings}
        self.by_id[row["id"]] = row
        return row

    async def get(self, audit_id: str):
        return self.by_id.get(audit_id)

    async def get_authorized(self, audit_id: str, token):
        # The real one checks the per-row access token; these tests are about
        # the payload, not the ownership check, which has its own coverage.
        return self.by_id.get(audit_id)

    async def get_access_token(self, audit_id: str):
        row = self.by_id.get(audit_id)
        return (row or {}).get("access_token")


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
        if not matches:
            return None
        return max(matches, key=lambda r: r["created_at"])

    def stored(self, job_id: str) -> dict:
        """The stored row, for a test that wants to move a job's status on.

        Needed because create_paid hands back a copy, not this row: the real
        repository returns a RETURNING result, and mutating that never reached
        the database. A test that wrote to the returned dict was asserting
        against something the endpoint would not have seen."""
        return next(r for r in self.rows if r["id"] == job_id)


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

    async def list_pending(self, provider, *, created_after=None):
        return [r for r in self.rows.values()
                if r["provider"] == provider and r["status"] == "pending"
                and (created_after is None
                     or r.get("created_at") is None
                     or r["created_at"] >= created_after)]


def _telegram_transport(calls: list):
    def handler(request: httpx.Request) -> httpx.Response:
        import json
        method = request.url.path.rsplit("/", 1)[-1]
        calls.append((method, json.loads(request.content) if request.content else {}))
        return httpx.Response(200, json={"ok": True, "result": {"message_id": 1}})
    return httpx.MockTransport(handler)


def _trongrid_transport(transfers: list, *, success: bool = True):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"success": success, "data": transfers})
    return httpx.MockTransport(handler)


def _transfer(value_micros: int, *, tx_id: str, to: str = ADDRESS):
    return {
        "transaction_id": tx_id, "type": "Transfer", "from": "TSenderXYZ",
        "to": to, "value": str(value_micros),
        "token_info": {"symbol": "USDT", "address": USDT_CONTRACT, "decimals": 6},
        "block_timestamp": 1784040468000,
    }


def _text_update(text: str, chat_id: int = 555):
    return {"update_id": 1, "message": {
        "chat": {"id": chat_id}, "from": {"id": chat_id}, "text": text}}


async def _send(update, *, audits, payments, fixpacks, accounts, calls):
    return await telegram_stars.handle_update(
        update, account_repo=accounts, payment_repo=payments,
        audit_repo=audits, fixpack_repo=fixpacks,
        token="t", transport=_telegram_transport(calls),
    )


# =========================================================================
# 1. Telegram /fixpack <audit_id>
# =========================================================================

async def test_fixpack_command_github_audit_sends_invoice(monkeypatch):
    monkeypatch.delenv("FIXPACK_STARS_PRICE", raising=False)
    audits, payments = FakeAuditRepo(), FakePaymentRepo()
    fixpacks, accounts, calls = FakeFixpackRepo(), FakeAccountRepo(), []
    audit = audits.add(repo_url=REPO_URL)

    result = await _send(_text_update(f"/fixpack {audit['id']}"),
                         audits=audits, payments=payments,
                         fixpacks=fixpacks, accounts=accounts, calls=calls)
    assert result == {"ok": True, "handled": "fixpack", "result": "invoice_sent"}

    invoices = [c for c in calls if c[0] == "sendInvoice"]
    assert len(invoices) == 1
    body = invoices[0][1]
    assert body["title"] == telegram_stars.FIXPACK_TITLE
    assert body["currency"] == "XTR"
    assert body["provider_token"] == ""
    # Payload encodes which audit this purchase is for.
    assert body["payload"] == f"fixpack:{audit['id']}"
    # 600 Stars by default.
    assert body["prices"] == [{"label": telegram_stars.FIXPACK_TITLE, "amount": 600}]


async def test_fixpack_command_env_overrides_price(monkeypatch):
    monkeypatch.setenv("FIXPACK_STARS_PRICE", "750")
    audits, payments = FakeAuditRepo(), FakePaymentRepo()
    fixpacks, accounts, calls = FakeFixpackRepo(), FakeAccountRepo(), []
    audit = audits.add(repo_url=REPO_URL)
    await _send(_text_update(f"/fixpack {audit['id']}"),
               audits=audits, payments=payments,
               fixpacks=fixpacks, accounts=accounts, calls=calls)
    body = [c for c in calls if c[0] == "sendInvoice"][0][1]
    assert body["prices"][0]["amount"] == 750


async def test_fixpack_command_zip_audit_is_rejected_no_invoice():
    audits, payments = FakeAuditRepo(), FakePaymentRepo()
    fixpacks, accounts, calls = FakeFixpackRepo(), FakeAccountRepo(), []
    audit = audits.add(repo_url=None)  # zip-upload audit

    result = await _send(_text_update(f"/fixpack {audit['id']}"),
                         audits=audits, payments=payments,
                         fixpacks=fixpacks, accounts=accounts, calls=calls)
    assert result["result"] == "not_github_audit"
    # No invoice sent, just an explanatory message.
    assert not [c for c in calls if c[0] == "sendInvoice"]
    msg = [c for c in calls if c[0] == "sendMessage"][-1][1]["text"]
    assert "GitHub" in msg


async def test_fixpack_command_unknown_audit_is_rejected_no_invoice():
    audits, payments = FakeAuditRepo(), FakePaymentRepo()
    fixpacks, accounts, calls = FakeFixpackRepo(), FakeAccountRepo(), []

    result = await _send(_text_update(f"/fixpack {uuid.uuid4()}"),
                         audits=audits, payments=payments,
                         fixpacks=fixpacks, accounts=accounts, calls=calls)
    assert result["result"] == "audit_not_found"
    assert not [c for c in calls if c[0] == "sendInvoice"]


async def test_fixpack_command_without_audit_id_shows_usage():
    audits, payments = FakeAuditRepo(), FakePaymentRepo()
    fixpacks, accounts, calls = FakeFixpackRepo(), FakeAccountRepo(), []
    result = await _send(_text_update("/fixpack"),
                         audits=audits, payments=payments,
                         fixpacks=fixpacks, accounts=accounts, calls=calls)
    assert result["result"] == "missing_audit_id"
    assert not [c for c in calls if c[0] == "sendInvoice"]
    assert "Usage" in [c for c in calls if c[0] == "sendMessage"][-1][1]["text"]


# =========================================================================
# 2. Telegram successful_payment for a Fix Pack
# =========================================================================

def _fixpack_payment_update(charge_id: str, audit_id: str, chat_id: int = 555):
    return {"update_id": 1, "message": {
        "chat": {"id": chat_id}, "from": {"id": chat_id},
        "successful_payment": {
            "currency": "XTR", "total_amount": 600,
            "invoice_payload": f"fixpack:{audit_id}",
            "telegram_payment_charge_id": charge_id,
            "provider_payment_charge_id": "prov_1",
        }}}


async def test_fixpack_payment_creates_job_and_not_a_pro_account():
    audits, payments = FakeAuditRepo(), FakePaymentRepo()
    fixpacks, accounts, calls = FakeFixpackRepo(), FakeAccountRepo(), []
    audit = audits.add(stack="fastapi", repo_url=REPO_URL)

    result = await _send(_fixpack_payment_update("charge_fp", audit["id"]),
                         audits=audits, payments=payments,
                         fixpacks=fixpacks, accounts=accounts, calls=calls)
    assert result == {"ok": True, "handled": "fixpack_payment", "persisted": True}

    # Exactly one paid fixpack job, linked to the right audit, right stack.
    assert len(fixpacks.rows) == 1
    job = fixpacks.rows[0]
    assert job["audit_id"] == audit["id"]
    assert job["status"] == "paid"
    assert job["stack"] == "fastapi"

    # Payment recorded as a completed fixpack purchase.
    assert len(payments.rows) == 1
    pay = next(iter(payments.rows.values()))
    assert pay["product"] == "fixpack"
    assert pay["audit_id"] == audit["id"]
    assert pay["status"] == "completed"

    # Crucially: NO account/tier was granted (that's grant_pro_tier's job).
    assert accounts.by_id == {}
    # And the confirmation DM leaks no API key.
    dm = [c for c in calls if c[0] == "sendMessage"][-1][1]["text"]
    assert "sk_live_" not in dm
    # A Fix Pack is bought for one audit, so the DM links that audit's
    # report directly (the /audit/{id} route) -- not a bare homepage link.
    # WITH the row's access token: GET /v1/audits/{id} authorises on it, so
    # the bare URL this used to send was a flat 404 for the person who just
    # paid. Asserting only the prefix let that ship, so assert the whole URL.
    assert f"https://drydock.co/audit/{audit['id']}?token=tok-abc123" in dm


async def test_fixpack_payment_sends_no_link_when_the_token_is_unavailable():
    """No token means no openable report URL. Send the confirmation without a
    link rather than with one that 404s: a missing line asks nothing of the
    buyer, a dead link tells them the order they paid for does not exist."""
    audits, payments = FakeAuditRepo(), FakePaymentRepo()
    fixpacks, accounts, calls = FakeFixpackRepo(), FakeAccountRepo(), []
    audit = audits.add(repo_url=REPO_URL, access_token=None)

    result = await _send(_fixpack_payment_update("charge_no_tok", audit["id"]),
                         audits=audits, payments=payments,
                         fixpacks=fixpacks, accounts=accounts, calls=calls)

    # The purchase itself still completes -- delivery is unaffected.
    assert result == {"ok": True, "handled": "fixpack_payment", "persisted": True}
    assert len(fixpacks.rows) == 1
    dm = [c for c in calls if c[0] == "sendMessage"][-1][1]["text"]
    assert "Payment received" in dm
    assert "/audit/" not in dm


async def test_duplicate_fixpack_payment_is_idempotent():
    audits, payments = FakeAuditRepo(), FakePaymentRepo()
    fixpacks, accounts, calls = FakeFixpackRepo(), FakeAccountRepo(), []
    audit = audits.add(repo_url=REPO_URL)

    for _ in range(2):  # Telegram retries the webhook until it gets 200
        await _send(_fixpack_payment_update("charge_dup_fp", audit["id"]),
                    audits=audits, payments=payments,
                    fixpacks=fixpacks, accounts=accounts, calls=calls)
    # No second job, no second payment for the same charge id.
    assert len(fixpacks.rows) == 1
    assert len(payments.rows) == 1


# =========================================================================
# 3. USDT fixpack invoice endpoint
# =========================================================================

_TRON_ADDR_RE = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")


def _override(*, audits, payments):
    app.dependency_overrides[get_audit_repo] = lambda: audits
    app.dependency_overrides[get_payment_repo] = lambda: payments


def _clear():
    for dep in (get_audit_repo, get_payment_repo, get_account_repo,
                get_fixpack_repo, get_billing_transport):
        app.dependency_overrides.pop(dep, None)


def test_usdt_fixpack_invoice_github_audit(monkeypatch):
    monkeypatch.setenv("USDT_TRC20_ADDRESS", ADDRESS)
    monkeypatch.delenv("FIXPACK_USDT_PRICE", raising=False)
    audits, payments = FakeAuditRepo(), FakePaymentRepo()
    audit = audits.add(repo_url=REPO_URL)
    _override(audits=audits, payments=payments)
    try:
        r = client.post(f"/v1/audits/{audit['id']}/fixpack/usdt-invoice")
        assert r.status_code == 201
        body = r.json()
        assert body["address"] == ADDRESS
        assert _TRON_ADDR_RE.match(body["address"])
        assert body["audit_id"] == audit["id"]
        # 12 USDT base price + sub-dollar nonce.
        assert 12.0 <= body["amount"] < 13.0
        # A pending fixpack payment row scoped to the audit was persisted.
        row = next(iter(payments.rows.values()))
        assert row["product"] == "fixpack"
        assert row["audit_id"] == audit["id"]
        assert row["status"] == "pending"
    finally:
        _clear()


def test_usdt_fixpack_invoice_env_overrides_price(monkeypatch):
    monkeypatch.setenv("USDT_TRC20_ADDRESS", ADDRESS)
    monkeypatch.setenv("FIXPACK_USDT_PRICE", "20")
    audits, payments = FakeAuditRepo(), FakePaymentRepo()
    audit = audits.add(repo_url=REPO_URL)
    _override(audits=audits, payments=payments)
    try:
        r = client.post(f"/v1/audits/{audit['id']}/fixpack/usdt-invoice")
        assert r.status_code == 201
        assert 20.0 <= r.json()["amount"] < 21.0
    finally:
        _clear()


def test_usdt_fixpack_invoice_zip_audit_is_422(monkeypatch):
    monkeypatch.setenv("USDT_TRC20_ADDRESS", ADDRESS)
    audits, payments = FakeAuditRepo(), FakePaymentRepo()
    audit = audits.add(repo_url=None)
    _override(audits=audits, payments=payments)
    try:
        r = client.post(f"/v1/audits/{audit['id']}/fixpack/usdt-invoice")
        assert r.status_code == 422
        assert r.json()["detail"]["reason"] == "not_github_audit"
        # No invoice/payment created.
        assert payments.rows == {}
    finally:
        _clear()


def test_usdt_fixpack_invoice_unknown_audit_is_404(monkeypatch):
    monkeypatch.setenv("USDT_TRC20_ADDRESS", ADDRESS)
    audits, payments = FakeAuditRepo(), FakePaymentRepo()
    _override(audits=audits, payments=payments)
    try:
        r = client.post(f"/v1/audits/{uuid.uuid4()}/fixpack/usdt-invoice")
        assert r.status_code == 404
        assert r.json()["detail"]["reason"] == "audit_not_found"
    finally:
        _clear()


# =========================================================================
# 4. USDT poll completing a fixpack invoice
# =========================================================================

async def test_usdt_poll_matches_fixpack_and_creates_job_not_account():
    audits, payments = FakeAuditRepo(), FakePaymentRepo()
    fixpacks, accounts = FakeFixpackRepo(), FakeAccountRepo()
    audit = audits.add(stack="vite-react", repo_url=REPO_URL)

    inv = await usdt_trc20.create_fixpack_invoice(
        payments, address=ADDRESS, audit_id=audit["id"])
    micros = usdt_trc20.amount_to_micros(inv["amount"])
    transport = _trongrid_transport([_transfer(micros, tx_id="0xfixpack")])

    result = await usdt_trc20.poll_and_match(
        payments, accounts, address=ADDRESS, transport=transport,
        fixpack_repo=fixpacks, audit_repo=audits)
    assert result["matched"] == 1

    # Invoice row completed, still no account.
    row = payments.rows[inv["invoice_id"]]
    assert row["status"] == "completed"
    assert row["external_ref"] == "0xfixpack"
    assert row["account_id"] is None
    assert accounts.by_id == {}

    # A paid fixpack job for the audit exists, with the audit's stack.
    assert len(fixpacks.rows) == 1
    job = fixpacks.rows[0]
    assert job["audit_id"] == audit["id"]
    assert job["status"] == "paid"
    assert job["stack"] == "vite-react"


async def test_usdt_poll_fixpack_is_idempotent():
    audits, payments = FakeAuditRepo(), FakePaymentRepo()
    fixpacks, accounts = FakeFixpackRepo(), FakeAccountRepo()
    audit = audits.add(repo_url=REPO_URL)

    inv = await usdt_trc20.create_fixpack_invoice(
        payments, address=ADDRESS, audit_id=audit["id"])
    micros = usdt_trc20.amount_to_micros(inv["amount"])
    transport = _trongrid_transport([_transfer(micros, tx_id="0xsamefp")])

    first = await usdt_trc20.poll_and_match(
        payments, accounts, address=ADDRESS, transport=transport,
        fixpack_repo=fixpacks, audit_repo=audits)
    second = await usdt_trc20.poll_and_match(
        payments, accounts, address=ADDRESS, transport=transport,
        fixpack_repo=fixpacks, audit_repo=audits)
    assert first["matched"] == 1
    assert second["matched"] == 0        # same tx, already applied
    assert len(fixpacks.rows) == 1       # no second job


# =========================================================================
# 5. GET /v1/audits/{audit_id}/fixpack-status — results-page poll target
# =========================================================================

def _override_status(*, audits, fixpacks):
    app.dependency_overrides[get_audit_repo] = lambda: audits
    app.dependency_overrides[get_fixpack_repo] = lambda: fixpacks


def test_fixpack_status_no_job_returns_null_status():
    audits, fixpacks = FakeAuditRepo(), FakeFixpackRepo()
    audit = audits.add(repo_url=REPO_URL)
    _override_status(audits=audits, fixpacks=fixpacks)
    try:
        r = client.get(f"/v1/audits/{audit['id']}/fixpack-status")
        assert r.status_code == 200
        assert r.json() == {"audit_id": audit["id"], "status": None,
                            "pr_url": None, "failure_kind": None}
    finally:
        _clear()


async def test_fixpack_status_reports_paid_then_delivered():
    audits, fixpacks = FakeAuditRepo(), FakeFixpackRepo()
    audit = audits.add(repo_url=REPO_URL)
    created = await fixpacks.create_paid(audit_id=audit["id"], stack="fastapi")
    job = fixpacks.stored(created["id"])
    _override_status(audits=audits, fixpacks=fixpacks)
    try:
        r = client.get(f"/v1/audits/{audit['id']}/fixpack-status")
        assert r.json() == {"audit_id": audit["id"], "status": "paid",
                            "pr_url": None, "failure_kind": None}

        job["status"] = "delivered"
        job["pr_url"] = "https://github.com/acme/widget/pull/7"
        r = client.get(f"/v1/audits/{audit['id']}/fixpack-status")
        assert r.json() == {
            "audit_id": audit["id"], "status": "delivered",
            "pr_url": "https://github.com/acme/widget/pull/7",
            "failure_kind": None,
        }
    finally:
        _clear()


async def test_fixpack_status_marks_a_reaped_failure_as_infrastructure():
    # A 'failed' the reaper wrote means the job never ran, so the frontend must
    # be able to say "on us", not "your fix couldn't be generated".
    audits, fixpacks = FakeAuditRepo(), FakeFixpackRepo()
    audit = audits.add(repo_url=REPO_URL)
    created = await fixpacks.create_paid(audit_id=audit["id"], stack="fastapi")
    job = fixpacks.stored(created["id"])
    _override_status(audits=audits, fixpacks=fixpacks)
    try:
        job["status"] = "failed"
        job["detail"] = (f"{STALE_LEASE_DETAIL_PREFIX} no completion after 3 "
                         f"attempt(s), last lease older than 15m")
        r = client.get(f"/v1/audits/{audit['id']}/fixpack-status")
        assert r.json()["failure_kind"] == "infrastructure"
    finally:
        _clear()


async def test_fixpack_status_leaves_a_generation_failure_unlabelled():
    audits, fixpacks = FakeAuditRepo(), FakeFixpackRepo()
    audit = audits.add(repo_url=REPO_URL)
    created = await fixpacks.create_paid(audit_id=audit["id"], stack="fastapi")
    job = fixpacks.stored(created["id"])
    _override_status(audits=audits, fixpacks=fixpacks)
    try:
        job["status"] = "failed"
        job["detail"] = "could not open pull request: 403"
        r = client.get(f"/v1/audits/{audit['id']}/fixpack-status")
        assert r.json()["failure_kind"] is None
    finally:
        _clear()


def test_fixpack_status_unknown_audit_is_404():
    audits, fixpacks = FakeAuditRepo(), FakeFixpackRepo()
    _override_status(audits=audits, fixpacks=fixpacks)
    try:
        r = client.get(f"/v1/audits/{uuid.uuid4()}/fixpack-status")
        assert r.status_code == 404
        assert r.json()["detail"]["reason"] == "audit_not_found"
    finally:
        _clear()


def test_usdt_fixpack_invoice_refused_while_a_job_is_live(monkeypatch):
    """The same sell-side refusal as the bank-transfer route, on the USDT one.

    Worth having in both places rather than trusting the shared helper: the
    three sell points grew independently (they already duplicate the audit and
    repo_url gates), so the thing that breaks is one of them being missed when
    a fourth provider is added.
    """
    monkeypatch.setenv("USDT_TRC20_ADDRESS", ADDRESS)
    audits, payments = FakeAuditRepo(), FakePaymentRepo()
    fixpacks = FakeFixpackRepo()
    audit = audits.add(repo_url=REPO_URL)
    fixpacks.rows.append({
        "id": str(uuid.uuid4()), "audit_id": audit["id"], "pack": "fixpack",
        "stack": "fastapi", "status": "running", "verified": None,
        "detail": None, "pr_url": None, "pr_delivered": False,
        "created_at": datetime.datetime.now(datetime.timezone.utc),
    })
    _override(audits=audits, payments=payments)
    app.dependency_overrides[get_fixpack_repo] = lambda: fixpacks
    try:
        r = client.post(f"/v1/audits/{audit['id']}/fixpack/usdt-invoice")
        assert r.status_code == 409
        assert r.json()["detail"]["reason"] == "fixpack_already_in_progress"
        assert payments.rows == {}
    finally:
        _clear()


# --- refusing to sell what cannot be delivered ---
#
# Audit 05fa18f5 was sold a Fix Pack with zero fixable findings. The job ran,
# found nothing, and the payer was charged for "Nothing to auto-fix". It was
# computable before the sale, from the findings already on the audit.


ADVICE_ONLY = [
    {"rule_id": "no-tests", "file": "", "line": 0, "title": "No tests",
     "context": None},
    {"rule_id": "no-ci", "file": "", "line": 0, "title": "No CI",
     "context": None},
]


def test_usdt_refuses_when_nothing_is_auto_fixable(monkeypatch):
    monkeypatch.setenv("USDT_TRC20_ADDRESS", ADDRESS)
    audits, payments = FakeAuditRepo(), FakePaymentRepo()
    audit = audits.add(repo_url=REPO_URL, findings=ADVICE_ONLY)
    _override(audits=audits, payments=payments)
    try:
        r = client.post(f"/v1/audits/{audit['id']}/fixpack/usdt-invoice")
        assert r.status_code == 409
        assert r.json()["detail"]["reason"] == "no_auto_fixable_findings"
        assert payments.rows == {}
    finally:
        _clear()


def test_a_finding_only_in_a_comment_is_not_something_to_sell(monkeypatch):
    """The seam with #132. That change stopped the Fix Pack from rewriting
    comments; this one stops us charging for the rewrite it will not do."""
    monkeypatch.setenv("USDT_TRC20_ADDRESS", ADDRESS)
    audits, payments = FakeAuditRepo(), FakePaymentRepo()
    audit = audits.add(repo_url=REPO_URL, findings=[
        {"rule_id": "aws-access-key-id", "file": "app.py", "line": 3,
         "title": "AWS Access Key ID", "context": "comment"},
    ])
    _override(audits=audits, payments=payments)
    try:
        r = client.post(f"/v1/audits/{audit['id']}/fixpack/usdt-invoice")
        assert r.status_code == 409
    finally:
        _clear()


def test_a_real_secret_is_still_sellable(monkeypatch):
    """The boundary. A check that refuses everything would be worse than the
    bug: it would stop the product selling at all."""
    monkeypatch.setenv("USDT_TRC20_ADDRESS", ADDRESS)
    audits, payments = FakeAuditRepo(), FakePaymentRepo()
    audit = audits.add(repo_url=REPO_URL)     # default fixture: a real secret
    _override(audits=audits, payments=payments)
    try:
        r = client.post(f"/v1/audits/{audit['id']}/fixpack/usdt-invoice")
        assert r.status_code == 201
    finally:
        _clear()


def test_an_audit_with_no_findings_at_all_is_refused(monkeypatch):
    """A clean repository. Nothing was found, so there is nothing to fix --
    and this is the state a customer is most likely to try to buy from,
    because a good score reads as 'everything is fine, but let me tidy up'."""
    monkeypatch.setenv("USDT_TRC20_ADDRESS", ADDRESS)
    audits, payments = FakeAuditRepo(), FakePaymentRepo()
    audit = audits.add(repo_url=REPO_URL, findings=[])
    _override(audits=audits, payments=payments)
    try:
        assert client.post(
            f"/v1/audits/{audit['id']}/fixpack/usdt-invoice"
        ).status_code == 409
    finally:
        _clear()


def test_the_audit_response_tells_the_page_whether_to_offer_a_fix_pack():
    """The page must not decide this itself: the answer depends on which rules
    the Fix Pack knows how to rewrite, and a second copy of that list in
    TypeScript is exactly the drift #132 was about."""
    audits = FakeAuditRepo()
    sellable = audits.add(repo_url=REPO_URL)
    nothing = audits.add(repo_url=REPO_URL, findings=ADVICE_ONLY)
    _override(audits=audits, payments=FakePaymentRepo())
    try:
        assert client.get(
            f"/v1/audits/{sellable['id']}?token=t"
        ).json()["fixpack_auto_fixable"] is True
        assert client.get(
            f"/v1/audits/{nothing['id']}?token=t"
        ).json()["fixpack_auto_fixable"] is False
    finally:
        _clear()

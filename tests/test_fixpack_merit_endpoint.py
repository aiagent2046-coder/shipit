"""The verdict, where the operator actually decides.

app/fixpack/merit.py is pure and tested on its own. What is asserted here is
the join: that the endpoint finds the right job and the right outcome row for a
payment, that it refuses to invent a verdict about a purchase it cannot judge,
that it is safe to ask twice, and that the refund endpoint carries the same
answer so the decision and the evidence arrive together.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.routes.dependencies import (
    get_billing_transport,
    get_fix_outcome_repo,
    get_fixpack_repo,
    get_payment_repo,
)

client = TestClient(app, raise_server_exceptions=False)

AUTH = {"authorization": "Bearer flags"}


class Payments:
    def __init__(self, rows: dict) -> None:
        self.rows = rows
        self.refunded: list[str] = []

    async def get(self, payment_id):
        return self.rows.get(payment_id)

    async def mark_refunded(self, payment_id, *, reason):
        row = self.rows.get(payment_id)
        if row is None or row.get("status") != "completed":
            return None
        self.refunded.append(payment_id)
        return {**row, "status": "refunded", "refund_reason": reason}


class Jobs:
    def __init__(self, by_audit: dict | None = None) -> None:
        self.by_audit = by_audit or {}
        self.asked: list[str] = []

    async def get_by_audit(self, audit_id):
        self.asked.append(audit_id)
        return self.by_audit.get(audit_id)


class Outcomes:
    def __init__(self, by_job: dict | None = None) -> None:
        self.by_job = by_job or {}

    async def get_by_job(self, job_id):
        return self.by_job.get(job_id)


def _wire(payments, jobs=None, outcomes=None):
    app.dependency_overrides[get_payment_repo] = lambda: payments
    app.dependency_overrides[get_fixpack_repo] = lambda: jobs or Jobs()
    app.dependency_overrides[get_fix_outcome_repo] = lambda: outcomes or Outcomes()
    app.dependency_overrides[get_billing_transport] = lambda: None


@pytest.fixture(autouse=True)
def _configured(monkeypatch):
    monkeypatch.setenv("SERVICE_FLAGS_TOKEN", "flags")
    yield
    app.dependency_overrides.clear()


def _fixpack_payment(audit_id: str, payment_id: str) -> dict:
    return {
        "id": payment_id, "product": "fixpack", "audit_id": audit_id,
        "status": "completed", "amount": 10.79, "currency": "USD",
        "external_ref": "DRY-MERIT1",
    }


# --- it reads the right rows ------------------------------------------------

def test_it_finds_the_job_and_the_outcome_for_that_payment() -> None:
    audit_id, payment_id, job_id = (str(uuid.uuid4()) for _ in range(3))
    jobs = Jobs({audit_id: {"id": job_id, "status": "delivered",
                            "verified": True, "detail": None}})
    outcomes = Outcomes({job_id: {
        "outcome": "delivered", "rule_ids": ["aws-access-key-id"],
        "is_regression": False, "pr_merged": True,
    }})
    _wire(Payments({payment_id: _fixpack_payment(audit_id, payment_id)}),
          jobs, outcomes)

    resp = client.get(
        f"/internal/payments/{payment_id}/fixpack-merit", headers=AUTH)

    assert resp.status_code == 200
    body = resp.json()
    assert body["conclusion"] == "delivered"
    assert body["audit_id"] == audit_id
    assert jobs.asked == [audit_id]
    assert {r["code"] for r in body["reasons"]} == {
        "delivered_fixes", "pr_merged"}


def test_a_paid_fixpack_with_no_job_reads_as_owed() -> None:
    """Money taken, nothing generated. The loudest case, and the one the
    operator most wants to find before the customer does."""
    audit_id, payment_id = str(uuid.uuid4()), str(uuid.uuid4())
    _wire(Payments({payment_id: _fixpack_payment(audit_id, payment_id)}),
          Jobs({}), Outcomes())

    body = client.get(
        f"/internal/payments/{payment_id}/fixpack-merit",
        headers=AUTH).json()

    assert body["conclusion"] == "owed"
    assert body["reasons"][0]["decisive"] is True


# --- money that never arrived cannot be owed back ---------------------------

@pytest.mark.parametrize("status", ["pending", "expired", "", None])
def test_an_invoice_nobody_paid_gets_no_verdict(status) -> None:
    """FOUND LIVE IN THE PRE-LAUNCH RUN OF 2026-08-21, on two rows.

    A payer who opens a second invoice for an audit and pays the first leaves
    an abandoned `pending` row behind. The job is looked up by audit_id, so
    that abandoned row was told what happened to the audit's one Fix Pack and
    inherited its verdict -- `owed`, in both real cases, on money that was
    never received. One of them sat on an audit whose real charge had already
    been refunded, so the endpoint was recommending the same refund twice.

    Why this is dangerous and not merely untidy: a refund here is sent BY HAND
    and the system is told afterwards. mark_refunded's CAS gate does refuse a
    pending row -- but it refuses after the transfer has left. Its own
    docstring warns about this exact case and names the two references this
    endpoint got wrong.

    `assess()` opens with "Judge one PAID Fix Pack". That was a precondition
    written in a docstring and enforced nowhere; this is it enforced.
    """
    audit_id, payment_id, job_id = (str(uuid.uuid4()) for _ in range(3))
    payment = {**_fixpack_payment(audit_id, payment_id), "status": status}
    # A real, decisive, `owed`-shaped job sitting on the same audit -- bought
    # and paid for by somebody else's invoice. Without the gate this row
    # borrows that verdict.
    jobs = Jobs({audit_id: {"id": job_id, "status": "delivered",
                            "verified": True, "detail": None}})
    outcomes = Outcomes({job_id: {
        "outcome": "no_fix_needed", "rule_ids": [], "is_regression": False,
    }})
    _wire(Payments({payment_id: payment}), jobs, outcomes)

    body = client.get(
        f"/internal/payments/{payment_id}/fixpack-merit",
        headers=AUTH).json()

    assert body["conclusion"] == "undetermined"
    assert [r["code"] for r in body["reasons"]] == ["not_paid"]
    assert jobs.asked == [], "looked up work for an invoice nobody paid"


def test_a_refunded_payment_is_still_judged() -> None:
    """The other side of the gate, and it must not be collateral damage.

    A refunded payment DID receive money, and the verdict is the record of why
    it went back -- consulted six weeks later when somebody asks what happened.
    Gating on `completed` alone would erase the reasoning behind every refund
    already made, including the one this whole mechanism was built for.
    """
    audit_id, payment_id, job_id = (str(uuid.uuid4()) for _ in range(3))
    payment = {**_fixpack_payment(audit_id, payment_id), "status": "refunded"}
    jobs = Jobs({audit_id: {"id": job_id, "status": "delivered",
                            "verified": True, "detail": None}})
    outcomes = Outcomes({job_id: {
        "outcome": "no_fix_needed", "rule_ids": [], "is_regression": False,
    }})
    _wire(Payments({payment_id: payment}), jobs, outcomes)

    body = client.get(
        f"/internal/payments/{payment_id}/fixpack-merit",
        headers=AUTH).json()

    assert body["conclusion"] == "owed"
    assert body["reasons"][0]["code"] == "nothing_to_fix"


def test_the_refund_date_is_reported_when_there_is_one() -> None:
    """The endpoint renders `refunded_at`, and until 2026-08-21 it rendered
    `null` for every payment in existence: PaymentRepository.get() did not
    select the column. `status` said "refunded" in the same response, so two
    fields contradicted each other and the wrong one was the one that looks
    precise -- read by an operator deciding whether a refund is still owed.
    """
    audit_id, payment_id = str(uuid.uuid4()), str(uuid.uuid4())
    payment = {**_fixpack_payment(audit_id, payment_id),
               "status": "refunded",
               "refunded_at": "2026-08-01T10:00:00+00:00"}
    _wire(Payments({payment_id: payment}), Jobs({}), Outcomes())

    body = client.get(
        f"/internal/payments/{payment_id}/fixpack-merit",
        headers=AUTH).json()

    assert body["refunded_at"] == "2026-08-01T10:00:00+00:00"


# --- it refuses to invent a verdict ----------------------------------------

def test_a_pro_purchase_gets_no_verdict_about_generated_work() -> None:
    """There is no Fix Pack to judge. Returning "delivered" here would be a
    verdict about work that was never done."""
    payment_id = str(uuid.uuid4())
    _wire(Payments({payment_id: {
        "id": payment_id, "product": "pro_tier", "status": "completed"}}))

    body = client.get(
        f"/internal/payments/{payment_id}/fixpack-merit",
        headers=AUTH).json()

    assert body["conclusion"] == "undetermined"
    assert body["reasons"][0]["code"] == "not_a_fixpack"


def test_a_fixpack_payment_with_no_audit_id_says_so() -> None:
    payment_id = str(uuid.uuid4())
    _wire(Payments({payment_id: {
        "id": payment_id, "product": "fixpack", "audit_id": None,
        "status": "completed"}}))

    body = client.get(
        f"/internal/payments/{payment_id}/fixpack-merit",
        headers=AUTH).json()

    assert body["conclusion"] == "undetermined"
    assert body["reasons"][0]["code"] == "no_audit"


# --- it is safe to ask ------------------------------------------------------

def test_asking_twice_changes_nothing() -> None:
    """Deliberately GET. The verdict is consulted BEFORE deciding, so it must
    not record anything about a refund that has not happened."""
    audit_id, payment_id = str(uuid.uuid4()), str(uuid.uuid4())
    payments = Payments({payment_id: _fixpack_payment(audit_id, payment_id)})
    _wire(payments, Jobs({}), Outcomes())

    first = client.get(
        f"/internal/payments/{payment_id}/fixpack-merit", headers=AUTH).json()
    second = client.get(
        f"/internal/payments/{payment_id}/fixpack-merit", headers=AUTH).json()

    assert first == second
    assert payments.refunded == []


def test_it_needs_the_operator_credential() -> None:
    """It reads one customer's purchase history."""
    payment_id = str(uuid.uuid4())
    _wire(Payments({payment_id: _fixpack_payment(str(uuid.uuid4()), payment_id)}))

    assert client.get(
        f"/internal/payments/{payment_id}/fixpack-merit").status_code == 401
    assert client.get(
        f"/internal/payments/{payment_id}/fixpack-merit",
        headers={"authorization": "Bearer wrong"}).status_code == 401


def test_an_unknown_payment_is_404() -> None:
    _wire(Payments({}))
    assert client.get(
        f"/internal/payments/{uuid.uuid4()}/fixpack-merit",
        headers=AUTH).status_code == 404


# --- the refund carries the same answer ------------------------------------

def test_the_refund_response_carries_the_verdict() -> None:
    """The decision and the evidence arrive together, so the record of a
    refund says what we knew at the moment we made it."""
    audit_id, payment_id, job_id = (str(uuid.uuid4()) for _ in range(3))
    jobs = Jobs({audit_id: {"id": job_id, "status": "delivered",
                            "verified": True, "detail": None}})
    outcomes = Outcomes({job_id: {
        "outcome": "delivered", "rule_ids": [], "is_regression": False,
        "pr_merged": None,
    }})
    _wire(Payments({payment_id: _fixpack_payment(audit_id, payment_id)}),
          jobs, outcomes)

    resp = client.post(
        f"/internal/payments/{payment_id}/refund",
        json={"reason": "customer says the Fix Pack did nothing"},
        headers=AUTH,
    )

    assert resp.status_code == 200
    merit = resp.json()["fixpack_merit"]
    # And it agrees with the customer: an empty pull request is not the
    # product, which our own tables said before they complained.
    assert merit["conclusion"] == "owed"
    assert "delivered_nothing" in {r["code"] for r in merit["reasons"]}


def test_a_verdict_that_cannot_be_reached_does_not_block_the_refund() -> None:
    """The refund is the thing that matters, and the record of it is this
    endpoint's whole product. A merit check that raised would take that down
    over an analytics table."""
    audit_id, payment_id = str(uuid.uuid4()), str(uuid.uuid4())

    class Exploding:
        async def get_by_audit(self, audit_id):
            raise RuntimeError("fixpack_jobs is unreachable")

    _wire(Payments({payment_id: _fixpack_payment(audit_id, payment_id)}),
          Exploding(), Outcomes())

    resp = client.post(
        f"/internal/payments/{payment_id}/refund",
        json={"reason": "duplicate charge"}, headers=AUTH,
    )

    assert resp.status_code == 200
    assert resp.json()["status"] == "refunded"
    merit = resp.json()["fixpack_merit"]
    assert merit["conclusion"] == "undetermined"
    # And it says WHY it could not answer, rather than letting "undetermined"
    # read as "we looked and could not tell".
    assert merit["reasons"][0]["code"] == "assessment_unavailable"


def test_the_read_only_endpoint_does_not_hide_a_failure() -> None:
    """The opposite rule to the one above, and the reason the wrapper is on the
    refund and not here. The operator asked for the verdict and nothing else;
    answering "undetermined" when the tables could not be read would be a lie
    told in the exact shape of an honest answer."""
    audit_id, payment_id = str(uuid.uuid4()), str(uuid.uuid4())

    class Exploding:
        async def get_by_audit(self, audit_id):
            raise RuntimeError("fixpack_jobs is unreachable")

    _wire(Payments({payment_id: _fixpack_payment(audit_id, payment_id)}),
          Exploding(), Outcomes())

    resp = client.get(
        f"/internal/payments/{payment_id}/fixpack-merit", headers=AUTH)

    assert resp.status_code == 500

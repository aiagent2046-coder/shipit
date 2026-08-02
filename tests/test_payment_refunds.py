"""Recording a refund: POST /internal/payments/{id}/refund.

The endpoint moves no money and no endpoint here could. A bank transfer lands
on a private individual's account and goes back the same way, by hand; Telegram
Stars and USDT have no refund call this deployment holds a credential for. The
operator sends the money and then tells the system.

So what is worth testing is the record, and the two ways it could lie: a refund
of a payment nobody made, and one refund counted twice. Both are compare-and-set
in SQL, so those tests run against real Postgres. Auth and body validation are
not SQL and use a fake.

Occasion: on 2026-08-01 payment DRY-UPRQKH took 10.79 USD for a Fix Pack on an
audit with nothing a Fix Pack could fix, while DRY-XZCNTN sat at 10.60 pending
and unpaid. Refunding the wrong one of those two would have recorded a payout
that never happened and left the real charge looking clean.
"""

from __future__ import annotations

import os
import uuid

import pytest
from fastapi.testclient import TestClient

import app.db as db_mod
from app.main import app, get_payment_repo


client = TestClient(app, raise_server_exceptions=False)

_DB_URL = os.environ.get("DATABASE_URL")

requires_postgres = pytest.mark.skipif(
    not _DB_URL,
    reason="real-Postgres integration test: set DATABASE_URL to a live Postgres",
)

TOKEN = {"authorization": "Bearer fake-flags-token-not-a-real-secret"}


@pytest.fixture
def operator_token(monkeypatch):
    monkeypatch.setenv("SERVICE_FLAGS_TOKEN",
                       "fake-flags-token-not-a-real-secret")


class _RefusingRepo:
    """Every refund refused. Enough for the paths that never reach SQL."""

    async def mark_refunded(self, payment_id, *, reason):
        return None


@pytest.fixture
def fake_repo():
    app.dependency_overrides[get_payment_repo] = lambda: _RefusingRepo()
    yield
    app.dependency_overrides.pop(get_payment_repo, None)


def test_a_refund_needs_the_operator_token(operator_token, fake_repo):
    response = client.post(
        f"/internal/payments/{uuid.uuid4()}/refund", json={"reason": "x"})

    assert response.status_code == 401


def test_without_a_configured_token_the_endpoint_refuses_to_act(
    monkeypatch, fake_repo,
):
    """Same posture as the other operator endpoints: an unset token means the
    check would be a no-op, and a no-op auth check on something that edits the
    books is worse than no endpoint."""
    monkeypatch.delenv("SERVICE_FLAGS_TOKEN", raising=False)

    response = client.post(
        f"/internal/payments/{uuid.uuid4()}/refund",
        json={"reason": "x"}, headers=TOKEN)

    assert response.status_code == 503


@pytest.mark.parametrize("body", [{}, {"reason": ""}, {"reason": "   "},
                                  {"reason": 42}])
def test_a_refund_must_say_why(operator_token, fake_repo, body):
    """A reason-less refund is an unexplained hole in the books. The whole
    point of the record is to be readable a month later."""
    response = client.post(
        f"/internal/payments/{uuid.uuid4()}/refund", json=body, headers=TOKEN)

    assert response.status_code == 422


def test_a_payment_id_that_is_not_a_uuid_is_refused(operator_token, fake_repo):
    response = client.post(
        "/internal/payments/not-a-uuid/refund",
        json={"reason": "x"}, headers=TOKEN)

    assert response.status_code == 422


# --- the SQL, against real Postgres ----------------------------------------

@pytest.fixture
async def real_db(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", _DB_URL)
    await db_mod.close_pool()
    pool = await db_mod.get_pool()
    async with pool.connection() as conn:
        await conn.execute("delete from payments")
    yield pool
    await db_mod.close_pool()


async def _insert_payment(pool, *, status, amount, external_ref):
    async with pool.connection() as conn:
        cur = await conn.execute(
            "insert into payments (provider, status, amount, currency, "
            "product, external_ref) values ('bank_transfer', %s, %s, 'USD', "
            "'fixpack', %s) returning id",
            (status, amount, external_ref),
        )
        return str((await cur.fetchone())["id"])


@requires_postgres
async def test_a_completed_payment_is_recorded_as_refunded(real_db):
    payment_id = await _insert_payment(
        real_db, status="completed", amount="10.79", external_ref="DRY-UPRQKH")

    refunded = await db_mod.PaymentRepository().mark_refunded(
        payment_id, reason="nothing was auto-fixable")

    assert refunded["status"] == "refunded"
    assert refunded["refund_reason"] == "nothing was auto-fixable"
    assert refunded["refunded_at"] is not None


@requires_postgres
async def test_an_invoice_nobody_paid_cannot_be_refunded(real_db):
    """DRY-XZCNTN, 10.60, pending. Money never arrived, so a refund of it
    would be a payout that never happened -- and it would leave the charge
    that DID happen still looking clean."""
    payment_id = await _insert_payment(
        real_db, status="pending", amount="10.60", external_ref="DRY-XZCNTN")

    assert await db_mod.PaymentRepository().mark_refunded(
        payment_id, reason="cleaning up") is None

    async with real_db.connection() as conn:
        cur = await conn.execute(
            "select status from payments where id = %s",
            (uuid.UUID(payment_id),))
        assert (await cur.fetchone())["status"] == "pending"


@requires_postgres
async def test_refunding_twice_records_one_refund(real_db):
    """An operator who runs the command twice, or a retried request, must not
    turn one refund into two entries. The status predicate is inside the
    UPDATE, so the second attempt matches nothing."""
    payment_id = await _insert_payment(
        real_db, status="completed", amount="10.79", external_ref="DRY-UPRQKH")
    repo = db_mod.PaymentRepository()

    first = await repo.mark_refunded(payment_id, reason="first")
    second = await repo.mark_refunded(payment_id, reason="second")

    assert first is not None
    assert second is None
    async with real_db.connection() as conn:
        cur = await conn.execute(
            "select refund_reason from payments where id = %s",
            (uuid.UUID(payment_id),))
        # The first reason stands; the second call changed nothing at all.
        assert (await cur.fetchone())["refund_reason"] == "first"


@requires_postgres
async def test_the_endpoint_records_the_refund_end_to_end(
    real_db, operator_token,
):
    payment_id = await _insert_payment(
        real_db, status="completed", amount="10.79", external_ref="DRY-UPRQKH")

    response = client.post(
        f"/internal/payments/{payment_id}/refund",
        json={"reason": "nothing was auto-fixable"}, headers=TOKEN)

    assert response.status_code == 200
    assert response.json()["status"] == "refunded"

    repeat = client.post(
        f"/internal/payments/{payment_id}/refund",
        json={"reason": "again"}, headers=TOKEN)
    assert repeat.status_code == 404
    assert repeat.json()["detail"]["reason"] == "not_refundable"

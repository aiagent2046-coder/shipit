"""Real database authorization/funding boundaries; synthetic encrypted values only."""
from __future__ import annotations

import asyncio
import os
import uuid

import psycopg
import pytest
from fastapi import HTTPException

from app import db
from app.deploypack.paid_delivery_store import PaidDeliveryStore
from app.foundation.fixpack_funding import funding_key
from app.routes._shared import _reject_if_fixpack_already_live

_DB_URL = os.environ.get("DATABASE_URL")
pytestmark = pytest.mark.skipif(not _DB_URL, reason="requires disposable Postgres")


@pytest.fixture
async def live_db(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", _DB_URL)
    await db.close_pool()
    pool = await db.get_pool()
    try:
        yield pool
    finally:
        try:
            # Later smoke suites claim globally, so leave no synthetic paid
            # work for them. Restrict cleanup to this module's own audit tag
            # and fixture repository; never touch another suite's jobs.
            async with pool.connection() as conn:
                await conn.execute(
                    """update fixpack_jobs j set status = 'failed', started_at = null
                         from audits a where j.audit_id = a.id
                          and a.engine_version = 'paid-delivery-store-test'
                          and a.repo_url = 'https://github.com/example/synthetic'
                          and j.status in ('paid', 'running', 'awaiting_authorization')""",
                )
        finally:
            await db.close_pool()


async def _seed(*, grant="encrypted-test-grant", status="completed"):
    reference = uuid.uuid4().hex
    audit = await db.AuditRepository().create(
        stack="fastapi", file_count=1, score_total=7.0,
        score_json={"total": 7.0}, findings_json=[],
        repo_url="https://github.com/example/synthetic",
        content_hash=reference, engine_version="paid-delivery-store-test",
    )
    job = await db.FixpackJobRepository().create_paid(
        audit_id=audit["id"], stack="fastapi",
        funding_key=funding_key("bank_transfer", reference),
    )
    payment = await db.PaymentRepository().create(
        account_id=None, provider="bank_transfer", external_ref=reference,
        amount=990, currency="RUB", status=status, tier_granted=None,
        product="fixpack", audit_id=audit["id"], fixpack_job_id=job["id"],
        delivery_grant=grant,
    )
    return audit, job, payment


async def test_secret_is_private_and_only_funding_payment_can_supply_it(live_db):
    _, job, payment = await _seed()
    assert "delivery_grant" not in payment and "encrypted_grant" not in payment
    public_row = await db.PaymentRepository().get(payment["id"])
    assert "encrypted_grant" not in public_row
    store = PaidDeliveryStore()
    grant = await store.get_for_job(job["id"])
    assert grant["payment_id"] == payment["id"]
    assert grant["encrypted_grant"] == "encrypted-test-grant"
    async with live_db.connection() as conn:
        await conn.execute("delete from fixpack_delivery_grants where payment_id = %s",
                           (uuid.UUID(payment["id"]),))
    await db.PaymentRepository().create(
        account_id=None, provider="bank_transfer", external_ref=uuid.uuid4().hex,
        amount=990, currency="RUB", status="completed", tier_granted=None,
        product="fixpack", audit_id=job["audit_id"], fixpack_job_id=job["id"],
        delivery_grant="wrong-payer-grant",
    )
    assert (await store.get_for_job(job["id"]))["encrypted_grant"] is None


async def test_grant_failure_rolls_back_invoice(live_db, monkeypatch):
    original = psycopg.AsyncConnection.execute
    reference = uuid.uuid4().hex

    async def execute(conn, query, params=None, **kwargs):
        if isinstance(query, str) and query.startswith("insert into fixpack_delivery_grants"):
            raise RuntimeError("synthetic grant store failure")
        return await original(conn, query, params, **kwargs)

    monkeypatch.setattr(psycopg.AsyncConnection, "execute", execute)
    with pytest.raises(RuntimeError, match="synthetic"):
        await db.PaymentRepository().create(
            account_id=None, provider="bank_transfer", external_ref=reference,
            amount=990, currency="RUB", status="pending", tier_granted=None,
            product="fixpack", delivery_grant="encrypted-test-grant",
        )
    assert await db.PaymentRepository().get_by_external_ref("bank_transfer", reference) is None


async def test_waiting_job_keeps_live_identity_and_renewal_requeues_once(live_db):
    audit, job, payment = await _seed()
    store = PaidDeliveryStore()
    async with live_db.connection() as conn:
        await conn.execute("update fixpack_jobs set status = 'running', attempts = 2 where id = %s",
                           (uuid.UUID(job["id"]),))
    await store.await_authorization(job["id"], "github_token_expired")
    duplicate = await db.FixpackJobRepository().create_paid(
        audit_id=audit["id"], stack="fastapi", funding_key="different-payment",
    )
    assert duplicate["id"] == job["id"]
    results = await asyncio.gather(*(
        store.replace_for_payment(payment["id"], f"renewed-{n}") for n in range(4)
    ))
    assert results.count(True) == 1
    async with live_db.connection() as conn:
        cur = await conn.execute("select status, attempts from fixpack_jobs where id = %s",
                                 (uuid.UUID(job["id"]),))
        row = await cur.fetchone()
    assert row == {"status": "paid", "attempts": 1}


@pytest.mark.parametrize("status", ["delivered", "failed", "blocked", "running", "paid"])
async def test_renewal_never_restarts_nonwaiting_jobs(live_db, status):
    _, job, payment = await _seed()
    await db.FixpackJobRepository().mark_status(job["id"], status)
    store = PaidDeliveryStore()
    assert await store.replace_for_payment(payment["id"], "replacement") is False
    assert (await store.get_for_job(job["id"]))["encrypted_grant"] == "encrypted-test-grant"


async def test_unconfirmed_and_refunded_receipts_cannot_authorize(live_db):
    _, job, payment = await _seed(status="pending")
    store = PaidDeliveryStore()
    assert await store.get_for_job(job["id"]) is None
    await db.FixpackJobRepository().mark_status(job["id"], "awaiting_authorization")
    assert await store.replace_for_payment(payment["id"], "replacement") is False
    async with live_db.connection() as conn:
        await conn.execute("update payments set status = 'refunded' where id = %s",
                           (uuid.UUID(payment["id"]),))
    assert await store.get_for_job(job["id"]) is None
    assert await store.replace_for_payment(payment["id"], "replacement") is False


async def test_delivered_grants_are_erased_and_rls_enabled(live_db):
    _, job, payment = await _seed()
    store = PaidDeliveryStore()
    await db.FixpackJobRepository().mark_fixpack_delivered(job["id"],
                                                       "https://example.invalid/pull/1")
    await store.clear_for_job(job["id"])
    assert (await store.get_for_job(job["id"]))["encrypted_grant"] is None
    assert await store.replace_for_payment(payment["id"], "replacement") is False
    async with live_db.connection() as conn:
        cur = await conn.execute(
            "select relrowsecurity from pg_class where oid = 'fixpack_delivery_grants'::regclass")
        assert (await cur.fetchone())["relrowsecurity"] is True


@pytest.mark.parametrize("status", ["paid", "running", "awaiting_authorization"])
async def test_newer_deploy_preview_does_not_hide_live_paid_work(live_db, status):
    audit, job, _ = await _seed()
    jobs = db.FixpackJobRepository()
    await jobs.mark_status(job["id"], status)
    preview = await jobs.create(
        audit_id=audit["id"], pack="deploy", stack="fastapi", verified=True,
        detail="synthetic preview", preview_local_url=None, preview_expires_at=None,
    )
    # Pin ordering explicitly; the regression must not depend on clock precision.
    async with live_db.connection() as conn:
        await conn.execute(
            "update fixpack_jobs set created_at = now() + interval '1 hour' where id = %s",
            (uuid.UUID(preview["id"]),),
        )
    visible = await jobs.get_by_audit(audit["id"])
    assert visible["id"] == job["id"]
    assert visible["status"] == status
    with pytest.raises(HTTPException) as refused:
        await _reject_if_fixpack_already_live(jobs, audit["id"])
    assert refused.value.status_code == 409
    assert refused.value.detail["reason"] == "fixpack_already_in_progress"


async def test_pending_funding_recognized_before_invoice_job_link(live_db):
    _, job, payment = await _seed(status="pending")
    async with live_db.connection() as conn:
        await conn.execute("update payments set fixpack_job_id = null where id = %s",
                           (uuid.UUID(payment["id"]),))
    store = PaidDeliveryStore()
    assert await store.get_for_job(job["id"]) is None
    assert await store.funding_pending(job["id"]) is True
    completed = await db.PaymentRepository().mark_completed_fixpack(
        payment["id"], external_ref=payment["external_ref"], fixpack_job_id=job["id"],
    )
    assert completed is not None
    assert await store.funding_pending(job["id"]) is False
    assert (await store.get_for_job(job["id"]))["payment_id"] == payment["id"]


@pytest.mark.parametrize("mismatch", ["provider", "reference", "audit"])
async def test_another_pending_invoice_cannot_explain_missing_funding(live_db, mismatch):
    _, job, payment = await _seed(status="pending")
    async with live_db.connection() as conn:
        if mismatch == "provider":
            await conn.execute("update payments set provider = 'yookassa' where id = %s",
                               (uuid.UUID(payment["id"]),))
        elif mismatch == "reference":
            await conn.execute("update payments set external_ref = %s where id = %s",
                               (uuid.uuid4().hex, uuid.UUID(payment["id"])))
        else:
            await conn.execute("update payments set audit_id = null where id = %s",
                               (uuid.UUID(payment["id"]),))
    store = PaidDeliveryStore()
    assert await store.get_for_job(job["id"]) is None
    assert await store.funding_pending(job["id"]) is False

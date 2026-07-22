"""Real-Postgres write-path smoke test for every repository in app/db.py.

This is the layer the rest of the suite structurally cannot provide. Every
other test runs with DATABASE_URL unset (tests/conftest.py's autouse
_no_ambient_database_url fixture), so every repository write takes the
`except DatabaseNotConfigured: return None` path and never builds real SQL;
tests/test_db.py then substitutes a FakePool that records query text/params
but never sends them to a real database. That catches wiring/param-order
cheaply, but it can never catch a mismatch between a Python value's type and a
real Postgres column type -- which is exactly the bug that hit prod twice
(`psycopg.errors.DatatypeMismatch: column "expires_at" is of type timestamp
with time zone but expression is of type integer`).

This file closes that gap: it runs the REAL repositories against a REAL
Postgres with the full migration set applied, calling the write path of every
repository at least once. A future migration that adds a column or changes a
type without updating the corresponding write method makes one of these calls
raise -- which is the whole point.

It is SKIPPED unless DATABASE_URL is set, so a developer running `pytest -q`
locally without a Postgres sees nothing new. CI sets DATABASE_URL to a service
container and applies migrations first -- see
.github/workflows/db-postgres-smoke.yml and POSTGRES_CI_SMOKE_TEST_PLAN.md.

The DATABASE_URL dance below is load-bearing: conftest's autouse fixture
DELETES DATABASE_URL at runtime (before this test body runs), even in CI. So
the value is captured at import (collection) time -- before any fixture runs --
and re-injected by the real_db fixture, which runs after the autouse one. A
naive `skipif`-only test would find DATABASE_URL gone at runtime and silently
exercise the not-configured None path: a false green.
"""

from __future__ import annotations

import datetime
import os
import time
import uuid

import pytest

import app.db as db_mod
from app.accounts import generate_api_key
from app.db import (
    AccountRepository,
    AuditRepository,
    FixOutcomeRepository,
    FixpackJobRepository,
    MonitoringRunRepository,
    PaymentRepository,
    SubscriptionRepository,
)

# Captured at import time, before conftest's autouse _no_ambient_database_url
# deletes it. skipif is evaluated at collection time too, so both see the
# CI-provided value; the real_db fixture re-injects it at runtime.
_SMOKE_DB_URL = os.environ.get("DATABASE_URL")

pytestmark = pytest.mark.skipif(
    not _SMOKE_DB_URL,
    reason=(
        "real-Postgres smoke test: set DATABASE_URL to a live Postgres "
        "(CI does; local runs without it are skipped)"
    ),
)


@pytest.fixture
async def real_db(monkeypatch):
    """Re-establish the captured DATABASE_URL (and a throwaway API_KEY_PEPPER)
    after conftest's autouse fixture has stripped them, and give each test a
    fresh pool bound to this test's event loop. Closes the pool on teardown so
    it never leaks across the loop boundary."""
    monkeypatch.setenv("DATABASE_URL", _SMOKE_DB_URL)
    # AccountRepository.create hashes the key and raises loudly without a
    # pepper. A made-up value is fine here -- nothing verifies a real key.
    monkeypatch.setenv("API_KEY_PEPPER", "ci-smoke-pepper-not-a-real-secret")
    await db_mod.close_pool()
    yield
    await db_mod.close_pool()


async def test_all_repository_write_paths(real_db):
    """One real call per repository write path against live Postgres. Ordered
    so foreign keys resolve (audit -> fixpack_job -> fix_outcome; account ->
    payment). Asserts no exception + read-back with correct types -- the type
    round-trip the FakePool can't prove."""
    # Per-run token so re-running against a persistent DB doesn't collide on
    # unique constraints (payments (provider, external_ref); the subscription
    # natural key is handled by its own upsert).
    run = uuid.uuid4().hex[:12]

    audit_repo = AuditRepository()
    fixpack_repo = FixpackJobRepository()
    outcome_repo = FixOutcomeRepository()
    account_repo = AccountRepository()
    payment_repo = PaymentRepository()
    sub_repo = SubscriptionRepository()
    monitoring_repo = MonitoringRunRepository()

    # ---- AuditRepository.create -----------------------------------------
    audit = await audit_repo.create(
        stack="fastapi", file_count=3, score_total=8.5,
        score_json={"total": 8.5, "categories": {}}, findings_json=[],
        repo_url="https://github.com/acme/app",
        content_hash=f"smoke-{run}", engine_version="smoke-engine-1",
    )
    assert audit is not None, "DATABASE_URL not reaching get_pool -- false green"
    audit_id = audit["id"]
    uuid.UUID(audit_id)  # a real uuid string
    assert audit["access_token"]  # minted by the column default (migration 0010)
    assert isinstance(audit["score_total"], float)  # numeric -> float, not str
    assert audit["score_json"] == {"total": 8.5, "categories": {}}  # jsonb round-trip

    # Read-back paths (bonus -- the focus is writes, but these exercise the
    # SELECTs and prove the row is really there with sane types).
    assert (await audit_repo.get(audit_id))["stack"] == "fastapi"
    # status defaults to 'completed' (migration 0001), so the content-hash cache
    # lookup finds this row.
    cached = await audit_repo.get_by_content_hash(f"smoke-{run}", "smoke-engine-1")
    assert cached is not None and cached["id"] == audit_id
    assert (
        await audit_repo.get_authorized(audit_id, audit["access_token"])
    )["id"] == audit_id

    # ---- FixpackJobRepository -------------------------------------------
    # create: preview_expires_at is a float (Unix seconds) -> datetime at the
    # boundary, the same conversion class as the subscription bug.
    job = await fixpack_repo.create(
        audit_id=audit_id, pack="deploy", stack="fastapi",
        verified=True, detail="HTTP 200 on /",
        preview_local_url="http://localhost:20000/",
        preview_expires_at=time.time() + 3600,
    )
    assert job is not None
    job_id = job["id"]
    assert job["audit_id"] == audit_id  # real FK round-trip
    fetched_job = await fixpack_repo.get(job_id)
    assert isinstance(fetched_job["preview_expires_at"], datetime.datetime)

    await fixpack_repo.mark_delivered(job_id, f"https://github.com/acme/app/pull/{run}-1")

    # create_paid -> claim_one_paid (atomic paid->running) -> mark_fixpack_delivered
    paid = await fixpack_repo.create_paid(audit_id=audit_id, stack="fastapi")
    assert paid["status"] == "paid"
    claimed = await fixpack_repo.claim_one_paid()
    assert claimed is not None and claimed["status"] == "running"
    await fixpack_repo.mark_fixpack_delivered(
        claimed["id"], f"https://github.com/acme/app/pull/{run}-2"
    )
    assert (await fixpack_repo.get(claimed["id"]))["status"] == "delivered"

    # mark_status: both branches (detail=None, then detail=...)
    paid2 = await fixpack_repo.create_paid(audit_id=audit_id, stack="fastapi")
    await fixpack_repo.mark_status(paid2["id"], "no_fix_needed")  # detail=None branch
    await fixpack_repo.mark_status(paid2["id"], "failed", "smoke failure detail")
    assert (await fixpack_repo.get(paid2["id"]))["status"] == "failed"

    # reap_stale_running: the make_interval(...) SQL executes and returns counts.
    reap = await fixpack_repo.reap_stale_running(max_age_minutes=15, max_attempts=3)
    assert set(reap) == {"requeued", "failed"}

    # fixpack_processor_lock: the advisory-lock SQL round-trips.
    async with db_mod.fixpack_processor_lock():
        pass

    # ---- FixOutcomeRepository -------------------------------------------
    pr_url = f"https://github.com/acme/app/pull/{run}-outcome"
    outcome = await outcome_repo.record(
        fixpack_job_id=job_id, audit_id=audit_id,
        rule_ids=["SEC001", "CFG002"], stack="fastapi",
        outcome="delivered", is_regression=False, pr_url=pr_url,
    )
    assert outcome is not None
    assert outcome["rule_ids"] == ["SEC001", "CFG002"]  # jsonb array round-trip
    assert outcome["pr_merged"] is None
    updated = await outcome_repo.set_pr_merged_by_pr_url(pr_url, True)
    assert updated == 1  # rowcount of the matched delivered outcome

    # ---- AccountRepository.create (needs API_KEY_PEPPER) ----------------
    original_key = generate_api_key()
    account = await account_repo.create(api_key=original_key, tier="pro")
    assert account is not None
    account_id = account["id"]
    assert account["tier"] == "pro"

    # rotate_key: overwrite prefix+hash in place, surface a new plaintext once.
    # The old key's hash must no longer resolve; the new one must.
    from app.accounts import hash_api_key
    old_hash = account["key_hash"]
    rotated = await account_repo.rotate_key(account_id)
    assert rotated is not None
    assert rotated["api_key"] != original_key
    assert rotated["tier"] == "pro"
    assert await account_repo.get_by_key_hash(old_hash) is None
    assert (
        await account_repo.get_by_key_hash(hash_api_key(rotated["api_key"]))
    )["id"] == account_id

    # ---- PaymentRepository ----------------------------------------------
    payment = await payment_repo.create(
        account_id=account_id, provider="usdt_trc20",
        external_ref=None, amount=9.99, currency="USD",
        status="pending", tier_granted="pro",
    )
    assert payment is not None
    payment_id = payment["id"]
    assert isinstance(payment["amount"], float)  # numeric -> float, not str
    await payment_repo.mark_completed(
        payment_id, account_id=account_id, external_ref=f"0xcompleted-{run}"
    )
    assert (await payment_repo.get(payment_id))["status"] == "completed"

    # mark_completed_fixpack: a fixpack-product payment, no account granted.
    fp_payment = await payment_repo.create(
        account_id=None, provider="usdt_trc20", external_ref=None,
        amount=5.0, currency="USD", status="pending", tier_granted=None,
        product="fixpack", audit_id=audit_id,
    )
    await payment_repo.mark_completed_fixpack(
        fp_payment["id"], external_ref=f"0xfixpack-{run}"
    )

    # link_telegram_chat_id: the null-guard anti-hijack UPDATE + read-back.
    linked = await payment_repo.link_telegram_chat_id(payment_id, f"chat-{run}")
    assert linked is not None and linked["telegram_chat_id"] == f"chat-{run}"

    # PayPal one-time order (migration 0018's payments.paypal_order_id): create
    # a pending row keyed by the order id, resolve it back by that id, then
    # transition it to completed the way the capture webhook does. Proves the
    # new column + partial unique index + get_by_paypal_order_id SELECT against
    # real Postgres, not just the FakePool.
    paypal_order_id = f"ORDER-{run}"
    pp_payment = await payment_repo.create(
        account_id=None, provider="paypal", external_ref=None,
        amount=5.0, currency="USD", status="pending", tier_granted="pro",
        product="pro_tier", paypal_order_id=paypal_order_id,
    )
    assert pp_payment is not None
    assert pp_payment["paypal_order_id"] == paypal_order_id  # column round-trip
    by_order = await payment_repo.get_by_paypal_order_id(paypal_order_id)
    assert by_order is not None and by_order["id"] == pp_payment["id"]
    await payment_repo.mark_completed(
        pp_payment["id"], account_id=account_id,
        external_ref=f"CAPTURE-{run}",
    )
    completed_pp = await payment_repo.get_by_paypal_order_id(paypal_order_id)
    assert completed_pp["status"] == "completed"
    assert completed_pp["external_ref"] == f"CAPTURE-{run}"

    # ---- SubscriptionRepository (THE prod bug's write path) -------------
    # expires_at is passed as a Unix int -- exactly the shape Telegram sends.
    # Without _expires_at_to_timestamptz this raises DatatypeMismatch against
    # the timestamptz column. See the red->green proof in the PR.
    unix_ts = 1787133600  # 2026-08-19T10:00:00+00:00
    sub = await sub_repo.upsert_first(
        telegram_user_id=f"user-{run}", invoice_payload=f"sub-{run}",
        tier="test-monitoring", telegram_chat_id=f"chat-{run}",
        telegram_payment_charge_id="ch_1", expires_at=unix_ts,
    )
    assert sub is not None
    sub_id = sub["id"]

    # Read the row back and assert the stored value is a real timestamptz --
    # the exact assertion the FakePool cannot make (it never touches SQL types).
    fetched_sub = await sub_repo.get_by_user_and_payload(f"user-{run}", f"sub-{run}")
    assert isinstance(fetched_sub["expires_at"], datetime.datetime)
    assert fetched_sub["expires_at"].tzinfo is not None
    assert fetched_sub["expires_at"] == datetime.datetime.fromtimestamp(
        unix_ts, tz=datetime.timezone.utc
    )

    # renew: also a Unix int into the timestamptz column.
    renewed = await sub_repo.renew(
        sub_id, expires_at=unix_ts + 2_592_000,
        telegram_payment_charge_id="ch_2",
    )
    assert renewed is not None
    assert renewed["telegram_payment_charge_id"] == "ch_2"

    # set_status: renewal-state update only.
    canceled = await sub_repo.set_status(sub_id, "canceled")
    assert canceled["status"] == "canceled"

    # PayPal recurring subscription (migration 0018's subscriptions.
    # payment_provider + paypal_subscription_id): the PayPal-keyed write path,
    # distinct from the Stars (telegram_user_id, invoice_payload) key above.
    # upsert_first_paypal (ACTIVATED) -> resolve by the 'I-XXXX' id -> renew_paypal
    # (SALE) pushes expires_at out. expires_at is an aware datetime here (the
    # shape the PayPal handlers pass), asserted to round-trip as a real
    # timestamptz -- the type the FakePool can't prove.
    pp_sub_id = f"I-{run}"
    pp_repo_name = f"acme/paypal-smoke-{run}"
    pp_expires = datetime.datetime(2026, 9, 19, 10, 0, tzinfo=datetime.timezone.utc)
    pp_sub = await sub_repo.upsert_first_paypal(
        paypal_subscription_id=pp_sub_id, tier="monitoring",
        expires_at=pp_expires, repo_full_name=pp_repo_name,
    )
    assert pp_sub is not None
    assert pp_sub["status"] == "active"
    assert pp_sub["payment_provider"] == "paypal"

    fetched_pp_sub = await sub_repo.get_by_paypal_subscription_id(pp_sub_id)
    assert fetched_pp_sub is not None and fetched_pp_sub["id"] == pp_sub["id"]
    assert fetched_pp_sub["repo_full_name"] == pp_repo_name
    assert isinstance(fetched_pp_sub["expires_at"], datetime.datetime)
    assert fetched_pp_sub["expires_at"].tzinfo is not None
    assert fetched_pp_sub["expires_at"] == pp_expires

    pp_renewed = await sub_repo.renew_paypal(
        pp_sub["id"], expires_at=pp_expires + datetime.timedelta(days=30),
    )
    assert pp_renewed is not None
    reread_pp_sub = await sub_repo.get_by_paypal_subscription_id(pp_sub_id)
    assert reread_pp_sub["expires_at"] == pp_expires + datetime.timedelta(days=30)
    assert reread_pp_sub["status"] == "active"

    # ---- MonitoringRunRepository (async monitoring queue, migration 0017) ---
    # The push webhook's durable queue. Same real-Postgres write-path coverage
    # the other queue (fixpack_jobs) gets above: enqueue -> claim_one_pending
    # (atomic pending->running) -> mark_done, then a second run driven to the
    # 'failed' terminal state, plus reap_stale_running and the processor lock.
    # This repository stamps every timestamp via SQL now() (no Python-side Unix
    # conversion), so it can't hit the subscription DatatypeMismatch class of
    # bug -- but the point of this file is that EVERY repository is exercised
    # against real Postgres, not only the ones present when it was written.
    mon_repo_name = f"acme/monitor-smoke-{run}"

    enq = await monitoring_repo.enqueue(mon_repo_name)
    assert enq is not None, "DATABASE_URL not reaching get_pool -- false green"
    assert enq["status"] == "pending"
    assert enq["repo_full_name"] == mon_repo_name
    uuid.UUID(enq["id"])  # a real uuid string
    assert isinstance(enq["created_at"], datetime.datetime)  # timestamptz round-trip

    # claim_one_pending returns exactly the row we just enqueued (oldest pending;
    # this run terminalizes every row it creates, so no leftovers precede it),
    # leased pending -> running with started_at stamped and attempts bumped.
    claimed_run = await monitoring_repo.claim_one_pending()
    assert claimed_run is not None
    assert claimed_run["id"] == enq["id"]
    assert claimed_run["status"] == "running"
    assert claimed_run["attempts"] == 1
    assert isinstance(claimed_run["started_at"], datetime.datetime)
    await monitoring_repo.mark_done(claimed_run["id"])

    # A second run taken to 'failed' with a diagnosable error. Read the row back
    # via raw SQL (the repository has no getter) to prove the terminal write
    # landed with the error text intact -- the assertion the FakePool can't make.
    enq2 = await monitoring_repo.enqueue(mon_repo_name)
    claimed2 = await monitoring_repo.claim_one_pending()
    assert claimed2 is not None and claimed2["id"] == enq2["id"]
    await monitoring_repo.mark_failed(claimed2["id"], "smoke failure detail")

    pool = await db_mod.get_pool()
    async with pool.connection() as conn:
        cur = await conn.execute(
            "select status, error, completed_at from monitoring_runs where id = %s",
            (uuid.UUID(claimed2["id"]),),
        )
        failed_row = await cur.fetchone()
    assert failed_row["status"] == "failed"
    assert failed_row["error"] == "smoke failure detail"
    assert isinstance(failed_row["completed_at"], datetime.datetime)

    # reap_stale_running: the make_interval(...) SQL executes and returns counts.
    mon_reap = await monitoring_repo.reap_stale_running(
        max_age_minutes=15, max_attempts=3
    )
    assert set(mon_reap) == {"requeued", "failed"}

    # monitoring_processor_lock: the advisory-lock SQL round-trips.
    async with db_mod.monitoring_processor_lock():
        pass

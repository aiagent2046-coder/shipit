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

import asyncio
import datetime
import os
import time
import uuid

import httpx
import pytest

import app.db as db_mod
from app.accounts import api_key_prefix, generate_api_key
from app.billing import bank_transfer
from app.db import (
    AccountRepository,
    AuditRepository,
    FixOutcomeRepository,
    FixpackJobRepository,
    MonitoringRunRepository,
    PaymentRepository,
    ProcessorLockBusy,
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


# `confirm()` now tells the PAYER their transfer landed, and pages the operator
# when it cannot reach them. Both go out over httpx, so a direct call to
# confirm() in a test reaches api.telegram.org unless a transport is handed in
# -- which it did, at 0.4s of DNS per call, until this was noticed. The suite's
# rule is that nothing touches the network; this is how these call sites keep
# it.
def _no_network() -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True, "result": {"message_id": 1}})
    return httpx.MockTransport(handler)


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
        score_json={"total": 8.5, "categories": {}, "basis": "static+llm"}, findings_json=[],
        repo_url="https://github.com/acme/app",
        content_hash=f"smoke-{run}", engine_version="smoke-engine-1",
    )
    assert audit is not None, "DATABASE_URL not reaching get_pool -- false green"
    audit_id = audit["id"]
    uuid.UUID(audit_id)  # a real uuid string
    assert audit["access_token"]  # minted by the column default (migration 0010)
    assert isinstance(audit["score_total"], float)  # numeric -> float, not str
    assert audit["score_json"] == {"total": 8.5, "categories": {}, "basis": "static+llm"}  # jsonb round-trip

    # Read-back paths (bonus -- the focus is writes, but these exercise the
    # SELECTs and prove the row is really there with sane types).
    assert (await audit_repo.get(audit_id))["stack"] == "fastapi"
    # status defaults to 'completed' (migration 0001), so the content-hash cache
    # lookup finds this row -- provided score_json carries a basis, which is the
    # third element of the cache key. A row written without one (there are such
    # rows, from before basis existed) matches no depth and falls through to a
    # recompute, which is the safe direction.
    cached = await audit_repo.get_by_content_hash(
        f"smoke-{run}", "smoke-engine-1", "static+llm")
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
    # inserted: migration 0025's xmax idiom. This audit is new in this run, so
    # nothing live can precede it and a real INSERT must have happened.
    assert paid["inserted"] is True
    claimed = await fixpack_repo.claim_one_paid()
    # The oldest 'paid' row globally, which is this one: every test in this file
    # terminalizes the jobs it creates, so no live leftover precedes it.
    assert claimed is not None and claimed["id"] == paid["id"]
    assert claimed["status"] == "running"
    await fixpack_repo.mark_fixpack_delivered(
        claimed["id"], f"https://github.com/acme/app/pull/{run}-2"
    )
    assert (await fixpack_repo.get(claimed["id"]))["status"] == "delivered"

    # mark_status: both branches (detail=None, then detail=...)
    # Also a second insert for the SAME audit: legal because the first job is
    # 'delivered' and so outside fixpack_jobs_audit_live_idx's predicate.
    paid2 = await fixpack_repo.create_paid(audit_id=audit_id, stack="fastapi")
    assert paid2["inserted"] is True and paid2["id"] != paid["id"]
    await fixpack_repo.mark_status(paid2["id"], "no_fix_needed")  # detail=None branch
    await fixpack_repo.mark_status(paid2["id"], "failed", "smoke failure detail")
    assert (await fixpack_repo.get(paid2["id"]))["status"] == "failed"

    # reap_stale_running: the make_interval(...) SQL executes and returns counts.
    reap = await fixpack_repo.reap_stale_running(max_age_minutes=15, max_attempts=3)
    assert set(reap) == {"requeued", "failed", "failed_ids"}
    # the RETURNING id the processor alerts an operator on, per reaped job
    assert reap["failed_ids"] == []

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

    # get_by_job: the first read of this table that DECIDES anything. From
    # migration 0014 until 2026-08-20 nothing read fix_outcomes at all --
    # "collection only, nothing reads it for decisions yet" is what its
    # docstring said -- so this SELECT has never run against real Postgres
    # before, jsonb round-trip of rule_ids included. app/fixpack/merit.py
    # treats that column as a list, and a str would make every verdict wrong
    # in the direction of "it fixed nothing".
    by_job = await outcome_repo.get_by_job(job_id)
    assert by_job is not None, "the outcome just recorded is not readable back"
    assert isinstance(by_job["rule_ids"], list)
    assert by_job["rule_ids"] == ["SEC001", "CFG002"]
    assert by_job["is_regression"] is False

    # The verdict an operator would see, computed from the real rows rather
    # than from a dict a test wrote.
    from app.fixpack.merit import DELIVERED, assess
    verdict = assess(job=await fixpack_repo.get(job_id), outcome=by_job)
    assert verdict.conclusion == DELIVERED
    assert any("SEC001" in r.detail for r in verdict.reasons)

    assert await outcome_repo.get_by_job(str(uuid.uuid4())) is None
    assert await outcome_repo.get_by_job("not-a-uuid") is None
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

    # get_by_id: pins the post-0019 contract against the real database. There is
    # no api_key column any more, so the row this returns carries no key text at
    # all -- only the prefix that is safe to show. Four billing call sites used
    # to read ["api_key"] off exactly this row and 500 on the KeyError; the
    # shared FakeAccountRepo in tests/conftest.py copies this shape, and this
    # assertion is what keeps that fake honest.
    by_id = await account_repo.get_by_id(account_id)
    assert by_id is not None
    assert "api_key" not in by_id
    assert by_id["key_prefix"] == api_key_prefix(rotated["api_key"])
    assert await account_repo.get_by_id(str(uuid.uuid4())) is None

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

    # claim_key_delivery: migration 0024's one-shot claim, first asker wins.
    # This is the whole mechanism the two unauthenticated poll endpoints and
    # /link rely on to hand the plaintext key over exactly once, so both the
    # win and the loss have to come from real SQL rather than a fake's dict.
    assert await payment_repo.claim_key_delivery(payment_id) is True
    assert await payment_repo.claim_key_delivery(payment_id) is False
    await payment_repo.release_key_delivery(payment_id)
    assert await payment_repo.claim_key_delivery(payment_id) is True

    # A payment that is not completed is never claimable -- the status guard is
    # in the same UPDATE, so an unpaid invoice cannot mint a key.
    unpaid = await payment_repo.create(
        account_id=account_id, provider="usdt_trc20", external_ref=None,
        amount=5.0, currency="USD", status="pending", tier_granted="pro",
    )
    assert await payment_repo.claim_key_delivery(unpaid["id"]) is False

    # link_telegram_chat_id: the null-guard anti-hijack UPDATE + read-back.
    linked = await payment_repo.link_telegram_chat_id(payment_id, f"chat-{run}")
    assert linked is not None and linked["telegram_chat_id"] == f"chat-{run}"

    # migration 0018's payments.paypal_order_id is STILL SELECTED, and this is
    # what checks it. PayPal was removed as a way to pay, so nothing writes the
    # column any more -- but the rows it wrote are the books, and a SELECT list
    # that quietly drops a column is how a historical payment stops being
    # readable without anything failing. The write path that used to be
    # exercised here is gone with the provider; the read path is not.
    assert "paypal_order_id" in linked
    assert linked["paypal_order_id"] is None

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

    # Same rule one table over: migration 0018's subscriptions.
    # paypal_subscription_id and payment_provider are still SELECTed, and the
    # PayPal-keyed create/upsert/renew trio that wrote them is gone with the
    # provider. A row written by the surviving (telegram_user_id,
    # invoice_payload) key must still carry both columns back.
    assert "paypal_subscription_id" in canceled
    assert canceled["paypal_subscription_id"] is None
    assert canceled["payment_provider"] == "telegram_stars"

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

    # pending_summary reads the backlog WITHOUT consuming it -- the guard that
    # refuses to drain while monitoring is withdrawn from sale (#184) relies on
    # that, and on `count(*) over ()` plus dict-row access, neither of which a
    # fake can prove. Asserted here because a query only a stub has ever
    # executed is how #185 shipped a reference to an undefined name.
    summary = await monitoring_repo.pending_summary(limit=100)
    assert summary is not None, "DATABASE_URL not reaching get_pool -- false green"
    assert summary["total"] >= 1
    ours = [r for r in summary["runs"] if r["id"] == enq["id"]]
    assert ours, "the row just enqueued is missing from the pending summary"
    assert ours[0]["repo_full_name"] == mon_repo_name
    assert isinstance(ours[0]["created_at"], datetime.datetime)

    # claim_one_pending returns exactly the row we just enqueued (oldest pending;
    # this run terminalizes every row it creates, so no leftovers precede it),
    # leased pending -> running with started_at stamped and attempts bumped.
    # Reaching 'running' also proves pending_summary left the row claimable.
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

    # fixpack_processor_lock: same round-trip. Its mutual-exclusion behaviour
    # under real concurrency is a separate test below.
    async with db_mod.fixpack_processor_lock():
        pass


async def test_processor_lock_second_caller_skipped(real_db):
    """Three overlapping processor runs on REAL Postgres: one holds the lock,
    two are refused and do nothing.

    This is the assertion a FakePool cannot make. `pg_try_advisory_lock` is a
    SESSION lock, so mutual exclusion depends on the callers holding DIFFERENT
    pooled connections and the real lock manager arbitrating between them -- a
    fake returning a canned {"locked": ...} proves only that the wrapper reads
    the column it was handed.

    It was written against usdt_poll_lock, where the lock was the only thing
    standing between two polls and a double grant. That rail is gone; the lock
    machinery is not, and the Fix Pack processor still depends on it. Retargeted
    rather than deleted: the wrapper is what is under test, and it would have
    lost its only real-concurrency coverage.
    """
    holding = asyncio.Event()   # winner: "I hold the lock"
    release = asyncio.Event()   # driver: "the contenders have had their turn"

    async def winner():
        async with db_mod.fixpack_processor_lock():
            holding.set()
            await asyncio.wait_for(release.wait(), timeout=30)
            return "ran"

    async def contender():
        await holding.wait()      # only race once the lock is genuinely held
        try:
            async with db_mod.fixpack_processor_lock():
                return "acquired"
        except ProcessorLockBusy:
            # Exactly what the processor endpoint turns into
            # {"skipped_locked": True}.
            return "busy"

    async def drive():
        await asyncio.wait_for(holding.wait(), timeout=30)
        try:
            return await asyncio.gather(contender(), contender())
        finally:
            release.set()

    ran, contended = await asyncio.gather(winner(), drive())

    assert ran == "ran"
    # Neither overlapping run got in.
    assert contended == ["busy", "busy"]

    # The winner's `finally` really did pg_advisory_unlock: the next timer
    # firing must not be locked out forever by a finished run.
    async with db_mod.fixpack_processor_lock():
        pass


async def _fixpack_job_rows(audit_id: str) -> list[dict]:
    """Every Fix Pack job row for an audit, straight from SQL.

    The repository only offers get_by_audit (newest one), and the property these
    tests are about is a count, so it has to be read directly."""
    pool = await db_mod.get_pool()
    async with pool.connection() as conn:
        cur = await conn.execute(
            "select id, status, access_token from fixpack_jobs "
            "where audit_id = %s and pack = 'fixpack' order by created_at",
            (uuid.UUID(audit_id),),
        )
        return await cur.fetchall()


async def _fixpack_audit(audit_repo: AuditRepository, run: str) -> str:
    """A throwaway audit row to hang Fix Pack jobs off, since fixpack_jobs.
    audit_id is a real foreign key."""
    audit = await audit_repo.create(
        stack="fastapi", file_count=1, score_total=7.0,
        score_json={"total": 7.0, "categories": {}}, findings_json=[],
        repo_url="https://github.com/acme/app",
        content_hash=f"fixpack-{run}", engine_version="smoke-engine-1",
    )
    assert audit is not None, "DATABASE_URL not reaching get_pool -- false green"
    return audit["id"]


async def test_concurrent_mark_completed_only_one_wins(real_db):
    """Six concurrent completions of ONE invoice under SIX DIFFERENT charge ids,
    on real Postgres: exactly one may win, and the winner's account_id must
    survive.

    This is the race the old unconditional `update payments set ... where id = %s`
    lost silently. Every caller "succeeded", the last write decided which account
    the invoice pointed at, and the payer whose key was minted by an earlier
    caller was left holding a key for an account nothing references. The gate is
    now in the WHERE clause (`status = 'pending' or ...`), so the decision and the
    write happen in one statement and Postgres' row lock arbitrates.

    A real race, on separate pooled connections via asyncio.gather, in the shape
    of tests/test_audit_jobs_repo.py's concurrent-claim test -- sequential calls
    would prove only that the predicate reads its own writes.

    A different external_ref per contender is the point: same-ref replays are the
    idempotent case and are covered in the next test. Different refs mean these
    are six DISTINCT charges, and completing an invoice twice under two of them
    is the anomaly that must be refused rather than overwritten."""
    payment_repo, account_repo = PaymentRepository(), AccountRepository()
    run = uuid.uuid4().hex[:12]

    invoice = await payment_repo.create(
        account_id=None, provider="usdt_trc20", external_ref=None,
        amount=9.99, currency="USD", status="pending", tier_granted="pro",
    )
    assert invoice is not None, "DATABASE_URL not reaching get_pool -- false green"

    # One account per contender, so the row's final account_id identifies which
    # caller's write landed -- the assertion that catches a lost update.
    accounts = []
    for _ in range(6):
        account = await account_repo.create(api_key=generate_api_key(), tier="pro")
        assert account is not None
        accounts.append(account["id"])

    results = await asyncio.gather(*(
        payment_repo.mark_completed(
            invoice["id"], account_id=account_id,
            external_ref=f"0xrace-{run}-{i}",
        )
        for i, account_id in enumerate(accounts)
    ))

    winners = [row for row in results if row is not None]
    assert len(winners) == 1, (
        f"{len(winners)} callers completed one invoice under different charges"
    )
    winner = winners[0]

    # The winner's own write is what is at rest -- no loser overwrote it.
    stored = await payment_repo.get(invoice["id"])
    assert stored["status"] == "completed"
    assert stored["account_id"] == winner["account_id"]
    assert stored["external_ref"] == winner["external_ref"]

    # And the losers' accounts are not the one the invoice points at.
    losing = [a for a in accounts if a != winner["account_id"]]
    assert len(losing) == 5
    assert stored["account_id"] not in losing


async def test_mark_completed_same_external_ref_idempotent(real_db):
    """The other side of the gate: the SAME charge arriving twice must be told
    "yes, that's done" -- a row, not None.

    A retried Telegram webhook, a TRC20 transfer seen on two consecutive polls
    and a re-delivered PayPal capture all replay the same external_ref against an
    already-completed invoice. If that returned None the caller could not tell a
    harmless replay from the genuine two-distinct-charges anomaly, and would have
    to treat its own completed payment as failed.

    Covers both completion methods, since each carries its own copy of the
    predicate."""
    payment_repo, account_repo = PaymentRepository(), AccountRepository()
    run = uuid.uuid4().hex[:12]
    account = await account_repo.create(api_key=generate_api_key(), tier="pro")
    assert account is not None, "DATABASE_URL not reaching get_pool -- false green"

    invoice = await payment_repo.create(
        account_id=None, provider="usdt_trc20", external_ref=None,
        amount=9.99, currency="USD", status="pending", tier_granted="pro",
    )
    charge = f"0xreplay-{run}"

    first = await payment_repo.mark_completed(
        invoice["id"], account_id=account["id"], external_ref=charge
    )
    assert first is not None and first["status"] == "completed"

    replay = await payment_repo.mark_completed(
        invoice["id"], account_id=account["id"], external_ref=charge
    )
    assert replay is not None, "a replay of the same charge was refused"
    assert replay["account_id"] == account["id"]

    # A DIFFERENT charge against the same completed invoice is the refusal case.
    other = await account_repo.create(api_key=generate_api_key(), tier="pro")
    assert await payment_repo.mark_completed(
        invoice["id"], account_id=other["id"], external_ref=f"0xother-{run}"
    ) is None
    assert (await payment_repo.get(invoice["id"]))["account_id"] == account["id"]

    # mark_completed_fixpack: same three outcomes, its own copy of the predicate.
    audit_id = await _fixpack_audit(AuditRepository(), run)
    fp_invoice = await payment_repo.create(
        account_id=None, provider="usdt_trc20", external_ref=None,
        amount=5.0, currency="USD", status="pending", tier_granted=None,
        product="fixpack", audit_id=audit_id,
    )
    fp_charge = f"0xfpreplay-{run}"
    assert await payment_repo.mark_completed_fixpack(
        fp_invoice["id"], external_ref=fp_charge
    ) is not None
    assert await payment_repo.mark_completed_fixpack(
        fp_invoice["id"], external_ref=fp_charge
    ) is not None, "a replay of the same fixpack charge was refused"
    assert await payment_repo.mark_completed_fixpack(
        fp_invoice["id"], external_ref=f"0xfpother-{run}"
    ) is None
    assert (await payment_repo.get(fp_invoice["id"]))["external_ref"] == fp_charge


async def test_concurrent_create_paid_one_job_per_audit(real_db):
    """Six concurrent create_paid calls for ONE audit yield ONE job, on real
    Postgres: the arbiter is migration 0025's partial unique index, so only the
    real index can prove it.

    One paid Fix Pack must never become two fix PRs, and the retry path in
    grant_fixpack now calls this a second time by design (see the self-healing
    test below), so idempotency here is load-bearing rather than defensive.

    access_token is asserted identical across every result because the losers
    take the ON CONFLICT DO UPDATE branch, which performs no INSERT and so does
    not evaluate the column default from migration 0012. A link handed to the
    payer by the first call therefore stays valid; a fresh token per caller would
    mean the retry silently invalidated it."""
    fixpack_repo = FixpackJobRepository()
    run = uuid.uuid4().hex[:12]
    audit_id = await _fixpack_audit(AuditRepository(), run)

    results = await asyncio.gather(*(
        fixpack_repo.create_paid(audit_id=audit_id, stack="fastapi")
        for _ in range(6)
    ))

    assert all(row is not None for row in results)
    assert len({row["id"] for row in results}) == 1, "one payment, two fix PRs"
    assert [row["inserted"] for row in results].count(True) == 1, (
        "more than one caller believed it created the job"
    )
    assert len({row["access_token"] for row in results}) == 1, (
        "a retry re-minted access_token and invalidated the first link"
    )
    assert {row["status"] for row in results} == {"paid"}

    rows = await _fixpack_job_rows(audit_id)
    assert len(rows) == 1

    # Terminalize so this audit leaves no live row behind: claim_one_paid in
    # test_all_repository_write_paths takes the oldest 'paid' row GLOBALLY.
    await fixpack_repo.mark_status(str(rows[0]["id"]), "failed", "smoke cleanup")


async def test_repurchase_after_failed_is_allowed(real_db):
    """A terminal job must NOT block a new purchase for the same audit.

    This is a regression test on the index PREDICATE rather than on the happy
    path. `where status in ('paid', 'running')` is deliberately partial, and an
    unconditional unique index on audit_id would have been simpler and wrong: it
    would have made a customer whose generation failed unable to ever buy again,
    and it would have collided with the Deploy Pack rows that share audit_id
    (pack='deploy', status 'generated') as well as with the delivered history.

    Both terminal states a real audit passes through are covered: 'failed' (the
    re-purchase case) and 'delivered' (the second-Fix-Pack case)."""
    fixpack_repo = FixpackJobRepository()
    run = uuid.uuid4().hex[:12]
    audit_id = await _fixpack_audit(AuditRepository(), run)

    first = await fixpack_repo.create_paid(audit_id=audit_id, stack="fastapi")
    assert first["inserted"] is True

    # While it is live, a second purchase joins it -- the property above.
    assert (await fixpack_repo.create_paid(
        audit_id=audit_id, stack="fastapi"
    ))["id"] == first["id"]

    await fixpack_repo.mark_status(first["id"], "failed", "generation failed")

    second = await fixpack_repo.create_paid(audit_id=audit_id, stack="fastapi")
    assert second["inserted"] is True, "re-purchase after a failure was blocked"
    assert second["id"] != first["id"]
    assert second["access_token"] != first["access_token"]

    # Same again from 'delivered', the other terminal state.
    await fixpack_repo.mark_fixpack_delivered(
        second["id"], f"https://github.com/acme/app/pull/{run}-repurchase"
    )
    third = await fixpack_repo.create_paid(audit_id=audit_id, stack="fastapi")
    assert third["inserted"] is True, "purchase after delivery was blocked"
    assert third["id"] not in (first["id"], second["id"])

    assert len(await _fixpack_job_rows(audit_id)) == 3

    await fixpack_repo.mark_status(third["id"], "failed", "smoke cleanup")


async def test_grant_fixpack_self_heals_when_a_write_crashes(real_db):
    """THE test this change exists for: a crash between grant_fixpack's two
    writes must leave a state a retry can finish, and the retry must not produce
    a second fix PR.

    RED ON THE OLD CODE, GREEN ON THE NEW, and the reason is purely the order of
    the two writes -- there is no transaction around them and nothing here adds
    one.

      * OLD order (mark_completed_fixpack -> create_paid): the crash lands after
        the payment is already 'completed' but before the job exists. The retry
        hits grant_fixpack's `if existing["status"] == "completed": return
        existing` early-return and never reaches create_paid. No job, ever.
        Money taken, nothing delivered, unrecoverable -- so the assertions below
        find zero jobs and a payment that was completed by the crashed attempt.
      * NEW order (create_paid -> mark_completed_fixpack): the crash leaves the
        job created and the payment still 'pending'. The retry skips the
        early-return, calls create_paid again, gets the SAME job back (migration
        0025), and completes the payment -- finishing what the first attempt
        started.

    The crash is injected after the FIRST successful write whichever method that
    is, deliberately, so the test does not encode the new order in its own
    setup: both repository subclasses below perform their real write and then
    raise. On the old code that trips in mark_completed_fixpack, on the new one
    in create_paid, and `crashed_in` records which -- so the test measures the
    order rather than assuming it."""
    from app.billing import grant_fixpack

    audit_repo = AuditRepository()
    payment_repo = PaymentRepository()
    fixpack_repo = FixpackJobRepository()
    run = uuid.uuid4().hex[:12]
    audit_id = await _fixpack_audit(audit_repo, run)

    invoice = await payment_repo.create(
        account_id=None, provider="usdt_trc20", external_ref=None,
        amount=5.0, currency="USD", status="pending", tier_granted=None,
        product="fixpack", audit_id=audit_id,
    )
    assert invoice is not None, "DATABASE_URL not reaching get_pool -- false green"
    charge = f"0xselfheal-{run}"

    crashed_in: list[str] = []

    class CrashAfterCreatePaid(FixpackJobRepository):
        async def create_paid(self, **kwargs):
            await super().create_paid(**kwargs)
            crashed_in.append("create_paid")
            raise RuntimeError("connection lost after create_paid")

    class CrashAfterMarkCompleted(PaymentRepository):
        async def mark_completed_fixpack(self, payment_id, **kwargs):
            await super().mark_completed_fixpack(payment_id, **kwargs)
            crashed_in.append("mark_completed_fixpack")
            raise RuntimeError("connection lost after mark_completed_fixpack")

    grant_kwargs = dict(
        audit_repo=audit_repo, provider="usdt_trc20", external_ref=charge,
        amount=5.0, currency="USD", audit_id=audit_id,
        invoice_payment_id=invoice["id"],
    )

    with pytest.raises(RuntimeError):
        await grant_fixpack(
            fixpack_repo=CrashAfterCreatePaid(),
            payment_repo=CrashAfterMarkCompleted(), **grant_kwargs,
        )

    # Which write went first is the whole difference, so assert it outright.
    assert crashed_in == ["create_paid"], (
        f"the first write was {crashed_in}, not create_paid -- grant_fixpack "
        "must create the job before completing the payment"
    )
    assert (await payment_repo.get(invoice["id"]))["status"] == "pending"
    assert len(await _fixpack_job_rows(audit_id)) == 1

    # The retry, run entirely normally -- no fakes, no patches.
    job = await grant_fixpack(
        fixpack_repo=fixpack_repo, payment_repo=payment_repo, **grant_kwargs
    )

    assert job is not None
    assert job["inserted"] is False, "the retry created a second job"
    settled = await payment_repo.get(invoice["id"])
    assert settled["status"] == "completed"
    assert settled["external_ref"] == charge

    rows = await _fixpack_job_rows(audit_id)
    assert len(rows) == 1, f"{len(rows)} jobs for one paid Fix Pack"
    assert rows[0]["id"] == uuid.UUID(job["id"])

    await fixpack_repo.mark_status(job["id"], "failed", "smoke cleanup")


async def test_the_processor_locks_do_not_serialize_against_each_other(real_db):
    """The distinct keys are load-bearing, on REAL Postgres: holding one
    processor's lock must not block another's. A shared key would silently
    couple independent schedulers -- a long run on one would stall the other's
    backlog, and each would report the other's work as skipped_locked. Only
    real Postgres can show this, since the keys are only ever compared by its
    lock manager."""
    async with db_mod.fixpack_processor_lock():
        async with db_mod.monitoring_processor_lock():
            pass
    async with db_mod.bank_transfer_amount_lock():
        async with db_mod.fixpack_processor_lock():
            pass


# --- bank_transfer: manual confirmation, on real Postgres ---
#
# The provider's whole safety argument is that the operator can press Confirm
# twice, and that two payers can have open invoices at the same time. Both
# rest on SQL the in-memory fakes in tests/test_billing_bank_transfer.py can
# only imitate: the CAS predicate in mark_completed/mark_completed_fixpack and
# migration 0004's partial unique index on (provider, external_ref).

BANK_DETAILS_SMOKE = {
    "bank_name": "Example Test Bank",
    "swift": "TESTKZKAXXX",
    "beneficiary": "Test Beneficiary",
    "account": "KZ00TEST0000000000000000",
    "address": "1 Test Street, Testville",
}


async def test_bank_transfer_double_confirm_grants_pro_once(real_db):
    """The operator presses Confirm twice. Both presses must report success and
    exactly one account may exist -- the second press replays the invoice's own
    reference code, which is precisely what the CAS predicate admits.

    Only Postgres can settle this: the second call's fate is decided by
    `where id = %s and (status = 'pending' or (status = 'completed' and
    external_ref = %s))` inside one statement, under the row lock."""
    payment_repo, account_repo = PaymentRepository(), AccountRepository()
    invoice = await bank_transfer.create_invoice(
        payment_repo, details=dict(BANK_DETAILS_SMOKE)
    )
    assert invoice is not None, "DATABASE_URL not reaching get_pool -- false green"

    confirm_kwargs = {
        "payment_repo": payment_repo, "account_repo": account_repo,
        "payment_id": invoice["payment_id"], "transport": _no_network(),
    }
    first = await bank_transfer.confirm(**confirm_kwargs)
    second = await bank_transfer.confirm(**confirm_kwargs)

    assert first["granted"] is True
    assert second["granted"] is True, "a second Confirm press was refused"

    stored = await payment_repo.get(invoice["payment_id"])
    assert stored["status"] == "completed"
    # The reference code, not a bank transaction id: a second press then carries
    # the SAME external_ref, so the gate reads it as a replay rather than as a
    # second distinct charge it must refuse.
    assert stored["external_ref"] == invoice["reference"]

    # One account, and the key is delivered exactly once however many times the
    # payer reloads the checkout page.
    account_id = stored["account_id"]
    assert account_id is not None
    assert (await account_repo.get_by_id(account_id))["tier"] == "pro"
    status = await bank_transfer.invoice_status(
        payment_repo, account_repo, invoice["reference"]
    )
    assert status["api_key"] is not None
    again = await bank_transfer.invoice_status(
        payment_repo, account_repo, invoice["reference"]
    )
    assert again["api_key"] is None and again["key_already_delivered"] is True
    assert (await payment_repo.get(invoice["payment_id"]))["account_id"] == account_id


async def test_bank_transfer_double_confirm_creates_one_fixpack(real_db):
    """Same double press for the Fix Pack product: one paid job for the audit,
    arbitrated by migration 0025's partial unique index rather than by a
    check-then-write in Python."""
    payment_repo, fixpack_repo = PaymentRepository(), FixpackJobRepository()
    audit_repo = AuditRepository()
    run = uuid.uuid4().hex[:12]
    audit_id = await _fixpack_audit(audit_repo, f"bank-{run}")

    invoice = await bank_transfer.create_fixpack_invoice(
        payment_repo, details=dict(BANK_DETAILS_SMOKE), audit_id=audit_id
    )
    assert invoice is not None, "DATABASE_URL not reaching get_pool -- false green"

    confirm_kwargs = {
        "payment_repo": payment_repo, "account_repo": AccountRepository(),
        "fixpack_repo": fixpack_repo, "audit_repo": audit_repo,
        "payment_id": invoice["payment_id"],
    }
    first = await bank_transfer.confirm(**confirm_kwargs)
    second = await bank_transfer.confirm(**confirm_kwargs)

    assert first["granted"] is True
    assert second["granted"] is True, "a second Confirm press was refused"
    assert first["product"] == "fixpack"

    rows = await _fixpack_job_rows(audit_id)
    assert len(rows) == 1, f"{len(rows)} Fix Pack jobs for one confirmed transfer"
    stored = await payment_repo.get(invoice["payment_id"])
    assert stored["status"] == "completed"
    assert stored["external_ref"] == invoice["reference"]

    await fixpack_repo.mark_status(str(rows[0]["id"]), "failed", "smoke cleanup")


async def test_bank_transfer_open_invoices_coexist(real_db):
    """Several payers waiting on the operator at once. Each invoice carries its
    own reference code, so migration 0004's unique index on (provider,
    external_ref) is satisfied and confirming one leaves the others pending.

    The USDT provider gets this for free by making the AMOUNT unique; a bank
    transfer cannot, because the bank converts at its own rate and what lands is
    never what was quoted. The reference code is the only distinguishing key
    this provider has, which is why its uniqueness is asserted against the real
    index rather than against a dict."""
    payment_repo, account_repo = PaymentRepository(), AccountRepository()
    invoices = [
        await bank_transfer.create_invoice(
            payment_repo, details=dict(BANK_DETAILS_SMOKE)
        )
        for _ in range(4)
    ]
    assert all(inv is not None for inv in invoices)
    references = [inv["reference"] for inv in invoices]
    assert len(set(references)) == 4

    confirmed = await bank_transfer.confirm(
        payment_repo=payment_repo, account_repo=account_repo,
        payment_id=invoices[1]["payment_id"], transport=_no_network(),
    )
    assert confirmed["granted"] is True

    for index, invoice in enumerate(invoices):
        row = await payment_repo.get(invoice["payment_id"])
        expected = "completed" if index == 1 else "pending"
        assert row["status"] == expected, f"invoice {index} is {row['status']}"
        # A reference lookup still resolves to its own invoice, so a payer
        # polling the checkout page never sees someone else's outcome.
        found = await payment_repo.get_by_external_ref(
            bank_transfer.PROVIDER, invoice["reference"]
        )
        assert found["id"] == invoice["payment_id"]


async def test_bank_transfer_reference_uniqueness_is_enforced_by_postgres(real_db):
    """The backstop behind _reserve_reference's re-roll: even if two concurrent
    creations picked the same code, the database refuses the second. Without
    this index a duplicate code would mean the operator confirming one payer's
    transfer and granting to another."""
    import psycopg

    payment_repo = PaymentRepository()
    reference = bank_transfer.generate_reference()

    first = await payment_repo.create(
        account_id=None, provider="bank_transfer", external_ref=reference,
        amount=5.0, currency="USD", status="pending", tier_granted="pro",
    )
    assert first is not None, "DATABASE_URL not reaching get_pool -- false green"

    with pytest.raises(psycopg.errors.UniqueViolation):
        await payment_repo.create(
            account_id=None, provider="bank_transfer", external_ref=reference,
            amount=5.0, currency="USD", status="pending", tier_granted="pro",
        )


# --- payer contact (migration 0026) against the real columns ---

# Obviously-fake stand-ins for a member of the public.
PAYER_NAME_SMOKE = "Test Payer"
PAYER_EMAIL_SMOKE = "test.payer@example.invalid"


async def test_bank_transfer_payer_contact_round_trips(real_db):
    """The columns exist, accept what the payer typed, and come back on every
    read path the operator's confirmation flow uses -- get() by id and
    get_by_external_ref() by reference code, which is what the Telegram
    notification is built from.

    payer_x (migration 0032) is checked on the same paths and not on its own,
    because the failure worth catching is a SELECT list that gained the column
    in one query and not another: Contact.from_payment reads whichever row it
    is handed, so a column missing from one read path is a customer silently
    losing a channel."""
    payment_repo = PaymentRepository()
    invoice = await bank_transfer.create_invoice(
        payment_repo, details=dict(BANK_DETAILS_SMOKE),
        payer_name=PAYER_NAME_SMOKE, payer_email=PAYER_EMAIL_SMOKE,
        payer_x="smoketest_x", payer_locale="ru-RU",
    )
    assert invoice is not None, "DATABASE_URL not reaching get_pool -- false green"

    by_id = await payment_repo.get(invoice["payment_id"])
    assert by_id["payer_name"] == PAYER_NAME_SMOKE
    assert by_id["payer_email"] == PAYER_EMAIL_SMOKE
    assert by_id["payer_x"] == "smoketest_x"

    by_ref = await payment_repo.get_by_external_ref(
        bank_transfer.PROVIDER, invoice["reference"]
    )
    assert by_ref["payer_name"] == PAYER_NAME_SMOKE
    assert by_ref["payer_email"] == PAYER_EMAIL_SMOKE
    assert by_ref["payer_x"] == "smoketest_x"
    assert by_id["payer_locale"] == "ru-RU"
    assert by_ref["payer_locale"] == "ru-RU"

    # And the whole point of the column: the row knows which channels this
    # customer has, without app/notify/ needing to know what a payment is.
    from app.notify.router import Contact
    assert Contact.from_payment(by_ref).channels() == ("email", "x")

    # And migration 0033: the language survives the round trip in the shape a
    # browser sends it, and the message picks it up. A payer who was shown
    # "мы напишем вам по-русски" at checkout must not get English hours later,
    # which is the only moment this column is ever read.
    from app.notify import messages
    assert messages.normalize(by_ref["payer_locale"]) == "ru"
    assert "Мы подтвердили" in messages.confirmation_body(
        product="pro_tier", reference=by_ref["external_ref"],
        site_url="https://drydock.co", locale=by_ref["payer_locale"])


async def test_payment_without_payer_contact_stores_nulls(real_db):
    """Both columns are nullable and stay nullable: an invoice created without
    them is not an error, it is the ordinary case. A NOT NULL here would have
    made every historical payment row invalid."""
    payment_repo = PaymentRepository()
    created = await payment_repo.create(
        account_id=None, provider="usdt_trc20",
        external_ref=None, amount=5.0, currency="USDT",
        status="pending", tier_granted="pro",
    )
    assert created is not None, "DATABASE_URL not reaching get_pool -- false green"
    assert created["payer_name"] is None
    assert created["payer_email"] is None
    assert (await payment_repo.get(created["id"]))["payer_name"] is None


async def test_payer_contact_is_not_format_checked_by_the_database(real_db):
    """A plain text column with no constraint, deliberately: this is a note for
    the operator's books, never an address anything is sent to."""
    payment_repo = PaymentRepository()
    invoice = await bank_transfer.create_invoice(
        payment_repo, details=dict(BANK_DETAILS_SMOKE),
        payer_name="Ünïcode Payer 名前", payer_email="not really an address",
    )
    assert invoice is not None
    stored = await payment_repo.get(invoice["payment_id"])
    assert stored["payer_name"] == "Ünïcode Payer 名前"
    assert stored["payer_email"] == "not really an address"


# Every foreign key in the schema, with the delete action it is meant to have.
# Ten are NO ACTION, reviewed 2026-08-02 -- see "Known gaps" in
# docs/status-active.md for the reasoning. The short version: NO ACTION cannot
# orphan a row, it refuses the delete that would; nothing in the application
# deletes a parent; and four of these keys reach money, where a cascade would
# quietly take a payment history with an account instead of making a human stop.
#
# ONE IS DIFFERENT, ON PURPOSE. `rls_live_checks.audit_id` is SET NULL, and it
# is the one row in this schema whose whole job is to outlive what it points
# at: the record that we sent a request to a database belonging to a third
# party. NO ACTION would let a consent row block an audit-retention job, and a
# ledger that stops unrelated deletes is a ledger somebody eventually removes.
# CASCADE would erase the record along with the audit, which is worse still.
#
# SET NULL is safe HERE and not in `payments` for a concrete reason: every
# column that gives the row meaning -- who consented, when, in which words,
# which project ref, which tables were asked about, what came back -- is on the
# row itself. `audit_id` is the least load-bearing column on it. A payment with
# no owner is money received that appears in nobody's history; a consent record
# with no audit is still a complete account of one check.
#
# This is a decision, not an oversight, so it is pinned. Changing an entry here
# is fine -- changing one without noticing is what this prevents.
EXPECTED_DELETE_ACTIONS = {
    "audit_jobs_account_id_fkey": "NO ACTION",
    "audit_jobs_audit_id_fkey": "NO ACTION",
    "fix_outcomes_audit_id_fkey": "NO ACTION",
    "fix_outcomes_fixpack_job_id_fkey": "NO ACTION",
    "fixpack_jobs_audit_id_fkey": "NO ACTION",
    "llm_usage_account_id_fkey": "NO ACTION",
    "llm_usage_audit_job_id_fkey": "NO ACTION",
    "payments_account_id_fkey": "NO ACTION",
    "payments_audit_id_fkey": "NO ACTION",
    "rls_live_checks_audit_id_fkey": "SET NULL",
    "subscriptions_account_id_fkey": "NO ACTION",
}


async def test_foreign_key_delete_actions_are_what_we_decided(real_db):
    """Read the delete action of every foreign key out of the live catalog.

    Also catches a new foreign key arriving without anyone choosing its delete
    behaviour: an unlisted constraint fails here rather than defaulting into
    the schema unexamined.
    """
    pool = await db_mod.get_pool()
    async with pool.connection() as conn:
        rows = await (await conn.execute(
            """
            select c.conname as name,
                   case c.confdeltype
                       when 'a' then 'NO ACTION'
                       when 'r' then 'RESTRICT'
                       when 'c' then 'CASCADE'
                       when 'n' then 'SET NULL'
                       when 'd' then 'SET DEFAULT'
                   end as delete_action
            from pg_constraint c
            where c.contype = 'f'
            """
        )).fetchall()

    # The pool hands back mapping rows, so unpacking a row yields its column
    # NAMES, not its values -- which silently produced {'conname': 'case'}.
    actual = {row["name"]: row["delete_action"] for row in rows}

    assert actual == EXPECTED_DELETE_ACTIONS, (
        "foreign key delete actions differ from the reviewed set; if this is "
        "intentional, update EXPECTED_DELETE_ACTIONS and the 'Known gaps' "
        "entry in README.md that explains why"
    )

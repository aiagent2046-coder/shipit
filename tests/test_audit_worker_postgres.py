"""The worker against the real queue: claim, run, finalize, repeat.

tests/test_audit_worker.py proves the worker's decisions with a fake repository;
tests/test_audit_jobs_repo.py proves the SQL. Neither proves they fit together
-- that the row a worker writes is the row the next claim_one sees, that a
transient failure really does come back after its backoff, that a permanent one
really is gone. Those are joins across the two, so they need Postgres.

What is still substituted here is _execute_job: a real scan means a zip, a
stack detector and an LLM provider, all covered elsewhere and none of it the
subject. Everything between claim_one and the committed row is real.

Same DATABASE_URL dance and the same skip as tests/test_audit_jobs_repo.py --
conftest's autouse _no_ambient_database_url deletes DATABASE_URL before the test
body, so it is captured at import time and re-injected by the fixture.
"""

from __future__ import annotations

import asyncio
import datetime
import os
import uuid

import pytest

import app.db as db_mod
from app.db import AuditJobRepository, AuditRepository
from app.ingest.github_fetch import RepoFetchError
from app.ingest.validators import ArchiveValidationError
from app.worker import main as worker

_SMOKE_DB_URL = os.environ.get("DATABASE_URL")

pytestmark = pytest.mark.skipif(
    not _SMOKE_DB_URL,
    reason=(
        "real-Postgres integration test: set DATABASE_URL to a live Postgres "
        "(CI does; local runs without it are skipped)"
    ),
)


@pytest.fixture
async def real_db(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", _SMOKE_DB_URL)
    await db_mod.close_pool()
    pool = await db_mod.get_pool()
    async with pool.connection() as conn:
        await conn.execute("delete from audit_jobs")
    yield
    await db_mod.close_pool()


@pytest.fixture
def no_emergency_stop(monkeypatch):
    """The flags table is a different subsystem; these tests are about the
    queue, so the stop is explicitly disengaged rather than left to whatever
    the database happens to hold."""
    async def running(flags_repo):
        return False, None

    monkeypatch.setattr(worker, "_emergency_stop_active", running)


def _enqueue_kwargs(**overrides):
    kwargs = {
        "source_kind": "repo_url",
        "source_ref": "https://github.com/acme/app",
        "content_hash": f"hash-{uuid.uuid4().hex[:12]}",
        "engine_version": "test-engine-1",
        "stack": "fastapi",
        "account_id": None,
        "quota_key": "ip:203.0.113.1",
        "idempotency_key": f"idem-{uuid.uuid4().hex}",
    }
    kwargs.update(overrides)
    return kwargs


async def _read_row(job_id: str) -> dict:
    pool = await db_mod.get_pool()
    async with pool.connection() as conn:
        cur = await conn.execute(
            "select * from audit_jobs where id = %s", (uuid.UUID(job_id),))
        return await cur.fetchone()


async def _make_audit() -> str:
    audit = await AuditRepository().create(
        stack="fastapi", file_count=2, score_total=7.5,
        score_json={"total": 7.5}, findings_json=[],
        content_hash=f"c-{uuid.uuid4().hex[:8]}", engine_version="test-engine-1",
    )
    return audit["id"]


async def _run_one_slot(monkeypatch, *, stop_after: float = 0.5) -> None:
    """Start slot 0, let it drain, then shut it down the way run_worker does."""
    monkeypatch.setattr(worker, "AUDIT_WORKER_POLL_INTERVAL_SECONDS", 0.01)
    shutting_down = asyncio.Event()
    task = asyncio.create_task(worker._slot(
        0, jobs=AuditJobRepository(), llm_client=object(),
        audit_repo=object(), llm_usage_repo=object(), flags_repo=object(),
        shutting_down=shutting_down,
    ))
    await asyncio.sleep(stop_after)
    shutting_down.set()
    await asyncio.wait_for(task, timeout=10)


# --- the three outcomes, end to end -----------------------------------------


async def test_the_worker_drains_a_queued_job_and_links_its_audit(
    real_db, no_emergency_stop, monkeypatch,
):
    audit_id = await _make_audit()
    jobs = AuditJobRepository()
    enqueued = await jobs.enqueue(**_enqueue_kwargs())

    async def fake_execute(job, **kwargs):
        # Proof the worker handed the real claimed row down, not a copy of the
        # enqueue arguments.
        assert job["source_ref"] == "https://github.com/acme/app"
        assert job["state"] == "running"
        return audit_id

    monkeypatch.setattr(worker, "_execute_job", fake_execute)

    await _run_one_slot(monkeypatch)

    row = await _read_row(enqueued["id"])
    assert row["state"] == "succeeded"
    assert str(row["audit_id"]) == audit_id
    assert row["claimed_by"].endswith("/0")
    assert isinstance(row["completed_at"], datetime.datetime)


async def test_a_transient_failure_comes_back_queued_with_a_backoff(
    real_db, no_emergency_stop, monkeypatch,
):
    """GitHub 503 is not the caller's fault, so the job waits and tries again
    -- and the wait is real, or a hot loop would hammer a struggling provider."""
    jobs = AuditJobRepository()
    enqueued = await jobs.enqueue(**_enqueue_kwargs())

    async def fake_execute(job, **kwargs):
        raise RepoFetchError("github_error", "GitHub returned 503")

    monkeypatch.setattr(worker, "_execute_job", fake_execute)

    await _run_one_slot(monkeypatch)

    row = await _read_row(enqueued["id"])
    assert row["state"] == "queued"
    assert row["error_code"] == "github_error"
    assert row["available_at"] > datetime.datetime.now(datetime.timezone.utc)
    assert row["attempts"] >= 1
    assert row["completed_at"] is None


async def test_a_permanent_failure_dead_letters_without_burning_attempts(
    real_db, no_emergency_stop, monkeypatch,
):
    jobs = AuditJobRepository()
    enqueued = await jobs.enqueue(**_enqueue_kwargs())

    async def fake_execute(job, **kwargs):
        raise ArchiveValidationError("zip_bomb", "1000x compression ratio")

    monkeypatch.setattr(worker, "_execute_job", fake_execute)

    await _run_one_slot(monkeypatch)

    row = await _read_row(enqueued["id"])
    assert row["state"] == "dead_letter"
    assert row["error_code"] == "zip_bomb"
    assert row["attempts"] == 1, "a permanent failure should not retry"


async def test_a_transient_failure_is_retried_until_the_budget_runs_out(
    real_db, no_emergency_stop, monkeypatch,
):
    """Three attempts, then dead_letter -- the bound that stops a job the
    provider will never accept from being retried forever."""
    monkeypatch.setattr(worker, "AUDIT_WORKER_POLL_INTERVAL_SECONDS", 0.01)
    jobs = AuditJobRepository()
    enqueued = await jobs.enqueue(**_enqueue_kwargs())
    attempts = {"n": 0}

    async def always_transient(job, **kwargs):
        attempts["n"] += 1
        raise RepoFetchError("github_unreachable", "timeout")

    monkeypatch.setattr(worker, "_execute_job", always_transient)

    # Drive the retries directly rather than waiting out the real backoff: the
    # backoff itself is asserted above, and sleeping through it here would make
    # the test slow and timing-dependent for no extra coverage.
    for _ in range(3):
        pool = await db_mod.get_pool()
        async with pool.connection() as conn:
            await conn.execute(
                "update audit_jobs set available_at = now() where id = %s",
                (uuid.UUID(enqueued["id"]),))
        claimed = await jobs.claim_one(worker_id="w1", lease_seconds=300)
        if claimed is None:
            break
        await worker._process_job(
            claimed, worker_id="w1", jobs=jobs, llm_client=object(),
            audit_repo=object(), llm_usage_repo=object(),
            shutting_down=asyncio.Event(),
        )

    row = await _read_row(enqueued["id"])
    assert attempts["n"] == 3
    assert row["state"] == "dead_letter"
    assert row["error_code"] == "github_unreachable"


# --- the zombie-writer guard, against the real row --------------------------


async def test_a_reaped_worker_writes_nothing_to_the_row_it_lost(
    real_db, monkeypatch,
):
    """The fake-repository version of this asserts the worker chose not to
    write. This asserts the row another worker is holding is untouched
    afterwards -- the thing the choice exists to protect."""
    monkeypatch.setattr(worker, "AUDIT_WORKER_HEARTBEAT_SECONDS", 0.01)
    jobs = AuditJobRepository()
    enqueued = await jobs.enqueue(**_enqueue_kwargs())

    stalled = await jobs.claim_one(worker_id="stalled", lease_seconds=-1)
    await jobs.reap_expired(error_message="lease expired")
    live = await jobs.claim_one(worker_id="live", lease_seconds=300)
    assert live["id"] == stalled["id"]

    scan_finished = asyncio.Event()

    async def slow_scan(job, **kwargs):
        await asyncio.sleep(0.05)  # let the heartbeat discover the loss first
        scan_finished.set()
        return await _make_audit()

    monkeypatch.setattr(worker, "_execute_job", slow_scan)

    await asyncio.wait_for(
        worker._process_job(
            stalled, worker_id="stalled", jobs=jobs, llm_client=object(),
            audit_repo=object(), llm_usage_repo=object(),
            shutting_down=asyncio.Event(),
        ),
        timeout=10,
    )

    row = await _read_row(stalled["id"])
    assert row["state"] == "running", "the zombie finalized a live attempt"
    assert row["claimed_by"] == "live"
    assert row["audit_id"] is None
    assert row["error_code"] is None


# --- graceful shutdown ------------------------------------------------------


async def test_shutdown_hands_an_unfinished_job_straight_back(
    real_db, no_emergency_stop, monkeypatch,
):
    """A redeploy must leave the job claimable immediately and no worse off
    than before -- not parked for a lease TTL with an attempt spent."""
    monkeypatch.setattr(worker, "AUDIT_WORKER_POLL_INTERVAL_SECONDS", 0.01)
    monkeypatch.setattr(worker, "AUDIT_WORKER_HEARTBEAT_SECONDS", 30)
    jobs = AuditJobRepository()
    enqueued = await jobs.enqueue(**_enqueue_kwargs())
    started = asyncio.Event()

    async def never_finishes(job, **kwargs):
        started.set()
        await asyncio.sleep(60)
        return await _make_audit()

    monkeypatch.setattr(worker, "_execute_job", never_finishes)
    shutting_down = asyncio.Event()

    # Exactly run_worker's sequence: stop claiming, let the grace budget lapse,
    # cancel what is still in flight.
    task = asyncio.create_task(worker._slot(
        0, jobs=jobs, llm_client=object(), audit_repo=object(),
        llm_usage_repo=object(), flags_repo=object(),
        shutting_down=shutting_down,
    ))
    await asyncio.wait_for(started.wait(), timeout=10)
    shutting_down.set()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    row = await _read_row(enqueued["id"])
    assert row["state"] == "queued"
    assert row["claimed_by"] is None
    assert row["attempts"] == 0, "a redeploy must not burn an attempt"
    assert row["error_code"] is None
    # And the next worker up takes it on its very next poll.
    reclaimed = await jobs.claim_one(worker_id="next", lease_seconds=300)
    assert reclaimed is not None and reclaimed["id"] == enqueued["id"]


async def test_a_job_that_lands_inside_the_grace_budget_is_recorded(
    real_db, no_emergency_stop, monkeypatch,
):
    audit_id = await _make_audit()
    jobs = AuditJobRepository()
    enqueued = await jobs.enqueue(**_enqueue_kwargs())

    async def quick(job, **kwargs):
        return audit_id

    monkeypatch.setattr(worker, "_execute_job", quick)
    monkeypatch.setattr(worker, "AUDIT_WORKER_POLL_INTERVAL_SECONDS", 0.01)

    # The slot loop rather than run_worker: run_worker owns the pool lifecycle
    # and closes it on exit, which would tear down real_db's pool mid-test.
    shutting_down = asyncio.Event()
    task = asyncio.create_task(worker._slot(
        0, jobs=jobs, llm_client=object(), audit_repo=object(),
        llm_usage_repo=object(), flags_repo=object(),
        shutting_down=shutting_down,
    ))
    await asyncio.sleep(0.2)
    shutting_down.set()
    await asyncio.wait_for(task, timeout=10)

    row = await _read_row(enqueued["id"])
    assert row["state"] == "succeeded"
    assert str(row["audit_id"]) == audit_id


# --- concurrency ------------------------------------------------------------


async def test_parallel_slots_never_run_the_same_job_twice(
    real_db, no_emergency_stop, monkeypatch,
):
    """SKIP LOCKED is proven in the repository tests; what this adds is that a
    worker built out of several slots on one pool inherits that property."""
    monkeypatch.setattr(worker, "AUDIT_WORKER_POLL_INTERVAL_SECONDS", 0.01)
    monkeypatch.setattr(worker, "AUDIT_WORKER_HEARTBEAT_SECONDS", 30)
    jobs = AuditJobRepository()
    enqueued = [await jobs.enqueue(**_enqueue_kwargs()) for _ in range(6)]
    seen: list[str] = []

    async def record(job, **kwargs):
        seen.append(str(job["id"]))
        await asyncio.sleep(0.01)
        return await _make_audit()

    monkeypatch.setattr(worker, "_execute_job", record)
    shutting_down = asyncio.Event()

    tasks = [
        asyncio.create_task(worker._slot(
            slot, jobs=jobs, llm_client=object(), audit_repo=object(),
            llm_usage_repo=object(), flags_repo=object(),
            shutting_down=shutting_down,
        ))
        for slot in range(4)
    ]
    await asyncio.sleep(0.6)
    shutting_down.set()
    await asyncio.wait_for(asyncio.gather(*tasks), timeout=10)

    assert len(seen) == len(set(seen)), "a job was executed by two slots"
    states = [(await _read_row(job["id"]))["state"] for job in enqueued]
    assert states == ["succeeded"] * 6


# --- the reaper -------------------------------------------------------------


async def test_the_reaper_recovers_a_job_from_a_killed_worker(
    real_db, monkeypatch,
):
    # The SIGKILL backstop: no shutdown hook ran, so the row sits in 'running'
    # with a dead lease until the reaper puts it back.
    monkeypatch.setattr(worker, "AUDIT_WORKER_REAP_INTERVAL_SECONDS", 0.01)
    jobs = AuditJobRepository()
    enqueued = await jobs.enqueue(**_enqueue_kwargs())
    await jobs.claim_one(worker_id="killed", lease_seconds=-1)

    shutting_down = asyncio.Event()
    task = asyncio.create_task(
        worker._reaper(jobs=jobs, shutting_down=shutting_down))
    await asyncio.sleep(0.15)
    shutting_down.set()
    await asyncio.wait_for(task, timeout=10)

    row = await _read_row(enqueued["id"])
    assert row["state"] == "queued"
    assert row["claimed_by"] is None


# --- the emergency stop -----------------------------------------------------


async def test_a_paused_worker_leaves_the_backlog_untouched(
    real_db, monkeypatch,
):
    monkeypatch.setattr(worker, "AUDIT_WORKER_POLL_INTERVAL_SECONDS", 0.01)
    jobs = AuditJobRepository()
    enqueued = await jobs.enqueue(**_enqueue_kwargs())

    async def paused(flags_repo):
        return True, "spending frozen by ops"

    monkeypatch.setattr(worker, "_emergency_stop_active", paused)

    async def must_not_run(job, **kwargs):
        raise AssertionError("a paused worker executed a job")

    monkeypatch.setattr(worker, "_execute_job", must_not_run)

    await _run_one_slot(monkeypatch, stop_after=0.15)

    row = await _read_row(enqueued["id"])
    assert row["state"] == "queued"
    assert row["attempts"] == 0

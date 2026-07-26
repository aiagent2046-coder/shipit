"""Worker semantics with a fake queue: the decisions, not the SQL.

AuditJobRepository's SQL is covered against real Postgres in
tests/test_audit_jobs_repo.py, and the worker end-to-end against real Postgres
in tests/test_audit_worker_postgres.py. What is left -- and what this file
covers -- is the worker's own logic, where the interesting cases are ones a
real database cannot be asked to produce on cue:

  - the lease is lost *while* a scan is running, and
  - SIGTERM arrives *while* a scan is running.

Both are races. Waiting for real timing to reproduce them would make this file
flaky and, worse, silently useless the day it stops reproducing them. A fake
repository lets the test decide exactly when renew_lease starts returning False
and exactly when the scan is still mid-flight, so the assertion "the worker
wrote nothing" is a real assertion every run.
"""

from __future__ import annotations

import asyncio
import uuid

import psycopg
import pytest

from app.ingest.github_fetch import RepoFetchError
from app.ingest.validators import ArchiveValidationError
from app.llm.client import LLMError
from app.worker import main as worker


class FakeJobs:
    """The slice of AuditJobRepository the worker touches, with every call
    recorded and every answer scriptable."""

    def __init__(self, *, jobs=None, renew_ok=True):
        self._to_claim = list(jobs or [])
        self.renew_ok = renew_ok
        self.claimed: list[str] = []
        self.renewals = 0
        self.succeeded: list[dict] = []
        self.failed: list[dict] = []
        self.released: list[str] = []
        self.reaps = 0

    async def claim_one(self, *, worker_id, lease_seconds):
        if not self._to_claim:
            return None
        job = self._to_claim.pop(0)
        job = {**job, "claimed_by": worker_id}
        self.claimed.append(str(job["id"]))
        return job

    async def renew_lease(self, *, job_id, worker_id, lease_seconds):
        self.renewals += 1
        return self.renew_ok

    async def finalize_succeeded(self, *, job_id, worker_id, audit_id):
        self.succeeded.append({"job_id": job_id, "audit_id": audit_id})
        return True

    async def finalize_failed(self, *, job_id, worker_id, error_code,
                              error_message, permanent, backoff_seconds=30):
        self.failed.append({
            "job_id": job_id, "error_code": error_code,
            "error_message": error_message, "permanent": permanent,
        })
        return True

    async def release_early(self, *, job_id, worker_id):
        self.released.append(job_id)
        return True

    async def reap_expired(self, *, error_message):
        self.reaps += 1
        return {"requeued": 0, "dead_lettered": 0}

    @property
    def wrote_anything(self) -> bool:
        return bool(self.succeeded or self.failed or self.released)


def _job(**overrides):
    job = {
        "id": str(uuid.uuid4()),
        "state": "running",
        "source_kind": "repo_url",
        "source_ref": "https://github.com/acme/app",
        "content_hash": "hash-1",
        "engine_version": "test-engine-1",
        "account_id": None,
        "attempts": 1,
        "max_attempts": 3,
    }
    job.update(overrides)
    return job


async def _process(jobs, job, *, shutting_down=None):
    """_process_job with the collaborators the worker does not exercise in
    these tests stubbed out -- _execute_job is always patched by the caller."""
    return await worker._process_job(
        job, worker_id="test-worker", jobs=jobs, llm_client=object(),
        audit_repo=object(), llm_usage_repo=object(),
        shutting_down=shutting_down or asyncio.Event(),
    )


# --- error classification ---------------------------------------------------
#
# The one rule: does a later attempt at the identical job stand any chance.


@pytest.mark.parametrize("exc, code, permanent", [
    # The caller's archive is broken on every attempt.
    (ArchiveValidationError("zip_bomb", "1000x ratio"), "zip_bomb", True),
    (ArchiveValidationError("too_large", "over 50MB"), "too_large", True),
    # Same split create_audit draws between 422 and 502.
    (RepoFetchError("repo_not_found", "private or gone"), "repo_not_found", True),
    (RepoFetchError("too_large", "zipball too big"), "too_large", True),
    (RepoFetchError("github_error", "GitHub returned 503"), "github_error", False),
    (RepoFetchError("github_unreachable", "timeout"), "github_unreachable", False),
    # Provider down / rate limited.
    (LLMError("all providers failed"), "llm_unavailable", False),
    # The database says nothing about the job.
    (psycopg.OperationalError("connection refused"), "database_unavailable", False),
])
def test_classify_failure_maps_known_causes(exc, code, permanent):
    got_code, _message, got_permanent = worker.classify_failure(exc)
    assert (got_code, got_permanent) == (code, permanent)


def test_classify_failure_dead_letters_an_unrecognised_crash():
    # A poison pill must not be retried into three burnt workers; an unknown
    # exception is a bug, and a bug belongs in front of a human.
    code, message, permanent = worker.classify_failure(
        KeyError("score_json"))
    assert permanent is True
    assert code == "unexpected_error"
    assert "KeyError" in message


def test_classify_failure_passes_a_job_execution_error_through():
    code, message, permanent = worker.classify_failure(
        worker.JobExecutionError("payload_missing", "gone", permanent=True))
    assert (code, message, permanent) == ("payload_missing", "gone", True)


# --- outcomes ---------------------------------------------------------------


async def test_successful_job_is_finalized_with_its_audit_id(monkeypatch):
    audit_id = str(uuid.uuid4())

    async def fake_execute(job, **kwargs):
        return audit_id

    monkeypatch.setattr(worker, "_execute_job", fake_execute)
    jobs, job = FakeJobs(), _job()

    await _process(jobs, job)

    assert jobs.succeeded == [{"job_id": str(job["id"]), "audit_id": audit_id}]
    assert jobs.failed == []


async def test_transient_failure_is_recorded_as_retryable(monkeypatch):
    async def fake_execute(job, **kwargs):
        raise RepoFetchError("github_unreachable", "connection reset")

    monkeypatch.setattr(worker, "_execute_job", fake_execute)
    jobs = FakeJobs()

    await _process(jobs, _job())

    assert len(jobs.failed) == 1
    assert jobs.failed[0]["permanent"] is False
    assert jobs.failed[0]["error_code"] == "github_unreachable"
    assert jobs.succeeded == []


async def test_permanent_failure_is_recorded_as_terminal(monkeypatch):
    async def fake_execute(job, **kwargs):
        raise ArchiveValidationError("not_a_zip", "bad magic")

    monkeypatch.setattr(worker, "_execute_job", fake_execute)
    jobs = FakeJobs()

    await _process(jobs, _job())

    assert jobs.failed[0]["permanent"] is True
    assert jobs.failed[0]["error_code"] == "not_a_zip"


async def test_an_unexpected_crash_never_escapes_the_job(monkeypatch):
    # One bad job must not take the slot -- and therefore the other jobs --
    # down with it.
    async def fake_execute(job, **kwargs):
        raise RuntimeError("something nobody predicted")

    monkeypatch.setattr(worker, "_execute_job", fake_execute)
    jobs = FakeJobs()

    await _process(jobs, _job())  # no raise

    assert jobs.failed[0]["permanent"] is True


# --- the zombie-writer guard ------------------------------------------------


async def test_a_lost_lease_cancels_the_scan_and_writes_nothing(monkeypatch):
    """The property the whole design rests on.

    renew_lease returning False means the reaper already wrote this attempt off
    and another worker may now hold the job. Anything this slot writes would
    corrupt that worker's row, so the correct number of writes is zero -- not
    "a failure", not "a success recorded late"."""
    monkeypatch.setattr(worker, "AUDIT_WORKER_HEARTBEAT_SECONDS", 0.01)
    scan_started = asyncio.Event()
    scan_completed = False

    async def slow_scan(job, **kwargs):
        nonlocal scan_completed
        scan_started.set()
        # Long enough that the heartbeat is guaranteed to fire first; the test
        # never actually waits this out, because the cancel arrives.
        await asyncio.sleep(30)
        scan_completed = True
        return str(uuid.uuid4())

    monkeypatch.setattr(worker, "_execute_job", slow_scan)
    jobs = FakeJobs(renew_ok=False)

    await asyncio.wait_for(_process(jobs, _job()), timeout=5)

    assert jobs.wrote_anything is False, (
        "a worker that lost its lease must not touch the row")
    assert scan_completed is False, "the scan should have been cancelled"
    assert jobs.renewals >= 1


async def test_a_lease_lost_just_as_the_scan_succeeds_still_writes_nothing(
    monkeypatch,
):
    # The nastier ordering: the scan finished, so there is a real audit_id in
    # hand and the temptation is to record it. It still belongs to an attempt
    # the queue has reassigned.
    monkeypatch.setattr(worker, "AUDIT_WORKER_HEARTBEAT_SECONDS", 0.01)

    async def scan_then_lose_lease(job, **kwargs):
        await asyncio.sleep(0.05)  # let at least one heartbeat fail first
        return str(uuid.uuid4())

    monkeypatch.setattr(worker, "_execute_job", scan_then_lose_lease)
    jobs = FakeJobs(renew_ok=False)

    await asyncio.wait_for(_process(jobs, _job()), timeout=5)

    assert jobs.succeeded == []
    assert jobs.wrote_anything is False


async def test_a_healthy_lease_keeps_being_renewed(monkeypatch):
    monkeypatch.setattr(worker, "AUDIT_WORKER_HEARTBEAT_SECONDS", 0.01)

    async def scan(job, **kwargs):
        await asyncio.sleep(0.08)
        return str(uuid.uuid4())

    monkeypatch.setattr(worker, "_execute_job", scan)
    jobs = FakeJobs(renew_ok=True)

    await _process(jobs, _job())

    assert jobs.renewals >= 2, "the heartbeat should have renewed repeatedly"
    assert len(jobs.succeeded) == 1


# --- graceful shutdown ------------------------------------------------------


async def test_shutdown_releases_an_unfinished_job_back_to_the_queue(
    monkeypatch,
):
    """A redeploy must not park a job until its lease expires.

    release_early hands it straight back as 'queued' with the attempt refunded,
    so the next worker picks it up immediately."""
    monkeypatch.setattr(worker, "AUDIT_WORKER_HEARTBEAT_SECONDS", 30)
    scan_started = asyncio.Event()

    async def never_finishes(job, **kwargs):
        scan_started.set()
        await asyncio.sleep(30)
        return str(uuid.uuid4())

    monkeypatch.setattr(worker, "_execute_job", never_finishes)
    jobs, job = FakeJobs(), _job()
    shutting_down = asyncio.Event()

    task = asyncio.create_task(_process(jobs, job, shutting_down=shutting_down))
    await asyncio.wait_for(scan_started.wait(), timeout=5)

    # Exactly what run_worker does when the grace budget runs out.
    shutting_down.set()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert jobs.released == [str(job["id"])]
    assert jobs.succeeded == [] and jobs.failed == []


async def test_a_job_that_finishes_inside_the_budget_is_not_released(
    monkeypatch,
):
    # The other half of graceful: shutdown is not a reason to throw away work
    # that completed.
    audit_id = str(uuid.uuid4())

    async def quick(job, **kwargs):
        return audit_id

    monkeypatch.setattr(worker, "_execute_job", quick)
    jobs = FakeJobs()
    shutting_down = asyncio.Event()
    shutting_down.set()

    await _process(jobs, _job(), shutting_down=shutting_down)

    assert len(jobs.succeeded) == 1
    assert jobs.released == []


async def test_cancellation_without_shutdown_does_not_release(monkeypatch):
    # Only a shutdown releases. A cancellation from anywhere else is not a
    # licence to rewrite the row -- the lease reaper is the backstop there.
    monkeypatch.setattr(worker, "AUDIT_WORKER_HEARTBEAT_SECONDS", 30)
    started = asyncio.Event()

    async def never_finishes(job, **kwargs):
        started.set()
        await asyncio.sleep(30)

    monkeypatch.setattr(worker, "_execute_job", never_finishes)
    jobs = FakeJobs()

    task = asyncio.create_task(_process(jobs, _job()))
    await asyncio.wait_for(started.wait(), timeout=5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert jobs.released == []


# --- the slot loop ----------------------------------------------------------


async def test_the_slot_does_not_claim_while_the_emergency_stop_is_engaged(
    monkeypatch,
):
    """Same soft-degrade as process_pending_monitoring: a background drain has
    nobody to answer 503, so it leaves the backlog queued and re-checks."""
    monkeypatch.setattr(worker, "AUDIT_WORKER_POLL_INTERVAL_SECONDS", 0.01)

    async def paused(flags_repo):
        return True, "spending frozen by ops"

    monkeypatch.setattr(worker, "_emergency_stop_active", paused)
    jobs = FakeJobs(jobs=[_job()])
    shutting_down = asyncio.Event()

    task = asyncio.create_task(worker._slot(
        0, jobs=jobs, llm_client=object(), audit_repo=object(),
        llm_usage_repo=object(), flags_repo=object(),
        shutting_down=shutting_down,
    ))
    await asyncio.sleep(0.1)
    shutting_down.set()
    await asyncio.wait_for(task, timeout=5)

    assert jobs.claimed == [], "a paused worker must not claim paid work"


async def test_the_slot_stops_claiming_on_shutdown(monkeypatch):
    monkeypatch.setattr(worker, "AUDIT_WORKER_POLL_INTERVAL_SECONDS", 0.01)

    async def running(flags_repo):
        return False, None

    monkeypatch.setattr(worker, "_emergency_stop_active", running)
    monkeypatch.setattr(worker, "AUDIT_WORKER_HEARTBEAT_SECONDS", 30)

    async def quick(job, **kwargs):
        return str(uuid.uuid4())

    monkeypatch.setattr(worker, "_execute_job", quick)
    jobs = FakeJobs(jobs=[_job(), _job()])
    shutting_down = asyncio.Event()

    task = asyncio.create_task(worker._slot(
        0, jobs=jobs, llm_client=object(), audit_repo=object(),
        llm_usage_repo=object(), flags_repo=object(),
        shutting_down=shutting_down,
    ))
    await asyncio.sleep(0.05)
    shutting_down.set()
    await asyncio.wait_for(task, timeout=5)

    assert len(jobs.succeeded) >= 1
    # An idle slot wakes on the event rather than sleeping out the interval.
    assert task.done()


async def test_the_reaper_runs_on_its_own_clock_and_survives_a_failure(
    monkeypatch,
):
    monkeypatch.setattr(worker, "AUDIT_WORKER_REAP_INTERVAL_SECONDS", 0.01)
    jobs = FakeJobs()
    calls = {"n": 0}

    async def flaky_reap(*, error_message):
        calls["n"] += 1
        if calls["n"] == 1:
            raise psycopg.OperationalError("connection reset")
        return {"requeued": 1, "dead_lettered": 0}

    jobs.reap_expired = flaky_reap
    shutting_down = asyncio.Event()

    task = asyncio.create_task(
        worker._reaper(jobs=jobs, shutting_down=shutting_down))
    await asyncio.sleep(0.06)
    shutting_down.set()
    await asyncio.wait_for(task, timeout=5)

    assert calls["n"] >= 2, "a failed reap pass must not kill the reaper"


def test_worker_id_identifies_host_pid_and_slot():
    # Migration 0022 documents this shape; it is what makes a stuck row
    # traceable to a process in the journal.
    assert worker._worker_id(3).count("/") == 2
    assert worker._worker_id(3).endswith("/3")

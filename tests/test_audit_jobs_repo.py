"""Real-Postgres tests for AuditJobRepository (migration 0022).

Integration, not mocked, and deliberately so. The claim/lease behaviour this
file covers is *entirely* Postgres semantics -- FOR UPDATE SKIP LOCKED, a
partial unique index, a CASE branch on a column the caller cannot see -- so a
FakePool that records query text (tests/test_db.py's approach) could assert
nothing that matters here. It can't prove two concurrent claims never return the
same job, and that is the single property the whole queue rests on.

Same DATABASE_URL dance as tests/test_db_postgres_smoke.py, for the same reason:
conftest's autouse _no_ambient_database_url DELETES DATABASE_URL before the test
body runs, so the CI value is captured at import (collection) time and
re-injected by the fixture. Without that, these tests would silently exercise
the not-configured None path -- a false green.

Skipped unless DATABASE_URL is set. CI provides it via a Postgres 17 service
container with every migration applied -- see .github/workflows/db-postgres-smoke.yml.
"""

from __future__ import annotations

import asyncio
import datetime
import os
import uuid

import pytest

import app.db as db_mod
from app.db import AuditJobRepository, AuditRepository

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
    """Re-establish the captured DATABASE_URL after conftest stripped it, give
    each test a fresh pool bound to its own event loop, and start from an empty
    queue.

    The truncate is load-bearing, not hygiene: claim_one takes the globally
    oldest claimable row, so a leftover job from an earlier test would be
    claimed instead of the one under test."""
    monkeypatch.setenv("DATABASE_URL", _SMOKE_DB_URL)
    await db_mod.close_pool()
    pool = await db_mod.get_pool()
    async with pool.connection() as conn:
        await conn.execute("delete from audit_jobs")
    yield
    await db_mod.close_pool()


def _enqueue_kwargs(**overrides):
    """A complete enqueue() call with a unique idempotency_key, so tests that
    don't care about idempotency never collide with each other."""
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
    """Raw read of every column, including the ones the repository never
    selects -- the point being to assert what actually landed in the row rather
    than what a method chose to hand back."""
    pool = await db_mod.get_pool()
    async with pool.connection() as conn:
        cur = await conn.execute(
            "select * from audit_jobs where id = %s", (uuid.UUID(job_id),)
        )
        return await cur.fetchone()


async def _set_attempts(job_id: str, attempts: int) -> None:
    pool = await db_mod.get_pool()
    async with pool.connection() as conn:
        await conn.execute(
            "update audit_jobs set attempts = %s where id = %s",
            (attempts, uuid.UUID(job_id)),
        )


# --- enqueue -------------------------------------------------------------

async def test_enqueue_creates_queued_job(real_db):
    repo = AuditJobRepository()

    job = await repo.enqueue(**_enqueue_kwargs())

    assert job is not None, "DATABASE_URL not reaching get_pool -- false green"
    assert job["inserted"] is True
    assert job["state"] == "queued"
    assert job["attempts"] == 0
    assert job["max_attempts"] == 3
    assert job["claimed_by"] is None
    assert job["audit_id"] is None
    uuid.UUID(job["id"])  # a real uuid string, not a UUID object
    # Minted by the column default, handed back exactly once.
    assert job["access_token"]
    # timestamptz round-trip, the type assertion a FakePool cannot make.
    assert isinstance(job["created_at"], datetime.datetime)
    assert isinstance(job["available_at"], datetime.datetime)


async def test_enqueue_with_account_id_round_trips(real_db):
    """account_id is a real FK to accounts(id) and crosses the Python/uuid
    boundary in both directions."""
    from app.accounts import generate_api_key
    from app.db import AccountRepository

    account = await AccountRepository().create(api_key=generate_api_key(), tier="pro")
    repo = AuditJobRepository()

    job = await repo.enqueue(**_enqueue_kwargs(account_id=account["id"]))

    assert job["account_id"] == account["id"]  # str in, str out


async def test_enqueue_twice_with_live_job_returns_the_same_row(real_db):
    """The partial unique index collapses a duplicate submission onto the job
    already in flight instead of raising or creating a second one."""
    repo = AuditJobRepository()
    kwargs = _enqueue_kwargs(idempotency_key="idem-live")

    first = await repo.enqueue(**kwargs)
    second = await repo.enqueue(**kwargs)

    assert second["id"] == first["id"]
    assert second["inserted"] is False
    assert second["state"] == "queued"
    # And there is genuinely only one row, not a silently-swallowed second.
    pool = await db_mod.get_pool()
    async with pool.connection() as conn:
        cur = await conn.execute(
            "select count(*) as n from audit_jobs where idempotency_key = %s",
            ("idem-live",),
        )
        assert (await cur.fetchone())["n"] == 1


async def test_enqueue_after_terminal_state_creates_a_new_job(real_db):
    """The unique index is partial on the live states, so the same content can
    be resubmitted once the previous attempt is finished -- an engine bump, or a
    retry after whatever caused the dead_letter was fixed."""
    repo = AuditJobRepository()
    kwargs = _enqueue_kwargs(idempotency_key="idem-reusable")

    first = await repo.enqueue(**kwargs)
    claimed = await repo.claim_one(worker_id="w1", lease_seconds=300)
    await repo.finalize_failed(
        job_id=claimed["id"], worker_id="w1", error_code="bad_archive",
        error_message="corrupt zip", permanent=True,
    )
    assert (await _read_row(first["id"]))["state"] == "dead_letter"

    second = await repo.enqueue(**kwargs)

    assert second["inserted"] is True
    assert second["id"] != first["id"]
    assert second["state"] == "queued"


# --- the 'created' hop: staging an uploaded archive ------------------------
#
# A zip job is inserted as 'created', its bytes are written to the spool, and
# only then is it flipped to 'queued'. These cover the three ways that ends.

async def test_enqueue_honours_a_caller_supplied_job_id(real_db):
    """The spool filename IS the job id, so the API has to know the id before
    it can stage the archive -- which is before the row may become claimable."""
    repo = AuditJobRepository()
    chosen = str(uuid.uuid4())

    job = await repo.enqueue(**_enqueue_kwargs(job_id=chosen))

    assert job["id"] == chosen
    # And the default still applies when no id is offered.
    other = await repo.enqueue(**_enqueue_kwargs())
    uuid.UUID(other["id"])
    assert other["id"] != chosen


async def test_a_created_job_is_not_claimable(real_db):
    """The whole point of the intermediate state: an API crash between the
    insert and the write must not leave a claimable job whose payload does not
    exist."""
    repo = AuditJobRepository()
    await repo.enqueue(**_enqueue_kwargs(source_kind="zip", source_ref=None,
                                         initial_state="created"))

    assert await repo.claim_one(worker_id="w1", lease_seconds=300) is None


async def test_mark_queued_makes_it_claimable_and_records_the_payload(real_db):
    repo = AuditJobRepository()
    job = await repo.enqueue(**_enqueue_kwargs(source_kind="zip",
                                               source_ref=None,
                                               initial_state="created"))
    path = f"/srv/shipit/spool/{job['id']}.zip"

    assert await repo.mark_queued(job_id=job["id"], source_ref=path) is True

    claimed = await repo.claim_one(worker_id="w1", lease_seconds=300)
    assert claimed["id"] == job["id"]
    assert claimed["source_ref"] == path


async def test_mark_queued_fires_only_once_and_only_from_created(real_db):
    """Gated on 'created' so a late call can never drag a job that has already
    been claimed or finished back into the queue."""
    repo = AuditJobRepository()
    job = await repo.enqueue(**_enqueue_kwargs(source_kind="zip",
                                               source_ref=None,
                                               initial_state="created"))
    assert await repo.mark_queued(job_id=job["id"], source_ref="/p.zip") is True

    assert await repo.mark_queued(job_id=job["id"], source_ref="/other.zip") is False
    assert (await _read_row(job["id"]))["source_ref"] == "/p.zip"
    assert await repo.mark_queued(job_id=str(uuid.uuid4())) is False
    assert await repo.mark_queued(job_id="not-a-uuid") is False


async def test_abandon_created_releases_the_idempotency_key(real_db):
    """Staging failed, so the caller gets a 503 -- and their retry has to be
    able to queue a fresh job rather than colliding with the abandoned one."""
    repo = AuditJobRepository()
    kwargs = _enqueue_kwargs(source_kind="zip", source_ref=None,
                             initial_state="created",
                             idempotency_key="idem-staging-failed")
    job = await repo.enqueue(**kwargs)

    assert await repo.abandon_created(
        job_id=job["id"], error_code="staging_failed",
        error_message="OSError: No space left on device") is True

    row = await _read_row(job["id"])
    assert row["state"] == "dead_letter"
    assert row["error_code"] == "staging_failed"
    assert row["completed_at"] is not None
    # The key is free again because the live-state index no longer covers it.
    retry = await repo.enqueue(**kwargs)
    assert retry["inserted"] is True and retry["id"] != job["id"]


async def test_abandon_created_will_not_touch_a_queued_job(real_db):
    repo = AuditJobRepository()
    job = await repo.enqueue(**_enqueue_kwargs())  # inserted straight to queued

    assert await repo.abandon_created(
        job_id=job["id"], error_code="staging_failed", error_message="x") is False
    assert (await _read_row(job["id"]))["state"] == "queued"


async def test_reap_stuck_created_sweeps_only_the_old_ones(real_db):
    """The case abandon_created cannot cover: the API process died between the
    insert and either follow-up. reap_expired is no help -- a 'created' row was
    never claimed, so it has no lease to expire."""
    repo = AuditJobRepository()
    fresh = await repo.enqueue(**_enqueue_kwargs(source_kind="zip",
                                                 source_ref=None,
                                                 initial_state="created"))
    stale = await repo.enqueue(**_enqueue_kwargs(source_kind="zip",
                                                 source_ref=None,
                                                 initial_state="created"))
    pool = await db_mod.get_pool()
    async with pool.connection() as conn:
        await conn.execute(
            "update audit_jobs set created_at = now() - interval '2 hours' "
            "where id = %s", (uuid.UUID(stale["id"]),))

    swept = await repo.reap_stuck_created(
        older_than_seconds=600, error_message="staging never completed")

    assert swept == 1
    # A large upload mid-fsync is a legitimately live 'created' row.
    assert (await _read_row(fresh["id"]))["state"] == "created"
    reaped = await _read_row(stale["id"])
    assert reaped["state"] == "dead_letter"
    assert reaped["error_code"] == "staging_incomplete"


# --- claim ---------------------------------------------------------------

async def test_claim_one_returns_none_when_queue_is_empty(real_db):
    assert await AuditJobRepository().claim_one(
        worker_id="w1", lease_seconds=300
    ) is None


async def test_claim_one_leases_the_job(real_db):
    repo = AuditJobRepository()
    job = await repo.enqueue(**_enqueue_kwargs())

    claimed = await repo.claim_one(worker_id="worker-a/1", lease_seconds=300)

    assert claimed["id"] == job["id"]
    assert claimed["state"] == "running"
    assert claimed["claimed_by"] == "worker-a/1"
    assert claimed["attempts"] == 1
    assert isinstance(claimed["lease_expires_at"], datetime.datetime)
    assert claimed["lease_expires_at"] > claimed["claimed_at"]


async def test_claim_one_skips_a_job_still_in_backoff(real_db):
    """available_at is the retry gate: a job whose backoff has not elapsed is
    invisible to the claim even though it is 'queued'."""
    repo = AuditJobRepository()
    job = await repo.enqueue(**_enqueue_kwargs())
    pool = await db_mod.get_pool()
    async with pool.connection() as conn:
        await conn.execute(
            "update audit_jobs set available_at = now() + interval '1 hour' "
            "where id = %s",
            (uuid.UUID(job["id"]),),
        )

    assert await repo.claim_one(worker_id="w1", lease_seconds=300) is None


async def test_concurrent_claims_never_hand_out_the_same_job(real_db):
    """The property the whole queue rests on: FOR UPDATE SKIP LOCKED means two
    workers racing for the same row cannot both win, so one upload is never
    scanned (and paid for) twice.

    A real race, not two sequential calls: 12 claims are issued concurrently
    against 5 jobs on separate pooled connections, so they genuinely contend for
    the same rows. Exactly 5 must succeed, with 5 distinct ids -- a duplicate id
    here would mean the claim is not atomic."""
    repo = AuditJobRepository()
    jobs = [await repo.enqueue(**_enqueue_kwargs()) for _ in range(5)]

    results = await asyncio.gather(*(
        repo.claim_one(worker_id=f"worker-{i}", lease_seconds=300)
        for i in range(12)
    ))

    claimed = [row for row in results if row is not None]
    claimed_ids = [row["id"] for row in claimed]
    assert len(claimed_ids) == len(set(claimed_ids)), "a job was claimed twice"
    assert set(claimed_ids) == {job["id"] for job in jobs}
    assert all(row["attempts"] == 1 for row in claimed), "double-counted attempt"


# --- lease renewal -------------------------------------------------------

async def test_renew_lease_extends_a_held_lease(real_db):
    repo = AuditJobRepository()
    await repo.enqueue(**_enqueue_kwargs())
    claimed = await repo.claim_one(worker_id="w1", lease_seconds=60)

    assert await repo.renew_lease(
        job_id=claimed["id"], worker_id="w1", lease_seconds=600
    ) is True
    assert (await _read_row(claimed["id"]))["lease_expires_at"] > (
        claimed["lease_expires_at"]
    )


async def test_renew_lease_is_false_for_another_worker(real_db):
    repo = AuditJobRepository()
    await repo.enqueue(**_enqueue_kwargs())
    claimed = await repo.claim_one(worker_id="w1", lease_seconds=60)

    assert await repo.renew_lease(
        job_id=claimed["id"], worker_id="w2", lease_seconds=600
    ) is False


async def test_renew_lease_is_false_once_the_job_is_no_longer_running(real_db):
    """The signal a worker uses to notice it was reaped: the state moved on
    underneath it, so it must abort rather than keep spending on an attempt the
    queue has written off."""
    repo = AuditJobRepository()
    await repo.enqueue(**_enqueue_kwargs())
    claimed = await repo.claim_one(worker_id="w1", lease_seconds=-1)
    reaped = await repo.reap_expired(error_message="reaped")
    assert reaped["requeued"] == 1

    assert await repo.renew_lease(
        job_id=claimed["id"], worker_id="w1", lease_seconds=600
    ) is False


# --- finalize ------------------------------------------------------------

async def test_finalize_succeeded_links_the_audit(real_db):
    repo = AuditJobRepository()
    audit = await AuditRepository().create(
        stack="fastapi", file_count=3, score_total=8.5,
        score_json={"total": 8.5}, findings_json=[],
        content_hash=f"c-{uuid.uuid4().hex[:8]}", engine_version="test-engine-1",
    )
    await repo.enqueue(**_enqueue_kwargs())
    claimed = await repo.claim_one(worker_id="w1", lease_seconds=300)

    assert await repo.finalize_succeeded(
        job_id=claimed["id"], worker_id="w1", audit_id=audit["id"]
    ) is True

    row = await _read_row(claimed["id"])
    assert row["state"] == "succeeded"
    assert str(row["audit_id"]) == audit["id"]  # real FK round-trip
    assert isinstance(row["completed_at"], datetime.datetime)


async def test_finalize_succeeded_is_false_after_the_lease_was_lost(real_db):
    """The zombie-worker guard. A worker that stalled long enough to be reaped
    finishes its scan and tries to record a result -- but the job has already
    been requeued and may be running elsewhere, so the write must be refused
    outright rather than clobbering the live attempt."""
    repo = AuditJobRepository()
    audit = await AuditRepository().create(
        stack="fastapi", file_count=1, score_total=5.0,
        score_json={"total": 5.0}, findings_json=[],
        content_hash=f"c-{uuid.uuid4().hex[:8]}", engine_version="test-engine-1",
    )
    await repo.enqueue(**_enqueue_kwargs())
    stalled = await repo.claim_one(worker_id="stalled", lease_seconds=-1)
    await repo.reap_expired(error_message="reaped")
    live = await repo.claim_one(worker_id="live", lease_seconds=300)
    assert live["id"] == stalled["id"] and live["attempts"] == 2

    assert await repo.finalize_succeeded(
        job_id=stalled["id"], worker_id="stalled", audit_id=audit["id"]
    ) is False

    row = await _read_row(stalled["id"])
    assert row["state"] == "running", "the zombie overwrote the live attempt"
    assert row["claimed_by"] == "live"
    assert row["audit_id"] is None


async def test_finalize_failed_is_false_after_the_lease_was_lost(real_db):
    """Same guard on the failure path: a reaped worker must not be able to
    dead-letter a job another worker is now running."""
    repo = AuditJobRepository()
    await repo.enqueue(**_enqueue_kwargs())
    stalled = await repo.claim_one(worker_id="stalled", lease_seconds=-1)
    await repo.reap_expired(error_message="reaped")
    await repo.claim_one(worker_id="live", lease_seconds=300)

    assert await repo.finalize_failed(
        job_id=stalled["id"], worker_id="stalled",
        error_code="internal_error", error_message="boom", permanent=True,
    ) is False

    row = await _read_row(stalled["id"])
    assert row["state"] == "running"
    assert row["claimed_by"] == "live"
    assert row["error_code"] is None


async def test_finalize_failed_transient_requeues_with_backoff(real_db):
    """A provider blip is retryable, so the job returns to 'queued' with its
    lease cleared -- but not before the backoff elapses."""
    repo = AuditJobRepository()
    await repo.enqueue(**_enqueue_kwargs())
    claimed = await repo.claim_one(worker_id="w1", lease_seconds=300)

    assert await repo.finalize_failed(
        job_id=claimed["id"], worker_id="w1",
        error_code="llm_provider_unavailable", error_message="502 upstream",
        permanent=False, backoff_seconds=30,
    ) is True

    row = await _read_row(claimed["id"])
    assert row["state"] == "queued"
    assert row["claimed_by"] is None
    assert row["claimed_at"] is None
    assert row["lease_expires_at"] is None
    assert row["completed_at"] is None
    assert row["error_code"] == "llm_provider_unavailable"
    assert row["attempts"] == 1, "claim_one already counted the attempt"
    # 30 * 2**1 = 60s out.
    assert row["available_at"] > row["updated_at"] + datetime.timedelta(seconds=45)
    # ...and the backoff really does hide it from the next claim.
    assert await repo.claim_one(worker_id="w2", lease_seconds=300) is None


async def test_finalize_failed_transient_dead_letters_once_attempts_run_out(real_db):
    """Retrying forever is how a poison pill takes down every worker in turn;
    the same transient classification becomes terminal at max_attempts."""
    repo = AuditJobRepository()
    job = await repo.enqueue(**_enqueue_kwargs())
    await _set_attempts(job["id"], 2)  # claim will bump this to 3 == max_attempts
    claimed = await repo.claim_one(worker_id="w1", lease_seconds=300)
    assert claimed["attempts"] == 3

    assert await repo.finalize_failed(
        job_id=claimed["id"], worker_id="w1",
        error_code="llm_rate_limited", error_message="429", permanent=False,
    ) is True

    row = await _read_row(claimed["id"])
    assert row["state"] == "dead_letter"
    assert row["error_code"] == "llm_rate_limited"
    assert isinstance(row["completed_at"], datetime.datetime)
    # Kept as the forensic record of which worker last held it.
    assert row["claimed_by"] == "w1"


async def test_finalize_failed_permanent_dead_letters_on_the_first_attempt(real_db):
    """A corrupt archive fails identically on every worker, so it skips the
    retry budget entirely rather than burning three workers to prove it."""
    repo = AuditJobRepository()
    await repo.enqueue(**_enqueue_kwargs())
    claimed = await repo.claim_one(worker_id="w1", lease_seconds=300)
    assert claimed["attempts"] == 1  # well under max_attempts

    assert await repo.finalize_failed(
        job_id=claimed["id"], worker_id="w1", error_code="bad_archive",
        error_message="zip: central directory not found", permanent=True,
    ) is True

    row = await _read_row(claimed["id"])
    assert row["state"] == "dead_letter"
    assert row["error_code"] == "bad_archive"
    assert row["error_message"] == "zip: central directory not found"
    assert isinstance(row["completed_at"], datetime.datetime)


# --- early release -------------------------------------------------------
#
# The redeploy path. Everything above is a job that ran; these are jobs that
# were handed back untouched, and the distinction the row has to preserve is
# "not started" rather than "failed".


async def test_release_early_returns_the_job_to_the_queue(real_db):
    repo = AuditJobRepository()
    await repo.enqueue(**_enqueue_kwargs())
    claimed = await repo.claim_one(worker_id="w1", lease_seconds=300)

    assert await repo.release_early(job_id=claimed["id"], worker_id="w1") is True

    row = await _read_row(claimed["id"])
    assert row["state"] == "queued"
    assert row["claimed_by"] is None
    assert row["claimed_at"] is None
    assert row["lease_expires_at"] is None
    # Immediately, not after a backoff: a released job did not fail, and the
    # next worker up should take it on its very next poll.
    assert row["available_at"] <= datetime.datetime.now(datetime.timezone.utc)


async def test_release_early_refunds_the_attempt(real_db):
    """The reason this exists rather than letting the lease expire.

    claim_one counts an attempt optimistically, so a worker that shut down
    without running the job would otherwise spend one of three chances on a
    redeploy. Three redeploys in a row would dead-letter a job nobody ever
    tried."""
    repo = AuditJobRepository()
    await repo.enqueue(**_enqueue_kwargs())
    claimed = await repo.claim_one(worker_id="w1", lease_seconds=300)
    assert claimed["attempts"] == 1

    await repo.release_early(job_id=claimed["id"], worker_id="w1")

    assert (await _read_row(claimed["id"]))["attempts"] == 0


async def test_release_early_writes_no_error(real_db):
    # A released job is not a failed one; a stale error_code on a queued row
    # would show up in the poll endpoint as a failure that never happened.
    repo = AuditJobRepository()
    await repo.enqueue(**_enqueue_kwargs())
    claimed = await repo.claim_one(worker_id="w1", lease_seconds=300)

    await repo.release_early(job_id=claimed["id"], worker_id="w1")

    row = await _read_row(claimed["id"])
    assert row["error_code"] is None
    assert row["error_message"] is None
    assert row["completed_at"] is None


async def test_a_released_job_is_immediately_claimable_again(real_db):
    repo = AuditJobRepository()
    await repo.enqueue(**_enqueue_kwargs())
    first = await repo.claim_one(worker_id="w1", lease_seconds=300)
    await repo.release_early(job_id=first["id"], worker_id="w1")

    second = await repo.claim_one(worker_id="w2", lease_seconds=300)

    assert second is not None, "a released job must not wait out a backoff"
    assert second["id"] == first["id"]
    assert second["attempts"] == 1, "the refund makes this the first attempt again"


async def test_release_early_is_false_after_the_lease_was_lost(real_db):
    """The same lease gate as the finalize_* methods, and for the same reason.

    A shutting-down worker whose lease was already reaped must not drag the job
    out from under the worker that now holds it -- that would discard a scan in
    flight and refund an attempt that is being spent right now."""
    repo = AuditJobRepository()
    await repo.enqueue(**_enqueue_kwargs())
    claimed = await repo.claim_one(worker_id="w1", lease_seconds=-1)
    await repo.reap_expired(error_message="lease expired")
    stolen = await repo.claim_one(worker_id="w2", lease_seconds=300)
    assert stolen["id"] == claimed["id"]

    assert await repo.release_early(job_id=claimed["id"], worker_id="w1") is False

    row = await _read_row(claimed["id"])
    assert row["state"] == "running"
    assert row["claimed_by"] == "w2"


async def test_release_early_is_false_for_a_job_that_already_finished(real_db):
    # The shutdown race in the other direction: the scan completed and was
    # finalized, then the grace budget expired. Releasing would resurrect a
    # finished job and re-run a paid audit.
    repo = AuditJobRepository()
    await repo.enqueue(**_enqueue_kwargs())
    claimed = await repo.claim_one(worker_id="w1", lease_seconds=300)
    audit = await AuditRepository().create(
        stack="fastapi", file_count=1, score_total=7.0,
        score_json={"total": 7.0}, findings_json=[],
        content_hash=f"c-{uuid.uuid4().hex[:8]}", engine_version="test-engine-1",
    )
    await repo.finalize_succeeded(
        job_id=claimed["id"], worker_id="w1", audit_id=audit["id"])

    assert await repo.release_early(job_id=claimed["id"], worker_id="w1") is False
    assert (await _read_row(claimed["id"]))["state"] == "succeeded"


async def test_release_early_is_false_for_an_unknown_id(real_db):
    repo = AuditJobRepository()
    assert await repo.release_early(
        job_id=str(uuid.uuid4()), worker_id="w1") is False


async def test_release_early_is_false_for_a_malformed_id(real_db):
    # Same defensive parse as the other id-taking methods: a bad id is a False,
    # not a psycopg error escaping into a shutdown path.
    repo = AuditJobRepository()
    assert await repo.release_early(job_id="not-a-uuid", worker_id="w1") is False


# --- reaping -------------------------------------------------------------

async def test_reap_expired_requeues_while_attempts_remain(real_db):
    """A SIGKILLed worker loses nothing: the lease simply expires and the next
    pass picks the job back up."""
    repo = AuditJobRepository()
    await repo.enqueue(**_enqueue_kwargs())
    claimed = await repo.claim_one(worker_id="crashed", lease_seconds=-1)

    assert await repo.reap_expired(error_message="lease expired") == {
        "requeued": 1, "dead_lettered": 0,
    }

    row = await _read_row(claimed["id"])
    assert row["state"] == "queued"
    assert row["claimed_by"] is None
    assert row["lease_expires_at"] is None
    assert row["error_code"] is None, "a requeued job is not in a failed state"
    # Immediately claimable again -- available_at was reset, not backed off.
    assert (await repo.claim_one(
        worker_id="next", lease_seconds=300
    ))["id"] == claimed["id"]


async def test_reap_expired_dead_letters_once_attempts_run_out(real_db):
    repo = AuditJobRepository()
    job = await repo.enqueue(**_enqueue_kwargs())
    await _set_attempts(job["id"], 2)
    claimed = await repo.claim_one(worker_id="crashed", lease_seconds=-1)
    assert claimed["attempts"] == 3

    assert await repo.reap_expired(error_message="no completion after 3 attempts") == {
        "requeued": 0, "dead_lettered": 1,
    }

    row = await _read_row(claimed["id"])
    assert row["state"] == "dead_letter"
    assert row["error_code"] == "lease_expired"
    assert row["error_message"] == "no completion after 3 attempts"
    assert isinstance(row["completed_at"], datetime.datetime)


async def test_reap_expired_leaves_a_live_lease_alone(real_db):
    repo = AuditJobRepository()
    await repo.enqueue(**_enqueue_kwargs())
    await repo.claim_one(worker_id="w1", lease_seconds=600)

    assert await repo.reap_expired(error_message="lease expired") == {
        "requeued": 0, "dead_lettered": 0,
    }


# --- reads ---------------------------------------------------------------

async def test_get_authorized_requires_the_right_token(real_db):
    repo = AuditJobRepository()
    job = await repo.enqueue(**_enqueue_kwargs())

    found = await repo.get_authorized(
        job_id=job["id"], access_token=job["access_token"]
    )
    assert found["id"] == job["id"]
    assert found["state"] == "queued"
    # The token is matched in SQL and never re-selected, so it can't leak back
    # out through a response body built from this dict.
    assert "access_token" not in found

    assert await repo.get_authorized(job_id=job["id"], access_token="wrong") is None
    assert await repo.get_authorized(job_id=job["id"], access_token=None) is None
    assert await repo.get_authorized(
        job_id=str(uuid.uuid4()), access_token=job["access_token"]
    ) is None
    assert await repo.get_authorized(
        job_id="not-a-uuid", access_token=job["access_token"]
    ) is None


async def test_get_authorized_hands_over_the_audits_own_token(real_db):
    """Since the cutover this join is the submitter's only route to their
    result: the audits row has its own access_token, a different secret from
    the job's, and GET /v1/audits/{id} is gated by that one. Without it a
    caller would hold an audit_id they cannot read.

    Not a widening -- the old synchronous response handed this same submitter
    the same token in the POST body."""
    repo = AuditJobRepository()
    audit = await AuditRepository().create(
        stack="fastapi", file_count=3, score_total=8.5,
        score_json={"total": 8.5}, findings_json=[],
        content_hash=f"c-{uuid.uuid4().hex[:8]}", engine_version="test-engine-1",
    )
    job = await repo.enqueue(**_enqueue_kwargs())
    claimed = await repo.claim_one(worker_id="w1", lease_seconds=300)
    await repo.finalize_succeeded(
        job_id=claimed["id"], worker_id="w1", audit_id=audit["id"])

    found = await repo.get_authorized(
        job_id=job["id"], access_token=job["access_token"])

    assert found["state"] == "succeeded"
    assert found["audit_id"] == audit["id"]
    assert found["audit_access_token"] == audit["access_token"]
    assert found["audit_access_token"]  # not a null column read as a pass


async def test_get_authorized_has_no_audit_token_before_success(real_db):
    """The LEFT JOIN's other side: a job still in flight has no audits row, and
    must report that as null rather than failing to return at all."""
    repo = AuditJobRepository()
    job = await repo.enqueue(**_enqueue_kwargs())

    found = await repo.get_authorized(
        job_id=job["id"], access_token=job["access_token"])

    assert found["state"] == "queued"
    assert found["audit_id"] is None
    assert found["audit_access_token"] is None


async def test_backlog_stats_counts_by_state(real_db):
    repo = AuditJobRepository()
    for _ in range(3):
        await repo.enqueue(**_enqueue_kwargs())
    await repo.claim_one(worker_id="w1", lease_seconds=300)

    stats = await repo.backlog_stats()

    assert stats["states"] == {"queued": 2, "running": 1}
    assert stats["queued"] == 2
    assert stats["oldest_queued_seconds"] >= 0

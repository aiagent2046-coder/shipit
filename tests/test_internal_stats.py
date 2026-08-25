"""The observability read path: GET /internal/stats and the worker heartbeat.

Two halves, deliberately tested differently.

The endpoint's aggregates are SQL -- percentile_cont, a trailing-window
predicate, a GROUP BY that has to bucket by the right column. A fake repository
returning a hand-written dict would assert only that the endpoint copies keys
around, which is the part that cannot be wrong. So the aggregate tests run
against real Postgres, with rows planted at known timestamps, and at least one
row deliberately OUTSIDE each window so a predicate that silently matched
everything would fail. Auth and the not-configured branches need no database
and use the fake, matching tests/test_audit_intake_queue.py.

The heartbeat is not SQL: it is "does a periodic task emit the right record
without getting in the claim loop's way". Records are captured through a real
handler carrying the production ContextFilter and JsonFormatter, so a field
added to the log call but forgotten in logging_config.ALLOWED_FIELDS fails
here rather than silently vanishing in production.

Same DATABASE_URL dance as tests/test_audit_worker_postgres.py: conftest's
autouse _no_ambient_database_url strips the variable before the test body, so
it is captured at import time and re-injected by the real_db fixture.
"""

from __future__ import annotations

import asyncio
import datetime
import json
import logging
import os
import uuid

import pytest
from fastapi.testclient import TestClient

import app.db as db_mod
from app.logging_config import ContextFilter, JsonFormatter
from app.main import (
    app,
    get_audit_job_repo,
    get_fixpack_repo,
    get_llm_usage_repo,
)
from app.worker import main as worker

client = TestClient(app)

STATS_TOKEN = "fake-stats-token-not-a-real-secret"

_SMOKE_DB_URL = os.environ.get("DATABASE_URL")

requires_postgres = pytest.mark.skipif(
    not _SMOKE_DB_URL,
    reason=(
        "real-Postgres integration test: set DATABASE_URL to a live Postgres "
        "(CI does; local runs without it are skipped)"
    ),
)


@pytest.fixture
def stats_token(monkeypatch):
    monkeypatch.setenv("AUDIT_JOBS_STATS_TOKEN", STATS_TOKEN)
    return {"Authorization": f"Bearer {STATS_TOKEN}"}


class FakeBacklogRepo:
    """Enough of every repository the endpoint depends on to reach the auth
    and not-configured branches without a database. `None` everywhere is the
    DATABASE_URL-unset answer each real method gives."""

    def __init__(self, stats):
        self._stats = stats

    async def backlog_stats(self):
        return self._stats

    async def recent_outcomes(self, **kwargs):
        return self._stats

    async def status_counts(self):
        return self._stats

    async def spend_since(self, **kwargs):
        return self._stats


def _override_all(stats):
    for dependency in (get_audit_job_repo, get_fixpack_repo,
                       get_llm_usage_repo):
        app.dependency_overrides[dependency] = lambda s=stats: FakeBacklogRepo(s)


def _clear_overrides():
    for dependency in (get_audit_job_repo, get_fixpack_repo,
                       get_llm_usage_repo):
        app.dependency_overrides.pop(dependency, None)


# --- auth -------------------------------------------------------------------
#
# The same token and the same shape as /internal/audit-jobs/stats, which is the
# point: one credential for one monitoring audience.


def test_stats_requires_the_operator_token(stats_token):
    assert client.get("/internal/stats").status_code == 401
    bad = client.get("/internal/stats",
                     headers={"Authorization": "Bearer wrong"})
    assert bad.status_code == 401


def test_stats_rejects_a_token_that_is_a_prefix_of_the_real_one(stats_token):
    # compare_digest, not startswith.
    resp = client.get("/internal/stats",
                      headers={"Authorization": f"Bearer {STATS_TOKEN[:-1]}"})
    assert resp.status_code == 401


def test_stats_503s_when_the_token_is_not_configured(monkeypatch):
    monkeypatch.delenv("AUDIT_JOBS_STATS_TOKEN", raising=False)
    resp = client.get("/internal/stats",
                      headers={"Authorization": f"Bearer {STATS_TOKEN}"})
    # Not 401: an unset token means the check would be a no-op, and an endpoint
    # that cannot authenticate must refuse rather than answer.
    assert resp.status_code == 503
    assert resp.json()["detail"]["reason"] == "audit_jobs_stats_not_configured"


def test_stats_503s_without_a_database(stats_token):
    _override_all(None)
    try:
        resp = client.get("/internal/stats", headers=stats_token)
    finally:
        _clear_overrides()

    # Zeros from tables you cannot read would render as a healthy, idle system.
    assert resp.status_code == 503
    assert resp.json()["detail"]["reason"] == "not_configured"


# --- aggregates, against the real thing -------------------------------------


@pytest.fixture
async def real_db(monkeypatch):
    # conftest's autouse audit_queue fixture points get_audit_job_repo at an
    # in-memory fake so every test can POST /v1/audits. These tests are about
    # the SQL, so the real repository has to be back.
    _clear_overrides()
    monkeypatch.setenv("DATABASE_URL", _SMOKE_DB_URL)
    await db_mod.close_pool()
    pool = await db_mod.get_pool()
    async with pool.connection() as conn:
        await conn.execute("delete from audit_jobs")
        await conn.execute("delete from llm_usage")
        await conn.execute("delete from fix_outcomes")
        # payments.fixpack_job_id (migration 0035) made payments a child of
        # fixpack_jobs, and the key is ON DELETE NO ACTION -- so a payment
        # written by another test file refuses this wipe rather than being
        # orphaned by it. Release the reference instead of deleting the
        # payments: this fixture measures queues and outcomes, and money rows
        # are not its to remove.
        await conn.execute("update payments set fixpack_job_id = null")
        await conn.execute("delete from fixpack_jobs")
    yield pool
    await db_mod.close_pool()


def _ago(seconds: float) -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
        seconds=seconds)


async def _insert_audit_job(
    conn, *, state, claimed_ago=None, completed_ago=None, error_code=None,
    created_ago=0.0,
):
    await conn.execute(
        """
        insert into audit_jobs (
            state, source_kind, source_ref, content_hash, engine_version,
            idempotency_key, created_at, claimed_at, completed_at, error_code
        ) values (%s, 'repo_url', 'https://github.com/acme/app', %s,
                  'test-engine-1', %s, %s, %s, %s, %s)
        """,
        (
            state, f"hash-{uuid.uuid4().hex[:12]}", f"idem-{uuid.uuid4().hex}",
            _ago(created_ago),
            _ago(claimed_ago) if claimed_ago is not None else None,
            _ago(completed_ago) if completed_ago is not None else None,
            error_code,
        ),
    )


async def _insert_fixpack_job(conn, *, status, created_ago=0.0):
    await conn.execute(
        "insert into fixpack_jobs (pack, stack, status, created_at) "
        "values ('{}', 'fastapi', %s, %s)",
        (status, _ago(created_ago)),
    )


async def _insert_llm_usage(conn, *, calls, cost_usd, created_ago):
    await conn.execute(
        "insert into llm_usage (job_type, model, calls, cost_usd, created_at) "
        "values ('audit', 'claude-sonnet-4-6', %s, %s, %s)",
        (calls, cost_usd, _ago(created_ago)),
    )


@requires_postgres
async def test_stats_counts_audit_jobs_by_state(real_db, stats_token):
    async with real_db.connection() as conn:
        for _ in range(3):
            await _insert_audit_job(conn, state="queued", created_ago=90.0)
        await _insert_audit_job(conn, state="running", claimed_ago=10.0)
        await _insert_audit_job(conn, state="dead_letter", claimed_ago=60.0,
                                completed_ago=30.0, error_code="zip_bomb")

    resp = client.get("/internal/stats", headers=stats_token)

    assert resp.status_code == 200
    audit = resp.json()["audit_jobs"]
    assert audit["states"] == {"queued": 3, "running": 1, "dead_letter": 1}
    assert audit["queued"] == 3
    # The oldest queued row was planted 90s ago; the assertion is a band rather
    # than a value because the clock moves between the insert and the read.
    assert 85.0 < audit["oldest_queued_seconds"] < 120.0


@requires_postgres
async def test_stats_reports_recent_outcomes_and_the_error_rate(
    real_db, stats_token,
):
    async with real_db.connection() as conn:
        # Three terminal outcomes inside the hour: two failures, one success.
        await _insert_audit_job(conn, state="succeeded", claimed_ago=120.0,
                                completed_ago=100.0)
        await _insert_audit_job(conn, state="dead_letter", claimed_ago=300.0,
                                completed_ago=290.0, error_code="zip_bomb")
        await _insert_audit_job(conn, state="failed", claimed_ago=300.0,
                                completed_ago=280.0, error_code="zip_bomb")
        # Still running: not an outcome, must not appear in the denominator.
        await _insert_audit_job(conn, state="running", claimed_ago=5.0)

    body = client.get("/internal/stats", headers=stats_token).json()
    recent = body["audit_jobs"]["recent"]

    assert recent["terminal"] == {"succeeded": 1, "dead_letter": 1, "failed": 1}
    assert recent["terminal_total"] == 3
    assert recent["failed"] == 2
    assert body["errors"]["error_rate"] == pytest.approx(2 / 3)
    assert body["errors"]["source"] == "audit_jobs"
    assert body["errors"]["top_error_codes"] == [
        {"error_code": "zip_bomb", "jobs": 2}]


@requires_postgres
async def test_stats_measures_the_duration_a_worker_held_a_job(
    real_db, stats_token,
):
    async with real_db.connection() as conn:
        # 10s and 30s of held time; queued long before either, to prove the
        # duration is completed_at - claimed_at and not age since submission.
        await _insert_audit_job(conn, state="succeeded", created_ago=3000.0,
                                claimed_ago=110.0, completed_ago=100.0)
        await _insert_audit_job(conn, state="succeeded", created_ago=3000.0,
                                claimed_ago=130.0, completed_ago=100.0)
        # A failure has a duration too, but it must not move the success stats.
        await _insert_audit_job(conn, state="dead_letter", claimed_ago=900.0,
                                completed_ago=100.0, error_code="unexpected")

    recent = client.get("/internal/stats", headers=stats_token).json()[
        "audit_jobs"]["recent"]

    assert recent["succeeded_duration_ms"]["avg"] == pytest.approx(
        20_000, abs=200)
    assert recent["succeeded_duration_ms"]["p95"] == pytest.approx(
        29_000, abs=1_500)


@requires_postgres
async def test_stats_excludes_outcomes_older_than_the_window(
    real_db, stats_token,
):
    """The test that makes every other windowed assertion mean something: a
    predicate matching all rows would pass all of them and fail this one."""
    async with real_db.connection() as conn:
        await _insert_audit_job(conn, state="succeeded", claimed_ago=100.0,
                                completed_ago=60.0)
        await _insert_audit_job(conn, state="dead_letter", created_ago=7300.0,
                                claimed_ago=7300.0, completed_ago=7200.0,
                                error_code="ancient_history")

    body = client.get("/internal/stats", headers=stats_token).json()
    recent = body["audit_jobs"]["recent"]

    assert recent["terminal"] == {"succeeded": 1}
    assert recent["failed"] == 0
    assert body["errors"]["top_error_codes"] == []
    # The two-hour-old failure is gone from the window but its row still
    # exists, so the lifetime histogram still sees it -- the two numbers are
    # answering different questions.
    assert body["audit_jobs"]["states"]["dead_letter"] == 1


@requires_postgres
async def test_stats_error_rate_is_none_when_nothing_finished(
    real_db, stats_token,
):
    async with real_db.connection() as conn:
        await _insert_audit_job(conn, state="queued", created_ago=10.0)

    body = client.get("/internal/stats", headers=stats_token).json()

    # Not 0.0: "nothing failed" and "nothing ran" must not look identical to an
    # alert built on this field.
    assert body["errors"]["error_rate"] is None
    assert body["errors"]["terminal_total"] == 0
    assert body["audit_jobs"]["recent"]["succeeded_duration_ms"] == {
        "avg": None, "p95": None}


@requires_postgres
async def test_stats_reports_the_fixpack_queue(real_db, stats_token):
    async with real_db.connection() as conn:
        await _insert_fixpack_job(conn, status="paid", created_ago=300.0)
        await _insert_fixpack_job(conn, status="paid", created_ago=60.0)
        await _insert_fixpack_job(conn, status="delivered", created_ago=900.0)
        await _insert_fixpack_job(conn, status="failed", created_ago=900.0)

    fixpack = client.get("/internal/stats", headers=stats_token).json()[
        "fixpack_jobs"]

    assert fixpack["statuses"] == {"paid": 2, "delivered": 1, "failed": 1}
    # backlog is the 'paid' subset, the same definition /readyz uses.
    assert fixpack["paid_backlog"] == 2
    assert 295.0 < fixpack["oldest_paid_seconds"] < 330.0


@requires_postgres
async def test_stats_sums_llm_spend_over_both_windows(real_db, stats_token):
    async with real_db.connection() as conn:
        await _insert_llm_usage(conn, calls=3, cost_usd="0.250000",
                                created_ago=1800.0)     # inside the hour
        await _insert_llm_usage(conn, calls=5, cost_usd="1.500000",
                                created_ago=5 * 3600.0)  # inside the day only
        await _insert_llm_usage(conn, calls=99, cost_usd="99.000000",
                                created_ago=48 * 3600.0)  # outside both

    usage = client.get("/internal/stats", headers=stats_token).json()[
        "llm_usage"]

    assert usage["last_hour"] == {"calls": 3, "cost_usd": 0.25}
    assert usage["last_24h"] == {"calls": 8, "cost_usd": 1.75}


@requires_postgres
async def test_stats_answers_zeros_for_empty_tables(real_db, stats_token):
    resp = client.get("/internal/stats", headers=stats_token)

    assert resp.status_code == 200
    body = resp.json()
    assert body["window_seconds"] == 3600
    assert body["audit_jobs"]["states"] == {}
    assert body["audit_jobs"]["queued"] == 0
    assert body["audit_jobs"]["oldest_queued_seconds"] is None
    assert body["fixpack_jobs"] == {
        "statuses": {}, "paid_backlog": 0, "oldest_paid_seconds": None}
    # Nothing spent IS an answer, unlike nothing finished: a sum has an
    # identity element and a ratio does not.
    assert body["llm_usage"]["last_hour"] == {"calls": 0, "cost_usd": 0.0}


# --- the heartbeat ----------------------------------------------------------


class RecordCollector(logging.Handler):
    """Records as production would render them: the same ContextFilter, and the
    JSON line kept alongside so an `extra=` field missing from
    logging_config.ALLOWED_FIELDS fails a test instead of disappearing."""

    def __init__(self):
        super().__init__()
        self.addFilter(ContextFilter())
        self._formatter = JsonFormatter()
        self.records: list[logging.LogRecord] = []
        self.lines: list[dict] = []

    def emit(self, record):
        self.records.append(record)
        self.lines.append(json.loads(self._formatter.format(record)))

    def heartbeats(self) -> list[dict]:
        return [line for line in self.lines if line.get("event") == "heartbeat"]


@pytest.fixture
def collector():
    handler = RecordCollector()
    root = logging.getLogger()
    root.addHandler(handler)
    previous_level = root.level
    root.setLevel(logging.INFO)
    try:
        yield handler
    finally:
        root.removeHandler(handler)
        root.setLevel(previous_level)


class FakeQueue:
    """The two methods the heartbeat and the slot loop touch."""

    def __init__(self, stats=None, *, jobs=None):
        self.stats = stats or {"states": {"queued": 7}, "queued": 7,
                               "oldest_queued_seconds": 412.5}
        self._to_claim = list(jobs or [])
        self.claimed: list[str] = []
        self.succeeded: list[dict] = []
        self.stats_calls = 0

    async def backlog_stats(self):
        self.stats_calls += 1
        return self.stats

    async def claim_one(self, *, worker_id, lease_seconds):
        if not self._to_claim:
            return None
        job = self._to_claim.pop(0)
        self.claimed.append(str(job["id"]))
        return job

    async def renew_lease(self, *, job_id, worker_id, lease_seconds):
        return True

    async def finalize_succeeded(self, *, job_id, worker_id, audit_id):
        self.succeeded.append({"job_id": job_id, "audit_id": audit_id})
        return True

    async def finalize_failed(self, **kwargs):
        return True

    async def release_early(self, *, job_id, worker_id):
        return True


def _job():
    return {
        "id": str(uuid.uuid4()), "state": "running", "source_kind": "repo_url",
        "source_ref": "https://github.com/acme/app", "content_hash": "hash-1",
        "engine_version": "test-engine-1", "account_id": None,
        "attempts": 1, "max_attempts": 3,
    }


async def _run_heartbeat(jobs, *, for_seconds: float, monkeypatch,
                         interval: float = 0.02):
    monkeypatch.setattr(worker, "AUDIT_WORKER_STATS_INTERVAL_SECONDS", interval)
    shutting_down = asyncio.Event()
    task = asyncio.create_task(
        worker._stats_heartbeat(jobs=jobs, shutting_down=shutting_down))
    await asyncio.sleep(for_seconds)
    shutting_down.set()
    await asyncio.wait_for(task, timeout=5)


async def test_the_heartbeat_writes_the_queue_depth_as_a_log_event(
    collector, monkeypatch,
):
    """The record is the metric. Every field asserted here is one a
    `journalctl | jq` query would select or plot."""
    await _run_heartbeat(FakeQueue(), for_seconds=0.05, monkeypatch=monkeypatch)

    beats = collector.heartbeats()
    assert beats, "the heartbeat must emit unconditionally, not only when busy"
    first = beats[0]
    assert first["event"] == "heartbeat"
    assert first["queue_depth"] == 7
    assert first["oldest_queued_seconds"] == 412.5
    assert first["active_slots"] == 0
    assert first["level"] == "INFO"


async def test_heartbeat_fields_survive_the_json_allowlist(
    collector, monkeypatch,
):
    # JsonFormatter drops anything not in ALLOWED_FIELDS, so a field added to
    # the log call and forgotten in the allowlist is invisible in production
    # and only here. Asserting on the serialised line is the whole point.
    await _run_heartbeat(FakeQueue(), for_seconds=0.05, monkeypatch=monkeypatch)

    line = collector.heartbeats()[0]
    for field in ("event", "queue_depth", "oldest_queued_seconds",
                  "active_slots", "duration_ms"):
        assert field in line, f"{field} was dropped by ALLOWED_FIELDS"


async def test_the_heartbeat_repeats_on_its_interval(collector, monkeypatch):
    await _run_heartbeat(FakeQueue(), for_seconds=0.12, monkeypatch=monkeypatch,
                         interval=0.02)

    # A time series needs more than one point; this is what makes the interval
    # env var mean anything.
    assert len(collector.heartbeats()) >= 3


async def test_a_failing_stats_read_does_not_kill_the_heartbeat(
    collector, monkeypatch,
):
    jobs = FakeQueue()
    calls = {"n": 0}

    async def flaky_stats():
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("connection reset")
        return {"states": {"queued": 1}, "queued": 1,
                "oldest_queued_seconds": 1.0}

    jobs.backlog_stats = flaky_stats

    await _run_heartbeat(jobs, for_seconds=0.1, monkeypatch=monkeypatch)

    assert calls["n"] >= 2, "one failed pass must not end the reporting"
    # The failure is itself reported, so a gap in the series has a cause in the
    # journal next to it.
    assert any(line["level"] == "WARNING" for line in collector.heartbeats())


async def test_the_heartbeat_reports_slots_that_are_inside_a_job(
    collector, monkeypatch,
):
    """active_slots is the occupancy gauge; if it did not move, a saturated
    worker and an idle one would produce identical records."""
    monkeypatch.setattr(worker, "AUDIT_WORKER_POLL_INTERVAL_SECONDS", 0.01)
    monkeypatch.setattr(worker, "AUDIT_WORKER_HEARTBEAT_SECONDS", 30)
    monkeypatch.setattr(worker, "AUDIT_WORKER_STATS_INTERVAL_SECONDS", 0.02)

    async def running(flags_repo):
        return False, None

    monkeypatch.setattr(worker, "_emergency_stop_active", running)
    scan_started = asyncio.Event()

    async def slow_scan(job, **kwargs):
        scan_started.set()
        await asyncio.sleep(30)
        return str(uuid.uuid4())

    monkeypatch.setattr(worker, "_execute_job", slow_scan)
    jobs = FakeQueue(jobs=[_job()])
    shutting_down = asyncio.Event()

    slot_task = asyncio.create_task(worker._slot(
        0, jobs=jobs, llm_client=object(), audit_repo=object(),
        llm_usage_repo=object(), flags_repo=object(),
        shutting_down=shutting_down,
    ))
    await asyncio.wait_for(scan_started.wait(), timeout=5)
    beat_task = asyncio.create_task(
        worker._stats_heartbeat(jobs=jobs, shutting_down=shutting_down))
    await asyncio.sleep(0.05)
    shutting_down.set()
    slot_task.cancel()
    beat_task.cancel()
    await asyncio.gather(slot_task, beat_task, return_exceptions=True)

    assert collector.heartbeats()[0]["active_slots"] == 1
    # And the slot is not left counted as busy once it is gone.
    assert worker._active_slots == set()


async def test_a_slow_heartbeat_does_not_delay_the_claim_loop(monkeypatch):
    """The reason it is its own task. A stats read hanging on a wedged
    connection must not stop the worker from claiming and finishing jobs --
    which is precisely when someone is looking at the stats."""
    monkeypatch.setattr(worker, "AUDIT_WORKER_POLL_INTERVAL_SECONDS", 0.01)
    monkeypatch.setattr(worker, "AUDIT_WORKER_HEARTBEAT_SECONDS", 30)
    monkeypatch.setattr(worker, "AUDIT_WORKER_STATS_INTERVAL_SECONDS", 0.01)

    async def running(flags_repo):
        return False, None

    monkeypatch.setattr(worker, "_emergency_stop_active", running)

    async def quick(job, **kwargs):
        return str(uuid.uuid4())

    monkeypatch.setattr(worker, "_execute_job", quick)
    jobs = FakeQueue(jobs=[_job(), _job(), _job()])

    async def hanging_stats():
        await asyncio.sleep(30)

    jobs.backlog_stats = hanging_stats
    shutting_down = asyncio.Event()

    beat_task = asyncio.create_task(
        worker._stats_heartbeat(jobs=jobs, shutting_down=shutting_down))
    slot_task = asyncio.create_task(worker._slot(
        0, jobs=jobs, llm_client=object(), audit_repo=object(),
        llm_usage_repo=object(), flags_repo=object(),
        shutting_down=shutting_down,
    ))
    await asyncio.sleep(0.1)
    shutting_down.set()
    beat_task.cancel()
    await asyncio.wait_for(slot_task, timeout=5)
    await asyncio.gather(beat_task, return_exceptions=True)

    assert len(jobs.succeeded) == 3, (
        "the claim loop must drain the queue while the stats read is stuck")


async def test_run_worker_starts_and_stops_the_heartbeat(monkeypatch):
    # The wiring: a heartbeat nobody starts is not observability, and one
    # nobody cancels holds the process open past shutdown.
    started: list[str] = []

    async def fake_heartbeat(*, jobs, shutting_down):
        started.append("heartbeat")
        await shutting_down.wait()

    async def fake_reaper(*, jobs, shutting_down):
        await shutting_down.wait()

    async def fake_slot(slot, **kwargs):
        return None

    monkeypatch.setattr(worker, "_stats_heartbeat", fake_heartbeat)
    monkeypatch.setattr(worker, "_reaper", fake_reaper)
    monkeypatch.setattr(worker, "_slot", fake_slot)
    monkeypatch.setattr(worker.db_mod, "close_pool", lambda: asyncio.sleep(0))

    shutting_down = asyncio.Event()
    shutting_down.set()
    await asyncio.wait_for(
        worker.run_worker(concurrency=1, shutting_down=shutting_down),
        timeout=5)

    assert started == ["heartbeat"]


async def _insert_outcome(conn, *, rule_ids, outcome="delivered",
                          pr_merged=None, audit_id=None,
                          pr_url="https://github.com/acme/app/pull/1"):
    """One fix_outcomes row, optionally tied to a specific audit so the
    distinct-audit half of the threshold can be exercised."""
    if audit_id is None:
        cur = await conn.execute(
            "insert into audits (stack, status) values ('nextjs', 'completed') "
            "returning id"
        )
        audit_id = (await cur.fetchone())["id"]
    await conn.execute(
        "insert into fix_outcomes (audit_id, rule_ids, stack, outcome, "
        "pr_merged, pr_url) values (%s, %s::jsonb, 'nextjs', %s, %s, %s)",
        (audit_id, json.dumps(rule_ids), outcome, pr_merged, pr_url),
    )
    return audit_id


@requires_postgres
async def test_learning_counts_only_outcomes_that_carry_a_verdict(
    real_db, stats_token,
):
    """`labelled` is narrower than the row count on purpose.

    A rule teaches us something only when the Fix Pack was delivered AND the
    customer then merged or closed the PR. Blocked, failed, and
    still-undecided rows carry no verdict; counting them would report a rule
    as ready on evidence that cannot be learned from.
    """
    async with real_db.connection() as conn:
        await _insert_outcome(conn, rule_ids=["hardcoded_secret"],
                              pr_merged=True)
        await _insert_outcome(conn, rule_ids=["hardcoded_secret"],
                              pr_merged=False)
        # Delivered, nobody has decided yet -- reported, not counted.
        await _insert_outcome(conn, rule_ids=["hardcoded_secret"])
        # Never delivered, so its rule_ids never faced a customer.
        await _insert_outcome(conn, rule_ids=["hardcoded_secret"],
                              outcome="blocked")

    learning = client.get("/internal/stats", headers=stats_token).json()[
        "learning"]
    rule = next(r for r in learning["rules"]
                if r["rule_id"] == "hardcoded_secret")

    assert rule["labelled"] == 2
    assert rule["merged"] == 1
    assert rule["awaiting_verdict"] == 1
    assert rule["rows_total"] == 4
    assert rule["ready"] is False


@requires_postgres
async def test_learning_splits_a_multi_rule_outcome_across_its_rules(
    real_db, stats_token,
):
    """One Fix Pack fixes many findings, so one row carries many rule_ids and
    is evidence for each of them separately."""
    async with real_db.connection() as conn:
        await _insert_outcome(
            conn, rule_ids=["hardcoded_secret", "missing_env_example"],
            pr_merged=True)

    rules = {r["rule_id"]: r for r in
             client.get("/internal/stats", headers=stats_token).json()[
                 "learning"]["rules"]}

    assert rules["hardcoded_secret"]["labelled"] == 1
    assert rules["missing_env_example"]["labelled"] == 1


@requires_postgres
async def test_a_rule_is_not_ready_on_one_repository_alone(
    real_db, stats_token,
):
    """The load-bearing half of the threshold. Twenty merges from ONE
    customer's repository say the fix suits that repository; generalising from
    it is how a knowledge base learns something false with confidence."""
    async with real_db.connection() as conn:
        audit_id = await _insert_outcome(conn, rule_ids=["debug_true"],
                                         pr_merged=True)
        for _ in range(24):
            await _insert_outcome(conn, rule_ids=["debug_true"],
                                  pr_merged=True, audit_id=audit_id)

    learning = client.get("/internal/stats", headers=stats_token).json()[
        "learning"]
    rule = next(r for r in learning["rules"] if r["rule_id"] == "debug_true")

    assert rule["labelled"] == 25          # past the count threshold
    assert rule["audits"] == 1             # from a single codebase
    assert rule["ready"] is False
    assert learning["rules_ready"] == 0


@requires_postgres
async def test_a_rule_becomes_ready_once_both_thresholds_are_met(
    real_db, stats_token,
):
    """The other side of the boundary: a gate that never opens is not a gate."""
    async with real_db.connection() as conn:
        for _ in range(5):
            audit_id = await _insert_outcome(conn, rule_ids=["debug_true"],
                                             pr_merged=True)
            for _ in range(3):
                await _insert_outcome(conn, rule_ids=["debug_true"],
                                      pr_merged=True, audit_id=audit_id)

    learning = client.get("/internal/stats", headers=stats_token).json()[
        "learning"]
    rule = next(r for r in learning["rules"] if r["rule_id"] == "debug_true")

    assert rule["labelled"] == 20
    assert rule["audits"] == 5
    assert rule["ready"] is True
    assert learning["rules_ready"] == 1
    assert learning["thresholds"] == {"min_labelled": 20, "min_audits": 5}


@requires_postgres
async def test_a_verdict_on_a_fabricated_pr_url_does_not_count(
    real_db, stats_token,
):
    """The production table really held these on 2026-08-02.

    Four rows claiming pr_merged = true on URLs like
    ".../pull/278bcdc68ae9-outcome". A pull request number is an integer, so no
    such PR exists and no webhook ever fired for one -- they came from this
    very smoke suite, run four times against the PRODUCTION database instead of
    the throwaway container it is written for.

    They sat one distinct audit away from declaring SEC001 and CFG002 ready to
    learn from, on a fabricated 100% merge rate.
    """
    async with real_db.connection() as conn:
        for fake in ("278bcdc68ae9", "6771d0a8ca77", "dee92a1b284e",
                     "f6de4fc51a8c"):
            await _insert_outcome(
                conn, rule_ids=["SEC001", "CFG002"], pr_merged=True,
                pr_url=f"https://github.com/acme/app/pull/{fake}-outcome")

    rules = {r["rule_id"]: r for r in
             client.get("/internal/stats", headers=stats_token).json()[
                 "learning"]["rules"]}

    assert rules["SEC001"]["labelled"] == 0
    assert rules["SEC001"]["merged"] == 0
    assert rules["SEC001"]["audits"] == 0
    # Not deleted, and not hidden: the rows are still counted as rows, so the
    # history that they happened stays visible.
    assert rules["SEC001"]["rows_total"] == 4


@requires_postgres
async def test_a_verdict_from_a_real_webhook_still_counts(
    real_db, stats_token,
):
    """The boundary. A filter that refused everything would be worse than
    counting the fakes -- this is the shape GitHub actually sends."""
    async with real_db.connection() as conn:
        await _insert_outcome(
            conn, rule_ids=["sql-secret-assignment"], pr_merged=False,
            pr_url="https://github.com/aiagent2046-coder/shipit/pull/131")

    rules = {r["rule_id"]: r for r in
             client.get("/internal/stats", headers=stats_token).json()[
                 "learning"]["rules"]}

    assert rules["sql-secret-assignment"]["labelled"] == 1
    assert rules["sql-secret-assignment"]["merged"] == 0

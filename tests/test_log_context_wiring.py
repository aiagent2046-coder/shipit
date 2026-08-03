"""The wiring half of structured logging: who sets the correlation ids, and
whether the values are actually right.

PR1 built the mechanism (app/log_context.py, app/logging_config.py) and
deliberately called it from nowhere. This file covers the call sites:

  * the HTTP edge -- one id per request, returned in X-Request-ID, present on
    records emitted inside the request, gone again afterwards;
  * the 500 handler -- the id in the body is the SAME id as the header, which
    is only true because both come from one source;
  * the audit worker -- two slots running concurrently must never see each
    other's job_id. This is the assertion the whole design exists for, so it
    is written as "the values are correct", not "nothing blew up";
  * thread offloading -- the codebase moves blocking work off the loop with
    asyncio.to_thread and starlette's run_in_threadpool. Both must carry the
    context across, or every log line from a scan loses its job_id;
  * the monitoring drain -- the second durable queue, whose lines carried no
    ids at all until it bound them.

Records are captured with a real logging.Handler rather than caplog so the
ContextFilter (which is what copies the contextvars onto the record) is in the
path exactly as it is in production.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
import uuid

import pytest
from fastapi.testclient import TestClient
from starlette.concurrency import run_in_threadpool

import app.main as main_mod
from app import log_context as ctx
from app.logging_config import ContextFilter
from app.main import app, get_audit_repo
from app.worker import main as worker


class RecordCollector(logging.Handler):
    """Capture records with the production ContextFilter attached, so what is
    asserted is what a log line would actually carry."""

    def __init__(self):
        super().__init__()
        self.addFilter(ContextFilter())
        self.records: list[logging.LogRecord] = []

    def emit(self, record):
        self.records.append(record)


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


@pytest.fixture(autouse=True)
def _clean_context():
    """Contextvars set by one test must not colour the next one."""
    ctx.clear_log_context()
    yield
    ctx.clear_log_context()


# --- the HTTP edge --------------------------------------------------------


def test_every_response_carries_a_request_id():
    with TestClient(app) as client:
        first = client.get("/healthz")
        second = client.get("/healthz")

    assert first.headers["X-Request-ID"]
    assert second.headers["X-Request-ID"]
    # Minted per request, not per process.
    assert first.headers["X-Request-ID"] != second.headers["X-Request-ID"]


def test_an_inbound_request_id_is_ignored():
    """A public API must not let a caller choose what lands in its logs: the
    value is attacker-controlled text (newlines and all) and could be set to
    another user's id to poison a support investigation."""
    forged = "forged-by-the-client\nlevel=CRITICAL"
    with TestClient(app) as client:
        response = client.get("/healthz", headers={"X-Request-ID": forged})

    assert response.headers["X-Request-ID"] != forged
    assert "\n" not in response.headers["X-Request-ID"]


def test_records_emitted_inside_a_request_carry_that_requests_id(collector):
    logger = logging.getLogger("tests.inside-request")

    async def _log_something():
        logger.info("inside the request")
        return {"ok": True}

    app.add_api_route("/__test__/logs", _log_something, methods=["GET"])
    try:
        with TestClient(app) as client:
            response = client.get("/__test__/logs")
    finally:
        app.router.routes = [
            route for route in app.router.routes
            if getattr(route, "path", None) != "/__test__/logs"
        ]

    inside = [r for r in collector.records if r.name == "tests.inside-request"]
    assert len(inside) == 1
    assert inside[0].request_id == response.headers["X-Request-ID"]
    # trace_id follows the unit of work; at the edge that is the request.
    assert inside[0].trace_id == response.headers["X-Request-ID"]


def test_the_context_is_empty_again_after_the_request():
    with TestClient(app) as client:
        response = client.get("/healthz")

    # The header proves the binding happened at all, so the emptiness below is
    # a real reset rather than a context nobody ever set.
    assert response.headers["X-Request-ID"]
    assert ctx.current_log_context() == {
        "trace_id": None, "request_id": None, "job_id": None,
        "audit_id": None, "account_id": None,
    }


def test_the_500_body_and_the_header_are_the_same_id():
    """One source of truth. Starlette runs an Exception handler in
    ServerErrorMiddleware, OUTSIDE the user middleware stack, so the handler
    can see neither the contextvar (already reset) nor the middleware that adds
    the header -- it reads request.state and sets the header itself. If that
    ever regresses these two values drift apart."""

    async def _boom():
        raise RuntimeError("kaboom")

    app.add_api_route("/__test__/context-boom", _boom, methods=["GET"])
    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            response = client.get("/__test__/context-boom")
    finally:
        app.router.routes = [
            route for route in app.router.routes
            if getattr(route, "path", None) != "/__test__/context-boom"
        ]

    assert response.status_code == 500
    body_id = response.json()["detail"]["request_id"]
    assert body_id
    assert response.headers["X-Request-ID"] == body_id


# --- worker slot isolation ------------------------------------------------


class _SlotJobs:
    """Hands slot N exactly one job, then nothing. Enough of
    AuditJobRepository for _slot/_process_job to run."""

    def __init__(self, job_ids):
        self._to_claim = list(job_ids)
        self.succeeded: list[dict] = []

    async def claim_one(self, *, worker_id, lease_seconds):
        if not self._to_claim:
            return None
        return {
            "id": self._to_claim.pop(0), "state": "running",
            "source_kind": "repo_url",
            "source_ref": "https://github.com/acme/app",
            "content_hash": "hash", "engine_version": "test-engine",
            "account_id": None, "attempts": 1, "max_attempts": 3,
        }

    async def renew_lease(self, *, job_id, worker_id, lease_seconds):
        return True

    async def finalize_succeeded(self, *, job_id, worker_id, audit_id):
        self.succeeded.append({"job_id": job_id, "audit_id": audit_id})
        return True


async def test_concurrent_slots_never_mix_up_their_job_ids(
    monkeypatch, collector,
):
    """The assertion this whole change exists for.

    Two slots run as separate asyncio tasks against interleaved scans, and each
    one's log line must carry ITS job id. A module global or a thread-local
    would fail here; a ContextVar passes because a task runs in a copy of the
    context it was created in.
    """
    monkeypatch.setattr(worker, "AUDIT_WORKER_POLL_INTERVAL_SECONDS", 0.01)
    monkeypatch.setattr(worker, "AUDIT_WORKER_HEARTBEAT_SECONDS", 30)

    async def running(flags_repo):
        return False, None

    monkeypatch.setattr(worker, "_emergency_stop_active", running)

    job_a, job_b = "job-aaaa", "job-bbbb"
    audit_for = {job_a: "audit-aaaa", job_b: "audit-bbbb"}
    logger = logging.getLogger("tests.slot-scan")

    async def scan(job, **kwargs):
        # Yield twice, so the two scans are genuinely interleaved rather than
        # run one after the other -- otherwise a broken implementation that
        # merely overwrites a global would still pass.
        for _ in range(2):
            await asyncio.sleep(0)
            logger.info("scanning")
        return audit_for[str(job["id"])]

    monkeypatch.setattr(worker, "_execute_job", scan)

    jobs_a, jobs_b = _SlotJobs([job_a]), _SlotJobs([job_b])
    shutting_down = asyncio.Event()

    def spawn(slot, jobs):
        return asyncio.create_task(worker._slot(
            slot, jobs=jobs, llm_client=object(), audit_repo=object(),
            llm_usage_repo=object(), flags_repo=object(),
            shutting_down=shutting_down,
        ))

    tasks = [spawn(0, jobs_a), spawn(1, jobs_b)]
    await asyncio.sleep(0.1)
    shutting_down.set()
    await asyncio.wait_for(asyncio.gather(*tasks), timeout=5)

    scan_lines = [r for r in collector.records if r.name == "tests.slot-scan"]
    # Both slots logged, and every line names the job its own slot claimed.
    assert {r.job_id for r in scan_lines} == {job_a, job_b}
    assert len(scan_lines) == 4
    for record in scan_lines:
        assert record.trace_id == record.job_id

    # audit_id is bound only on success, and only for the matching job.
    finalize = [
        r for r in collector.records
        if r.name == worker.logger.name and "succeeded" in r.getMessage()
    ]
    assert {(r.job_id, r.audit_id) for r in finalize} == {
        (job_a, "audit-aaaa"), (job_b, "audit-bbbb"),
    }
    # The terminal line answers "which step, how long".
    for record in finalize:
        assert record.step == "finalize"
        assert isinstance(record.duration_ms, int)


async def test_a_slot_does_not_inherit_the_previous_jobs_ids(
    monkeypatch, collector,
):
    """Two jobs in sequence through one slot: the second must not be logged
    under the first job's audit_id, which is what would happen if the context
    were set once and never reset."""
    monkeypatch.setattr(worker, "AUDIT_WORKER_POLL_INTERVAL_SECONDS", 0.01)
    monkeypatch.setattr(worker, "AUDIT_WORKER_HEARTBEAT_SECONDS", 30)

    async def running(flags_repo):
        return False, None

    monkeypatch.setattr(worker, "_emergency_stop_active", running)

    logger = logging.getLogger("tests.sequential-scan")
    seen: list[tuple[str | None, str | None]] = []

    async def scan(job, **kwargs):
        logger.info("scanning")
        seen.append((ctx.job_id.get(), ctx.audit_id.get()))
        return "audit-" + str(job["id"])

    monkeypatch.setattr(worker, "_execute_job", scan)

    jobs = _SlotJobs(["job-1", "job-2"])
    shutting_down = asyncio.Event()
    task = asyncio.create_task(worker._slot(
        0, jobs=jobs, llm_client=object(), audit_repo=object(),
        llm_usage_repo=object(), flags_repo=object(),
        shutting_down=shutting_down,
    ))
    await asyncio.sleep(0.1)
    shutting_down.set()
    await asyncio.wait_for(task, timeout=5)

    # audit_id is None at the start of BOTH jobs, including the second.
    assert seen == [("job-1", None), ("job-2", None)]
    assert ctx.current_log_context()["job_id"] is None


# --- thread offloading ----------------------------------------------------
#
# Everything slow in this codebase runs off the event loop. If the context did
# not cross that boundary, the scan itself -- the part worth tracing -- would
# be the one part with no job_id on its lines.


async def test_asyncio_to_thread_carries_the_context():
    """Used by the worker for _load_payload and the spool sweep."""
    with ctx.log_context(job_id="job-to-thread"):
        got = await asyncio.to_thread(ctx.job_id.get)
    assert got == "job-to-thread"


async def test_starlette_run_in_threadpool_carries_the_context():
    """Used by the API for staging, repo fetch, the scan and the Fix Pack
    build."""
    with ctx.log_context(job_id="job-threadpool"):
        got = await run_in_threadpool(ctx.job_id.get)
    assert got == "job-threadpool"


async def test_a_raw_executor_does_not_carry_the_context():
    """The one form that silently loses it, pinned so nobody reaches for it.

    loop.run_in_executor submits the callable directly, with no context copy --
    unlike asyncio.to_thread, which copies the caller's context by design.
    Nothing in the codebase uses this form; if a future change does, the log
    lines from that work would quietly lose every correlation id. Use
    asyncio.to_thread, or pass contextvars.copy_context().run.
    """
    loop = asyncio.get_running_loop()
    with ctx.log_context(job_id="job-executor"):
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            got = await loop.run_in_executor(pool, ctx.job_id.get)
    assert got is None


# --- API handler bindings -------------------------------------------------


def test_a_read_handler_binds_the_id_it_was_asked_for():
    """audit_id is bound BEFORE the authorization lookup, not after it
    succeeds: a rejected read is exactly the request whose log lines need to
    say which id someone asked for. Observed from inside the lookup, since the
    404 path itself emits no record."""
    unknown = str(uuid.uuid4())
    seen: list[dict] = []

    class _RecordingRepo:
        async def get_authorized(self, audit_id, token):
            seen.append(ctx.current_log_context())
            return None

    app.dependency_overrides[get_audit_repo] = _RecordingRepo
    try:
        with TestClient(app) as client:
            response = client.get(f"/v1/audits/{unknown}?token=nope")
    finally:
        app.dependency_overrides.pop(get_audit_repo, None)

    assert response.status_code == 404
    assert len(seen) == 1
    assert seen[0]["audit_id"] == unknown
    assert seen[0]["request_id"] == response.headers["X-Request-ID"]
    # And the binding is scoped to the request that made it.
    assert ctx.current_log_context()["audit_id"] is None


# --- the monitoring drain -------------------------------------------------


async def test_the_monitoring_drain_binds_the_run_and_its_audit(
    monkeypatch, collector,
):
    """The other durable queue. Its lines used to carry no ids at all, which
    made a failed monitoring run the one piece of work that could not be traced
    -- the audit_id in particular, because run_repo_audit does not bind it, so
    only the drain knows which audit the diff came from."""
    logger = logging.getLogger("tests.monitoring-drain")
    seen: list[dict] = []

    async def fake_audit(repo_url, *, llm_client, audit_repo, repo_fetcher,
                         llm_usage_repo=None, job_type="audit"):
        # Before the audit exists: the run is already identified.
        seen.append(ctx.current_log_context())
        return {"audit_id": "audit-mon", "findings": [], "repo_url": repo_url,
                "reused": False}

    monkeypatch.setattr(main_mod, "run_repo_audit", fake_audit)

    class _Subs:
        async def list_active_for_repo(self, repo_full_name):
            return [{"telegram_chat_id": "chat-1"}]

    class _Audits:
        async def get_latest_by_repo_url(self, repo_full_name):
            return None

    class _Runs:
        def __init__(self):
            self.done: list[str] = []

        async def mark_done(self, run_id):
            self.done.append(run_id)
            logger.info("run finished")

    runs = _Runs()
    outcome = await main_mod._process_one_monitoring_run(
        {"id": "run-ctx", "repo_full_name": "acme/app"},
        monitoring_repo=runs, subscription_repo=_Subs(), audit_repo=_Audits(),
        llm_client=object(), repo_fetcher=object(), transport=object(),
        llm_usage_repo=None,
    )

    assert outcome == "no_new"
    assert runs.done == ["run-ctx"]
    # job_id is the queue-row id here, the same field the audit-job and Fix Pack
    # queues use, so one jq filter spans all three.
    assert seen[0]["job_id"] == "run-ctx"
    assert seen[0]["audit_id"] is None

    lines = [r for r in collector.records if r.name == "tests.monitoring-drain"]
    assert len(lines) == 1
    assert lines[0].job_id == "run-ctx"
    assert lines[0].audit_id == "audit-mon"

"""Spend is recorded because it happened, not because the audit worked.

Until now an llm_usage row was written at the end of app/worker/main.py's
_execute_job, after audit_repo.create() returned a row. Everything that spends
money and then fails to reach that line -- a provider dying on the second
rubric, a database blip on the insert, a lost lease cancelling the coroutine, a
job exhausting its attempts into dead_letter -- charged the account at the
provider and recorded nothing. These tests pin the money, not the audit:

  * the fake-repo half proves each of those paths now writes its row, and that
    the paths which already worked still write exactly one;
  * the Postgres half proves the retry arithmetic -- three attempts leave three
    rows under one audit_jobs.id and sum_by_audit_job adds them up, which is
    the question "what did this job actually cost" that could not be asked
    before.
"""

from __future__ import annotations

import asyncio
import io
import json
import os
import uuid
import zipfile
from decimal import Decimal

import pytest

import app.db as db_mod
from app.db import AuditJobRepository, AuditRepository, LlmUsageRepository
from app.llm.client import LLMClient, LLMError, LLMUsage, Provider
from app.scan.pipeline import PAID_AUDIT_PASSES
from app.worker import main as worker
from app.worker.main import JobExecutionError, _execute_job

# Every _job() below carries an account, so its scan runs the paid depth:
# each matching rubric is prompted PAID_AUDIT_PASSES times, and the money a
# both-rubric fixture spends is 2 x passes calls.
_FULL_SCAN_CALLS = 2 * PAID_AUDIT_PASSES

NEXT_PKG = json.dumps({"dependencies": {"next": "15.0.0", "react": "19.0.0"}}).encode()


def _make_zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _both_rubrics_zip() -> bytes:
    """Content matching BOTH rubric keyword sets, so the scan makes two
    .complete() calls -- the shape a mid-scan provider failure needs."""
    return _make_zip({
        "package.json": NEXT_PKG,
        "app/auth.ts": b"const password = 'x'  // check auth token",
        "app/query.ts": b"const sql = `select * from t where id=${input}`  // env",
    })


class _Usage:
    """Captures the kwargs of every llm_usage row create() is asked to write."""

    def __init__(self):
        self.rows: list[dict] = []

    async def create(self, **kwargs):
        self.rows.append(kwargs)
        return {"id": str(uuid.uuid4()), **kwargs}

    async def sum_anon_spend_today(self):
        return Decimal("0")


class _Audits:
    """AuditRepository stand-in whose create() can be made to misbehave the
    three ways that matter: return None, raise, or be cancelled."""

    def __init__(self, *, on_create=None):
        self.rows: list[dict] = []
        self._on_create = on_create

    async def create(self, **kwargs):
        if self._on_create is not None:
            outcome = self._on_create()
            if isinstance(outcome, BaseException):
                raise outcome
            if outcome is None:
                return None
        row = {"id": str(uuid.uuid4()), "access_token": "tok", **kwargs}
        self.rows.append(row)
        return row

    async def get_by_content_hash(self, content_hash, engine_version, basis):
        return None


class _LLM(LLMClient):
    """One paid call per rubric, optionally failing from the Nth call on."""

    def __init__(self, *, fail_from: int | None = None):
        super().__init__(providers=[Provider("anthropic", "https://x", "k", "m")])
        self.calls = 0
        self._fail_from = fail_from

    def complete(self, system, user, max_tokens=4096):
        self.calls += 1
        if self._fail_from is not None and self.calls >= self._fail_from:
            raise LLMError("provider returned 503")
        return "[]", LLMUsage(
            model="claude-sonnet-4.6", input_tokens=1000, output_tokens=200)


# Every test in this file is about LLM spend, and only a paying account
# reaches the provider now: the free tier is static-only by policy
# (basis_for_account in app/scan/pipeline.py). An anonymous job here would
# record nothing and the file would pass while testing nothing.
_ACCOUNT_ID = "22222222-2222-2222-2222-222222222222"

_real_account_id: str | None = None


async def _account_row_id() -> str:
    """A real accounts row id, cached for the module.

    The in-memory paths here can use any uuid, but audit_jobs.account_id is a
    foreign key: the two tests that enqueue through the real Postgres queue need
    an account that actually exists.
    """
    global _real_account_id
    if _real_account_id is None:
        from app.accounts import generate_api_key
        from app.db import AccountRepository
        acct = await AccountRepository().create(
            api_key=generate_api_key(), tier="pro")
        _real_account_id = str(acct["id"])
    return _real_account_id


def _job(raw: bytes, *, attempts: int = 1) -> dict:
    from app.audit_spool import stage_archive

    job_id = str(uuid.uuid4())
    return {
        "id": job_id,
        "source_kind": "zip",
        "source_ref": stage_archive(job_id, raw),
        "account_id": _ACCOUNT_ID,
        "attempts": attempts,
        "max_attempts": 3,
    }


# One paid call = 1000 in @ $3/M + 200 out @ $15/M = $0.003 + $0.003.
ONE_CALL_USD = Decimal("0.006")


# --- the behaviour that already worked, pinned before it is changed ---------

async def test_a_successful_audit_still_writes_exactly_one_linked_row():
    """Regression guard. The success path is the one that was never broken, and
    the new failure branches must not turn it into two rows or unlink it."""
    audits, usage = _Audits(), _Usage()
    job = _job(_both_rubrics_zip())

    audit_id = await _execute_job(
        job, llm_client=_LLM(), audit_repo=audits, llm_usage_repo=usage)

    assert len(usage.rows) == 1
    row = usage.rows[0]
    assert row["job_id"] == audit_id            # still points at the audit
    assert row["audit_job_id"] == job["id"]     # and now also at the queue row
    assert row["calls"] == _FULL_SCAN_CALLS     # both rubrics, paid passes
    assert row["cost_usd"] == _FULL_SCAN_CALLS * ONE_CALL_USD


async def test_a_scan_that_never_called_the_llm_still_writes_nothing():
    """calls=0 must stay the "no row" condition: an audit whose content matched
    no rubric costs nothing and inventing a $0 row would make every per-job
    aggregate count audits instead of spends."""
    audits, usage = _Audits(), _Usage()
    # No rubric keywords anywhere, so the LLM stage runs and prompts nothing.
    raw = _make_zip({"package.json": NEXT_PKG, "app/page.tsx": b"export default 1"})

    await _execute_job(
        _job(raw), llm_client=_LLM(), audit_repo=audits, llm_usage_repo=usage)

    assert usage.rows == []


# --- money spent, audit lost ------------------------------------------------

async def test_the_row_lands_when_the_audit_cannot_be_persisted():
    """audit_repo.create returns nothing -> audit_not_persisted, a transient
    failure the job will retry. The scan before it still bought two calls."""
    audits, usage = _Audits(on_create=lambda: None), _Usage()
    job = _job(_both_rubrics_zip())

    with pytest.raises(JobExecutionError) as excinfo:
        await _execute_job(job, llm_client=_LLM(),
                           audit_repo=audits, llm_usage_repo=usage)

    assert excinfo.value.code == "audit_not_persisted"
    assert len(usage.rows) == 1
    row = usage.rows[0]
    assert row["job_id"] is None                # there is no audit to point at
    assert row["audit_job_id"] == job["id"]     # but the job is still known
    assert row["cost_usd"] == _FULL_SCAN_CALLS * ONE_CALL_USD


async def test_the_row_lands_when_the_persist_raises():
    """The database going away mid-insert is the same money as the branch
    above, reached through a raise rather than a None."""
    boom = RuntimeError("connection reset by peer")
    audits, usage = _Audits(on_create=lambda: boom), _Usage()
    job = _job(_both_rubrics_zip())

    with pytest.raises(RuntimeError):
        await _execute_job(job, llm_client=_LLM(),
                           audit_repo=audits, llm_usage_repo=usage)

    assert len(usage.rows) == 1
    assert usage.rows[0]["audit_job_id"] == job["id"]
    assert usage.rows[0]["cost_usd"] == _FULL_SCAN_CALLS * ONE_CALL_USD


async def test_the_row_lands_when_the_lease_is_lost_mid_persist():
    """Losing the lease cancels _execute_job where it stands. A cancelled
    attempt burned exactly as much as a failed one, and the recording must
    survive the cancellation that triggered it -- an unshielded await here
    would itself be cancelled and write nothing."""
    audits = _Audits(on_create=lambda: asyncio.CancelledError())
    usage = _Usage()
    job = _job(_both_rubrics_zip())

    with pytest.raises(asyncio.CancelledError):
        await _execute_job(job, llm_client=_LLM(),
                           audit_repo=audits, llm_usage_repo=usage)

    assert len(usage.rows) == 1
    assert usage.rows[0]["audit_job_id"] == job["id"]
    assert usage.rows[0]["cost_usd"] == _FULL_SCAN_CALLS * ONE_CALL_USD


async def test_calls_made_before_a_provider_failure_are_still_charged():
    """The quietest leak of the four, because the AUDIT SUCCEEDS. The first
    rubric's call is paid for, the second raises, run_scan degrades to
    static-only and reports the string "failed: ..." -- and the accounting used
    to read spend off that same field, so a real $0.006 was recorded as $0."""
    audits, usage = _Audits(), _Usage()
    job = _job(_both_rubrics_zip())
    llm = _LLM(fail_from=2)

    audit_id = await _execute_job(
        job, llm_client=llm, audit_repo=audits, llm_usage_repo=usage)

    assert llm.calls == 2                       # one served, one raised
    assert audit_id                             # the audit itself still landed
    assert len(usage.rows) == 1
    row = usage.rows[0]
    assert row["calls"] == 1                    # only the served call is billed
    assert row["cost_usd"] == ONE_CALL_USD
    assert row["audit_job_id"] == job["id"]


async def test_a_cost_capped_partial_scan_is_unchanged(monkeypatch):
    """JOB_COST_CAP_USD stopping a scan early is an honest partial success, not
    a failure, and Stage 4's semantics are explicitly out of scope here: the cap
    still truncates the scan, the job still succeeds, and the row still records
    what the calls made before the ceiling actually cost."""
    from app.scan import llm_scan

    # Cap below the price of one call, so the ceiling trips after the first.
    monkeypatch.setattr(llm_scan, "JOB_COST_CAP_USD", Decimal("0.001"))
    audits, usage = _Audits(), _Usage()
    job = _job(_both_rubrics_zip())
    llm = _LLM()

    audit_id = await _execute_job(
        job, llm_client=llm, audit_repo=audits, llm_usage_repo=usage)

    assert audit_id
    assert llm.calls == 1                       # stopped before the second
    assert len(usage.rows) == 1
    assert usage.rows[0]["calls"] == 1
    assert usage.rows[0]["cost_usd"] == ONE_CALL_USD
    assert usage.rows[0]["job_id"] == audit_id  # a success, linked as one


# --- the same thing against the real queue ----------------------------------

_SMOKE_DB_URL = os.environ.get("DATABASE_URL")

pg = pytest.mark.skipif(
    not _SMOKE_DB_URL,
    reason=("real-Postgres integration test: set DATABASE_URL to a live "
            "Postgres (CI does; local runs without it are skipped)"),
)


@pytest.fixture
async def real_db(monkeypatch):
    # conftest's autouse _no_ambient_database_url clears DATABASE_URL before the
    # body runs, so it is captured at import time and re-injected here -- same
    # dance as tests/test_audit_worker_postgres.py.
    monkeypatch.setenv("DATABASE_URL", _SMOKE_DB_URL)
    await db_mod.close_pool()
    pool = await db_mod.get_pool()
    async with pool.connection() as conn:
        await conn.execute("delete from llm_usage")
        await conn.execute("delete from audit_jobs")
    yield
    await db_mod.close_pool()


@pytest.fixture
def no_emergency_stop(monkeypatch):
    async def running(flags_repo):
        return False, None

    monkeypatch.setattr(worker, "_emergency_stop_active", running)


async def _enqueue_zip_job(jobs: AuditJobRepository, raw: bytes) -> dict:
    from app.audit_spool import stage_archive

    staged = stage_archive(str(uuid.uuid4()), raw)
    return await jobs.enqueue(
        source_kind="zip", source_ref=staged,
        content_hash=f"hash-{uuid.uuid4().hex[:12]}",
        engine_version="test-engine-1", stack="nextjs",
        account_id=await _account_row_id(),
        quota_key="ip:203.0.113.1", idempotency_key=f"idem-{uuid.uuid4().hex}",
    )


async def _clear_backoff(job_id: str) -> None:
    """finalize_failed parks a retry behind an exponential backoff. Waiting it
    out would make this test sleep for a minute; moving available_at into the
    past is the same state the clock would produce."""
    pool = await db_mod.get_pool()
    async with pool.connection() as conn:
        await conn.execute(
            "update audit_jobs set available_at = now() - interval '1 hour' "
            "where id = %s", (uuid.UUID(job_id),))


async def _drain(monkeypatch, *, audit_repo, llm_client) -> None:
    monkeypatch.setattr(worker, "AUDIT_WORKER_POLL_INTERVAL_SECONDS", 0.01)
    shutting_down = asyncio.Event()
    task = asyncio.create_task(worker._slot(
        0, jobs=AuditJobRepository(), llm_client=llm_client,
        audit_repo=audit_repo, llm_usage_repo=LlmUsageRepository(),
        flags_repo=object(), shutting_down=shutting_down,
    ))
    await asyncio.sleep(0.5)
    shutting_down.set()
    await asyncio.wait_for(task, timeout=10)


async def _row_state(job_id: str) -> str:
    pool = await db_mod.get_pool()
    async with pool.connection() as conn:
        cur = await conn.execute(
            "select state from audit_jobs where id = %s", (uuid.UUID(job_id),))
        return (await cur.fetchone())["state"]


@pg
async def test_every_attempt_of_a_retried_job_is_billed(
    real_db, no_emergency_stop, monkeypatch,
):
    """Two attempts spend and lose their audit, the third succeeds. The cost of
    the JOB is all three scans -- reading only the row the successful attempt
    wrote would under-report it by two thirds."""
    jobs = AuditJobRepository()
    enqueued = await _enqueue_zip_job(jobs, _both_rubrics_zip())

    class _FlakyAudits:
        """Transient persistence failure twice, then the real repository -- the
        third attempt has to write a genuine audits row, because
        finalize_succeeded carries a foreign key to it."""

        def __init__(self):
            self.real = AuditRepository()
            self.attempts = 0

        async def create(self, **kwargs):
            self.attempts += 1
            if self.attempts <= 2:
                return None
            return await self.real.create(**kwargs)

        async def get_by_content_hash(self, content_hash, engine_version, basis):
            return None

    audits = _FlakyAudits()

    for _ in range(3):
        await _drain(monkeypatch, audit_repo=audits, llm_client=_LLM())
        await _clear_backoff(enqueued["id"])

    assert await _row_state(enqueued["id"]) == "succeeded"

    total = await LlmUsageRepository().sum_by_audit_job(enqueued["id"])
    assert total["attempts"] == 3               # one row per attempt
    assert total["calls"] == 6                  # two rubrics x three attempts
    assert total["cost_usd"] == 6 * ONE_CALL_USD

    # And the rows are distinguishable: only the winning attempt has an audit.
    pool = await db_mod.get_pool()
    async with pool.connection() as conn:
        cur = await conn.execute(
            "select job_id from llm_usage where audit_job_id = %s",
            (uuid.UUID(enqueued["id"]),))
        linked = [r["job_id"] for r in await cur.fetchall()]
    assert sum(1 for j in linked if j is not None) == 1


@pg
async def test_a_dead_lettered_job_still_has_its_spend_on_record(
    real_db, no_emergency_stop, monkeypatch,
):
    """The case with no audits row anywhere. Every attempt spends and fails,
    the job exhausts max_attempts and dead-letters -- and the money is still
    answerable, which before this change it was not: zero rows existed."""
    jobs = AuditJobRepository()
    enqueued = await _enqueue_zip_job(jobs, _both_rubrics_zip())
    audits = _Audits(on_create=lambda: None)

    for _ in range(4):
        await _drain(monkeypatch, audit_repo=audits, llm_client=_LLM())
        await _clear_backoff(enqueued["id"])

    assert await _row_state(enqueued["id"]) == "dead_letter"
    assert audits.rows == []                    # no audit was ever persisted

    total = await LlmUsageRepository().sum_by_audit_job(enqueued["id"])
    assert total["attempts"] == 3               # max_attempts scans happened
    assert total["cost_usd"] == 6 * ONE_CALL_USD

    pool = await db_mod.get_pool()
    async with pool.connection() as conn:
        cur = await conn.execute(
            "select count(*) as n from llm_usage "
            "where audit_job_id = %s and job_id is null",
            (uuid.UUID(enqueued["id"]),))
        assert (await cur.fetchone())["n"] == 3


@pg
async def test_sum_by_audit_job_is_zero_for_a_job_that_never_spent(real_db):
    """A caller totalling a batch of jobs must not have to special-case the
    ones whose scans never reached the provider."""
    total = await LlmUsageRepository().sum_by_audit_job(str(uuid.uuid4()))
    assert total == {"calls": 0, "input_tokens": 0, "output_tokens": 0,
                     "cost_usd": Decimal(0), "attempts": 0}

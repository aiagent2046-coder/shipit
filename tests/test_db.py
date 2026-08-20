"""Tests for app/db.py. No real Postgres involved -- a FakePool stands
in for psycopg_pool.AsyncConnectionPool. Proves the query wiring,
param order, and row-to-dict conversion (UUID -> str, jsonb handling)
-- not that psycopg can really reach a live Postgres. See
scripts/verify_db_locally.py for that, run by the user with their own
DATABASE_URL against the real Supabase project (already confirmed
working by hand during this migration from asyncpg -- see app/db.py's
module docstring for why asyncpg was replaced).
"""

import datetime
import uuid

import pytest

import app.db as db_mod
from app.db import (
    AccountRepository,
    AuditRepository,
    FixpackJobRepository,
    PaymentRepository,
    SubscriptionRepository,
)


class FakeCursor:
    def __init__(self, result):
        self._result = result

    async def fetchone(self):
        return self._result

    async def fetchall(self):
        if self._result is None:
            return []
        return list(self._result) if isinstance(self._result, list) else [self._result]


class FakeConnection:
    def __init__(self, pool):
        self._pool = pool

    async def execute(self, query, params=None):
        self._pool.calls.append((query, params))
        return FakeCursor(self._pool.fetchone_result)


class FakeConnectionContext:
    def __init__(self, pool):
        self._pool = pool

    async def __aenter__(self):
        return FakeConnection(self._pool)

    async def __aexit__(self, *exc_info):
        return False


class FakePool:
    def __init__(self, fetchone_result=None):
        self.calls: list[tuple] = []
        self.fetchone_result = fetchone_result

    def connection(self):
        return FakeConnectionContext(self)


@pytest.fixture(autouse=True)
def no_database_url(monkeypatch):
    """Default: DATABASE_URL unset, matching this dev sandbox and the
    main pytest suite -- individual tests override with a FakePool
    where they need the "happy path" instead."""
    monkeypatch.delenv("DATABASE_URL", raising=False)


class TestGetPool:
    async def test_pool_disables_prepared_statements(self, monkeypatch):
        """Regression guard: prepare_threshold=None works around a real
        hang -- psycopg's server-side statement preparation makes the
        first parameterized query through Supabase's Supavisor pooler
        hang indefinitely, confirmed by hand against the actual
        project (same underlying issue class as asyncpg's, which this
        driver replaced -- see app/db.py's module docstring). Don't
        remove this without re-testing against a real pooler.
        """
        monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@localhost/db")
        db_mod._pool = None
        captured = {}

        class FakeAsyncConnectionPool:
            def __init__(self, url, **kwargs):
                captured["kwargs"] = kwargs

            async def open(self):
                pass

        monkeypatch.setattr(db_mod, "AsyncConnectionPool", FakeAsyncConnectionPool)
        try:
            pool = await db_mod.get_pool()
        finally:
            db_mod._pool = None

        assert isinstance(pool, FakeAsyncConnectionPool)
        assert captured["kwargs"]["kwargs"]["prepare_threshold"] is None

    async def test_failed_open_is_not_cached_and_retries(self, monkeypatch):
        """A failed .open() (bad password, transient blip) must leave
        _pool unset so the next call retries, instead of poisoning the
        global with a broken pool that every later call returns."""
        monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@localhost/db")
        db_mod._pool = None
        opens = {"n": 0}

        class FlakyPool:
            def __init__(self, url, **kwargs):
                pass

            async def open(self):
                opens["n"] += 1
                if opens["n"] == 1:
                    raise RuntimeError("connection refused")

        monkeypatch.setattr(db_mod, "AsyncConnectionPool", FlakyPool)
        try:
            with pytest.raises(RuntimeError):
                await db_mod.get_pool()
            assert db_mod._pool is None  # not cached after the failed open

            pool = await db_mod.get_pool()  # retries, succeeds this time
            assert isinstance(pool, FlakyPool)
            assert opens["n"] == 2
        finally:
            db_mod._pool = None

    async def test_concurrent_first_callers_build_one_pool(self, monkeypatch):
        """Two concurrent first-callers must not each construct a pool --
        the loser's would leak (never closed). The lock + re-check means
        the constructor runs exactly once."""
        import asyncio

        monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@localhost/db")
        db_mod._pool = None
        built = {"n": 0}

        class SlowOpenPool:
            def __init__(self, url, **kwargs):
                built["n"] += 1

            async def open(self):
                await asyncio.sleep(0)  # yield so both callers overlap

        monkeypatch.setattr(db_mod, "AsyncConnectionPool", SlowOpenPool)
        try:
            a, b = await asyncio.gather(db_mod.get_pool(), db_mod.get_pool())
            assert built["n"] == 1       # constructed once, not twice
            assert a is b                # same shared instance
        finally:
            db_mod._pool = None


class TestAuditRepositoryNotConfigured:
    async def test_create_returns_none(self):
        repo = AuditRepository()
        result = await repo.create(
            stack="fastapi", file_count=3, score_total=8.5,
            score_json={"total": 8.5}, findings_json=[],
        )
        assert result is None

    async def test_get_returns_none(self):
        repo = AuditRepository()
        result = await repo.get(str(uuid.uuid4()))
        assert result is None


class TestAuditRepositoryWithFakePool:
    async def test_create_inserts_and_returns_row(self, monkeypatch):
        audit_id = uuid.uuid4()
        fake = FakePool(fetchone_result={
            "id": audit_id, "stack": "fastapi", "status": "completed",
            "file_count": 3, "score_total": 8.5,
            "score_json": {"total": 8.5}, "findings_json": [],
            "access_token": "deadbeefdeadbeefdeadbeefdeadbeef",
            "created_at": "2026-07-12T10:00:00Z",
        })
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))

        repo = AuditRepository()
        result = await repo.create(
            stack="fastapi", file_count=3, score_total=8.5,
            score_json={"total": 8.5}, findings_json=[],
        )

        assert result["id"] == str(audit_id)
        assert result["score_json"] == {"total": 8.5}
        assert result["findings_json"] == []
        # The per-row token is returned (RETURNING access_token) so the API can
        # deliver it once at creation. It is not an INSERT param -- the DB
        # column default mints it.
        assert result["access_token"] == "deadbeefdeadbeefdeadbeefdeadbeef"
        query, params = fake.calls[0]
        assert "insert into audits" in query
        assert "access_token" in query  # in the RETURNING clause
        assert "access_token" not in [str(p) for p in params]  # not an insert param
        assert params[0] == "fastapi"

    async def test_create_persists_repo_url(self, monkeypatch):
        audit_id = uuid.uuid4()
        fake = FakePool(fetchone_result={
            "id": audit_id, "stack": "nextjs", "status": "completed",
            "file_count": 1, "score_total": 8.5,
            "score_json": {"total": 8.5}, "findings_json": [],
            "repo_url": "https://github.com/acme/app",
            "created_at": "2026-07-16T10:00:00Z",
        })
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))

        repo = AuditRepository()
        result = await repo.create(
            stack="nextjs", file_count=1, score_total=8.5,
            score_json={"total": 8.5}, findings_json=[],
            repo_url="https://github.com/acme/app",
        )

        assert result["repo_url"] == "https://github.com/acme/app"
        query, params = fake.calls[0]
        assert "repo_url" in query
        assert "https://github.com/acme/app" in params

    async def test_create_persists_engine_version(self, monkeypatch):
        # engine_version is a real INSERT param (unlike access_token, which the
        # column default mints): the app supplies the current
        # AUDIT_ENGINE_VERSION so the row records which engine produced it.
        audit_id = uuid.uuid4()
        fake = FakePool(fetchone_result={
            "id": audit_id, "stack": "fastapi", "status": "completed",
            "file_count": 1, "score_total": 8.5,
            "score_json": {"total": 8.5}, "findings_json": [],
            "content_hash": "abc123", "engine_version": "2026-07-19-1",
            "created_at": "2026-07-19T10:00:00Z",
        })
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))

        repo = AuditRepository()
        result = await repo.create(
            stack="fastapi", file_count=1, score_total=8.5,
            score_json={"total": 8.5}, findings_json=[],
            content_hash="abc123", engine_version="2026-07-19-1",
        )

        assert result["engine_version"] == "2026-07-19-1"
        query, params = fake.calls[0]
        assert "engine_version" in query
        assert "2026-07-19-1" in params

    async def test_get_by_content_hash_filters_on_engine_version(self, monkeypatch):
        # The cache lookup keys on BOTH content_hash and engine_version, so a
        # row written under an older engine version no longer matches -- the
        # miss that recomputes across an engine change (migration 0013).
        audit_id = uuid.uuid4()
        fake = FakePool(fetchone_result={
            "id": audit_id, "stack": "fastapi", "status": "completed",
            "file_count": 1, "score_total": 8.5,
            "score_json": {"total": 8.5}, "findings_json": [],
            "content_hash": "abc123", "engine_version": "2026-07-19-1",
            "access_token": "deadbeefdeadbeefdeadbeefdeadbeef",
            "created_at": "2026-07-19T10:00:00Z",
        })
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))

        repo = AuditRepository()
        result = await repo.get_by_content_hash(
            "abc123", "2026-07-19-1", "static+llm")

        assert result["id"] == str(audit_id)
        query, params = fake.calls[0]
        assert "content_hash = %s and engine_version = %s" in query
        # The scan depth is part of the key, not an afterthought: without this
        # predicate the cache crossed the pricing boundary in both directions --
        # an anonymous visitor could be served a paying account's full audit,
        # and a paying account a free static-only row.
        assert "score_json->>'basis' = %s" in query
        assert params == ("abc123", "2026-07-19-1", "static+llm")

    async def test_get_latest_by_repo_url_filters_on_scan_depth(self,
                                                               monkeypatch):
        """The monitoring diff baseline must be a full audit, never a free one.

        This query had no depth filter and no test at all -- 1272 passing tests
        did not notice when it was temporarily broken. Unfiltered, one anonymous
        static-only audit of a watched repository becomes the baseline, and the
        next monitoring run (always full depth) reports every auth and injection
        finding as newly appeared: a DM to a paying subscriber about problems
        that were already there, triggered by a stranger with the URL.
        """
        audit_id = uuid.uuid4()
        fake = FakePool(fetchone_result={
            "id": audit_id, "stack": "nextjs", "status": "completed",
            "file_count": 12, "score_total": 7.2,
            "score_json": {"total": 7.2, "basis": "static+llm"},
            "findings_json": [], "repo_url": "https://github.com/o/r",
            "created_at": "2026-08-04T10:00:00Z",
        })
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))

        repo = AuditRepository()
        result = await repo.get_latest_by_repo_url("o/r", "static+llm")

        assert result["id"] == str(audit_id)
        query, params = fake.calls[0]
        assert "score_json->>'basis' = %s" in query
        assert params == ("o/r", "static+llm")

    async def test_get_returns_none_for_missing_row(self, monkeypatch):
        fake = FakePool(fetchone_result=None)
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))
        repo = AuditRepository()
        assert await repo.get(str(uuid.uuid4())) is None

    async def test_get_rejects_malformed_id_without_querying(self, monkeypatch):
        fake = FakePool()
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))
        repo = AuditRepository()
        assert await repo.get("not-a-uuid") is None
        assert fake.calls == []

    async def test_get_authorized_matches_id_and_token_in_sql(self, monkeypatch):
        audit_id = uuid.uuid4()
        fake = FakePool(fetchone_result={
            "id": audit_id, "stack": "fastapi", "status": "completed",
            "file_count": 3, "score_total": 8.5,
            "score_json": {"total": 8.5}, "findings_json": [],
            "created_at": "2026-07-12T10:00:00Z",
        })
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))
        repo = AuditRepository()
        result = await repo.get_authorized(str(audit_id), "sekret-token")

        assert result["id"] == str(audit_id)
        # Never selects the token, so it can't ride out in the response body.
        assert "access_token" not in result
        query, params = fake.calls[0]
        assert "where id = %s and access_token = %s" in query
        assert "access_token" not in query.split("where")[0]  # not in select list
        assert params == (audit_id, "sekret-token")

    async def test_get_authorized_without_token_never_queries(self, monkeypatch):
        # No token -> None, and crucially no DB round-trip: a caller who knows
        # only a leaked id can't even probe.
        fake = FakePool()
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))
        repo = AuditRepository()
        assert await repo.get_authorized(str(uuid.uuid4()), None) is None
        assert await repo.get_authorized(str(uuid.uuid4()), "") is None
        assert fake.calls == []

    async def test_get_authorized_rejects_malformed_id_without_querying(self, monkeypatch):
        fake = FakePool()
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))
        repo = AuditRepository()
        assert await repo.get_authorized("not-a-uuid", "tok") is None
        assert fake.calls == []

    async def test_get_authorized_wrong_token_returns_none(self, monkeypatch):
        # The SQL filter (id AND token) yields no row -> fetchone None -> None.
        fake = FakePool(fetchone_result=None)
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))
        repo = AuditRepository()
        assert await repo.get_authorized(str(uuid.uuid4()), "wrong") is None

    async def test_score_total_numeric_is_cast_to_json_number_not_string(self, monkeypatch):
        """psycopg hands back a Postgres `numeric` as a decimal.Decimal,
        which the default JSON encoder renders as a *string*. It must come
        out a float so the API response matches score_json.total."""
        import decimal
        import json

        audit_id = uuid.uuid4()
        fake = FakePool(fetchone_result={
            "id": audit_id, "stack": "fastapi", "status": "completed",
            "file_count": 3, "score_total": decimal.Decimal("8.5"),
            "score_json": {"total": 8.5}, "findings_json": [],
            "created_at": "2026-07-12T10:00:00Z",
        })
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))
        repo = AuditRepository()
        result = await repo.get(str(audit_id))

        assert isinstance(result["score_total"], float)
        assert result["score_total"] == 8.5
        # serializes as a JSON number, consistent with score_json.total
        assert json.loads(json.dumps(result))["score_total"] == 8.5

    async def test_jsonb_string_is_parsed_if_driver_hands_back_text(self, monkeypatch):
        """Defensive: handle both already-parsed dict/list and raw
        JSON text, since driver behavior here isn't guaranteed."""
        audit_id = uuid.uuid4()
        fake = FakePool(fetchone_result={
            "id": audit_id, "stack": "fastapi", "status": "completed",
            "file_count": 3, "score_total": 8.5,
            "score_json": '{"total": 8.5}', "findings_json": "[]",
            "created_at": "2026-07-12T10:00:00Z",
        })
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))
        repo = AuditRepository()
        result = await repo.get(str(audit_id))
        assert result["score_json"] == {"total": 8.5}
        assert result["findings_json"] == []


class TestFixpackJobRepositoryNotConfigured:
    async def test_create_returns_none(self):
        repo = FixpackJobRepository()
        result = await repo.create(
            audit_id=None, pack="deploy", stack="fastapi",
            verified=True, detail="HTTP 200 on /",
            preview_local_url=None, preview_expires_at=None,
        )
        assert result is None

    async def test_mark_delivered_is_a_silent_noop(self):
        repo = FixpackJobRepository()
        await repo.mark_delivered(str(uuid.uuid4()), "https://github.com/a/b/pull/1")
        # no exception -- that's the whole point of the not-configured contract


class TestFixpackJobRepositoryWithFakePool:
    async def test_create_inserts_with_correct_param_order(self, monkeypatch):
        job_id = uuid.uuid4()
        fake = FakePool(fetchone_result={
            "id": job_id, "audit_id": None, "pack": "deploy", "stack": "fastapi",
            "verified": True, "detail": "HTTP 200 on /",
            "preview_local_url": "http://localhost:20000/",
            "preview_expires_at": None, "pr_url": None, "pr_delivered": False,
            "access_token": "deadbeefdeadbeefdeadbeefdeadbeef",
            "created_at": "2026-07-12T10:00:00Z",
        })
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))

        repo = FixpackJobRepository()
        result = await repo.create(
            audit_id=None, pack="deploy", stack="fastapi",
            verified=True, detail="HTTP 200 on /",
            preview_local_url="http://localhost:20000/",
            preview_expires_at=None,
        )

        assert result["id"] == str(job_id)
        assert result["audit_id"] is None
        # The per-row token is returned (RETURNING access_token) so the API can
        # deliver it once at creation. It is not an INSERT param -- the DB
        # column default mints it (migration 0012).
        assert result["access_token"] == "deadbeefdeadbeefdeadbeefdeadbeef"
        query, params = fake.calls[0]
        assert "access_token" in query  # in the RETURNING clause
        assert "access_token" not in [str(p) for p in params]  # not an insert param
        assert params == (None, "deploy", "fastapi", True, "HTTP 200 on /",
                           "http://localhost:20000/", None)

    async def test_create_paid_returns_access_token(self, monkeypatch):
        job_id = uuid.uuid4()
        fake = FakePool(fetchone_result={
            "id": job_id, "audit_id": None, "pack": "fixpack", "stack": "fastapi",
            "verified": None, "detail": None, "preview_local_url": None,
            "preview_expires_at": None, "pr_url": None, "pr_delivered": False,
            "status": "paid", "access_token": "cafebabecafebabecafebabecafebabe",
            "created_at": "2026-07-19T10:00:00Z",
        })
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))

        result = await FixpackJobRepository().create_paid(
            audit_id=None, stack="fastapi",
        )

        assert result["access_token"] == "cafebabecafebabecafebabecafebabe"
        query, params = fake.calls[0]
        assert "access_token" in query  # in the RETURNING clause
        assert "access_token" not in [str(p) for p in params]  # not an insert param

    async def test_get_authorized_matches_id_and_token_in_sql(self, monkeypatch):
        job_id = uuid.uuid4()
        fake = FakePool(fetchone_result={
            "id": job_id, "audit_id": None, "pack": "deploy", "stack": "fastapi",
            "verified": True, "detail": "HTTP 200 on /",
            "preview_local_url": None, "preview_expires_at": None,
            "pr_url": None, "pr_delivered": False, "status": "generated",
            "created_at": "2026-07-19T10:00:00Z",
        })
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))
        repo = FixpackJobRepository()
        result = await repo.get_authorized(str(job_id), "sekret-token")

        assert result["id"] == str(job_id)
        # Never selects the token, so it can't ride out in the response body.
        assert "access_token" not in result
        query, params = fake.calls[0]
        assert "where id = %s and access_token = %s" in query
        assert "access_token" not in query.split("where")[0]  # not in select list
        assert params == (job_id, "sekret-token")

    async def test_get_authorized_without_token_never_queries(self, monkeypatch):
        # No token -> None, and crucially no DB round-trip: a caller who knows
        # only a leaked id can't even probe.
        fake = FakePool()
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))
        repo = FixpackJobRepository()
        assert await repo.get_authorized(str(uuid.uuid4()), None) is None
        assert await repo.get_authorized(str(uuid.uuid4()), "") is None
        assert fake.calls == []

    async def test_get_authorized_rejects_malformed_id_without_querying(self, monkeypatch):
        fake = FakePool()
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))
        repo = FixpackJobRepository()
        assert await repo.get_authorized("not-a-uuid", "tok") is None
        assert fake.calls == []

    async def test_get_authorized_wrong_token_returns_none(self, monkeypatch):
        # The SQL filter (id AND token) yields no row -> fetchone None -> None.
        fake = FakePool(fetchone_result=None)
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))
        repo = FixpackJobRepository()
        assert await repo.get_authorized(str(uuid.uuid4()), "wrong") is None

    async def test_mark_delivered_executes_update(self, monkeypatch):
        fake = FakePool()
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))
        repo = FixpackJobRepository()
        job_id = str(uuid.uuid4())
        await repo.mark_delivered(job_id, "https://github.com/a/b/pull/1")

        query, params = fake.calls[0]
        assert "update fixpack_jobs" in query
        assert params == ("https://github.com/a/b/pull/1", uuid.UUID(job_id))


class TestFixpackLeaseNotConfigured:
    """The durable-lease primitives honor the same not-configured contract
    as the rest of the repository: no DATABASE_URL -> a benign default, never
    an exception."""

    async def test_claim_one_paid_returns_none(self):
        assert await FixpackJobRepository().claim_one_paid() is None

    async def test_reap_returns_zero_counts(self):
        result = await FixpackJobRepository().reap_stale_running(
            max_age_minutes=15, max_attempts=3
        )
        assert result == {"requeued": 0, "failed": 0, "failed_ids": []}

    async def test_processor_lock_is_a_silent_noop(self):
        # No pool to lock against, so it just yields -- nothing to serialize.
        async with db_mod.fixpack_processor_lock():
            pass


class TestFixpackLeaseWithFakePool:
    async def test_claim_uses_skip_locked_and_leases_running(self, monkeypatch):
        job_id = uuid.uuid4()
        fake = FakePool(fetchone_result={
            "id": job_id, "audit_id": None, "pack": "fixpack", "stack": "fastapi",
            "verified": None, "detail": None, "preview_local_url": None,
            "preview_expires_at": None, "pr_url": None, "pr_delivered": False,
            "status": "running", "created_at": "2026-07-19T10:00:00Z",
        })
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))

        result = await FixpackJobRepository().claim_one_paid()

        assert result["id"] == str(job_id)
        assert result["status"] == "running"
        query, _ = fake.calls[0]
        # The concurrency guard: atomic paid->running claim, skipping rows a
        # concurrent run already locked.
        assert "for update skip locked" in query
        assert "status = 'running'" in query
        assert "attempts = attempts + 1" in query

    async def test_claim_returns_none_when_backlog_empty(self, monkeypatch):
        fake = FakePool(fetchone_result=None)  # UPDATE matched no row
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))
        assert await FixpackJobRepository().claim_one_paid() is None

    async def test_reap_passes_thresholds_as_params(self, monkeypatch):
        fake = FakePool(fetchone_result=[])  # no stale rows either query
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))

        result = await FixpackJobRepository().reap_stale_running(
            max_age_minutes=15, max_attempts=3
        )

        assert result == {"requeued": 0, "failed": 0, "failed_ids": []}
        requeue_q, requeue_p = fake.calls[0]
        assert "set status = 'paid'" in requeue_q
        assert "make_interval(mins => %s)" in requeue_q
        assert requeue_p == (15, 3)
        fail_q, fail_p = fake.calls[1]
        assert "set status = 'failed'" in fail_q
        assert fail_p[1:] == (15, 3)  # (detail, max_age_minutes, max_attempts)
        # the detail carries the prefix the status endpoint reads to tell the
        # customer this was our infrastructure, not their code
        assert fail_p[0].startswith(db_mod.STALE_LEASE_DETAIL_PREFIX)

    async def test_reap_returns_the_ids_it_failed(self, monkeypatch):
        # The processor alerts an operator per reaped-to-failed id; without the
        # ids a paying customer's dead job would be silent.
        failed_id = uuid.uuid4()
        fake = FakePool(fetchone_result=[{"id": failed_id}])
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))

        result = await FixpackJobRepository().reap_stale_running(
            max_age_minutes=15, max_attempts=3
        )

        assert result["failed_ids"] == [str(failed_id)]
        assert result["failed"] == 1

    async def test_processor_lock_acquires_and_releases(self, monkeypatch):
        fake = FakePool(fetchone_result={"locked": True})
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))

        async with db_mod.fixpack_processor_lock():
            pass

        assert "pg_try_advisory_lock" in fake.calls[0][0]
        assert "pg_advisory_unlock" in fake.calls[1][0]

    async def test_processor_lock_busy_raises(self, monkeypatch):
        fake = FakePool(fetchone_result={"locked": False})
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))

        with pytest.raises(db_mod.ProcessorLockBusy):
            async with db_mod.fixpack_processor_lock():
                pass
        # Never unlocked something it didn't hold.
        assert all("pg_advisory_unlock" not in q for q, _ in fake.calls)


class TestAccountRepositoryNotConfigured:
    async def test_create_returns_none(self):
        repo = AccountRepository()
        result = await repo.create(api_key="sk_live_x", tier="pro")
        assert result is None

    async def test_rotate_key_returns_none(self):
        repo = AccountRepository()
        assert await repo.rotate_key(str(uuid.uuid4())) is None


class TestAccountRepositoryWithFakePool:
    async def test_create_stores_prefix_and_hash_not_plaintext(self, monkeypatch):
        # A made-up test pepper, never the real one.
        monkeypatch.setenv("API_KEY_PEPPER", "test-pepper-not-real")
        account_id = uuid.uuid4()
        fake = FakePool(fetchone_result={
            "id": account_id, "api_key": None,
            "key_prefix": "sk_live_x", "key_hash": "unused-in-return",
            "tier": "pro", "created_at": "2026-07-14T10:00:00Z",
        })
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))

        repo = AccountRepository()
        result = await repo.create(api_key="sk_live_secretvalue", tier="pro")

        assert result["id"] == str(account_id)
        assert result["tier"] == "pro"
        # Plaintext is returned in-memory for one-time delivery...
        assert result["api_key"] == "sk_live_secretvalue"

        query, params = fake.calls[0]
        assert "insert into accounts" in query
        # ...but what is WRITTEN is prefix + hash + tier, never the plaintext.
        assert "key_prefix" in query and "key_hash" in query
        assert "sk_live_secretvalue" not in query
        assert params[2] == "pro"
        assert params[0] == "sk_live_secr"  # prefix (KEY_PREFIX_LEN=12)
        assert params[1] != "sk_live_secretvalue"  # a hash, not the key
        assert len(params[1]) == 64  # sha256 hex digest

    async def test_get_by_key_hash_returns_row(self, monkeypatch):
        account_id = uuid.uuid4()
        fake = FakePool(fetchone_result={
            "id": account_id, "api_key": None, "key_prefix": "sk_live_x",
            "key_hash": "deadbeef", "tier": "pro",
            "created_at": "2026-07-14T10:00:00Z",
        })
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))
        repo = AccountRepository()
        result = await repo.get_by_key_hash("deadbeef")
        assert result["id"] == str(account_id)
        query, params = fake.calls[0]
        assert "from accounts where key_hash" in query
        assert params == ("deadbeef",)

    async def test_rotate_key_updates_hash_and_returns_new_plaintext(self, monkeypatch):
        # A made-up test pepper, never the real one.
        monkeypatch.setenv("API_KEY_PEPPER", "test-pepper-not-real")
        account_id = uuid.uuid4()
        fake = FakePool(fetchone_result={
            "id": account_id, "key_prefix": "sk_live_new1",
            "key_hash": "unused-in-return", "tier": "pro",
            "created_at": "2026-07-14T10:00:00Z",
        })
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))
        repo = AccountRepository()

        result = await repo.rotate_key(str(account_id))

        assert result["id"] == str(account_id)
        assert result["tier"] == "pro"
        # The freshly minted plaintext is surfaced once for delivery.
        assert result["api_key"].startswith("sk_live_")

        query, params = fake.calls[0]
        assert "update accounts" in query
        assert "set key_prefix" in query and "key_hash" in query
        # What is WRITTEN is prefix + hash, never the plaintext key.
        assert result["api_key"] not in query
        assert params[0] == result["api_key"][:12]  # prefix (KEY_PREFIX_LEN=12)
        assert params[1] != result["api_key"]  # a hash, not the key
        assert len(params[1]) == 64  # sha256 hex digest
        assert params[2] == account_id  # scoped to the account id

    async def test_rotate_key_returns_none_for_missing_row(self, monkeypatch):
        monkeypatch.setenv("API_KEY_PEPPER", "test-pepper-not-real")
        fake = FakePool(fetchone_result=None)
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))
        repo = AccountRepository()
        assert await repo.rotate_key(str(uuid.uuid4())) is None

    async def test_rotate_key_returns_none_for_bad_uuid(self, monkeypatch):
        monkeypatch.setenv("API_KEY_PEPPER", "test-pepper-not-real")
        fake = FakePool(fetchone_result=None)
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))
        repo = AccountRepository()
        assert await repo.rotate_key("not-a-uuid") is None


class TestPaymentRepositoryNotConfigured:
    async def test_create_returns_none(self):
        repo = PaymentRepository()
        result = await repo.create(
            account_id=None, provider="telegram_stars", external_ref="ch_1",
            amount=9.99, currency="USD", status="pending", tier_granted="pro",
        )
        assert result is None

    async def test_get_returns_none(self):
        repo = PaymentRepository()
        assert await repo.get(str(uuid.uuid4())) is None


class TestPaymentRepositoryWithFakePool:
    async def test_create_inserts_with_correct_param_order(self, monkeypatch):
        payment_id = uuid.uuid4()
        account_id = uuid.uuid4()
        fake = FakePool(fetchone_result={
            "id": payment_id, "account_id": account_id,
            "provider": "usdt_trc20", "external_ref": "0xabc", "amount": 9.99,
            "currency": "USD", "status": "completed", "tier_granted": "pro",
            "created_at": "2026-07-14T10:00:00Z",
        })
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))

        repo = PaymentRepository()
        result = await repo.create(
            account_id=str(account_id), provider="usdt_trc20",
            external_ref="0xabc", amount=9.99, currency="USD",
            status="completed", tier_granted="pro",
        )

        assert result["id"] == str(payment_id)
        assert result["account_id"] == str(account_id)
        query, params = fake.calls[0]
        assert "insert into payments" in query
        # The three trailing Nones are payer_name, payer_email (migration 0026)
        # and payer_x (0032): supplied only by bank_transfer, so every other
        # provider writes the row exactly as it did before those columns
        # existed. The one before them is audit_id.
        #
        # paypal_order_id was the tenth parameter until PayPal was removed as a
        # way to pay. The COLUMN is still there and still SELECTed -- the rows
        # PayPal wrote are the books -- but nothing binds it any more, so an
        # insert that still did would be writing a provider we no longer have.
        assert params == (account_id, "usdt_trc20", "0xabc", 9.99, "USD",
                          "completed", "pro", "pro_tier", None,
                          None, None, None)

    async def test_amount_numeric_is_cast_to_json_number_not_string(self, monkeypatch):
        """Postgres `numeric` -> decimal.Decimal renders as a JSON *string*
        under the default encoder; it must come out a float, same fix as
        audits.score_total."""
        import decimal
        import json

        payment_id = uuid.uuid4()
        fake = FakePool(fetchone_result={
            "id": payment_id, "account_id": None, "provider": "telegram_stars",
            "external_ref": None, "amount": decimal.Decimal("9.99"),
            "currency": "USD", "status": "pending", "tier_granted": "pro",
            "created_at": "2026-07-14T10:00:00Z",
        })
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))
        repo = PaymentRepository()
        result = await repo.get(str(payment_id))
        assert isinstance(result["amount"], float)
        assert json.loads(json.dumps(result))["amount"] == 9.99
        assert result["account_id"] is None

    async def test_get_rejects_malformed_id_without_querying(self, monkeypatch):
        fake = FakePool()
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))
        repo = PaymentRepository()
        assert await repo.get("not-a-uuid") is None
        assert fake.calls == []


def _subscription_row(sub_id):
    """A fetchone_result shaped like the RETURNING clause of the subscription
    writes, enough for _row_to_subscription."""
    return {
        "id": sub_id, "account_id": None, "telegram_user_id": "42",
        "telegram_chat_id": "42", "tier": "test-monitoring",
        "invoice_payload": "sub_test", "telegram_payment_charge_id": "ch_1",
        "status": "active", "expires_at": "2026-08-19T10:00:00Z",
        "created_at": "2026-07-20T10:00:00Z", "updated_at": "2026-07-20T10:00:00Z",
    }


class TestSubscriptionRepositoryExpiresAtType:
    """Regression tests for the prod incident where Telegram's
    successful_payment.subscription_expiration_date (Unix int) was passed
    straight into the timestamptz expires_at column, raising
    psycopg DatatypeMismatch. These assert the *type* of the SQL param --
    the exact thing the in-memory FakeSubscriptionRepo in the billing tests
    cannot catch, since it never touches real SQL types."""

    # 2026-08-19T10:00:00+00:00 as Unix seconds -- the shape Telegram sends.
    UNIX_TS = 1787133600

    async def test_upsert_first_passes_datetime_not_int(self, monkeypatch):
        sub_id = uuid.uuid4()
        fake = FakePool(fetchone_result=_subscription_row(sub_id))
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))

        repo = SubscriptionRepository()
        await repo.upsert_first(
            telegram_user_id="42", invoice_payload="sub_test",
            tier="test-monitoring", telegram_chat_id="42",
            telegram_payment_charge_id="ch_1", expires_at=self.UNIX_TS,
        )

        query, params = fake.calls[0]
        assert "insert into subscriptions" in query
        expires_param = params[-1]
        # The bug: a bare int reached the timestamptz column. It must now be a
        # tz-aware datetime, matching the Unix timestamp interpreted as UTC.
        assert isinstance(expires_param, datetime.datetime)
        assert not isinstance(expires_param, bool)
        assert expires_param.tzinfo is not None
        assert expires_param == datetime.datetime.fromtimestamp(
            self.UNIX_TS, tz=datetime.timezone.utc
        )

    async def test_renew_passes_datetime_not_int(self, monkeypatch):
        sub_id = uuid.uuid4()
        fake = FakePool(fetchone_result=_subscription_row(sub_id))
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))

        repo = SubscriptionRepository()
        await repo.renew(
            str(sub_id), expires_at=self.UNIX_TS,
            telegram_payment_charge_id="ch_2",
        )

        query, params = fake.calls[0]
        assert "update subscriptions" in query
        expires_param = params[0]
        assert isinstance(expires_param, datetime.datetime)
        assert expires_param.tzinfo is not None
        assert expires_param == datetime.datetime.fromtimestamp(
            self.UNIX_TS, tz=datetime.timezone.utc
        )

    async def test_upsert_first_none_expires_at_passes_through(self, monkeypatch):
        """No expiry known -> None must survive as None (not 0 / epoch)."""
        sub_id = uuid.uuid4()
        fake = FakePool(fetchone_result=_subscription_row(sub_id))
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))

        repo = SubscriptionRepository()
        await repo.upsert_first(
            telegram_user_id="42", invoice_payload="sub_test",
            tier="test-monitoring", telegram_chat_id="42",
            telegram_payment_charge_id="ch_1", expires_at=None,
        )

        _query, params = fake.calls[0]
        assert params[-1] is None


async def _async_return(value):
    return value


def test_backfill_marks_old_free_audits_unexamined():
    """A stored static-only row predating `unexamined` must not read as if
    everything was examined: both report surfaces decide whether to draw a
    category's bar from that key, and absent would draw Auth at a full 10.0.
    """
    from app.db import _backfill_unexamined

    row = {"total": 6.1, "basis": "static_only", "categories": {"Auth": 10.0}}
    assert _backfill_unexamined(row)["unexamined"] == ["Auth", "Money & Data", "Frontend"]


def test_backfill_leaves_paid_and_fresh_rows_alone():
    from app.db import _backfill_unexamined

    paid = {"total": 5.4, "basis": "static+llm", "categories": {}}
    assert "unexamined" not in _backfill_unexamined(paid)

    # Already recorded, and empty means "nothing was skipped" -- the backfill
    # must not overwrite that with a guess.
    fresh = {"total": 6.1, "basis": "static_only", "unexamined": []}
    assert _backfill_unexamined(fresh)["unexamined"] == []

    assert _backfill_unexamined(None) is None


def test_row_to_audit_applies_the_backfill():
    """Through the serializer, not the helper.

    Testing _backfill_unexamined directly leaves its call site uncovered:
    deleting the call from _row_to_audit passed the whole suite, and every
    stored free audit would have started drawing Auth as a full bar again.
    """
    from app.db import _row_to_audit

    row = {
        "id": "abc",
        "score_total": None,
        "score_json": {"total": 6.1, "basis": "static_only",
                       "categories": {"Auth": 10.0}},
        "findings_json": [],
    }
    assert _row_to_audit(row)["score_json"]["unexamined"] == [
        "Auth", "Money & Data", "Frontend"]

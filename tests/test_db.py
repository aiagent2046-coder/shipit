"""Tests for app/db.py. No real Postgres involved -- a FakePool stands
in for psycopg_pool.AsyncConnectionPool. Proves the query wiring,
param order, and row-to-dict conversion (UUID -> str, jsonb handling)
-- not that psycopg can really reach a live Postgres. See
scripts/verify_db_locally.py for that, run by the user with their own
DATABASE_URL against the real Supabase project (already confirmed
working by hand during this migration from asyncpg -- see app/db.py's
module docstring for why asyncpg was replaced).
"""

import uuid

import pytest

import app.db as db_mod
from app.db import (
    AccountRepository,
    AuditRepository,
    DatabaseNotConfigured,
    FixpackJobRepository,
    PaymentRepository,
)


class FakeCursor:
    def __init__(self, result):
        self._result = result

    async def fetchone(self):
        return self._result


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
        query, params = fake.calls[0]
        assert "insert into audits" in query
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
        _, params = fake.calls[0]
        assert params == (None, "deploy", "fastapi", True, "HTTP 200 on /",
                           "http://localhost:20000/", None)

    async def test_mark_delivered_executes_update(self, monkeypatch):
        fake = FakePool()
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))
        repo = FixpackJobRepository()
        job_id = str(uuid.uuid4())
        await repo.mark_delivered(job_id, "https://github.com/a/b/pull/1")

        query, params = fake.calls[0]
        assert "update fixpack_jobs" in query
        assert params == ("https://github.com/a/b/pull/1", uuid.UUID(job_id))


class TestAccountRepositoryNotConfigured:
    async def test_create_returns_none(self):
        repo = AccountRepository()
        result = await repo.create(api_key="sk_live_x", tier="pro")
        assert result is None

    async def test_get_by_api_key_returns_none(self):
        repo = AccountRepository()
        assert await repo.get_by_api_key("sk_live_x") is None


class TestAccountRepositoryWithFakePool:
    async def test_create_inserts_and_returns_row(self, monkeypatch):
        account_id = uuid.uuid4()
        fake = FakePool(fetchone_result={
            "id": account_id, "api_key": "sk_live_x", "tier": "pro",
            "created_at": "2026-07-14T10:00:00Z",
        })
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))

        repo = AccountRepository()
        result = await repo.create(api_key="sk_live_x", tier="pro")

        assert result["id"] == str(account_id)
        assert result["tier"] == "pro"
        query, params = fake.calls[0]
        assert "insert into accounts" in query
        assert params == ("sk_live_x", "pro")

    async def test_get_by_api_key_returns_row(self, monkeypatch):
        account_id = uuid.uuid4()
        fake = FakePool(fetchone_result={
            "id": account_id, "api_key": "sk_live_x", "tier": "pro",
            "created_at": "2026-07-14T10:00:00Z",
        })
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))
        repo = AccountRepository()
        result = await repo.get_by_api_key("sk_live_x")
        assert result["id"] == str(account_id)
        query, params = fake.calls[0]
        assert "from accounts where api_key" in query
        assert params == ("sk_live_x",)

    async def test_get_by_api_key_returns_none_for_missing_row(self, monkeypatch):
        fake = FakePool(fetchone_result=None)
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))
        repo = AccountRepository()
        assert await repo.get_by_api_key("sk_live_absent") is None


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
        assert params == (account_id, "usdt_trc20", "0xabc", 9.99, "USD",
                          "completed", "pro", "pro_tier", None)

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


async def _async_return(value):
    return value

"""Tests for app/db.py. No real Postgres involved -- a FakePool stands
in for asyncpg.Pool (plain dicts work fine as fake rows: `_row_to_*`
only ever does `dict(row)` then indexes the result, and `dict(dict)` is
a valid copy). This proves the query wiring, param order, and
row-to-dict conversion (UUID -> str, jsonb -> parsed dict/list) -- not
that asyncpg can really reach a live Postgres. See
scripts/verify_db_locally.py for that, run by the user with their own
DATABASE_URL against the real Supabase project.
"""

import uuid

import pytest

import app.db as db_mod
from app.db import AuditRepository, DatabaseNotConfigured, FixpackJobRepository


class FakePool:
    def __init__(self, fetchrow_result=None):
        self.fetchrow_calls = []
        self.execute_calls = []
        self.fetchrow_result = fetchrow_result

    async def fetchrow(self, query, *args):
        self.fetchrow_calls.append((query, args))
        return self.fetchrow_result

    async def execute(self, query, *args):
        self.execute_calls.append((query, args))


@pytest.fixture(autouse=True)
def no_database_url(monkeypatch):
    """Default: DATABASE_URL unset, matching this dev sandbox and the
    main pytest suite -- individual tests override with a FakePool
    where they need the "happy path" instead."""
    monkeypatch.delenv("DATABASE_URL", raising=False)


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
        fake = FakePool(fetchrow_result={
            "id": audit_id, "stack": "fastapi", "status": "completed",
            "file_count": 3, "score_total": 8.5,
            "score_json": '{"total": 8.5}', "findings_json": "[]",
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
        query, args = fake.fetchrow_calls[0]
        assert "insert into audits" in query
        assert args[0] == "fastapi"

    async def test_get_returns_none_for_missing_row(self, monkeypatch):
        fake = FakePool(fetchrow_result=None)
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))
        repo = AuditRepository()
        assert await repo.get(str(uuid.uuid4())) is None

    async def test_get_rejects_malformed_id_without_querying(self, monkeypatch):
        fake = FakePool()
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))
        repo = AuditRepository()
        assert await repo.get("not-a-uuid") is None
        assert fake.fetchrow_calls == []


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
        fake = FakePool(fetchrow_result={
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
        _, args = fake.fetchrow_calls[0]
        assert args == (None, "deploy", "fastapi", True, "HTTP 200 on /",
                         "http://localhost:20000/", None)

    async def test_mark_delivered_executes_update(self, monkeypatch):
        fake = FakePool()
        monkeypatch.setattr(db_mod, "get_pool", lambda: _async_return(fake))
        repo = FixpackJobRepository()
        job_id = str(uuid.uuid4())
        await repo.mark_delivered(job_id, "https://github.com/a/b/pull/1")

        query, args = fake.execute_calls[0]
        assert "update fixpack_jobs" in query
        assert args == ("https://github.com/a/b/pull/1", uuid.UUID(job_id))


async def _async_return(value):
    return value

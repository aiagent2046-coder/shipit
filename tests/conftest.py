"""Shared test fixtures.

Autouse: give every test a fresh, generous rate limiter so tests in
different files that each hit /v1/audits a few times never trip each
other's daily budget (they'd otherwise all share the same TestClient
key). Tests that want to exercise real limiting override
`get_rate_limiter` themselves inside the test body — see
test_ratelimit.py — which simply shadows this default for the
duration of that test.

Autouse: keep DATABASE_URL out of the default suite regardless of what
the shell happens to have exported. Without this, a DATABASE_URL left
over from running scripts/verify_db_locally.py by hand makes
unrelated tests (test_fixpack_api.py, test_ingest_api.py, ...) open
real connections to Supabase through app/db.py's module-global pool --
slow, and the pool ends up bound to one test's asyncio event loop
while a later test runs on a different (already-closed) one, which is
what the `Event loop is closed` / `another operation is in progress`
cascade actually was. tests/test_db.py sets DATABASE_URL back
explicitly, per test, where it wants the configured-path behavior.
"""

from __future__ import annotations

import pytest

import app.db as db_mod
from app.main import app, get_rate_limiter
from app.ratelimit import RateLimiter


@pytest.fixture(autouse=True)
def _generous_rate_limit_by_default():
    app.dependency_overrides[get_rate_limiter] = lambda: RateLimiter(limit=10_000)
    yield
    app.dependency_overrides.pop(get_rate_limiter, None)


@pytest.fixture(autouse=True)
def _no_ambient_database_url(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    db_mod._pool = None
    yield
    db_mod._pool = None

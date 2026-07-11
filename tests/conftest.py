"""Shared test fixtures.

Autouse: give every test a fresh, generous rate limiter so tests in
different files that each hit /v1/audits a few times never trip each
other's daily budget (they'd otherwise all share the same TestClient
key). Tests that want to exercise real limiting override
`get_rate_limiter` themselves inside the test body — see
test_ratelimit.py — which simply shadows this default for the
duration of that test.
"""

from __future__ import annotations

import pytest

from app.main import app, get_rate_limiter
from app.ratelimit import RateLimiter


@pytest.fixture(autouse=True)
def _generous_rate_limit_by_default():
    app.dependency_overrides[get_rate_limiter] = lambda: RateLimiter(limit=10_000)
    yield
    app.dependency_overrides.pop(get_rate_limiter, None)

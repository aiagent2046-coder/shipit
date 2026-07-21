"""Tests for the Redis-backed rate limiter and env-driven selection.

Uses an in-process fake Redis that emulates the exact semantics the limiter's
Lua script relies on (INCR, first-hit PEXPIRE, PTTL, and TTL-driven auto-expiry
of the key). No real server and no new locked dependency — the fake is injected
through the same `eval` interface redis-py exposes.
"""

import io
import json
import zipfile

import redis
from fastapi.testclient import TestClient

from app.main import app, get_rate_limiter
from app.ratelimit import (
    DEFAULT_LIMIT,
    RateLimiter,
    RateLimitExceeded,
    RedisRateLimiter,
    limiter_from_env,
)


class FakeRedis:
    """Minimal fake implementing just `eval` for the fixed-window script.

    `clock_ms` is injectable so tests move time without sleeping; real Redis
    auto-deletes an expired key, which is emulated here on each access.
    """

    def __init__(self, clock_ms=None):
        self._counts: dict[str, int] = {}
        self._expire_at: dict[str, float] = {}
        self._clock_ms = clock_ms or (lambda: 0.0)

    def _evict_if_expired(self, key: str) -> None:
        exp = self._expire_at.get(key)
        if exp is not None and self._clock_ms() >= exp:
            self._counts.pop(key, None)
            self._expire_at.pop(key, None)

    def eval(self, script, numkeys, key, window_ms):
        # Mirrors _WINDOW_LUA: INCR, set expiry only on the first hit, return
        # (count, pttl_ms). PTTL is -2 when the key is missing (never here,
        # since INCR just created it) and -1 when it has no expiry.
        self._evict_if_expired(key)
        current = self._counts.get(key, 0) + 1
        self._counts[key] = current
        if current == 1:
            self._expire_at[key] = self._clock_ms() + window_ms
        exp = self._expire_at.get(key)
        pttl = int(exp - self._clock_ms()) if exp is not None else -1
        return [current, pttl]


# --- env-driven selection ------------------------------------------------

def test_from_env_returns_inmemory_without_redis_url(monkeypatch):
    monkeypatch.delenv("REDIS_URL", raising=False)
    limiter = limiter_from_env()
    assert isinstance(limiter, RateLimiter)
    assert not isinstance(limiter, RedisRateLimiter)


def test_from_env_returns_redis_with_redis_url(monkeypatch):
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setattr(redis.Redis, "from_url", lambda url: FakeRedis())
    limiter = limiter_from_env()
    assert isinstance(limiter, RedisRateLimiter)
    assert limiter.limit == DEFAULT_LIMIT


def test_from_env_redis_honors_configured_limit(monkeypatch):
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("AUDIT_RATE_LIMIT_PER_DAY", "9")
    monkeypatch.setattr(redis.Redis, "from_url", lambda url: FakeRedis())
    assert limiter_from_env().limit == 9


# --- RedisRateLimiter unit behavior --------------------------------------

def test_allows_up_to_the_limit():
    limiter = RedisRateLimiter(FakeRedis(), limit=3, window_seconds=100)
    for _ in range(3):
        limiter.check("1.2.3.4")  # must not raise


def test_blocks_after_the_limit():
    limiter = RedisRateLimiter(FakeRedis(), limit=2, window_seconds=100)
    limiter.check("1.2.3.4")
    limiter.check("1.2.3.4")
    try:
        limiter.check("1.2.3.4")
        assert False, "expected RateLimitExceeded"
    except RateLimitExceeded as exc:
        assert exc.retry_after > 0


def test_keys_are_independent():
    limiter = RedisRateLimiter(FakeRedis(), limit=1, window_seconds=100)
    limiter.check("1.2.3.4")
    limiter.check("5.6.7.8")  # different key, must not raise


def test_window_resets_after_it_elapses():
    now = [0.0]
    fake = FakeRedis(clock_ms=lambda: now[0])
    limiter = RedisRateLimiter(fake, limit=1, window_seconds=100)
    limiter.check("1.2.3.4")
    now[0] = 100_000.1  # window (100s) just elapsed, in ms
    limiter.check("1.2.3.4")  # key auto-expired -> fresh window, must not raise


def test_per_call_limit_override():
    # The tier-aware path: check(key, limit=...) overrides the default budget
    # for this call only, exactly like the in-memory limiter.
    limiter = RedisRateLimiter(FakeRedis(), limit=1, window_seconds=100)
    limiter.check("acct", limit=3)
    limiter.check("acct", limit=3)
    limiter.check("acct", limit=3)
    try:
        limiter.check("acct", limit=3)
        assert False, "expected RateLimitExceeded"
    except RateLimitExceeded:
        pass


def test_retry_after_derived_from_ttl():
    now = [0.0]
    fake = FakeRedis(clock_ms=lambda: now[0])
    limiter = RedisRateLimiter(fake, limit=1, window_seconds=100)
    limiter.check("1.2.3.4")
    now[0] = 30_000.0  # 30s into the window
    try:
        limiter.check("1.2.3.4")
        assert False, "expected RateLimitExceeded"
    except RateLimitExceeded as exc:
        # ~70s remain; retry_after is int(ttl_seconds)+1
        assert 60 <= exc.retry_after <= 71


# --- endpoint integration ------------------------------------------------

def make_valid_zip() -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "package.json",
            json.dumps({"dependencies": {"next": "15.0.0", "react": "19.0.0"}}).encode(),
        )
    buf.seek(0)
    return buf


def test_audit_endpoint_429s_with_redis_limiter():
    tiny = RedisRateLimiter(FakeRedis(), limit=2, window_seconds=100)
    app.dependency_overrides[get_rate_limiter] = lambda: tiny
    try:
        client = TestClient(app)
        for _ in range(2):
            resp = client.post(
                "/v1/audits",
                files={"archive": ("app.zip", make_valid_zip(), "application/zip")},
            )
            assert resp.status_code == 202
        resp = client.post(
            "/v1/audits",
            files={"archive": ("app.zip", make_valid_zip(), "application/zip")},
        )
        assert resp.status_code == 429
        assert resp.json()["detail"]["reason"] == "rate_limited"
        assert int(resp.headers["retry-after"]) > 0
    finally:
        app.dependency_overrides.pop(get_rate_limiter, None)

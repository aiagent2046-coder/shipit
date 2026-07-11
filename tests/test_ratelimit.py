"""Tests for the rate limiter, standalone and wired into /v1/audits."""

import io
import zipfile

from fastapi.testclient import TestClient

from app.main import app, get_rate_limiter
from app.ratelimit import RateLimiter, RateLimitExceeded


# --- unit tests: RateLimiter in isolation, no HTTP involved ---

def test_allows_up_to_the_limit():
    limiter = RateLimiter(limit=3, window_seconds=100, clock=lambda: 0.0)
    for _ in range(3):
        limiter.check("1.2.3.4")  # must not raise


def test_blocks_after_the_limit():
    limiter = RateLimiter(limit=2, window_seconds=100, clock=lambda: 0.0)
    limiter.check("1.2.3.4")
    limiter.check("1.2.3.4")
    try:
        limiter.check("1.2.3.4")
        assert False, "expected RateLimitExceeded"
    except RateLimitExceeded as exc:
        assert exc.retry_after > 0


def test_keys_are_independent():
    limiter = RateLimiter(limit=1, window_seconds=100, clock=lambda: 0.0)
    limiter.check("1.2.3.4")
    limiter.check("5.6.7.8")  # different key, must not raise


def test_window_resets_after_it_elapses():
    now = [0.0]
    limiter = RateLimiter(limit=1, window_seconds=100, clock=lambda: now[0])
    limiter.check("1.2.3.4")
    now[0] = 100.1  # window just elapsed
    limiter.check("1.2.3.4")  # must not raise


# --- integration: the endpoint returns 429 + Retry-After once tripped ---

def make_zip() -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.html", b"<html></html>")
    buf.seek(0)
    return buf


def test_audit_endpoint_429s_once_limit_is_hit():
    tiny_limiter = RateLimiter(limit=2, window_seconds=100, clock=lambda: 0.0)
    app.dependency_overrides[get_rate_limiter] = lambda: tiny_limiter
    try:
        client = TestClient(app)
        # each attempt uses an unsupported stack, but the rate-limit check
        # runs first, so status codes tell us where each request was stopped
        for _ in range(2):
            resp = client.post(
                "/v1/audits", files={"archive": ("app.zip", make_zip(), "application/zip")}
            )
            assert resp.status_code == 422  # allowed through, rejected on stack

        resp = client.post(
            "/v1/audits", files={"archive": ("app.zip", make_zip(), "application/zip")}
        )
        assert resp.status_code == 429
        assert resp.json()["detail"]["reason"] == "rate_limited"
        assert int(resp.headers["retry-after"]) > 0
    finally:
        app.dependency_overrides.pop(get_rate_limiter, None)

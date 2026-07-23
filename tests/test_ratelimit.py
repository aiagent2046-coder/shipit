"""Tests for the rate limiter, standalone and wired into /v1/audits."""

import io
import json
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


def test_expired_key_is_evicted_not_just_emptied():
    # The leak: a key seen once and never again used to sit in _windows
    # forever. A later call for ANY key must evict the stale one entirely.
    now = [0.0]
    limiter = RateLimiter(limit=5, window_seconds=100, clock=lambda: now[0])
    limiter.check("1.2.3.4")
    assert "1.2.3.4" in limiter._windows

    now[0] = 100.1  # 1.2.3.4's window has fully elapsed
    limiter.check("5.6.7.8")  # a different client's request drives the sweep

    assert "1.2.3.4" not in limiter._windows  # actually removed, not left empty
    assert set(limiter._windows) == {"5.6.7.8"}


def test_eviction_does_not_leak_across_many_expired_keys():
    # Boundedness: N distinct one-shot clients, then time passes; the next
    # request collapses the dict back down to just the active key.
    now = [0.0]
    limiter = RateLimiter(limit=5, window_seconds=100, clock=lambda: now[0])
    for i in range(50):
        limiter.check(f"10.0.0.{i}")
    assert len(limiter._windows) == 50

    now[0] = 100.1
    limiter.check("192.168.1.1")
    assert set(limiter._windows) == {"192.168.1.1"}


# --- integration: the endpoint returns 429 + Retry-After once tripped ---

def make_zip() -> io.BytesIO:
    """An unsupported-stack zip: rejected at validation (422), before quota."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.html", b"<html></html>")
    buf.seek(0)
    return buf


def make_valid_zip() -> io.BytesIO:
    """A valid Next.js zip: passes validation + stack detection, so it
    reaches the rate-limit check and consumes one unit of quota."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "package.json",
            json.dumps({"dependencies": {"next": "15.0.0", "react": "19.0.0"}}).encode(),
        )
    buf.seek(0)
    return buf


def test_audit_endpoint_429s_once_limit_is_hit():
    tiny_limiter = RateLimiter(limit=2, window_seconds=100, clock=lambda: 0.0)
    app.dependency_overrides[get_rate_limiter] = lambda: tiny_limiter
    try:
        client = TestClient(app)
        # valid audits consume quota: the first two go through, the third is
        # over budget and gets rejected before any scan work runs
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


def test_invalid_uploads_do_not_consume_quota():
    """A hostile/garbage upload is rejected at validation, before the quota
    check, so it must not burn the client's daily budget. Submitting far
    more invalid zips than the limit still leaves a valid audit able to run.
    """
    tiny_limiter = RateLimiter(limit=2, window_seconds=100, clock=lambda: 0.0)
    app.dependency_overrides[get_rate_limiter] = lambda: tiny_limiter
    try:
        client = TestClient(app)
        # 5 invalid uploads, well over the limit of 2 -- all rejected at
        # validation, none should touch the quota
        for _ in range(5):
            resp = client.post(
                "/v1/audits",
                files={"archive": ("app.zip", make_zip(), "application/zip")},
            )
            assert resp.status_code == 422

        # quota is untouched, so two real audits still succeed
        for _ in range(2):
            resp = client.post(
                "/v1/audits",
                files={"archive": ("app.zip", make_valid_zip(), "application/zip")},
            )
            assert resp.status_code == 202
    finally:
        app.dependency_overrides.pop(get_rate_limiter, None)

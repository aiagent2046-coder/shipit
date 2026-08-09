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
    """An archive rejected by validation itself (422), before the quota check.

    A path-traversal entry, not an unrecognised stack. This fixture used to be
    a plain index.html, which was rejected only because stack detection refused
    anything outside Next.js / Vite / FastAPI. Once an unknown stack became a
    normal audit rather than a refusal, that upload started returning 202 and
    the test was asserting on a fixture that no longer meant what its name
    said. The property here -- a rejected upload must not burn quota -- is
    unchanged and worth keeping, so the fixture is now invalid for a reason
    that cannot quietly stop being one.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("../../etc/evil", b"x")
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


# --- which IP the quota is keyed on -------------------------------------
#
# _client_key resolves the quota key from X-Forwarded-For. Caddy APPENDS the
# peer address to whatever header arrived, so the leftmost entry is chosen by
# the client and the rightmost is the one our proxy wrote. Keying on the
# leftmost let anyone rotate the header for unlimited free audits, i.e.
# unlimited LLM spend — these pin the resolution to the trusted entry.

class _FakeRequest:
    """The two attributes _client_key reads, nothing else."""

    def __init__(self, forwarded=None, peer="10.0.0.1"):
        self.headers = {"x-forwarded-for": forwarded} if forwarded else {}
        self.client = type("C", (), {"host": peer})()


def test_client_key_uses_the_hop_our_proxy_wrote():
    from app.main import _client_key
    assert _client_key(_FakeRequest("9.9.9.9")) == "9.9.9.9"


def test_client_key_ignores_a_client_supplied_prefix():
    """`XFF: 1.2.3.4` from the client + Caddy's append = `1.2.3.4, 9.9.9.9`.
    The forged entry must not change the key."""
    from app.main import _client_key
    honest = _client_key(_FakeRequest("9.9.9.9"))
    forged = _client_key(_FakeRequest("1.2.3.4, 9.9.9.9"))
    assert forged == honest == "9.9.9.9"


def test_client_key_a_rotating_forged_prefix_maps_to_one_key():
    from app.main import _client_key
    keys = {_client_key(_FakeRequest(f"1.2.3.{i}, 9.9.9.9")) for i in range(50)}
    assert keys == {"9.9.9.9"}


def test_client_key_falls_back_to_the_peer_without_the_header():
    from app.main import _client_key
    assert _client_key(_FakeRequest(peer="10.0.0.7")) == "10.0.0.7"

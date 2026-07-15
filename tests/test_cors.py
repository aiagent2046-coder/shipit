"""Tests for env-driven CORS (browser frontend on Vercel calling this API).

configure_cors() reads env at call time, so each test monkeypatches env
and builds a throwaway FastAPI app with a single route to exercise. We
assert on the Access-Control-Allow-Origin header of a real (simple) GET
carrying an Origin, which is what Starlette echoes for an allowed origin.
"""

from __future__ import annotations

from app.main import configure_cors
from fastapi import FastAPI
from fastapi.testclient import TestClient


def _app_with_cors() -> TestClient:
    fresh = FastAPI()

    @fresh.get("/ping")
    async def ping():
        return {"ok": True}

    configure_cors(fresh)
    return TestClient(fresh)


LISTED = "https://shipit-web.vercel.app"
PREVIEW = "https://shipit-web-abc123-team.vercel.app"


def test_explicit_origin_is_allowed(monkeypatch):
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", f"{LISTED},https://shipit.app")
    monkeypatch.delenv("CORS_ALLOW_VERCEL_PREVIEWS", raising=False)
    client = _app_with_cors()

    r = client.get("/ping", headers={"Origin": LISTED})
    assert r.status_code == 200
    assert r.headers["access-control-allow-origin"] == LISTED
    assert r.headers["access-control-allow-credentials"] == "true"


def test_unlisted_origin_is_not_allowed(monkeypatch):
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", LISTED)
    monkeypatch.delenv("CORS_ALLOW_VERCEL_PREVIEWS", raising=False)
    client = _app_with_cors()

    r = client.get("/ping", headers={"Origin": "https://evil.example.com"})
    assert r.status_code == 200
    assert "access-control-allow-origin" not in r.headers


def test_vercel_preview_allowed_when_opted_in(monkeypatch):
    monkeypatch.delenv("CORS_ALLOWED_ORIGINS", raising=False)
    monkeypatch.setenv("CORS_ALLOW_VERCEL_PREVIEWS", "true")
    client = _app_with_cors()

    r = client.get("/ping", headers={"Origin": PREVIEW})
    assert r.status_code == 200
    assert r.headers["access-control-allow-origin"] == PREVIEW
    # credentials are on because the preview regex is enabled
    assert r.headers["access-control-allow-credentials"] == "true"


def test_vercel_preview_not_allowed_when_off(monkeypatch):
    # No explicit origins and previews disabled => deny-by-default, even for
    # a perfectly valid-looking *.vercel.app origin.
    monkeypatch.delenv("CORS_ALLOWED_ORIGINS", raising=False)
    monkeypatch.delenv("CORS_ALLOW_VERCEL_PREVIEWS", raising=False)
    client = _app_with_cors()

    r = client.get("/ping", headers={"Origin": PREVIEW})
    assert r.status_code == 200
    assert "access-control-allow-origin" not in r.headers


def test_preflight_advertises_methods_and_auth_header(monkeypatch):
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", LISTED)
    monkeypatch.delenv("CORS_ALLOW_VERCEL_PREVIEWS", raising=False)
    client = _app_with_cors()

    r = client.options(
        "/ping",
        headers={
            "Origin": LISTED,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "authorization,content-type",
        },
    )
    assert r.status_code == 200
    assert r.headers["access-control-allow-origin"] == LISTED
    allowed_methods = r.headers["access-control-allow-methods"]
    assert "GET" in allowed_methods and "POST" in allowed_methods
    assert "authorization" in r.headers["access-control-allow-headers"].lower()

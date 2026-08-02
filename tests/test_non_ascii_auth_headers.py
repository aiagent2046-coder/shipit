"""A header with a byte above 127 must be answered 401, never 5xx.

`hmac.compare_digest` on two str arguments raises TypeError as soon as either
side holds a character above 127. Header values arrive as str, and a client
can put any byte in one, so this raised inside the auth check and reached the
global handler -- a 500, a traceback, and an operator alert, for a request
that should simply have been refused. Measured before the fix:

    500  POST /internal/preview/reap
    500  POST /internal/monitoring/process-pending
    500  GET  /internal/audit-jobs/stats
    500  GET  /internal/stats
    500  POST /internal/service-flags/llm_paid_ops
    500  POST /v1/webhooks/telegram          (X-Telegram-Bot-Api-Secret-Token)
    500  POST /v1/webhooks/github            (X-Hub-Signature-256)

Note the header values below are BYTES, not str. That is not decoration: httpx
refuses to send a str header it cannot encode as ASCII, so a str test would
fail in the client and never reach the app. curl has no such scruples, which
is exactly why this was reachable from the open internet without a credential.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app, raise_server_exceptions=False)

# UTF-8 for "тест" -- the bytes a normal client would put on the wire.
CYRILLIC = b"\xd1\x82\xd0\xb5\xd1\x81\xd1\x82"

# (method, path, header name, value prefix)
SECRET_HEADER_ENDPOINTS = [
    ("POST", "/internal/preview/reap", "authorization", b"Bearer "),
    ("POST", "/internal/monitoring/process-pending", "authorization", b"Bearer "),
    ("GET", "/internal/audit-jobs/stats", "authorization", b"Bearer "),
    ("GET", "/internal/stats", "authorization", b"Bearer "),
    ("POST", "/internal/service-flags/llm_paid_ops", "authorization", b"Bearer "),
    ("POST", "/v1/webhooks/telegram", "x-telegram-bot-api-secret-token", b""),
    ("POST", "/v1/webhooks/github", "x-hub-signature-256", b"sha256="),
]


@pytest.fixture(autouse=True)
def _configured(monkeypatch):
    """Every secret set, so each endpoint gets past its 503 gate and reaches
    the comparison. The values are ASCII on purpose: the bug is in the
    PROVIDED side, and an ASCII secret is what production actually has."""
    for name in (
        "PREVIEW_REAP_TOKEN", "MONITORING_PROCESS_TOKEN", "USDT_POLL_TOKEN",
        "FIXPACK_PROCESS_TOKEN", "INTERNAL_STATS_TOKEN", "SERVICE_FLAGS_TOKEN",
        "AUDIT_JOBS_STATS_TOKEN", "TELEGRAM_BOT_TOKEN",
        "TELEGRAM_WEBHOOK_SECRET", "GITHUB_APP_WEBHOOK_SECRET",
    ):
        monkeypatch.setenv(name, "t")
    monkeypatch.setenv("DATABASE_URL", "postgresql://u@/db")


@pytest.mark.parametrize("method,path,header,prefix", SECRET_HEADER_ENDPOINTS)
def test_non_ascii_secret_header_is_refused_not_crashed(method, path, header, prefix):
    resp = client.request(
        method, path, content='{"enabled": true}',
        headers={header: prefix + CYRILLIC, "content-type": "application/json"},
    )

    assert resp.status_code == 401, (
        f"{method} {path} answered {resp.status_code}; a 5xx here is an "
        "operator alert triggered by an unauthenticated stranger"
    )


@pytest.mark.parametrize("method,path,header,prefix", SECRET_HEADER_ENDPOINTS)
def test_a_plain_wrong_ascii_secret_is_still_refused(method, path, header, prefix):
    """The boundary on the other side: the fix must not turn a rejection into
    an acceptance. An ordinary wrong token stays 401."""
    resp = client.request(
        method, path, content='{"enabled": true}',
        headers={header: prefix + b"wrong", "content-type": "application/json"},
    )

    assert resp.status_code == 401


def test_the_right_secret_still_gets_through():
    """The regression that would matter most: encoding both sides must not
    break the comparison that is supposed to succeed.

    Against the function rather than an endpoint. Every endpoint here reaches
    for the database the moment auth passes, so the HTTP version of this test
    spent 30 seconds waiting for a connection that cannot exist -- a minute of
    CI to assert something the function answers immediately."""
    from app.main import _secret_equals

    assert _secret_equals("Bearer t", "Bearer t")
    assert not _secret_equals("Bearer wrong", "Bearer t")


def test_a_non_ascii_secret_can_actually_be_used():
    """_secret_equals encodes the provided side latin-1 (reconstructing the
    wire bytes) and the expected side UTF-8 (as a shell wrote it). This is
    what makes that pairing a claim rather than a guess: a Cyrillic token,
    sent as the UTF-8 bytes a client puts on the wire, must match.

    latin-1 decoding of those bytes is what the ASGI server does, so this
    reproduces it exactly."""
    from app.main import _secret_equals

    on_the_wire = (b"Bearer " + CYRILLIC).decode("latin-1")

    assert _secret_equals(on_the_wire, "Bearer тест")
    assert not _secret_equals(on_the_wire, "Bearer тесm")


def test_the_sandbox_runner_refuses_the_same_way(monkeypatch):
    """app/runner/auth.py mirrors this comparison rather than importing it, so
    it can drift. It has its own test for that reason.

    Called directly against a Request built from a scope: the runner is a
    separate app, and standing one up here would test the wiring instead of
    the comparison."""
    from fastapi import HTTPException
    from starlette.requests import Request

    from app.runner import auth as runner_auth

    monkeypatch.setattr(runner_auth, "SANDBOX_RUNNER_TOKEN", "t")
    request = Request({
        "type": "http", "method": "POST", "path": "/run",
        "headers": [(b"authorization", b"Bearer " + CYRILLIC)],
    })

    with pytest.raises(HTTPException) as raised:
        runner_auth.require_sandbox_token(request)

    assert raised.value.status_code == 401

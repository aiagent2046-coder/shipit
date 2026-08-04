"""Every endpoint that parses a JSON body must refuse a broken one with 422.

`await request.json()` raises on a malformed body, and a bare call turned a
client's typo into a 500 -- which the global handler logs with a traceback and
pages the operator for. Eight of them, measured before the fix:

    500  /v1/paypal/orders          (malformed)
    500  /v1/paypal/subscriptions   (malformed)
    500  /v1/webhooks/paypal        (malformed)
    500  /v1/webhooks/telegram      (malformed)
    502  /v1/webhooks/paypal        (body `[]`, AttributeError deeper in)
    ...

A parameterized sweep rather than five near-identical tests: the failure this
guards against is a NEW endpoint parsing a body and forgetting the helper, and
a list at the top of a file is the thing someone extends.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app
from tests.conftest import enable_monitoring


client = TestClient(app, raise_server_exceptions=False)


# (path, extra headers). Auth headers are supplied where the endpoint checks
# them first -- the point is to reach the body parse, not to test auth.
BODY_PARSING_ENDPOINTS = [
    ("/v1/paypal/orders", {}),
    ("/v1/paypal/subscriptions", {}),
    ("/v1/webhooks/paypal", {}),
    ("/v1/webhooks/telegram", {"x-telegram-bot-api-secret-token": "s"}),
    ("/internal/service-flags/llm_paid_ops", {"authorization": "Bearer f"}),
]

# Bodies that are not a JSON object. The first two do not parse; the rest
# parse into something without .get(), which used to fail one line later.
BAD_BODIES = ["{not json", "", "[]", '"a string"', "42", "null"]


@pytest.fixture(autouse=True)
def _configured(monkeypatch):
    """Enough configuration that each endpoint gets past its 503 gates and
    reaches the body parse. Values are placeholders; nothing here talks to a
    real service, because the refusal happens before any of them are used."""
    for name, value in (
        ("PAYPAL_CLIENT_ID", "x"), ("PAYPAL_CLIENT_SECRET", "y"),
        ("PAYPAL_MONITOR_PLAN_ID", "P-1"), ("PAYPAL_WEBHOOK_ID", "WH-1"),
        ("DATABASE_URL", "postgresql://u@/db"),
        ("TELEGRAM_BOT_TOKEN", "t"), ("TELEGRAM_WEBHOOK_SECRET", "s"),
        ("SERVICE_FLAGS_TOKEN", "f"),
    ):
        monkeypatch.setenv(name, value)
    # /v1/paypal/subscriptions refuses with 503 monitoring_not_for_sale before
    # it parses anything (#184). Enabled here rather than dropped from the
    # sweep: the invariant is about that endpoint's body handling being right,
    # and keeping it under test means the guard is already proven whenever
    # monitoring goes back on sale.
    enable_monitoring(monkeypatch)


@pytest.mark.parametrize("path,headers", BODY_PARSING_ENDPOINTS)
@pytest.mark.parametrize("body", BAD_BODIES)
def test_a_body_that_is_not_a_json_object_is_refused(path, headers, body):
    resp = client.post(
        path, content=body,
        headers={"content-type": "application/json", **headers},
    )

    assert resp.status_code == 422, (
        f"{path} answered {resp.status_code} for {body!r}; a 5xx here is an "
        "operator alert for someone else's typo"
    )


@pytest.mark.parametrize("path,headers", BODY_PARSING_ENDPOINTS)
def test_the_refusal_says_what_is_wrong(path, headers):
    """A 422 with no reason is only marginally better than a 500 -- the caller
    still cannot tell a broken body from a rejected value."""
    resp = client.post(
        path, content="{not json",
        headers={"content-type": "application/json", **headers},
    )

    detail = resp.json()["detail"]
    assert detail["reason"] == "invalid_json"
    assert "JSON object" in detail["detail"]


def test_a_valid_object_still_gets_past_the_guard():
    """The boundary. A guard that refused everything would be worse than the
    bug: this body is well-formed, so it must fail LATER, on its contents."""
    resp = client.post(
        "/v1/paypal/orders", json={"product": "nonsense"},
        headers={"content-type": "application/json"},
    )

    assert resp.status_code != 422 or \
        resp.json()["detail"].get("reason") != "invalid_json"

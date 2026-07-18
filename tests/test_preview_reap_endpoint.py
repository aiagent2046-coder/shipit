"""Tests for POST /internal/preview/reap \u2014 the endpoint shipit-reap.timer
on the production VPS calls hourly."""

from fastapi.testclient import TestClient

from app.main import app, get_preview_registry

client = TestClient(app)


class FakeRegistry:
    def __init__(self):
        self.reap_calls = 0

    def reap_expired(self, *args, **kwargs):
        self.reap_calls += 1
        return 3

    def active_count(self):
        return 1


def test_503_when_token_not_configured(monkeypatch):
    monkeypatch.delenv("PREVIEW_REAP_TOKEN", raising=False)
    resp = client.post("/internal/preview/reap")
    assert resp.status_code == 503
    assert resp.json()["detail"]["reason"] == "reap_not_configured"


def test_401_when_no_auth_header(monkeypatch):
    monkeypatch.setenv("PREVIEW_REAP_TOKEN", "secret123")
    resp = client.post("/internal/preview/reap")
    assert resp.status_code == 401


def test_401_when_wrong_token(monkeypatch):
    monkeypatch.setenv("PREVIEW_REAP_TOKEN", "secret123")
    resp = client.post(
        "/internal/preview/reap",
        headers={"Authorization": "Bearer wrong"},
    )
    assert resp.status_code == 401


def test_200_and_reaps_with_correct_token(monkeypatch):
    monkeypatch.setenv("PREVIEW_REAP_TOKEN", "secret123")
    fake = FakeRegistry()
    app.dependency_overrides[get_preview_registry] = lambda: fake
    try:
        resp = client.post(
            "/internal/preview/reap",
            headers={"Authorization": "Bearer secret123"},
        )
    finally:
        app.dependency_overrides.pop(get_preview_registry, None)

    assert resp.status_code == 200
    body = resp.json()
    assert body["reaped"] == 3
    assert body["active"] == 1
    # Docker isn't available in this test sandbox, so the Docker-truth
    # reconciler short-circuits rather than shelling out.
    assert body["reconciled"] == {"docker": False, "checked": 0, "removed": []}
    assert fake.reap_calls == 1

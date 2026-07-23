"""Tests for POST /internal/preview/reap \u2014 the endpoint shipit-reap.timer
on the production VPS calls hourly."""

from fastapi.testclient import TestClient

from app.main import app, get_preview_reconciler, get_preview_registry

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
    # Inject a fake reconciler so the outcome is deterministic regardless of
    # whether a `docker` binary exists in the runtime — the real
    # reconcile_previews shells out to `docker ps` when Docker is present.
    fake_reconciled = {
        "docker": True,
        "checked": 2,
        "removed": [{"container": "abc", "name": "shipit-preview-abc"}],
    }
    app.dependency_overrides[get_preview_registry] = lambda: fake
    app.dependency_overrides[get_preview_reconciler] = lambda: lambda: fake_reconciled
    try:
        resp = client.post(
            "/internal/preview/reap",
            headers={"Authorization": "Bearer secret123"},
        )
    finally:
        app.dependency_overrides.pop(get_preview_registry, None)
        app.dependency_overrides.pop(get_preview_reconciler, None)

    assert resp.status_code == 200
    body = resp.json()
    assert body["reaped"] == 3
    assert body["active"] == 1
    # The endpoint forwards the reconciler's result verbatim.
    assert body["reconciled"] == fake_reconciled
    assert fake.reap_calls == 1

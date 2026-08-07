"""Tests for the Phase 3 observability surface wired into app/main.py:

  * GET /health — public, leak-free readiness (db + Fix Pack backlog age),
    always 200;
  * the unhandled-5xx exception handler — logs a request id, fires exactly
    one operator alert, and returns 500 with that id; intentional
    HTTPExceptions (422/404) fire none;
  * a Fix Pack job landing on 'failed' fires one alert; 'delivered' fires
    none.

No real Telegram: notify_operator is replaced with an async recorder so the
tests assert *whether/what* we alert without any network.
"""

from __future__ import annotations

import io
import zipfile

from fastapi import HTTPException
import pytest
from fastapi.testclient import TestClient

import app.main as main_mod
from app import alerts
from app.fixpack.semantic_check import minimal_check as local_minimal_check
from app.deploypack.delivery import DeliveryError, PullRequestResult
from app.main import app, get_fixpack_repo



@pytest.fixture(autouse=True)
def _sandbox_runner_is_healthy(monkeypatch):
    """The processor refuses to claim while the sandbox runner is unhealthy, and
    in tests there is no runner at all. Default it to healthy so these tests keep
    exercising the delivery path; the gate itself is covered by its own tests,
    which override this."""
    monkeypatch.setattr(main_mod.sandbox_client, "runner_healthy", lambda: True)
    # Same reason for the check itself: with no runner, sandbox_client would
    # report "unavailable" and the processor would (correctly) defer every job.
    # The local implementation needs no docker for the plans these tests use.
    monkeypatch.setattr(main_mod.sandbox_client, "minimal_check",
                        local_minimal_check)


AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


class _AlertRecorder:
    """Async stand-in for notify_operator that records each alert text."""
    def __init__(self):
        self.texts: list[str] = []

    async def __call__(self, text, *, dedupe_key=None, **kwargs):
        self.texts.append(text)
        return True


# --- /health ---------------------------------------------------------------

class _FakeRepoStats:
    def __init__(self, stats):
        self._stats = stats

    async def backlog_stats(self):
        return self._stats


def _override_fixpack(repo):
    app.dependency_overrides[get_fixpack_repo] = lambda: repo


def _clear():
    app.dependency_overrides.pop(get_fixpack_repo, None)


def test_health_db_up_reports_backlog():
    client = TestClient(app)
    _override_fixpack(_FakeRepoStats({"backlog": 2, "oldest_paid_seconds": 43.0}))
    try:
        resp = client.get("/health")
    finally:
        _clear()
    assert resp.status_code == 200
    assert resp.json() == {
        "db": True, "fixpack_backlog": 2, "oldest_paid_seconds": 43.0,
        # None, not False: App auth simply isn't configured in the test
        # environment, which is not the same as a rejected key.
        "github_app": None,
    }


def test_health_db_unconfigured_is_200_with_db_false():
    client = TestClient(app)
    # backlog_stats returns None when DATABASE_URL isn't set / pool unbuildable.
    _override_fixpack(_FakeRepoStats(None))
    try:
        resp = client.get("/health")
    finally:
        _clear()
    assert resp.status_code == 200          # live process reporting degraded
    assert resp.json() == {
        "db": False, "fixpack_backlog": None, "oldest_paid_seconds": None,
        "github_app": None,
    }


def test_health_empty_backlog_has_null_age():
    client = TestClient(app)
    _override_fixpack(_FakeRepoStats({"backlog": 0, "oldest_paid_seconds": None}))
    try:
        resp = client.get("/health")
    finally:
        _clear()
    assert resp.json() == {
        "db": True, "fixpack_backlog": 0, "oldest_paid_seconds": None,
        "github_app": None,
    }


def test_healthz_stays_static():
    """The static liveness probe the README documents must be unchanged."""
    client = TestClient(app)
    assert client.get("/healthz").json() == {"status": "ok"}


# --- unhandled 5xx handler -------------------------------------------------

# Test-only routes exercising the exception handler on the real app.
async def _boom():
    raise RuntimeError("kaboom")


async def _teapot():
    raise HTTPException(status_code=422, detail={"reason": "bad_input"})


app.add_api_route("/__test__/boom", _boom, methods=["GET"])
app.add_api_route("/__test__/teapot", _teapot, methods=["GET"])


def test_unhandled_500_fires_one_alert_with_request_id(monkeypatch):
    recorder = _AlertRecorder()
    monkeypatch.setattr(alerts, "notify_operator", recorder)
    # raise_server_exceptions=False so we observe the handler's JSONResponse
    # rather than the exception being re-raised into the test.
    client = TestClient(app, raise_server_exceptions=False)

    resp = client.get("/__test__/boom")
    assert resp.status_code == 500
    body = resp.json()
    request_id = body["detail"]["request_id"]
    assert body["detail"]["reason"] == "internal_error"
    assert request_id                                   # non-empty id echoed
    assert len(recorder.texts) == 1                     # exactly one alert
    assert request_id in recorder.texts[0]              # alert carries the id


def test_intentional_httpexception_does_not_alert(monkeypatch):
    recorder = _AlertRecorder()
    monkeypatch.setattr(alerts, "notify_operator", recorder)
    client = TestClient(app)

    resp = client.get("/__test__/teapot")
    assert resp.status_code == 422                      # normal control flow
    assert recorder.texts == []                         # no alert


# --- Fix Pack failed => alert ----------------------------------------------

def _make_zip(entries: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, text in entries.items():
            zf.writestr(f"acme-app-deadbeef/{name}", text)
    return buf.getvalue()


class _FakeAuditRepo:
    def __init__(self, audits):
        self._audits = audits

    async def get(self, audit_id):
        return self._audits.get(audit_id)


class _FakeFixpackRepo:
    def __init__(self, jobs):
        self._paid = list(jobs)
        self.statuses = {}
        self.details = {}
        self.delivered = {}

    async def reap_stale_running(self, *, max_age_minutes, max_attempts):
        return {"requeued": 0, "failed": 0}

    async def claim_one_paid(self):
        if not self._paid:
            return None
        return {**self._paid.pop(0), "status": "running"}

    async def mark_fixpack_delivered(self, job_id, pr_url):
        self.delivered[job_id] = pr_url
        self.statuses[job_id] = "delivered"

    async def mark_status(self, job_id, status, detail=None):
        self.statuses[job_id] = status
        self.details[job_id] = detail


def _aws_audit():
    return {"a1": {
        "repo_url": "https://github.com/acme/app",
        "findings_json": [
            {"rule_id": "aws-access-key-id", "file": "config.py", "line": 1,
             "title": "AWS Access Key ID", "context": None},
        ],
    }}


def _run_process(monkeypatch, *, opener, jobs):
    from app.main import get_audit_repo, get_pr_opener, get_repo_fetcher

    monkeypatch.setenv("FIXPACK_PROCESS_TOKEN", "secret123")
    monkeypatch.setattr(main_mod, "app_credentials_from_env", lambda: None)

    # Stub the deep review as succeeding. It is not what these tests measure,
    # and a review that cannot run fires its own (correct) operator alert --
    # "the PR is fine, the review is owed" -- which would show up in the alert
    # counts asserted below and make "a delivered job is silent" untestable.
    # Its own behaviour is covered in tests/test_fixpack_process_endpoint.py.
    async def _review_ok(*args, **kwargs):
        return "### Your full review\n\nhttps://drydock.co/audit/r1?token=t1"

    monkeypatch.setattr(main_mod, "_deep_review_section", _review_ok)

    zip_bytes = _make_zip({"config.py": f'API_KEY = "{AWS_KEY}"\n'})
    repo = _FakeFixpackRepo(jobs)

    app.dependency_overrides[get_audit_repo] = lambda: _FakeAuditRepo(_aws_audit())
    app.dependency_overrides[get_fixpack_repo] = lambda: repo
    app.dependency_overrides[get_repo_fetcher] = lambda: (lambda o, r: zip_bytes)
    app.dependency_overrides[get_pr_opener] = lambda: opener
    client = TestClient(app)
    try:
        resp = client.post(
            "/internal/fixpack/process-paid",
            headers={"Authorization": "Bearer secret123"},
        )
    finally:
        for dep in (get_audit_repo, get_fixpack_repo, get_repo_fetcher, get_pr_opener):
            app.dependency_overrides.pop(dep, None)
    return resp, repo


def test_failed_job_fires_one_alert(monkeypatch):
    recorder = _AlertRecorder()
    monkeypatch.setattr(alerts, "notify_operator", recorder)

    def failing_opener(*a, **k):
        raise DeliveryError("open pull request failed: 422 base branch not found")

    resp, repo = _run_process(
        monkeypatch, opener=failing_opener,
        jobs=[{"id": "j1", "audit_id": "a1", "status": "paid"}],
    )
    assert resp.json()["failed"] == 1
    assert repo.statuses["j1"] == "failed"
    assert len(recorder.texts) == 1
    assert "j1" in recorder.texts[0]


def test_delivered_job_fires_no_alert(monkeypatch):
    recorder = _AlertRecorder()
    monkeypatch.setattr(alerts, "notify_operator", recorder)

    def ok_opener(*a, **k):
        return PullRequestResult(html_url="https://github.com/acme/app/pull/5",
                                 branch="b")

    resp, repo = _run_process(
        monkeypatch, opener=ok_opener,
        jobs=[{"id": "j1", "audit_id": "a1", "status": "paid"}],
    )
    assert resp.json()["delivered"] == 1
    assert repo.statuses["j1"] == "delivered"
    assert recorder.texts == []

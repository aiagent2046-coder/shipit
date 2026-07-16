"""Tests for POST /internal/fixpack/process-paid — the scheduled
processor that turns paid Fix Pack jobs into fix PRs.

All GitHub network calls are mocked: the PR opener is a fake injected via
the get_pr_opener dependency override (same pattern as the Deploy Pack
tests), and the repo fetcher / audit+fixpack repos are fakes too, so the
suite never touches the network or a database.
"""

import io
import zipfile

from fastapi.testclient import TestClient

import app.main as main_mod
from app.deploypack.delivery import DeliveryError, PullRequestResult
from app.main import (
    app,
    get_audit_repo,
    get_fixpack_repo,
    get_pr_opener,
    get_repo_fetcher,
)

client = TestClient(app)

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


def make_zip(entries: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, text in entries.items():
            zf.writestr(f"acme-app-deadbeef/{name}", text)
    return buf.getvalue()


class FakeAuditRepo:
    def __init__(self, audits: dict[str, dict]):
        self._audits = audits

    async def get(self, audit_id):
        return self._audits.get(audit_id)


class FakeFixpackRepo:
    def __init__(self, jobs: list[dict]):
        self._jobs = jobs
        self.delivered: dict[str, str] = {}
        self.statuses: dict[str, str] = {}

    async def list_paid(self):
        return list(self._jobs)

    async def mark_fixpack_delivered(self, job_id, pr_url):
        self.delivered[job_id] = pr_url

    async def mark_status(self, job_id, status):
        self.statuses[job_id] = status


def fake_fetcher_returning(zip_bytes: bytes):
    def _fetch(owner, repo):
        return zip_bytes
    return _fetch


def override(audit_repo=None, fixpack_repo=None, repo_fetcher=None, pr_opener=None):
    if audit_repo is not None:
        app.dependency_overrides[get_audit_repo] = lambda: audit_repo
    if fixpack_repo is not None:
        app.dependency_overrides[get_fixpack_repo] = lambda: fixpack_repo
    if repo_fetcher is not None:
        app.dependency_overrides[get_repo_fetcher] = lambda: repo_fetcher
    if pr_opener is not None:
        app.dependency_overrides[get_pr_opener] = lambda: pr_opener


def clear_overrides():
    for dep in (get_audit_repo, get_fixpack_repo, get_repo_fetcher, get_pr_opener):
        app.dependency_overrides.pop(dep, None)


def auth(token="secret123"):
    return {"Authorization": f"Bearer {token}"}


# --- auth / configuration guards ------------------------------------------

def test_503_when_token_not_configured(monkeypatch):
    monkeypatch.delenv("FIXPACK_PROCESS_TOKEN", raising=False)
    resp = client.post("/internal/fixpack/process-paid")
    assert resp.status_code == 503
    assert resp.json()["detail"]["reason"] == "fixpack_process_not_configured"


def test_401_when_no_auth_header(monkeypatch):
    monkeypatch.setenv("FIXPACK_PROCESS_TOKEN", "secret123")
    resp = client.post("/internal/fixpack/process-paid")
    assert resp.status_code == 401


def test_401_when_wrong_token(monkeypatch):
    monkeypatch.setenv("FIXPACK_PROCESS_TOKEN", "secret123")
    resp = client.post("/internal/fixpack/process-paid", headers=auth("wrong"))
    assert resp.status_code == 401


# --- the happy path + outcome accounting ----------------------------------

def test_paid_job_opens_pr_and_marks_delivered(monkeypatch):
    monkeypatch.setenv("FIXPACK_PROCESS_TOKEN", "secret123")
    monkeypatch.setattr(main_mod, "app_credentials_from_env", lambda: None)

    zip_bytes = make_zip({"config.py": f'API_KEY = "{AWS_KEY}"\n'})
    audits = {"a1": {
        "repo_url": "https://github.com/acme/app",
        "findings_json": [
            {"rule_id": "aws-access-key-id", "file": "config.py", "line": 1,
             "title": "AWS Access Key ID", "context": None},
        ],
    }}
    jobs = [{"id": "j1", "audit_id": "a1", "status": "paid"}]

    captured = {}

    def fake_opener(owner, repo, files, *, title, body, branch_prefix,
                    deletions=None, token=None):
        captured.update(owner=owner, repo=repo, files=files,
                        title=title, body=body, branch_prefix=branch_prefix)
        return PullRequestResult(
            html_url="https://github.com/acme/app/pull/5",
            branch="drydock/fix-pack-deadbeef",
        )

    fixpack_repo = FakeFixpackRepo(jobs)
    override(FakeAuditRepo(audits), fixpack_repo,
             fake_fetcher_returning(zip_bytes), fake_opener)
    try:
        resp = client.post("/internal/fixpack/process-paid", headers=auth())
    finally:
        clear_overrides()

    assert resp.status_code == 200
    assert resp.json() == {"processed": 1, "delivered": 1, "skipped": 0, "failed": 0}
    assert fixpack_repo.delivered["j1"] == "https://github.com/acme/app/pull/5"

    # The safety invariant end-to-end: the real value never reaches the PR.
    assert AWS_KEY not in captured["title"]
    assert AWS_KEY not in captured["body"]
    for text in captured["files"].values():
        assert AWS_KEY not in text
    assert captured["branch_prefix"] == "drydock/fix-pack"


def test_zero_eligible_findings_does_not_open_pr(monkeypatch):
    monkeypatch.setenv("FIXPACK_PROCESS_TOKEN", "secret123")
    monkeypatch.setattr(main_mod, "app_credentials_from_env", lambda: None)

    zip_bytes = make_zip({"config.py": f'API_KEY = "{AWS_KEY}"\n'})
    audits = {"a1": {
        "repo_url": "https://github.com/acme/app",
        # only ineligible findings
        "findings_json": [
            {"rule_id": "supabase-anon-key", "file": "config.py", "line": 1,
             "title": "anon", "context": None},
        ],
    }}
    jobs = [{"id": "j1", "audit_id": "a1", "status": "paid"}]

    called = {"n": 0}

    def fake_opener(*a, **k):
        called["n"] += 1
        return PullRequestResult(html_url="x", branch="y")

    fixpack_repo = FakeFixpackRepo(jobs)
    override(FakeAuditRepo(audits), fixpack_repo,
             fake_fetcher_returning(zip_bytes), fake_opener)
    try:
        resp = client.post("/internal/fixpack/process-paid", headers=auth())
    finally:
        clear_overrides()

    assert resp.json() == {"processed": 1, "delivered": 0, "skipped": 1, "failed": 0}
    assert called["n"] == 0  # never opened a PR
    assert fixpack_repo.statuses["j1"] == "no_fix_needed"


def test_delivery_error_marks_job_failed(monkeypatch):
    monkeypatch.setenv("FIXPACK_PROCESS_TOKEN", "secret123")
    monkeypatch.setattr(main_mod, "app_credentials_from_env", lambda: None)

    zip_bytes = make_zip({"config.py": f'API_KEY = "{AWS_KEY}"\n'})
    audits = {"a1": {
        "repo_url": "https://github.com/acme/app",
        "findings_json": [
            {"rule_id": "aws-access-key-id", "file": "config.py", "line": 1,
             "title": "AWS Access Key ID", "context": None},
        ],
    }}
    jobs = [{"id": "j1", "audit_id": "a1", "status": "paid"}]

    def failing_opener(*a, **k):
        raise DeliveryError("create branch failed")

    fixpack_repo = FakeFixpackRepo(jobs)
    override(FakeAuditRepo(audits), fixpack_repo,
             fake_fetcher_returning(zip_bytes), failing_opener)
    try:
        resp = client.post("/internal/fixpack/process-paid", headers=auth())
    finally:
        clear_overrides()

    assert resp.json() == {"processed": 1, "delivered": 0, "skipped": 0, "failed": 1}
    assert fixpack_repo.statuses["j1"] == "failed"


def test_missing_audit_marks_job_failed(monkeypatch):
    monkeypatch.setenv("FIXPACK_PROCESS_TOKEN", "secret123")
    monkeypatch.setattr(main_mod, "app_credentials_from_env", lambda: None)

    jobs = [{"id": "j1", "audit_id": "gone", "status": "paid"}]
    fixpack_repo = FakeFixpackRepo(jobs)
    override(FakeAuditRepo({}), fixpack_repo,
             fake_fetcher_returning(b""), lambda *a, **k: None)
    try:
        resp = client.post("/internal/fixpack/process-paid", headers=auth())
    finally:
        clear_overrides()

    assert resp.json() == {"processed": 1, "delivered": 0, "skipped": 0, "failed": 1}
    assert fixpack_repo.statuses["j1"] == "failed"


def test_no_paid_jobs_returns_zero_summary(monkeypatch):
    monkeypatch.setenv("FIXPACK_PROCESS_TOKEN", "secret123")
    fixpack_repo = FakeFixpackRepo([])
    override(FakeAuditRepo({}), fixpack_repo,
             fake_fetcher_returning(b""), lambda *a, **k: None)
    try:
        resp = client.post("/internal/fixpack/process-paid", headers=auth())
    finally:
        clear_overrides()

    assert resp.json() == {"processed": 0, "delivered": 0, "skipped": 0, "failed": 0}

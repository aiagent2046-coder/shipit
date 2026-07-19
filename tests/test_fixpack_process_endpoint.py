"""Tests for POST /internal/fixpack/process-paid — the scheduled
processor that turns paid Fix Pack jobs into fix PRs.

All GitHub network calls are mocked: the PR opener is a fake injected via
the get_pr_opener dependency override (same pattern as the Deploy Pack
tests), and the repo fetcher / audit+fixpack repos are fakes too, so the
suite never touches the network or a database.
"""

import asyncio
import io
import zipfile
from contextlib import asynccontextmanager

from fastapi.testclient import TestClient

import app.main as main_mod
from app.deploypack.delivery import DeliveryError, PullRequestResult
from app.deploypack.github_app import GitHubAppError
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
    """In-memory stand-in modelling the durable-lease processing model: a
    backlog of 'paid' jobs claimed one at a time into 'running', plus a
    stale-lease reaper. `reap` fixes what reap_stale_running reports for the
    run (default: nothing stale)."""

    def __init__(self, jobs: list[dict], reap: dict[str, int] | None = None):
        self._paid = list(jobs)
        self.delivered: dict[str, str] = {}
        self.statuses: dict[str, str] = {}
        self.details: dict[str, str | None] = {}
        self.claimed: list[str] = []
        self._reap = reap or {"requeued": 0, "failed": 0}

    async def reap_stale_running(self, *, max_age_minutes, max_attempts):
        return self._reap

    async def claim_one_paid(self):
        # Atomic-claim analogue: hand back each paid job exactly once, leased
        # into 'running'. A second claim of the same job returns None, which
        # is how the real FOR UPDATE SKIP LOCKED query stops two overlapping
        # runs from both processing one job.
        if not self._paid:
            return None
        job = self._paid.pop(0)
        self.claimed.append(job["id"])
        return {**job, "status": "running"}

    async def mark_fixpack_delivered(self, job_id, pr_url):
        self.delivered[job_id] = pr_url
        self.statuses[job_id] = "delivered"

    async def mark_status(self, job_id, status, detail=None):
        self.statuses[job_id] = status
        self.details[job_id] = detail


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


# --- semantic-check regression gate ---------------------------------------

def test_semantic_regression_blocks_pr_and_marks_job(monkeypatch):
    """When the semantic check reports a regression, the PR must be withheld
    and the job parked as 'blocked' with the reason in detail — never
    auto-delivered."""
    monkeypatch.setenv("FIXPACK_PROCESS_TOKEN", "secret123")
    monkeypatch.setattr(main_mod, "app_credentials_from_env", lambda: None)

    from app.fixpack.semantic_check import RunResult, SemanticCheckResult

    def fake_check(zip_bytes, plan):
        return SemanticCheckResult(
            ran=True, ecosystem="python",
            original=RunResult(5, 0, False, None),
            patched=RunResult(3, 2, False, None),
            regression=True,
            detail="patch introduced 2 new test failure(s)",
            pr_note=None,
        )
    monkeypatch.setattr(main_mod, "run_semantic_check", fake_check)

    zip_bytes = make_zip({"config.py": f'API_KEY = "{AWS_KEY}"\n'})
    audits = {"a1": {
        "repo_url": "https://github.com/acme/app",
        "findings_json": [
            {"rule_id": "aws-access-key-id", "file": "config.py", "line": 1,
             "title": "AWS Access Key ID", "context": None},
        ],
    }}
    jobs = [{"id": "j1", "audit_id": "a1", "status": "paid"}]

    opened = {"n": 0}

    def fake_opener(*a, **k):
        opened["n"] += 1
        return PullRequestResult(html_url="x", branch="y")

    fixpack_repo = FakeFixpackRepo(jobs)
    override(FakeAuditRepo(audits), fixpack_repo,
             fake_fetcher_returning(zip_bytes), fake_opener)
    try:
        resp = client.post("/internal/fixpack/process-paid", headers=auth())
    finally:
        clear_overrides()

    assert resp.json() == {"processed": 1, "delivered": 0, "skipped": 0,
                           "blocked": 1, "failed": 0, "requeued": 0}
    assert opened["n"] == 0                       # PR withheld
    assert fixpack_repo.statuses["j1"] == "blocked"
    assert "2 new test failure" in fixpack_repo.details["j1"]


def test_semantic_note_is_appended_to_pr_body(monkeypatch):
    """No client suite -> not a regression, but a soft recommendation note is
    appended to the PR body."""
    monkeypatch.setenv("FIXPACK_PROCESS_TOKEN", "secret123")
    monkeypatch.setattr(main_mod, "app_credentials_from_env", lambda: None)

    from app.fixpack.semantic_check import SemanticCheckResult

    def fake_check(zip_bytes, plan):
        return SemanticCheckResult(
            ran=False, ecosystem=None, original=None, patched=None,
            regression=False, detail="no client test suite detected",
            pr_note="> **Note:** add tests.",
        )
    monkeypatch.setattr(main_mod, "run_semantic_check", fake_check)

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
                    deletions=None, token=None, job_id=None):
        captured["body"] = body
        return PullRequestResult(html_url="https://github.com/acme/app/pull/9",
                                 branch="drydock/fix-pack-x")

    fixpack_repo = FakeFixpackRepo(jobs)
    override(FakeAuditRepo(audits), fixpack_repo,
             fake_fetcher_returning(zip_bytes), fake_opener)
    try:
        resp = client.post("/internal/fixpack/process-paid", headers=auth())
    finally:
        clear_overrides()

    assert resp.json()["delivered"] == 1
    assert "> **Note:** add tests." in captured["body"]


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
                    deletions=None, token=None, job_id=None):
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
    assert resp.json() == {"processed": 1, "delivered": 1, "skipped": 0,
                           "blocked": 0, "failed": 0, "requeued": 0}
    assert fixpack_repo.delivered["j1"] == "https://github.com/acme/app/pull/5"
    assert fixpack_repo.claimed == ["j1"]  # leased 'paid' -> 'running' once

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

    assert resp.json() == {"processed": 1, "delivered": 0, "skipped": 1,
                           "blocked": 0, "failed": 0, "requeued": 0}
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

    assert resp.json() == {"processed": 1, "delivered": 0, "skipped": 0,
                           "blocked": 0, "failed": 1, "requeued": 0}
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

    assert resp.json() == {"processed": 1, "delivered": 0, "skipped": 0,
                           "blocked": 0, "failed": 1, "requeued": 0}
    assert fixpack_repo.statuses["j1"] == "failed"


# --- observability: a failed job must never be silent ---------------------

def test_delivery_error_records_detail_and_logs(monkeypatch, caplog):
    """Regression for the silent-failure incident: when delivery raises, the
    job's `detail` must be populated and a full traceback logged — not a
    'failed' row with null detail and nothing in the logs."""
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
        raise DeliveryError("open pull request failed: 422 base branch main not found")

    fixpack_repo = FakeFixpackRepo(jobs)
    override(FakeAuditRepo(audits), fixpack_repo,
             fake_fetcher_returning(zip_bytes), failing_opener)
    try:
        with caplog.at_level("ERROR"):
            resp = client.post("/internal/fixpack/process-paid", headers=auth())
    finally:
        clear_overrides()

    assert resp.json()["failed"] == 1
    assert fixpack_repo.statuses["j1"] == "failed"

    detail = fixpack_repo.details["j1"]
    assert detail is not None and detail != ""
    assert "DeliveryError" in detail
    assert "base branch main not found" in detail

    # A full traceback reached the logs (logger.exception attaches exc_info).
    assert any(
        rec.exc_info is not None and "j1" in rec.getMessage()
        for rec in caplog.records
    )


def test_github_app_token_error_marks_failed_with_detail(monkeypatch, caplog):
    """The App-not-installed / token-exchange failure path (a prime suspect
    for the production incident) must also record a detail and log, instead
    of failing silently."""
    monkeypatch.setenv("FIXPACK_PROCESS_TOKEN", "secret123")
    # App IS configured, so _resolve_pr_token tries the installation-token
    # exchange — which raises for a repo the App isn't installed on.
    monkeypatch.setattr(main_mod, "app_credentials_from_env",
                        lambda: ("Iv23appid", "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----"))

    def raising_token(owner, repo, *, app_id, private_key):
        raise GitHubAppError(
            f"GitHub App is not installed on {owner}/{repo} — "
            "the repo owner needs to install it first"
        )

    monkeypatch.setattr(main_mod, "installation_token_for_repo", raising_token)

    zip_bytes = make_zip({"config.py": f'API_KEY = "{AWS_KEY}"\n'})
    audits = {"a1": {
        "repo_url": "https://github.com/donjonson-hash/drydock-fixpack-e2e-test",
        "findings_json": [
            {"rule_id": "aws-access-key-id", "file": "config.py", "line": 1,
             "title": "AWS Access Key ID", "context": None},
        ],
    }}
    jobs = [{"id": "j1", "audit_id": "a1", "status": "paid"}]

    fixpack_repo = FakeFixpackRepo(jobs)
    override(FakeAuditRepo(audits), fixpack_repo,
             fake_fetcher_returning(zip_bytes),
             lambda *a, **k: PullRequestResult(html_url="x", branch="y"))
    try:
        with caplog.at_level("ERROR"):
            resp = client.post("/internal/fixpack/process-paid", headers=auth())
    finally:
        clear_overrides()

    assert resp.json()["failed"] == 1
    assert fixpack_repo.statuses["j1"] == "failed"
    detail = fixpack_repo.details["j1"]
    assert detail is not None and "GitHubAppError" in detail
    assert "not installed" in detail


def test_missing_audit_records_detail(monkeypatch):
    monkeypatch.setenv("FIXPACK_PROCESS_TOKEN", "secret123")
    jobs = [{"id": "j1", "audit_id": "gone", "status": "paid"}]
    fixpack_repo = FakeFixpackRepo(jobs)
    override(FakeAuditRepo({}), fixpack_repo,
             fake_fetcher_returning(b""), lambda *a, **k: None)
    try:
        resp = client.post("/internal/fixpack/process-paid", headers=auth())
    finally:
        clear_overrides()

    assert resp.json()["failed"] == 1
    assert fixpack_repo.details["j1"]  # non-empty reason recorded


def test_committed_env_with_secret_is_untracked_not_committed(monkeypatch):
    """Regression: a committed `.env` that ALSO holds a hardcoded secret —
    the exact planted e2e scenario — must be UNTRACKED (deletion), never
    emitted as a scrubbed file. Otherwise the PR would carry two tree
    entries for `.env` (a blob and a deletion), a self-contradictory
    changeset."""
    monkeypatch.setenv("FIXPACK_PROCESS_TOKEN", "secret123")
    monkeypatch.setattr(main_mod, "app_credentials_from_env", lambda: None)

    stripe_key = "sk_live_" + "a" * 30
    zip_bytes = make_zip({
        "app/api/checkout/route.ts": f'const key = "{stripe_key}";\n',
        ".env": f"STRIPE_SECRET_KEY={stripe_key}\n",
        # no .gitignore
    })
    audits = {"a1": {
        "repo_url": "https://github.com/donjonson-hash/drydock-fixpack-e2e-test",
        # Persisted paths carry the zipball wrapper (see make_zip).
        "findings_json": [
            {"rule_id": "stripe-live-key",
             "file": "acme-app-deadbeef/app/api/checkout/route.ts",
             "line": 1, "title": "Stripe live secret key", "context": None},
            {"rule_id": "stripe-live-key", "file": "acme-app-deadbeef/.env",
             "line": 1, "title": "Stripe live secret key", "context": None},
            {"rule_id": "env-file-committed", "file": "acme-app-deadbeef/.env",
             "line": 0, "title": "Environment file committed", "context": None},
            {"rule_id": "gitignore-missing-secrets", "file": "", "line": 0,
             "title": "No .gitignore coverage", "context": None},
        ],
    }}
    jobs = [{"id": "j1", "audit_id": "a1", "status": "paid"}]

    captured = {}

    def fake_opener(owner, repo, files, *, title, body, branch_prefix,
                    deletions=None, token=None, job_id=None):
        captured.update(files=files, deletions=deletions or [])
        return PullRequestResult(html_url="https://github.com/x/y/pull/1",
                                 branch="b")

    fixpack_repo = FakeFixpackRepo(jobs)
    override(FakeAuditRepo(audits), fixpack_repo,
             fake_fetcher_returning(zip_bytes), fake_opener)
    try:
        resp = client.post("/internal/fixpack/process-paid", headers=auth())
    finally:
        clear_overrides()

    assert resp.json()["delivered"] == 1
    # .env is untracked, and NOT also present as a committed file.
    assert ".env" in captured["deletions"]
    assert ".env" not in captured["files"]
    # The route.ts secret is still scrubbed and delivered.
    assert "app/api/checkout/route.ts" in captured["files"]
    # And the value never leaks anywhere.
    assert stripe_key not in captured["files"]["app/api/checkout/route.ts"]
    for text in captured["files"].values():
        assert stripe_key not in text


def test_no_paid_jobs_returns_zero_summary(monkeypatch):
    monkeypatch.setenv("FIXPACK_PROCESS_TOKEN", "secret123")
    fixpack_repo = FakeFixpackRepo([])
    override(FakeAuditRepo({}), fixpack_repo,
             fake_fetcher_returning(b""), lambda *a, **k: None)
    try:
        resp = client.post("/internal/fixpack/process-paid", headers=auth())
    finally:
        clear_overrides()

    assert resp.json() == {"processed": 0, "delivered": 0, "skipped": 0,
                           "blocked": 0, "failed": 0, "requeued": 0}


# --- durable lease / restart recovery -------------------------------------

class LeaseFixpackRepo:
    """Stateful lease model so reap + claim behave like the real Postgres
    primitives: jobs carry status/attempts, and `age_minutes` stands in for
    how long ago a 'running' lease was taken. A single processor run reaps
    stale leases, then claims each 'paid' job exactly once into 'running'."""

    def __init__(self, jobs: list[dict]):
        self.jobs = {j["id"]: dict(j) for j in jobs}
        self.order = [j["id"] for j in jobs]
        self.delivered: dict[str, str] = {}
        self.claims = 0

    async def reap_stale_running(self, *, max_age_minutes, max_attempts):
        requeued = failed = 0
        for j in self.jobs.values():
            if j["status"] == "running" and j.get("age_minutes", 0) >= max_age_minutes:
                if j["attempts"] < max_attempts:
                    j["status"], j["age_minutes"] = "paid", 0
                    requeued += 1
                else:
                    j["status"], j["detail"] = "failed", "stale lease reaped"
                    failed += 1
        return {"requeued": requeued, "failed": failed}

    async def claim_one_paid(self):
        for jid in self.order:
            j = self.jobs[jid]
            if j["status"] == "paid":
                j["status"], j["age_minutes"] = "running", 0
                j["attempts"] += 1
                self.claims += 1
                return dict(j)
        return None

    async def mark_fixpack_delivered(self, job_id, pr_url):
        self.jobs[job_id]["status"] = "delivered"
        self.delivered[job_id] = pr_url

    async def mark_status(self, job_id, status, detail=None):
        self.jobs[job_id]["status"] = status
        if detail is not None:
            self.jobs[job_id]["detail"] = detail


def _aws_audit():
    return {"a1": {
        "repo_url": "https://github.com/acme/app",
        "findings_json": [
            {"rule_id": "aws-access-key-id", "file": "config.py", "line": 1,
             "title": "AWS Access Key ID", "context": None},
        ],
    }}


def test_happy_path_paid_running_delivered(monkeypatch):
    """(a) The clean state transition: a 'paid' job is leased into 'running'
    (attempts 0 -> 1), processed, and lands on 'delivered'."""
    monkeypatch.setenv("FIXPACK_PROCESS_TOKEN", "secret123")
    monkeypatch.setattr(main_mod, "app_credentials_from_env", lambda: None)

    zip_bytes = make_zip({"config.py": f'API_KEY = "{AWS_KEY}"\n'})
    repo = LeaseFixpackRepo(
        [{"id": "j1", "audit_id": "a1", "status": "paid", "attempts": 0}]
    )
    opened = {"n": 0}

    def fake_opener(*a, **k):
        opened["n"] += 1
        return PullRequestResult(html_url="https://github.com/acme/app/pull/7",
                                 branch="b")

    override(FakeAuditRepo(_aws_audit()), repo,
             fake_fetcher_returning(zip_bytes), fake_opener)
    try:
        resp = client.post("/internal/fixpack/process-paid", headers=auth())
    finally:
        clear_overrides()

    assert resp.json() == {"processed": 1, "delivered": 1, "skipped": 0,
                           "blocked": 0, "failed": 0, "requeued": 0}
    assert opened["n"] == 1
    assert repo.jobs["j1"]["status"] == "delivered"
    assert repo.jobs["j1"]["attempts"] == 1


def test_stale_running_job_requeued_then_delivered_once(monkeypatch):
    """(b) Restart recovery without a duplicate PR: a job left 'running' by a
    crashed worker (old lease) is reaped back to 'paid', re-claimed, and
    delivered — and the PR opener fires exactly once, not once per run."""
    monkeypatch.setenv("FIXPACK_PROCESS_TOKEN", "secret123")
    monkeypatch.setattr(main_mod, "app_credentials_from_env", lambda: None)

    zip_bytes = make_zip({"config.py": f'API_KEY = "{AWS_KEY}"\n'})
    # attempts=1 (< MAX), lease taken 30m ago (> 15m stale threshold).
    repo = LeaseFixpackRepo([{
        "id": "j1", "audit_id": "a1", "status": "running",
        "attempts": 1, "age_minutes": 30,
    }])
    opened = {"n": 0}

    def fake_opener(*a, **k):
        opened["n"] += 1
        return PullRequestResult(html_url="https://github.com/acme/app/pull/8",
                                 branch="b")

    override(FakeAuditRepo(_aws_audit()), repo,
             fake_fetcher_returning(zip_bytes), fake_opener)
    try:
        resp = client.post("/internal/fixpack/process-paid", headers=auth())
    finally:
        clear_overrides()

    body = resp.json()
    assert body["requeued"] == 1        # stale lease recovered
    assert body["delivered"] == 1
    assert body["processed"] == 1
    assert opened["n"] == 1             # exactly ONE PR despite the crash
    assert repo.jobs["j1"]["status"] == "delivered"
    assert repo.jobs["j1"]["attempts"] == 2  # one retry after the crash


def test_poison_pill_fails_after_max_attempts(monkeypatch):
    """A job that has already exhausted its attempts and is found stale is
    failed (not re-queued forever) — bounded retries. No PR is opened."""
    monkeypatch.setenv("FIXPACK_PROCESS_TOKEN", "secret123")

    # attempts already at MAX (3), stale lease -> reap must fail it.
    repo = LeaseFixpackRepo([{
        "id": "j1", "audit_id": "a1", "status": "running",
        "attempts": 3, "age_minutes": 30,
    }])
    opened = {"n": 0}

    def fake_opener(*a, **k):
        opened["n"] += 1
        return PullRequestResult(html_url="x", branch="y")

    override(FakeAuditRepo(_aws_audit()), repo,
             fake_fetcher_returning(b""), fake_opener)
    try:
        resp = client.post("/internal/fixpack/process-paid", headers=auth())
    finally:
        clear_overrides()

    body = resp.json()
    assert body["failed"] == 1
    assert body["processed"] == 0       # nothing left to claim
    assert opened["n"] == 0             # never opened a PR
    assert repo.jobs["j1"]["status"] == "failed"


def test_claim_hands_back_each_job_once():
    """The atomic-claim contract that stops double-processing: once a 'paid'
    job is claimed it is 'running', so a second claim of the same backlog
    returns None. Two overlapping runs therefore split work, never overlap."""
    repo = FakeFixpackRepo([{"id": "j1", "audit_id": "a1", "status": "paid"}])
    first = asyncio.run(repo.claim_one_paid())
    second = asyncio.run(repo.claim_one_paid())
    assert first is not None and first["id"] == "j1"
    assert first["status"] == "running"
    assert second is None
    assert repo.claimed == ["j1"]


def test_lock_busy_returns_skipped_locked(monkeypatch):
    """When another run already holds the advisory lock, the processor does
    no work and reports skipped_locked rather than stampeding the backlog."""
    monkeypatch.setenv("FIXPACK_PROCESS_TOKEN", "secret123")

    @asynccontextmanager
    async def busy_lock():
        raise main_mod.ProcessorLockBusy()
        yield  # unreachable, keeps this a valid async context manager

    monkeypatch.setattr(main_mod, "fixpack_processor_lock", busy_lock)

    repo = FakeFixpackRepo([{"id": "j1", "audit_id": "a1", "status": "paid"}])
    override(FakeAuditRepo(_aws_audit()), repo,
             fake_fetcher_returning(b""), lambda *a, **k: None)
    try:
        resp = client.post("/internal/fixpack/process-paid", headers=auth())
    finally:
        clear_overrides()

    assert resp.json() == {"skipped_locked": True}
    assert repo.claimed == []           # nothing was claimed/processed

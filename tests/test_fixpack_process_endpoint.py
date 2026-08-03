"""Tests for POST /internal/fixpack/process-paid — the scheduled
processor that turns paid Fix Pack jobs into fix PRs.

All GitHub network calls are mocked: the PR opener is a fake injected via
the get_pr_opener dependency override (same pattern as the Deploy Pack
tests), and the repo fetcher / audit+fixpack repos are fakes too, so the
suite never touches the network or a database.
"""

import asyncio
import io
import logging
import zipfile
from contextlib import asynccontextmanager

import pytest
from fastapi.testclient import TestClient

import app.main as main_mod
from app.fixpack.semantic_check import minimal_check as local_minimal_check
from app.deploypack.delivery import DeliveryError, PullRequestResult
from app.deploypack.github_app import GitHubAppAuthError, GitHubAppError
from app.main import (
    app,
    get_audit_repo,
    get_fixpack_repo,
    get_pr_opener,
    get_repo_fetcher,
)

client = TestClient(app)


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
        self.released: list[str] = []
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

    async def release_to_paid(self, job_id, detail):
        # The real one refunds the attempt the claim charged and puts the row
        # back on 'paid'. Here that means the job becomes claimable again --
        # which is precisely the property the loop has to cope with.
        self.statuses[job_id] = "paid"
        self.details[job_id] = detail
        self.released.append(job_id)
        self._paid.append({"id": job_id, "audit_id": "a1", "status": "paid"})


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

    def fake_check(zip_bytes, plan, **kwargs):
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
                           "blocked": 1, "failed": 0, "requeued": 0, "deferred": 0}
    assert opened["n"] == 0                       # PR withheld
    assert fixpack_repo.statuses["j1"] == "blocked"
    assert "2 new test failure" in fixpack_repo.details["j1"]


def test_semantic_note_is_appended_to_pr_body(monkeypatch):
    """No client suite -> not a regression, but a soft recommendation note is
    appended to the PR body."""
    monkeypatch.setenv("FIXPACK_PROCESS_TOKEN", "secret123")
    monkeypatch.setattr(main_mod, "app_credentials_from_env", lambda: None)

    from app.fixpack.semantic_check import SemanticCheckResult

    def fake_check(zip_bytes, plan, **kwargs):
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
                           "blocked": 0, "failed": 0, "requeued": 0, "deferred": 0}
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
                           "blocked": 0, "failed": 0, "requeued": 0, "deferred": 0}
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
                           "blocked": 0, "failed": 1, "requeued": 0, "deferred": 0}
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
                           "blocked": 0, "failed": 1, "requeued": 0, "deferred": 0}
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
                           "blocked": 0, "failed": 0, "requeued": 0, "deferred": 0}


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
        requeued, failed = 0, []
        for j in self.jobs.values():
            if j["status"] == "running" and j.get("age_minutes", 0) >= max_age_minutes:
                if j["attempts"] < max_attempts:
                    j["status"], j["age_minutes"] = "paid", 0
                    requeued += 1
                else:
                    j["status"], j["detail"] = "failed", "stale lease reaped"
                    failed.append(j["id"])
        return {"requeued": requeued, "failed": len(failed),
                "failed_ids": failed}

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
                           "blocked": 0, "failed": 0, "requeued": 0, "deferred": 0}
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


# --- sandbox runner unavailable: defer, don't deliver and don't block -------

def _unavailable_result():
    from app.fixpack.semantic_check import RunResult
    return RunResult(0, 0, False, "sandbox runner unavailable: refused",
                     unavailable=True)


def _runner_down(monkeypatch):
    """Runner passes the pre-flight gate, then the check itself can't reach it —
    the mid-run outage the per-job defer path exists for."""
    monkeypatch.setattr(main_mod.sandbox_client, "runner_healthy", lambda: True)
    monkeypatch.setattr(main_mod.sandbox_client, "minimal_check",
                        lambda plan: _unavailable_result())
    monkeypatch.setattr(main_mod.sandbox_client, "run_suite",
                        lambda z, r: _unavailable_result())


def test_unverifiable_job_is_deferred_not_delivered(monkeypatch):
    monkeypatch.setenv("FIXPACK_PROCESS_TOKEN", "secret123")
    monkeypatch.setattr(main_mod, "app_credentials_from_env", lambda: None)
    _runner_down(monkeypatch)

    zip_bytes = make_zip({"config.py": f'API_KEY = "{AWS_KEY}"\n'})
    repo = LeaseFixpackRepo(
        [{"id": "j1", "audit_id": "a1", "status": "paid", "attempts": 0}]
    )
    opened = {"n": 0}

    def fake_opener(*a, **k):
        opened["n"] += 1
        return PullRequestResult(html_url="x", branch="y")

    override(FakeAuditRepo(_aws_audit()), repo,
             fake_fetcher_returning(zip_bytes), fake_opener)
    try:
        resp = client.post("/internal/fixpack/process-paid", headers=auth())
    finally:
        clear_overrides()

    body = resp.json()
    assert body["deferred"] == 1
    assert body["delivered"] == 0
    assert body["blocked"] == 0
    assert body["failed"] == 0
    # no unverified PR for a paying customer
    assert opened["n"] == 0
    # the lease is left alone so reap_stale_running re-queues it, bounded by
    # MAX_JOB_ATTEMPTS -- no second retry counter of our own
    assert repo.jobs["j1"]["status"] == "running"
    assert repo.jobs["j1"]["attempts"] == 1
    assert "could not verify" in repo.jobs["j1"]["detail"]


def test_deferred_job_records_no_fix_outcome_row(monkeypatch):
    # A deferred job is not terminal. Writing a row here is what poisoned the
    # Phase-B analytics with is_regression=True for runs that never happened.
    monkeypatch.setenv("FIXPACK_PROCESS_TOKEN", "secret123")
    monkeypatch.setattr(main_mod, "app_credentials_from_env", lambda: None)
    _runner_down(monkeypatch)

    recorded = []

    class RecordingOutcomeRepo:
        async def create(self, **fields):
            recorded.append(fields)
            return None

    zip_bytes = make_zip({"config.py": f'API_KEY = "{AWS_KEY}"\n'})
    repo = LeaseFixpackRepo(
        [{"id": "j1", "audit_id": "a1", "status": "paid", "attempts": 0}]
    )
    override(FakeAuditRepo(_aws_audit()), repo,
             fake_fetcher_returning(zip_bytes), lambda *a, **k: None)
    app.dependency_overrides[main_mod.get_fix_outcome_repo] = \
        lambda: RecordingOutcomeRepo()
    try:
        resp = client.post("/internal/fixpack/process-paid", headers=auth())
    finally:
        clear_overrides()
        app.dependency_overrides.pop(main_mod.get_fix_outcome_repo, None)

    assert resp.json()["deferred"] == 1
    assert recorded == []


def test_deferred_job_eventually_fails_and_alerts_after_max_attempts(monkeypatch):
    """Bounded by the EXISTING mechanism: a job deferred until its lease is
    stale and its attempts are spent lands on 'failed', and the operator hears
    about it (the reaper writes that row itself, so the processor must alert)."""
    monkeypatch.setenv("FIXPACK_PROCESS_TOKEN", "secret123")
    monkeypatch.setattr(main_mod, "app_credentials_from_env", lambda: None)
    _runner_down(monkeypatch)

    alerts = []

    async def recorder(text, *, dedupe_key=None, **kwargs):
        alerts.append(text)
        return True

    monkeypatch.setattr(main_mod, "notify_operator", recorder)

    zip_bytes = make_zip({"config.py": f'API_KEY = "{AWS_KEY}"\n'})
    repo = LeaseFixpackRepo([{
        "id": "j1", "audit_id": "a1", "status": "paid", "attempts": 0,
    }])
    override(FakeAuditRepo(_aws_audit()), repo,
             fake_fetcher_returning(zip_bytes), lambda *a, **k: None)
    try:
        # Each pass: claim (attempts += 1) -> defer, leaving 'running'. Age the
        # lease past the stale threshold so the next pass reaps it.
        for _ in range(main_mod.MAX_JOB_ATTEMPTS + 1):
            repo.jobs["j1"]["age_minutes"] = main_mod.STALE_LEASE_MINUTES + 1
            client.post("/internal/fixpack/process-paid", headers=auth())
    finally:
        clear_overrides()

    assert repo.jobs["j1"]["status"] == "failed"
    assert repo.jobs["j1"]["attempts"] == main_mod.MAX_JOB_ATTEMPTS
    assert len(alerts) == 1
    assert "j1" in alerts[0]
    assert "stale lease" in alerts[0]


# --- health gate before claiming -------------------------------------------

def test_unhealthy_runner_claims_nothing_and_spends_no_attempts(monkeypatch):
    monkeypatch.setenv("FIXPACK_PROCESS_TOKEN", "secret123")
    monkeypatch.setattr(main_mod.sandbox_client, "runner_healthy", lambda: False)

    repo = LeaseFixpackRepo(
        [{"id": "j1", "audit_id": "a1", "status": "paid", "attempts": 0}]
    )
    override(FakeAuditRepo(_aws_audit()), repo,
             fake_fetcher_returning(b""), lambda *a, **k: None)
    try:
        resp = client.post("/internal/fixpack/process-paid", headers=auth())
    finally:
        clear_overrides()

    body = resp.json()
    assert body["skipped_unhealthy_runner"] is True
    assert body["processed"] == 0
    assert repo.claims == 0
    # the whole point of the gate: an outage must not eat the paid backlog's
    # attempt budget, it must pause it
    assert repo.jobs["j1"]["status"] == "paid"
    assert repo.jobs["j1"]["attempts"] == 0


def test_unhealthy_runner_still_reaps_stale_leases(monkeypatch):
    # Skipping the claim must not skip recovery: a crashed worker's lease still
    # needs re-queueing, and that costs nothing while the runner is down.
    monkeypatch.setenv("FIXPACK_PROCESS_TOKEN", "secret123")
    monkeypatch.setattr(main_mod.sandbox_client, "runner_healthy", lambda: False)

    repo = LeaseFixpackRepo([{
        "id": "j1", "audit_id": "a1", "status": "running",
        "attempts": 1, "age_minutes": 30,
    }])
    override(FakeAuditRepo(_aws_audit()), repo,
             fake_fetcher_returning(b""), lambda *a, **k: None)
    try:
        resp = client.post("/internal/fixpack/process-paid", headers=auth())
    finally:
        clear_overrides()

    assert resp.json()["requeued"] == 1
    assert repo.jobs["j1"]["status"] == "paid"
    assert repo.claims == 0


def test_healthy_runner_claims_normally(monkeypatch):
    monkeypatch.setenv("FIXPACK_PROCESS_TOKEN", "secret123")
    monkeypatch.setattr(main_mod, "app_credentials_from_env", lambda: None)
    monkeypatch.setattr(main_mod.sandbox_client, "runner_healthy", lambda: True)

    zip_bytes = make_zip({"config.py": f'API_KEY = "{AWS_KEY}"\n'})
    repo = LeaseFixpackRepo(
        [{"id": "j1", "audit_id": "a1", "status": "paid", "attempts": 0}]
    )
    override(FakeAuditRepo(_aws_audit()), repo,
             fake_fetcher_returning(zip_bytes),
             lambda *a, **k: PullRequestResult(html_url="u", branch="b"))
    try:
        resp = client.post("/internal/fixpack/process-paid", headers=auth())
    finally:
        clear_overrides()

    body = resp.json()
    assert "skipped_unhealthy_runner" not in body
    assert body["delivered"] == 1


# --- _resolve_pr_token log level ------------------------------------------
#
# The presence/length diagnostic below was left at warning after the "no
# GitHub token configured" incident closed, so it fired on every successful PR
# delivery. Only the contradiction it was written to catch is anomalous.

# Opaque stand-in for a private key: these tests only care that the value is
# never echoed, so it needs no PEM shape (and carrying one would trip the CI
# secret scanner on a line that holds no secret).
FAKE_PEM = "not-a-real-key-only-a-placeholder"


def _resolve(owner="acme", repo="app"):
    return asyncio.run(main_mod._resolve_pr_token(owner, repo))


def test_pr_token_resolve_is_quiet_on_the_healthy_path(monkeypatch, caplog):
    """App configured and resolving: the normal path of every PR delivery."""
    monkeypatch.setattr(main_mod, "app_credentials_from_env",
                        lambda: ("Iv23appid", FAKE_PEM))
    monkeypatch.setattr(main_mod, "installation_token_for_repo",
                        lambda owner, repo, *, app_id, private_key: "ghs-token")

    with caplog.at_level(logging.DEBUG, logger="app.main"):
        assert _resolve() == "ghs-token"

    assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []
    # Still emitted, just at debug -- the diagnostic keeps its value.
    assert any("PR token resolve" in r.message for r in caplog.records)


def test_pr_token_resolve_is_quiet_when_no_app_is_configured(monkeypatch, caplog):
    """The documented GITHUB_PR_TOKEN fallback is a supported deployment, not
    a fault: nothing configured, nothing resolved, nothing to warn about."""
    monkeypatch.delenv("GITHUB_APP_ID", raising=False)
    monkeypatch.delenv("GITHUB_APP_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("GITHUB_APP_PRIVATE_KEY_B64", raising=False)
    monkeypatch.setattr(main_mod, "app_credentials_from_env", lambda: None)

    with caplog.at_level(logging.DEBUG, logger="app.main"):
        assert _resolve() is None

    assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []


def test_pr_token_resolve_warns_when_creds_are_present_but_unresolved(
        monkeypatch, caplog):
    """The incident signature, and the only reason this log line exists: the
    env carries App credentials yet resolution still yields nothing."""
    monkeypatch.setenv("GITHUB_APP_ID", "4278482")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", FAKE_PEM)
    monkeypatch.setattr(main_mod, "app_credentials_from_env", lambda: None)

    with caplog.at_level(logging.DEBUG, logger="app.main"):
        assert _resolve() is None

    warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert len(warnings) == 1
    assert "app_credentials_from_env=None" in warnings[0].getMessage()
    # Lengths, never the values.
    assert FAKE_PEM not in warnings[0].getMessage()


def test_pr_token_resolve_counts_the_base64_pem_variable(monkeypatch, caplog):
    """A deployment on the systemd-safe base64 path leaves
    GITHUB_APP_PRIVATE_KEY unset and is healthy; reporting it as MISSING sent
    an operator hunting for a key that was never supposed to be there."""
    monkeypatch.delenv("GITHUB_APP_PRIVATE_KEY", raising=False)
    monkeypatch.setenv("GITHUB_APP_ID", "4278482")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY_B64", "Zm9vYmFy")
    monkeypatch.setattr(main_mod, "app_credentials_from_env", lambda: None)

    with caplog.at_level(logging.DEBUG, logger="app.main"):
        _resolve()

    warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert len(warnings) == 1
    assert "GITHUB_APP_PRIVATE_KEY=MISSING" not in warnings[0].getMessage()


# --- GitHub rejects OUR credentials ---
#
# Every other failure in this processor is about the customer's repository.
# This one is about us: the key on this deployment no longer matches the App,
# so no Fix Pack anywhere can open a PR. Treating it like the others billed a
# customer for our outage -- the job went terminal 'failed', the payment was
# spent, and recovery meant editing the database by hand.


def _auth_rejected_setup(monkeypatch, jobs):
    monkeypatch.setenv("FIXPACK_PROCESS_TOKEN", "secret123")
    monkeypatch.setattr(
        main_mod, "app_credentials_from_env",
        # Any non-empty string: installation_token_for_repo is replaced
        # below, so nothing ever parses this. A PEM header here would only
        # trip the added-lines secret scanner in CI, for no benefit.
        lambda: ("Iv23appid", "placeholder-key-never-parsed"),
    )

    def rejecting_token(owner, repo, *, app_id, private_key):
        raise GitHubAppAuthError(
            'resolve installation failed: 401 {"message": "A JSON web token '
            'could not be decoded"}'
        )

    monkeypatch.setattr(main_mod, "installation_token_for_repo", rejecting_token)

    zip_bytes = make_zip({"config.py": f'API_KEY = "{AWS_KEY}"\n'})
    audits = {"a1": {
        "repo_url": "https://github.com/donjonson-hash/drydock-fixpack-e2e-test",
        "findings_json": [
            {"rule_id": "aws-access-key-id", "file": "config.py", "line": 1,
             "title": "AWS Access Key ID", "context": None},
        ],
    }}
    fixpack_repo = FakeFixpackRepo(jobs)
    override(FakeAuditRepo(audits), fixpack_repo,
             fake_fetcher_returning(zip_bytes),
             lambda *a, **k: PullRequestResult(html_url="x", branch="y"))
    return fixpack_repo


def test_rejected_credentials_requeue_the_job_instead_of_failing_it(monkeypatch):
    """The job is deliverable the moment an operator fixes the key, so it goes
    back on the queue rather than to a terminal state a customer paid for."""
    fixpack_repo = _auth_rejected_setup(
        monkeypatch, [{"id": "j1", "audit_id": "a1", "status": "paid"}])
    try:
        resp = client.post("/internal/fixpack/process-paid", headers=auth())
    finally:
        clear_overrides()

    body = resp.json()
    assert body["failed"] == 0
    assert body["delivered"] == 0
    assert body["skipped_github_app_auth"] is True
    assert fixpack_repo.released == ["j1"]
    assert fixpack_repo.statuses["j1"] == "paid"
    assert "credentials rejected" in fixpack_repo.details["j1"]


def test_rejected_credentials_write_no_fix_outcome_row(monkeypatch):
    """fix_outcomes is the table we intend to learn from. Our own outage is
    not the outcome of a fix and must not be recorded as one."""
    recorded = []

    class RecordingOutcomes:
        async def record(self, **kwargs):
            recorded.append(kwargs)
            return None

    fixpack_repo = _auth_rejected_setup(
        monkeypatch, [{"id": "j1", "audit_id": "a1", "status": "paid"}])
    app.dependency_overrides[main_mod.get_fix_outcome_repo] = \
        lambda: RecordingOutcomes()
    try:
        client.post("/internal/fixpack/process-paid", headers=auth())
    finally:
        clear_overrides()
        app.dependency_overrides.pop(main_mod.get_fix_outcome_repo, None)

    assert recorded == []
    assert fixpack_repo.released == ["j1"]


def test_rejected_credentials_stop_the_drain_instead_of_spinning(monkeypatch):
    """The released job is immediately re-claimable, unlike the sandbox
    'deferred' path which leaves it leased. Without the break, one broken key
    would spin the loop releasing and re-claiming the same rows forever."""
    fixpack_repo = _auth_rejected_setup(monkeypatch, [
        {"id": "j1", "audit_id": "a1", "status": "paid"},
        {"id": "j2", "audit_id": "a1", "status": "paid"},
        {"id": "j3", "audit_id": "a1", "status": "paid"},
    ])
    try:
        resp = client.post("/internal/fixpack/process-paid", headers=auth())
    finally:
        clear_overrides()

    # Exactly one job claimed, then the run stopped. The other two are
    # untouched, with their attempts unspent.
    assert fixpack_repo.claimed == ["j1"]
    assert resp.json()["processed"] == 1
    assert fixpack_repo.statuses.get("j2") is None


def test_an_uninstalled_app_still_fails_terminally(monkeypatch):
    """The boundary. 'Not installed on this repo' is the customer's problem
    and stays a real failure -- relaxing the auth case must not relax that,
    or a repo that will never work would be retried forever."""
    monkeypatch.setenv("FIXPACK_PROCESS_TOKEN", "secret123")
    monkeypatch.setattr(
        main_mod, "app_credentials_from_env",
        # Any non-empty string: installation_token_for_repo is replaced
        # below, so nothing ever parses this. A PEM header here would only
        # trip the added-lines secret scanner in CI, for no benefit.
        lambda: ("Iv23appid", "placeholder-key-never-parsed"),
    )

    def not_installed(owner, repo, *, app_id, private_key):
        raise GitHubAppError(f"GitHub App is not installed on {owner}/{repo}")

    monkeypatch.setattr(main_mod, "installation_token_for_repo", not_installed)

    zip_bytes = make_zip({"config.py": f'API_KEY = "{AWS_KEY}"\n'})
    audits = {"a1": {
        "repo_url": "https://github.com/donjonson-hash/drydock-fixpack-e2e-test",
        "findings_json": [
            {"rule_id": "aws-access-key-id", "file": "config.py", "line": 1,
             "title": "AWS Access Key ID", "context": None},
        ],
    }}
    fixpack_repo = FakeFixpackRepo([{"id": "j1", "audit_id": "a1", "status": "paid"}])
    override(FakeAuditRepo(audits), fixpack_repo,
             fake_fetcher_returning(zip_bytes),
             lambda *a, **k: PullRequestResult(html_url="x", branch="y"))
    try:
        resp = client.post("/internal/fixpack/process-paid", headers=auth())
    finally:
        clear_overrides()

    assert resp.json()["failed"] == 1
    assert fixpack_repo.statuses["j1"] == "failed"
    assert fixpack_repo.released == []

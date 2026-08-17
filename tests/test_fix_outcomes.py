"""Tests for the fix_outcomes knowledge base (Phase B, instrumentation only).

Two halves:
  1. The processor records one fix_outcomes row per terminal Fix Pack outcome
     (delivered / blocked / failed / no_fix_needed), and a recording failure
     never changes the job's real outcome (analytics is secondary to delivery).
  2. POST /v1/webhooks/github verifies the GitHub HMAC signature and backfills
     pr_merged for the matching PR.

All fakes are in-memory; no DB or network. The processor tests reuse the same
dependency-override pattern as tests/test_fixpack_process_endpoint.py.
"""

import hashlib
import hmac
import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient

import app.main as main_mod
from app.deploypack import github_app
from app.fixpack.semantic_check import minimal_check as local_minimal_check
from app.deploypack.delivery import PullRequestResult
from app.main import (
    app,
    get_audit_repo,
    get_fix_outcome_repo,
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
    """Backlog of 'paid' jobs claimed one at a time (see the fuller version in
    tests/test_fixpack_process_endpoint.py)."""

    def __init__(self, jobs: list[dict]):
        self._paid = list(jobs)
        self.delivered: dict[str, str] = {}
        self.statuses: dict[str, str] = {}
        self.details: dict[str, str | None] = {}
        self.proof_json: dict[str, dict] = {}

    async def set_proof_json(self, job_id, proof):
        # Without this the proof stage raises AttributeError, run_proof_stage
        # swallows it fail-open, and the suite passes with a dead proof stage.
        self.proof_json[job_id] = proof

    async def reap_stale_running(self, *, max_age_minutes, max_attempts):
        return {"requeued": 0, "failed": 0}

    async def claim_one_paid(self):
        if not self._paid:
            return None
        job = self._paid.pop(0)
        return {**job, "status": "running"}

    async def mark_fixpack_delivered(self, job_id, pr_url):
        self.delivered[job_id] = pr_url
        self.statuses[job_id] = "delivered"

    async def mark_status(self, job_id, status, detail=None):
        self.statuses[job_id] = status
        self.details[job_id] = detail


class FakeFixOutcomeRepo:
    def __init__(self, raise_on_record: bool = False):
        self.recorded: list[dict] = []
        self.merged_updates: list[tuple[str, bool]] = []
        self._raise = raise_on_record
        self._by_pr_url: dict[str, dict] = {}

    async def record(self, *, fixpack_job_id, audit_id, rule_ids, stack,
                     outcome, is_regression, pr_url):
        if self._raise:
            raise RuntimeError("simulated analytics failure")
        row = {
            "fixpack_job_id": fixpack_job_id, "audit_id": audit_id,
            "rule_ids": rule_ids, "stack": stack, "outcome": outcome,
            "is_regression": is_regression, "pr_url": pr_url,
            "pr_merged": None,
        }
        self.recorded.append(row)
        if pr_url:
            self._by_pr_url[pr_url] = row
        return row

    async def set_pr_merged_by_pr_url(self, pr_url, merged):
        self.merged_updates.append((pr_url, merged))
        row = self._by_pr_url.get(pr_url)
        if row is None:
            return 0
        row["pr_merged"] = merged
        return 1


def fake_fetcher_returning(zip_bytes: bytes):
    def _fetch(owner, repo):
        return zip_bytes
    return _fetch


def override(*, audit_repo=None, fixpack_repo=None, fix_outcome_repo=None,
             repo_fetcher=None, pr_opener=None):
    if audit_repo is not None:
        app.dependency_overrides[get_audit_repo] = lambda: audit_repo
    if fixpack_repo is not None:
        app.dependency_overrides[get_fixpack_repo] = lambda: fixpack_repo
    if fix_outcome_repo is not None:
        app.dependency_overrides[get_fix_outcome_repo] = lambda: fix_outcome_repo
    if repo_fetcher is not None:
        app.dependency_overrides[get_repo_fetcher] = lambda: repo_fetcher
    if pr_opener is not None:
        app.dependency_overrides[get_pr_opener] = lambda: pr_opener


def clear_overrides():
    for dep in (get_audit_repo, get_fixpack_repo, get_fix_outcome_repo,
                get_repo_fetcher, get_pr_opener):
        app.dependency_overrides.pop(dep, None)


def auth(token="secret123"):
    return {"Authorization": f"Bearer {token}"}


def _secret_finding():
    return {"rule_id": "aws-access-key-id", "file": "config.py", "line": 1,
            "title": "AWS Access Key ID", "context": None}


def _run_processor():
    return client.post("/internal/fixpack/process-paid", headers=auth())


# --- (a) outcome recording at each terminal state -------------------------

def test_records_delivered_outcome(monkeypatch):
    monkeypatch.setenv("FIXPACK_PROCESS_TOKEN", "secret123")
    monkeypatch.setattr(github_app, "app_credentials_from_env", lambda: None)

    from app.fixpack.semantic_check import SemanticCheckResult

    def fake_check(zip_bytes, plan, **kwargs):
        return SemanticCheckResult(
            ran=False, ecosystem=None, original=None, patched=None,
            regression=False, detail="no client test suite", pr_note=None,
        )
    monkeypatch.setattr(main_mod, "run_semantic_check", fake_check)

    zip_bytes = make_zip({"config.py": f'API_KEY = "{AWS_KEY}"\n'})
    audits = {"a1": {"repo_url": "https://github.com/acme/app",
                     "findings_json": [_secret_finding()]}}
    jobs = [{"id": "j1", "audit_id": "a1", "stack": "fastapi", "status": "paid"}]

    def fake_opener(owner, repo, files, *, title, body, branch_prefix,
                    deletions=None, token=None, job_id=None):
        return PullRequestResult(
            html_url="https://github.com/acme/app/pull/9", branch="b")

    outcomes = FakeFixOutcomeRepo()
    override(audit_repo=FakeAuditRepo(audits), fixpack_repo=FakeFixpackRepo(jobs),
             fix_outcome_repo=outcomes, repo_fetcher=fake_fetcher_returning(zip_bytes),
             pr_opener=fake_opener)
    try:
        resp = _run_processor()
    finally:
        clear_overrides()

    assert resp.json()["delivered"] == 1
    assert len(outcomes.recorded) == 1
    row = outcomes.recorded[0]
    assert row["outcome"] == "delivered"
    assert row["fixpack_job_id"] == "j1"
    assert row["audit_id"] == "a1"
    assert row["stack"] == "fastapi"
    assert row["is_regression"] is False
    assert row["pr_url"] == "https://github.com/acme/app/pull/9"
    assert "aws-access-key-id" in row["rule_ids"]


def test_records_blocked_outcome_with_regression_flag(monkeypatch):
    monkeypatch.setenv("FIXPACK_PROCESS_TOKEN", "secret123")
    monkeypatch.setattr(github_app, "app_credentials_from_env", lambda: None)

    from app.fixpack.semantic_check import RunResult, SemanticCheckResult

    def fake_check(zip_bytes, plan, **kwargs):
        return SemanticCheckResult(
            ran=True, ecosystem="python",
            original=RunResult(5, 0, False, None),
            patched=RunResult(3, 2, False, None),
            regression=True, detail="patch introduced 2 new failure(s)",
            pr_note=None,
        )
    monkeypatch.setattr(main_mod, "run_semantic_check", fake_check)

    zip_bytes = make_zip({"config.py": f'API_KEY = "{AWS_KEY}"\n'})
    audits = {"a1": {"repo_url": "https://github.com/acme/app",
                     "findings_json": [_secret_finding()]}}
    jobs = [{"id": "j1", "audit_id": "a1", "stack": "fastapi", "status": "paid"}]

    outcomes = FakeFixOutcomeRepo()
    override(audit_repo=FakeAuditRepo(audits), fixpack_repo=FakeFixpackRepo(jobs),
             fix_outcome_repo=outcomes, repo_fetcher=fake_fetcher_returning(zip_bytes),
             pr_opener=lambda *a, **k: PullRequestResult("x", "y"))
    try:
        resp = _run_processor()
    finally:
        clear_overrides()

    assert resp.json()["blocked"] == 1
    row = outcomes.recorded[0]
    assert row["outcome"] == "blocked"
    assert row["is_regression"] is True
    assert row["pr_url"] is None
    assert "aws-access-key-id" in row["rule_ids"]


def test_records_failed_outcome(monkeypatch):
    monkeypatch.setenv("FIXPACK_PROCESS_TOKEN", "secret123")
    monkeypatch.setattr(github_app, "app_credentials_from_env", lambda: None)

    # Audit has no repo_url -> early 'failed' branch, before any plan.
    audits = {"a1": {"repo_url": None, "findings_json": []}}
    jobs = [{"id": "j1", "audit_id": "a1", "stack": "nextjs", "status": "paid"}]

    outcomes = FakeFixOutcomeRepo()
    override(audit_repo=FakeAuditRepo(audits), fixpack_repo=FakeFixpackRepo(jobs),
             fix_outcome_repo=outcomes,
             repo_fetcher=fake_fetcher_returning(b""),
             pr_opener=lambda *a, **k: PullRequestResult("x", "y"))
    try:
        resp = _run_processor()
    finally:
        clear_overrides()

    assert resp.json()["failed"] == 1
    row = outcomes.recorded[0]
    assert row["outcome"] == "failed"
    assert row["rule_ids"] == []
    assert row["pr_url"] is None
    assert row["stack"] == "nextjs"


def test_records_no_fix_needed_outcome(monkeypatch):
    monkeypatch.setenv("FIXPACK_PROCESS_TOKEN", "secret123")
    monkeypatch.setattr(github_app, "app_credentials_from_env", lambda: None)

    # A repo with nothing to fix and an audit with no findings -> empty plan.
    zip_bytes = make_zip({"README.md": "# hi\n"})
    audits = {"a1": {"repo_url": "https://github.com/acme/app",
                     "findings_json": []}}
    jobs = [{"id": "j1", "audit_id": "a1", "stack": "vite-react", "status": "paid"}]

    outcomes = FakeFixOutcomeRepo()
    override(audit_repo=FakeAuditRepo(audits), fixpack_repo=FakeFixpackRepo(jobs),
             fix_outcome_repo=outcomes, repo_fetcher=fake_fetcher_returning(zip_bytes),
             pr_opener=lambda *a, **k: PullRequestResult("x", "y"))
    try:
        resp = _run_processor()
    finally:
        clear_overrides()

    assert resp.json()["skipped"] == 1
    row = outcomes.recorded[0]
    assert row["outcome"] == "no_fix_needed"
    assert row["rule_ids"] == []
    assert row["pr_url"] is None


def test_recording_failure_does_not_break_delivery(monkeypatch):
    """A fix_outcomes write that raises must be swallowed: the job still
    delivers and the endpoint still reports success."""
    monkeypatch.setenv("FIXPACK_PROCESS_TOKEN", "secret123")
    monkeypatch.setattr(github_app, "app_credentials_from_env", lambda: None)

    from app.fixpack.semantic_check import SemanticCheckResult

    monkeypatch.setattr(main_mod, "run_semantic_check", lambda z, p, **kwargs: SemanticCheckResult(
        ran=False, ecosystem=None, original=None, patched=None,
        regression=False, detail="no suite", pr_note=None))

    zip_bytes = make_zip({"config.py": f'API_KEY = "{AWS_KEY}"\n'})
    audits = {"a1": {"repo_url": "https://github.com/acme/app",
                     "findings_json": [_secret_finding()]}}
    jobs = [{"id": "j1", "audit_id": "a1", "stack": "fastapi", "status": "paid"}]

    fixpack_repo = FakeFixpackRepo(jobs)
    override(audit_repo=FakeAuditRepo(audits), fixpack_repo=fixpack_repo,
             fix_outcome_repo=FakeFixOutcomeRepo(raise_on_record=True),
             repo_fetcher=fake_fetcher_returning(zip_bytes),
             pr_opener=lambda *a, **k: PullRequestResult(
                 "https://github.com/acme/app/pull/9", "b"))
    try:
        resp = _run_processor()
    finally:
        clear_overrides()

    assert resp.json()["delivered"] == 1
    assert fixpack_repo.statuses["j1"] == "delivered"


# --- (b)(c)(d) the GitHub webhook -----------------------------------------

def _sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(
        secret.encode(), body, hashlib.sha256).hexdigest()


def _pr_closed_payload(html_url: str, merged: bool) -> bytes:
    return json.dumps({
        "action": "closed",
        "pull_request": {"html_url": html_url, "number": 9, "merged": merged},
        "repository": {"full_name": "acme/app"},
    }).encode()


def _post_webhook(body: bytes, *, signature: str, event: str = "pull_request"):
    return client.post(
        "/v1/webhooks/github", content=body,
        headers={"X-Hub-Signature-256": signature, "X-GitHub-Event": event},
    )


def test_webhook_valid_signature_merged_true(monkeypatch):
    monkeypatch.setenv("GITHUB_APP_WEBHOOK_SECRET", "whsecret")
    pr_url = "https://github.com/acme/app/pull/9"

    outcomes = FakeFixOutcomeRepo()
    # Pre-seed a delivered outcome for this PR.
    import asyncio
    asyncio.run(outcomes.record(
        fixpack_job_id="j1", audit_id="a1", rule_ids=["aws-access-key-id"],
        stack="fastapi", outcome="delivered", is_regression=False, pr_url=pr_url))

    override(fix_outcome_repo=outcomes)
    try:
        body = _pr_closed_payload(pr_url, merged=True)
        resp = _post_webhook(body, signature=_sign("whsecret", body))
    finally:
        clear_overrides()

    assert resp.status_code == 200
    assert resp.json() == {"updated": 1, "merged": True}
    assert outcomes._by_pr_url[pr_url]["pr_merged"] is True


def test_webhook_valid_signature_closed_unmerged(monkeypatch):
    monkeypatch.setenv("GITHUB_APP_WEBHOOK_SECRET", "whsecret")
    pr_url = "https://github.com/acme/app/pull/9"

    outcomes = FakeFixOutcomeRepo()
    import asyncio
    asyncio.run(outcomes.record(
        fixpack_job_id="j1", audit_id="a1", rule_ids=[], stack="fastapi",
        outcome="delivered", is_regression=False, pr_url=pr_url))

    override(fix_outcome_repo=outcomes)
    try:
        body = _pr_closed_payload(pr_url, merged=False)
        resp = _post_webhook(body, signature=_sign("whsecret", body))
    finally:
        clear_overrides()

    assert resp.json() == {"updated": 1, "merged": False}
    assert outcomes._by_pr_url[pr_url]["pr_merged"] is False


def test_webhook_invalid_signature_rejected(monkeypatch):
    monkeypatch.setenv("GITHUB_APP_WEBHOOK_SECRET", "whsecret")
    outcomes = FakeFixOutcomeRepo()
    override(fix_outcome_repo=outcomes)
    try:
        body = _pr_closed_payload("https://github.com/acme/app/pull/9", True)
        resp = _post_webhook(body, signature=_sign("wrong-secret", body))
    finally:
        clear_overrides()

    assert resp.status_code == 401
    assert outcomes.merged_updates == []  # no mutation attempted


def test_webhook_missing_signature_rejected(monkeypatch):
    monkeypatch.setenv("GITHUB_APP_WEBHOOK_SECRET", "whsecret")
    override(fix_outcome_repo=FakeFixOutcomeRepo())
    try:
        body = _pr_closed_payload("https://github.com/acme/app/pull/9", True)
        resp = client.post("/v1/webhooks/github", content=body,
                           headers={"X-GitHub-Event": "pull_request"})
    finally:
        clear_overrides()
    assert resp.status_code == 401


def test_webhook_503_when_secret_unconfigured(monkeypatch):
    monkeypatch.delenv("GITHUB_APP_WEBHOOK_SECRET", raising=False)
    body = _pr_closed_payload("https://github.com/acme/app/pull/9", True)
    resp = _post_webhook(body, signature="sha256=whatever")
    assert resp.status_code == 503
    assert resp.json()["detail"]["reason"] == "github_webhook_not_configured"


def test_webhook_unknown_pr_is_noop(monkeypatch):
    monkeypatch.setenv("GITHUB_APP_WEBHOOK_SECRET", "whsecret")
    outcomes = FakeFixOutcomeRepo()  # no rows seeded
    override(fix_outcome_repo=outcomes)
    try:
        body = _pr_closed_payload("https://github.com/other/repo/pull/1", True)
        resp = _post_webhook(body, signature=_sign("whsecret", body))
    finally:
        clear_overrides()

    assert resp.status_code == 200
    assert resp.json() == {"updated": 0, "merged": True}


def test_webhook_non_pull_request_event_ignored(monkeypatch):
    monkeypatch.setenv("GITHUB_APP_WEBHOOK_SECRET", "whsecret")
    outcomes = FakeFixOutcomeRepo()
    override(fix_outcome_repo=outcomes)
    try:
        body = json.dumps({"zen": "ping"}).encode()
        resp = _post_webhook(body, signature=_sign("whsecret", body),
                             event="ping")
    finally:
        clear_overrides()

    assert resp.status_code == 200
    assert resp.json()["ignored"] is True
    assert outcomes.merged_updates == []


def test_webhook_non_closed_action_ignored(monkeypatch):
    monkeypatch.setenv("GITHUB_APP_WEBHOOK_SECRET", "whsecret")
    outcomes = FakeFixOutcomeRepo()
    override(fix_outcome_repo=outcomes)
    try:
        body = json.dumps({
            "action": "opened",
            "pull_request": {"html_url": "https://github.com/acme/app/pull/9"},
        }).encode()
        resp = _post_webhook(body, signature=_sign("whsecret", body))
    finally:
        clear_overrides()

    assert resp.status_code == 200
    assert resp.json()["ignored"] is True
    assert outcomes.merged_updates == []

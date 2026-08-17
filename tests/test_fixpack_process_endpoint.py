"""Tests for POST /internal/fixpack/process-paid — the scheduled
processor that turns paid Fix Pack jobs into fix PRs.

All GitHub network calls are mocked: the PR opener is a fake injected via
the get_pr_opener dependency override (same pattern as the Deploy Pack
tests), and the repo fetcher / audit+fixpack repos are fakes too, so the
suite never touches the network or a database.
"""

import asyncio
import io
import json
import logging
import zipfile
from decimal import Decimal
from contextlib import asynccontextmanager

import pytest
from fastapi.testclient import TestClient

import app.main as main_mod
from app.deploypack import github_app
from app import alerts as alerts_mod
from app.fixpack.semantic_check import minimal_check as local_minimal_check
from app.deploypack.delivery import DeliveryError, PullRequestResult
from app.deploypack.github_app import GitHubAppAuthError, GitHubAppError
from app.llm.client import LLMClient, LLMError, LLMUsage, Provider
from app.main import (
    app,
    get_audit_repo,
    get_fixpack_repo,
    get_llm_client,
    get_llm_usage_repo,
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
        self.rows: list[dict] = []

    async def get(self, audit_id):
        return self._audits.get(audit_id)

    async def create(self, *, stack, file_count, score_total, score_json,
                     findings_json, repo_url=None, content_hash=None,
                     engine_version=None):
        row = {
            "id": f"review-{len(self.rows) + 1}", "stack": stack,
            "status": "completed", "file_count": file_count,
            "score_total": score_total, "score_json": score_json,
            "findings_json": findings_json, "repo_url": repo_url,
            "content_hash": content_hash, "engine_version": engine_version,
            "access_token": f"revtok{len(self.rows) + 1}",
        }
        self.rows.append(row)
        return row

    async def get_by_content_hash(self, content_hash, engine_version, basis):
        for row in reversed(self.rows):
            if (row["content_hash"] == content_hash
                    and row["engine_version"] == engine_version
                    and (row["score_json"] or {}).get("basis") == basis):
                return row
        return None


class FakeUsageRepo:
    def __init__(self):
        self.rows: list[dict] = []

    async def create(self, **kwargs):
        self.rows.append(kwargs)
        return {"id": "usage-1", **kwargs}

    async def sum_anon_spend_today(self):
        return Decimal("0")


class FakeLLM(LLMClient):
    def __init__(self, response: str | None = None):
        super().__init__(providers=[Provider("anthropic", "https://x", "k", "m")])
        self._response = response if response is not None else json.dumps(
            {"findings": [{
                "title": "Route has no authentication check",
                "severity": "high", "category": "Auth",
                "file": "app/auth.ts", "line": 1,
                "explanation": "anyone can call it", "confidence": 0.8,
            }]}
        )

    def complete(self, system, user, max_tokens=4096):
        return self._response, LLMUsage(
            model="claude-sonnet-4.6", input_tokens=1000, output_tokens=200)


class ExplodingLLM(LLMClient):
    def __init__(self):
        super().__init__(providers=[Provider("anthropic", "https://x", "k", "m")])

    def complete(self, system, user, max_tokens=4096):
        raise RuntimeError("model unavailable")


class DegradingLLM(LLMClient):
    def __init__(self):
        super().__init__(providers=[Provider("anthropic", "https://x", "k", "m")])

    def complete(self, system, user, max_tokens=4096):
        raise LLMError("402 payment required mid-run")


class FakeFixpackRepo:
    """In-memory stand-in modelling the durable-lease processing model."""

    def __init__(self, jobs: list[dict], reap: dict[str, int] | None = None):
        self._paid = list(jobs)
        self.delivered: dict[str, str] = {}
        self.statuses: dict[str, str] = {}
        self.details: dict[str, str | None] = {}
        self.claimed: list[str] = []
        self.released: list[str] = []
        self.proof_json: dict[str, dict] = {}
        self._reap = reap or {"requeued": 0, "failed": 0}

    async def reap_stale_running(self, *, max_age_minutes, max_attempts):
        return self._reap

    async def claim_one_paid(self):
        if not self._paid:
            return None
        job = self._paid.pop(0)
        self.claimed.append(job["id"])
        return {**job, "status": "running"}

    async def set_proof_json(self, job_id, proof):
        self.proof_json[job_id] = proof

    async def mark_fixpack_delivered(self, job_id, pr_url):
        self.delivered[job_id] = pr_url
        self.statuses[job_id] = "delivered"

    async def mark_status(self, job_id, status, detail=None):
        self.statuses[job_id] = status
        self.details[job_id] = detail

    async def release_to_paid(self, job_id, detail):
        self.statuses[job_id] = "paid"
        self.details[job_id] = detail
        self.released.append(job_id)
        self._paid.append({"id": job_id, "audit_id": "a1", "status": "paid"})


def fake_fetcher_returning(zip_bytes: bytes):
    def _fetch(owner, repo):
        return zip_bytes
    return _fetch


def override(audit_repo=None, fixpack_repo=None, repo_fetcher=None,
             pr_opener=None, llm_client=None, llm_usage_repo=None):
    if audit_repo is not None:
        app.dependency_overrides[get_audit_repo] = lambda: audit_repo
    if fixpack_repo is not None:
        app.dependency_overrides[get_fixpack_repo] = lambda: fixpack_repo
    if repo_fetcher is not None:
        app.dependency_overrides[get_repo_fetcher] = lambda: repo_fetcher
    if pr_opener is not None:
        app.dependency_overrides[get_pr_opener] = lambda: pr_opener
    if llm_client is not None:
        app.dependency_overrides[get_llm_client] = lambda: llm_client
    if llm_usage_repo is not None:
        app.dependency_overrides[get_llm_usage_repo] = lambda: llm_usage_repo


def clear_overrides():
    for dep in (get_audit_repo, get_fixpack_repo, get_repo_fetcher, get_pr_opener,
                get_llm_client, get_llm_usage_repo):
        app.dependency_overrides.pop(dep, None)


def auth(token="secret123"):
    return {"Authorization": f"Bearer {token}"}


def test_paid_job_opens_pr_and_marks_delivered(monkeypatch):
    monkeypatch.setenv("FIXPACK_PROCESS_TOKEN", "secret123")
    monkeypatch.setattr(github_app, "app_credentials_from_env", lambda: None)

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
    assert resp.json()["delivered"] == 1
    assert fixpack_repo.delivered["j1"] == "https://github.com/acme/app/pull/5"
    assert AWS_KEY not in captured["title"]
    assert AWS_KEY not in captured["body"]
    for text in captured["files"].values():
        assert AWS_KEY not in text

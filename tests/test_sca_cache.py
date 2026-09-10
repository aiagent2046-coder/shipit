"""Dependency entitlement must not be lost when the code analysis is cached."""
from copy import deepcopy
import io
from unittest.mock import AsyncMock

import pytest

from app.llm.client import LLMClient
from app.main import app, get_audit_repo, run_repo_audit
from app.sca.cache import complete_cached_dependencies, needs_dependency_scan
from app.sca.stage import RULE_ID
from app.scan.pipeline import content_digest, run_scan
from app.worker import main as worker
from tests.conftest import run_audit_job
from tests.test_audit_determinism import _post, force_pro_account
from tests.test_audit_preview_history import Repo, row, RAW
from tests.test_sca_wiring import fake_client, repo_with_lockfile
from tests.test_sca_stage import make_zip


INVENTORY = {"version": 1, "asked_at": "2026-09-10T00:00:00+00:00", "found": 1,
             "dependencies": [{"ecosystem": "npm", "name": "private-package",
                               "version": "1.0.0", "manifest": "package-lock.json"}]}


@pytest.mark.parametrize("path", ["worker", "monitor"])
@pytest.mark.asyncio
async def test_baseline_only_copy_preserves_inventory(monkeypatch, path):
    paid = row("static+llm", [], dependency_inventory=INVENTORY)
    repo = Repo(paid)
    runner = AsyncMock(side_effect=AssertionError("Cached code must not be scanned again"))
    monkeypatch.setattr(worker, "_run_scan_offthread", runner)
    if path == "worker":
        result = await run_audit_job(RAW, llm_client=LLMClient(providers=[]), audit_repo=repo,
                                     account_id="paid-account")
    else:
        await run_repo_audit("https://github.com/acme/app", zip_bytes=RAW,
                             repo_fetcher=None, audit_repo=repo, llm_client=LLMClient(providers=[]))
        result = repo.rows[-1]
    assert result["id"] != paid["id"]
    assert result["dependency_inventory"] == INVENTORY
    assert result["score_json"]["analysis_reused_from"] == paid["id"]
    runner.assert_not_awaited()


def unqueried_paid(raw, reason="no_client"):
    scan = run_scan(raw, LLMClient(providers=[]), sca_client=None)
    score = {**scan["score"], "basis": "static+llm", "free_baseline": {"status": "completed"}}
    score["scan_manifest"]["sca_skipped_reason"] = reason
    return row("static+llm", scan["findings"], score_json=score, content_hash=content_digest(raw))


@pytest.mark.parametrize("reason", ["no_client", "osv_unavailable: HTTP 503"])
@pytest.mark.asyncio
async def test_paid_worker_completes_only_missing_dependencies(monkeypatch, reason):
    raw = repo_with_lockfile()
    paid = unqueried_paid(raw, reason)
    original = deepcopy(paid)
    repo = Repo(paid)
    monkeypatch.setenv("SCA_ENABLED", "1")
    monkeypatch.setattr(worker, "sca_client_for", lambda **kwargs: fake_client())
    runner = AsyncMock(side_effect=AssertionError("An SCA cache miss must not repeat LLM analysis"))
    monkeypatch.setattr(worker, "_run_scan_offthread", runner)
    result = await run_audit_job(raw, llm_client=LLMClient(providers=[]), audit_repo=repo,
                                 account_id="paid-account")
    assert result["id"] != paid["id"]
    assert any(f["rule_id"] == RULE_ID for f in result["findings_json"])
    assert result["score_json"]["scan_manifest"]["sca_asked_at"]
    assert result["score_json"]["scan_manifest"]["sca_skipped_reason"] is None
    assert result["dependency_inventory"]["dependencies"][0]["name"] == "lodash"
    assert result["score_json"]["basis"] == paid["score_json"]["basis"]
    assert paid == original
    runner.assert_not_awaited()


def test_paid_intake_queues_missing_sca_without_leaking_inventory(monkeypatch, audit_queue):
    raw = repo_with_lockfile()
    paid = unqueried_paid(raw)
    paid["dependency_inventory"] = INVENTORY
    repo = Repo(paid)
    force_pro_account(monkeypatch)
    monkeypatch.setenv("SCA_ENABLED", "1")
    app.dependency_overrides[get_audit_repo] = lambda: repo
    try:
        response = _post(io.BytesIO(raw))
    finally:
        app.dependency_overrides.pop(get_audit_repo, None)
    assert response.status_code == 202
    assert response.json()["job_id"]
    assert "private-package" not in response.text
    assert "dependency_inventory" not in response.text


def test_dependency_outage_preserves_known_cached_evidence(monkeypatch):
    import app.sca.cache as cache

    paid = row("static+llm", [{"rule_id": RULE_ID, "title": "Known vulnerability"}],
               dependency_inventory=INVENTORY)
    original = deepcopy(paid)
    monkeypatch.setattr(cache, "run_sca_stage", lambda *_: ([], {
        "skipped_reason": "osv_unavailable: HTTP 503", "dependencies": 1,
        "dependencies_found": 1, "asked_at": None}))
    result = complete_cached_dependencies(paid, b"unused", fake_client())
    assert result["score"] == paid["score_json"]
    assert result["findings"] == paid["findings_json"]
    assert result["dependency_inventory"] == INVENTORY
    assert result["llm_usage"]["calls"] == 0
    assert paid == original


@pytest.mark.parametrize("files", [{"app.py": "print(1)\n"},
                                  {"go.sum": "example.com/module v1.0.0 h1:hash\n"}])
def test_missing_or_unsupported_lockfiles_remain_cacheable(monkeypatch, files):
    monkeypatch.setenv("SCA_ENABLED", "1")
    scan = run_scan(make_zip(files), LLMClient(providers=[]), sca_client=None)
    assert scan["score"]["scan_manifest"]["sca_checks"] == ["sca_dependencies"]
    assert not needs_dependency_scan({"score_json": scan["score"]})

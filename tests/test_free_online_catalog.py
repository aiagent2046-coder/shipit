"""The free online audit keeps the offline advisory check across its pipeline.

These tests exercise production entry points and persistence, rather than
retesting the matcher's range arithmetic. The GHSA boundaries below come from
the committed reviewed records and deliberately include advisories with no CVE.
"""

from __future__ import annotations

import hashlib
import io
import json
import socket
from copy import deepcopy
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from app.llm.client import LLMClient, LLMError
from app.local_cli import inspect_project
from app.report.sarif import build_sarif
from app.sca.cache import needs_dependency_scan
from app.scan import pipeline
from app.scan.browser import scan_archive
from app.scan.pipeline import AUDIT_ENGINE_VERSION, BASIS_FULL, BASIS_PREVIEW, run_scan
from tests.conftest import run_audit_job
from tests.test_audit_llm_wiring import FakeLLM
from tests.test_audit_determinism import _post, force_pro_account
from tests.test_audit_preview_history import Repo
from tests.test_browser_cve import CATALOG, project
from tests.test_sca_stage import make_zip
from tests.test_sca_wiring import fake_client, repo_with_lockfile


ROOT = Path(__file__).resolve().parents[1]
RULE_ID = "dependency-cve-match"
GHSA_CASES = [
    pytest.param("npm", "@apollo/server", "4.7.1", "GHSA-68jh-rf6x-836f", True,
                 id="apollo-affected"),
    pytest.param("npm", "@apollo/server", "4.7.4", "GHSA-68jh-rf6x-836f", False,
                 id="apollo-fixed-for-this-advisory"),
    pytest.param("PyPI", "adyen", "2.2.0", "GHSA-f3q4-ggfp-jv34", True,
                 id="adyen-affected"),
    pytest.param("PyPI", "adyen", "7.1.0", "GHSA-f3q4-ggfp-jv34", False,
                 id="adyen-fixed"),
]


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    attempts = []

    def reject(*args, **kwargs):
        attempts.append((args, kwargs))
        raise AssertionError("An offline advisory scan must not open a connection")

    monkeypatch.setattr(socket, "create_connection", reject)
    monkeypatch.setattr(socket.socket, "connect", reject)
    monkeypatch.setattr(socket.socket, "connect_ex", reject)
    yield
    assert not attempts, "Even a swallowed network failure violates the offline contract"


def free_scan(raw, **kwargs):
    return run_scan(raw, LLMClient(providers=[]), depth=BASIS_PREVIEW, **kwargs)


def dependency_findings(findings):
    return [finding for finding in findings if finding["rule_id"] == RULE_ID]


@pytest.fixture
def catalog_files(tmp_path, monkeypatch):
    from app.sca import snapshot

    catalog = tmp_path / "cve-catalog.json"
    checksum = tmp_path / "cve-catalog.json.sha256"
    catalog.write_bytes((ROOT / "app/data/cve-catalog.json").read_bytes())
    checksum.write_bytes((ROOT / "app/data/cve-catalog.json.sha256").read_bytes())
    monkeypatch.setattr(snapshot, "CATALOG_PATH", catalog)
    monkeypatch.setattr(snapshot, "CHECKSUM_PATH", checksum)
    return catalog, checksum


def remove_adyen_from_catalog(catalog_files):
    catalog, checksum = catalog_files
    changed = json.loads(catalog.read_bytes())
    del changed["packages"]["PyPI:adyen"]
    updated_bytes = json.dumps(changed).encode()
    catalog.write_bytes(updated_bytes)
    checksum.write_text(hashlib.sha256(updated_bytes).hexdigest())
    return updated_bytes


@pytest.mark.parametrize("ecosystem,name,version,advisory,affected", GHSA_CASES)
def test_free_online_ghsa_evidence_matches_browser_and_local(
    ecosystem, name, version, advisory, affected,
):
    raw = project(ecosystem, name, version)
    result = free_scan(raw)
    findings = dependency_findings(result["findings"])
    matching = [finding for finding in findings
                if finding["claim_evidence"]["advisory_id"] == advisory]
    assert bool(matching) is affected

    browser = scan_archive(raw, CATALOG)["report"]
    metadata = {"revision": "bundled", "sha256": hashlib.sha256(
        (ROOT / "app/data/cve-catalog.json").read_bytes()).hexdigest(),
        "sources": CATALOG["sources"]}
    local = inspect_project(raw, {}, CATALOG, metadata)
    assert findings == dependency_findings(browser["findings"])
    assert findings == dependency_findings(local["findings"])
    manifest = result["score"]["scan_manifest"]
    assert manifest["dependency_cve"] == browser["dependency_cve"] == local["dependency_cve"]
    assert manifest["dependency_cve"]["dependencies_checked"] == 1
    assert "dependency_check_not_run" not in manifest["limitations"]
    assert "dependency_snapshot_scope" in manifest["limitations"]
    assert "dependency_runtime_reachability_not_checked" in manifest["limitations"]
    assert manifest["runtime_verified"] is False
    assert manifest["sca_asked_at"] is None, "Snapshot matching is not a live OSV query"
    snapshot = manifest["dependency_snapshot"]
    assert snapshot["version"] == 1
    assert snapshot["mode"] == "bundled"
    assert snapshot["catalog_sha256"] == metadata["sha256"]
    assert len(snapshot["fingerprint"]) == 64
    assert datetime.fromisoformat(snapshot["checked_at"].replace("Z", "+00:00")).tzinfo is not None
    if affected:
        evidence = matching[0]["claim_evidence"]
        assert evidence["installed_version"] == version
        assert evidence["ghsa_id"] == advisory
        assert "cve_id" not in evidence
        assert evidence["reachability"] == "not_assessed"
        assert evidence["occurrences_recorded"] is True

    # The DB stores score/findings as JSON; the exported execution facts must
    # agree with those persisted facts, including the successful zero-match case.
    persisted = json.loads(json.dumps({"score": result["score"], "findings": result["findings"]}))
    sarif = build_sarif(persisted["findings"], engine_version=AUDIT_ENGINE_VERSION,
                        score=persisted["score"])
    assert sarif["runs"][0]["invocations"][0]["properties"]["dependencyCve"] == (
        manifest["dependency_cve"])


@pytest.mark.parametrize("llm_outcome", ["failed", "daily_spend_cap", "cost_cap_exceeded"])
def test_preview_dependency_check_survives_model_degradation(monkeypatch, llm_outcome):
    raw = project("PyPI", "adyen", "2.2.0", extra={
        "app/query.py": "def query(user_input):\n    return user_input\n",
    })
    calls = []

    def model_stage(*args, **kwargs):
        calls.append(True)
        if llm_outcome == "failed":
            raise LLMError("Provider unavailable")
        if llm_outcome == "cost_cap_exceeded":
            from app.scan.llm_scan import LLMScanStats
            return [], LLMScanStats(calls=1, rubrics_ran=("security",), cost_cap_exceeded=True)
        raise AssertionError("Daily spending cap must skip the model stage")

    monkeypatch.setattr(pipeline, "run_llm_scan", model_stage)
    result = run_scan(raw, FakeLLM(response="[]"), depth=BASIS_PREVIEW,
                      llm_skip_reason="daily_spend_cap" if llm_outcome == "daily_spend_cap" else None)
    assert bool(calls) is (llm_outcome != "daily_spend_cap")
    assert result["score"]["basis"] == (
        "static+partial" if llm_outcome == "cost_cap_exceeded" else "static_only")
    assert dependency_findings(result["findings"])
    manifest = result["score"]["scan_manifest"]
    assert manifest["dependency_cve"]["status"] == "checked"
    assert "dependency_check_not_run" not in manifest["limitations"]


@pytest.mark.parametrize("files, gaps", [
    pytest.param({"package.json": '{"dependencies":{"@apollo/server":"^4.7.1"}}'},
                 {"package.json": "unresolved"}, id="manifest-without-resolved-versions"),
    pytest.param({"Cargo.lock": 'version = 3\n[[package]]\nname = "example"\nversion = "1.0.0"\n'},
                 {"Cargo.lock": "unsupported"}, id="unsupported-ecosystem"),
])
def test_free_online_manifest_gaps_survive_pipeline(files, gaps):
    result = free_scan(make_zip(files))
    coverage = result["score"]["scan_manifest"]["dependency_cve"]
    assert coverage["status"] == "partial"
    assert coverage["dependencies_found"] == 0
    assert coverage["incomplete_manifests"] == gaps
    assert not dependency_findings(result["findings"])


def test_successful_zero_matches_is_a_completed_snapshot_check():
    result = free_scan(project("PyPI", "adyen", "7.1.0"))
    manifest = result["score"]["scan_manifest"]
    coverage = manifest["dependency_cve"]
    assert not dependency_findings(result["findings"])
    assert coverage["status"] == "checked"
    assert coverage["dependencies_found"] == coverage["dependencies_checked"] == 1
    assert coverage["status_counts"] == {
        "affected": 0, "unaffected": 1, "unknown": 0, "not_in_catalog": 0,
    }
    assert "dependency_check_not_run" not in manifest["limitations"]


def test_snapshot_does_not_satisfy_the_paid_live_lookup_cache_contract(monkeypatch):
    monkeypatch.setenv("SCA_ENABLED", "1")
    result = free_scan(project("PyPI", "adyen", "7.1.0"))
    assert result["score"]["scan_manifest"]["dependency_cve"]["status"] == "checked"
    assert needs_dependency_scan({"score_json": result["score"]})


@pytest.mark.parametrize("limit", ["MAX_EVALUATIONS", "MAX_FINDINGS"])
def test_incomplete_refresh_retains_previous_matches_with_their_original_provenance(monkeypatch, limit):
    from app.sca.snapshot import refresh_snapshot
    from app.scan import cve_match

    raw = project("PyPI", "adyen", "2.2.0")
    initial = free_scan(raw)
    original = deepcopy(initial)
    monkeypatch.setattr(cve_match, limit, 0)
    refreshed = refresh_snapshot(initial["score"], initial["findings"], raw)
    manifest = refreshed["score"]["scan_manifest"]
    assert manifest["dependency_cve"]["status"] == "partial"
    assert manifest["dependency_snapshot"]["retained_findings"] == 1
    assert dependency_findings(refreshed["findings"]) == dependency_findings(initial["findings"])
    assert refreshed["score"]["total"] == initial["score"]["total"]
    assert initial == original


def test_paid_scan_still_uses_the_supplied_osv_client():
    result = run_scan(repo_with_lockfile(), LLMClient(providers=[]),
                      depth=BASIS_FULL, sca_client=fake_client())
    assert any(finding["rule_id"] == "dependency-known-vulnerability"
               for finding in result["findings"])
    assert not dependency_findings(result["findings"])
    manifest = result["score"]["scan_manifest"]
    assert manifest["sca_checks"] == ["sca_dependencies"]
    assert manifest["sca_asked_at"]
    assert manifest["sca_skipped_reason"] is None


@pytest.mark.asyncio
async def test_worker_persists_and_reuses_free_snapshot_evidence(monkeypatch):
    from app.worker import main as worker

    raw = project("PyPI", "adyen", "2.2.0")
    repo = Repo()
    saved = await run_audit_job(raw, llm_client=FakeLLM(response="[]"), audit_repo=repo)
    assert saved["score_json"]["basis"] == BASIS_PREVIEW
    coverage = saved["score_json"]["scan_manifest"]["dependency_cve"]
    assert coverage["dependencies_checked"] == 1
    assert dependency_findings(saved["findings_json"])

    runner = AsyncMock(side_effect=AssertionError("A valid free cache hit must not rescan"))
    monkeypatch.setattr(worker, "_run_scan_offthread", runner)
    cached = await run_audit_job(raw, llm_client=FakeLLM(response="[]"), audit_repo=repo)
    runner.assert_not_awaited()
    assert cached["score_json"]["scan_manifest"]["dependency_cve"] == coverage
    assert dependency_findings(cached["findings_json"]) == dependency_findings(saved["findings_json"])


@pytest.mark.parametrize("damage", ["missing", "checksum", "schema"])
def test_catalog_failure_keeps_static_findings_with_explicit_unavailability(catalog_files, damage):
    catalog, checksum = catalog_files
    if damage == "missing":
        catalog.unlink()
    elif damage == "checksum":
        checksum.write_text("0" * 64)
    else:
        catalog.write_bytes(b"{}")
        checksum.write_text(hashlib.sha256(b"{}").hexdigest())
    raw = project("PyPI", "adyen", "2.2.0", extra={"src/render.ts": "element.innerHTML = userText;"})
    result = free_scan(raw)
    assert any(finding["rule_id"] == "xss-unsafe-html-injection" for finding in result["findings"])
    assert not dependency_findings(result["findings"])
    manifest = result["score"]["scan_manifest"]
    assert manifest["dependency_cve"]["status"] == "unavailable"
    assert "dependency_check_not_run" in manifest["limitations"]
    assert manifest["dependency_snapshot"]["catalog_sha256"] is None
    assert len(manifest["dependency_snapshot"]["fingerprint"]) == 64
    assert "unavailable" in json.dumps(manifest)


@pytest.mark.asyncio
async def test_catalog_change_refreshes_cached_evidence_without_repeating_the_model(
    catalog_files, monkeypatch,
):
    from app.sca.snapshot import snapshot_is_current

    raw = project("PyPI", "adyen", "2.2.0")
    repo = Repo()
    saved = await run_audit_job(raw, llm_client=FakeLLM(response="[]"), audit_repo=repo)
    original = deepcopy(saved)
    assert dependency_findings(saved["findings_json"])
    assert snapshot_is_current(saved["score_json"])

    # This simulates a new verified catalog publication, not a change to the
    # project's bytes or an advisory fetched over the network.
    updated_bytes = remove_adyen_from_catalog(catalog_files)
    assert not snapshot_is_current(saved["score_json"])

    def no_second_model(*args, **kwargs):
        raise AssertionError("Refreshing catalog evidence must reuse the existing model analysis")

    monkeypatch.setattr(pipeline, "run_llm_scan", no_second_model)
    refreshed = await run_audit_job(raw, llm_client=FakeLLM(response="[]"), audit_repo=repo)
    assert refreshed["id"] != saved["id"]
    assert saved == original, "The previous audit remains a historical snapshot"
    assert not dependency_findings(refreshed["findings_json"])
    assert [f for f in refreshed["findings_json"] if f["rule_id"] != RULE_ID] == [
        f for f in original["findings_json"] if f["rule_id"] != RULE_ID]
    manifest = refreshed["score_json"]["scan_manifest"]
    assert manifest["dependency_cve"]["status_counts"]["not_in_catalog"] == 1
    assert manifest["dependency_snapshot"]["catalog_sha256"] == hashlib.sha256(updated_bytes).hexdigest()
    assert snapshot_is_current(refreshed["score_json"])
    assert manifest["model_calls"] == original["score_json"]["scan_manifest"]["model_calls"]


@pytest.mark.asyncio
async def test_identical_catalog_failure_is_cacheable_and_repair_invalidates_it(catalog_files, monkeypatch):
    from app.sca.snapshot import snapshot_is_current
    from app.worker import main as worker

    catalog, checksum = catalog_files
    original_bytes, original_checksum = catalog.read_bytes(), checksum.read_bytes()
    catalog.write_bytes(b"corrupt catalog")
    raw = project("PyPI", "adyen", "2.2.0")
    repo = Repo()
    broken = await run_audit_job(raw, llm_client=FakeLLM(response="[]"), audit_repo=repo)
    before = deepcopy(broken)
    manifest = broken["score_json"]["scan_manifest"]
    assert manifest["dependency_cve"]["status"] == "unavailable"
    assert snapshot_is_current(broken["score_json"])

    runner = AsyncMock(side_effect=AssertionError("Snapshot refresh must not rerun the entire audit"))
    monkeypatch.setattr(worker, "_run_scan_offthread", runner)
    cached = await run_audit_job(raw, llm_client=FakeLLM(response="[]"), audit_repo=repo)
    assert cached["id"] == broken["id"]
    assert cached["score_json"]["scan_manifest"]["dependency_snapshot"] == manifest["dependency_snapshot"]

    catalog.write_bytes(original_bytes)
    checksum.write_bytes(original_checksum)
    assert not snapshot_is_current(broken["score_json"])
    repaired = await run_audit_job(raw, llm_client=FakeLLM(response="[]"), audit_repo=repo)
    assert repaired["id"] != broken["id"]
    assert dependency_findings(repaired["findings_json"])
    assert repaired["score_json"]["scan_manifest"]["dependency_cve"]["status"] == "checked"
    assert snapshot_is_current(repaired["score_json"])
    assert broken == before
    runner.assert_not_awaited()


@pytest.mark.parametrize("reason", ["no_providers_configured", "paid_job_cost_cap"])
@pytest.mark.asyncio
async def test_paid_baseline_keeps_deterministic_catalog_when_the_model_cannot_run(monkeypatch, reason):
    from app.audit_history import ensure_paid_baseline
    from app.scan import llm_scan

    raw = project("PyPI", "adyen", "2.2.0")
    paid_scan = run_scan(raw, LLMClient(providers=[]), depth=BASIS_FULL)
    calls = []

    class NoModelCalls(FakeLLM):
        def complete(self, *args, **kwargs):
            calls.append(True)
            raise AssertionError("An unavailable model must not prevent the offline baseline")

    client = LLMClient(providers=[]) if reason == "no_providers_configured" else NoModelCalls(response="[]")
    if reason == "paid_job_cost_cap":
        monkeypatch.setattr(llm_scan, "JOB_COST_CAP_USD", Decimal("0"))

    async def preview_runner(*args, **kwargs):
        return run_scan(*args, **kwargs)

    score = await ensure_paid_baseline(
        Repo(), paid_scan, raw, client, pipeline.content_digest(raw), AUDIT_ENGINE_VERSION,
        runner=preview_runner, record_usage=AsyncMock(),
    )
    baseline = score["free_baseline"]
    assert baseline["score"]["scan_manifest"]["dependency_cve"]["status"] == "checked"
    assert dependency_findings(baseline["findings"])
    assert baseline["score"]["scan_manifest"]["model_calls"] == 0
    assert not calls


@pytest.mark.asyncio
async def test_paid_cache_refreshes_its_nested_baseline_without_repeating_paid_analysis(
    catalog_files, monkeypatch,
):
    from app.sca.snapshot import baseline_is_current
    from app.worker import main as worker

    monkeypatch.setenv("SCA_ENABLED", "0")
    raw = project("PyPI", "adyen", "2.2.0")
    repo = Repo()
    saved = await run_audit_job(raw, llm_client=FakeLLM(response="[]"), audit_repo=repo,
                                account_id="paid-account")
    before = deepcopy(saved)
    assert saved["score_json"]["basis"] == BASIS_FULL
    assert dependency_findings(saved["score_json"]["free_baseline"]["findings"])
    assert not dependency_findings(saved["findings_json"])
    remove_adyen_from_catalog(catalog_files)
    assert not baseline_is_current(saved["score_json"])

    runner = AsyncMock(side_effect=AssertionError("An outdated included catalog is not an outdated paid analysis"))
    monkeypatch.setattr(worker, "_run_scan_offthread", runner)
    refreshed = await run_audit_job(raw, llm_client=FakeLLM(response="[]"), audit_repo=repo,
                                    account_id="paid-account")
    runner.assert_not_awaited()
    assert refreshed["id"] != saved["id"]
    assert saved == before
    assert refreshed["findings_json"] == saved["findings_json"]
    assert refreshed["score_json"]["basis"] == BASIS_FULL
    baseline = refreshed["score_json"]["free_baseline"]
    assert not dependency_findings(baseline["findings"])
    assert baseline["score"]["scan_manifest"]["dependency_cve"]["status_counts"]["not_in_catalog"] == 1
    assert baseline_is_current(refreshed["score_json"])


@pytest.mark.parametrize("catalog_change", ["withdrawn", "introduced"])
@pytest.mark.asyncio
async def test_stale_preview_is_refreshed_before_paid_fallback_reuses_it(catalog_files, catalog_change):
    from app.audit_history import ensure_paid_baseline, score_with_preview_history
    from app.sca.snapshot import baseline_is_current

    catalog, checksum = catalog_files
    full_catalog, full_checksum = catalog.read_bytes(), checksum.read_bytes()
    if catalog_change == "introduced":
        remove_adyen_from_catalog(catalog_files)
    raw = project("PyPI", "adyen", "2.2.0")
    repo = Repo()
    preview = await run_audit_job(raw, llm_client=FakeLLM(response="[]"), audit_repo=repo)
    before = deepcopy(preview)
    paid_scan = run_scan(raw, LLMClient(providers=[]), depth=BASIS_FULL)
    if catalog_change == "introduced":
        catalog.write_bytes(full_catalog)
        checksum.write_bytes(full_checksum)
    else:
        remove_adyen_from_catalog(catalog_files)
    digest = pipeline.content_digest(raw)

    # An intake without source bytes cannot refresh this historical result and
    # must leave it unattached; the worker later has the bytes to update it.
    no_source = await score_with_preview_history(
        repo, paid_scan["score"], paid_scan["findings"], digest, AUDIT_ENGINE_VERSION,
    )
    assert no_source is paid_scan["score"]
    assert "free_baseline" not in no_source

    runner = AsyncMock(side_effect=AssertionError("The previous preview model is already available"))
    record_usage = AsyncMock()
    refreshed = await ensure_paid_baseline(
        repo, paid_scan, raw, LLMClient(providers=[]), digest, AUDIT_ENGINE_VERSION,
        runner=runner, record_usage=record_usage,
    )
    runner.assert_not_awaited()
    record_usage.assert_not_awaited()
    assert preview == before
    baseline = refreshed["free_baseline"]
    assert baseline["origin"] == "refreshed"
    assert baseline["audit_id"] is None
    assert baseline["source_audit_id"] == preview["id"]
    assert bool(dependency_findings(baseline["findings"])) is (catalog_change == "introduced")
    # History belongs to the original audit_id. A newly published advisory is
    # current baseline evidence, never evidence that the earlier audit found it.
    history = refreshed["preview_history"]
    assert history["preview_audit_id"] == preview["id"]
    assert history["total"] == len(before["findings_json"])
    assert history["retained_findings"] == [
        finding for finding in before["findings_json"] if finding not in paid_scan["findings"]]
    assert bool(dependency_findings(history["retained_findings"])) is (catalog_change == "withdrawn")
    assert baseline_is_current(refreshed)


@pytest.mark.parametrize("paid", [False, True], ids=["free-preview", "paid-nested-baseline"])
@pytest.mark.asyncio
async def test_intake_queues_catalog_staleness_instead_of_returning_old_results(
    catalog_files, monkeypatch, audit_queue, paid,
):
    from app.main import app, get_audit_repo

    monkeypatch.setenv("SCA_ENABLED", "0")
    raw = project("PyPI", "adyen", "2.2.0")
    repo = Repo()
    saved = await run_audit_job(raw, llm_client=FakeLLM(response="[]"), audit_repo=repo,
                                account_id="paid-account" if paid else None)
    if paid:
        force_pro_account(monkeypatch)
    app.dependency_overrides[get_audit_repo] = lambda: repo
    try:
        fresh = _post(io.BytesIO(raw))
        assert fresh.status_code == 202
        assert fresh.json()["audit_id"] == saved["id"]
        assert "job_id" not in fresh.json()

        remove_adyen_from_catalog(catalog_files)
        stale = _post(io.BytesIO(raw))
    finally:
        app.dependency_overrides.pop(get_audit_repo, None)
    assert stale.status_code == 202
    assert stale.json()["job_id"]
    assert "audit_id" not in stale.json()

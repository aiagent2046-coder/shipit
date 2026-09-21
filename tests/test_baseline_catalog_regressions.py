"""A later catalog failure must preserve the latest embedded dependency answer."""

from copy import deepcopy
import hashlib
import json
import socket
from unittest.mock import AsyncMock

import pytest

from app.sca import snapshot
from tests.conftest import run_audit_job
from tests.test_audit_llm_wiring import FakeLLM
from tests.test_audit_preview_history import Repo
from tests.test_browser_cve import CATALOG, project


ADVISORY = "GHSA-f3q4-ggfp-jv34"


def dependency_findings(findings):
    return [finding for finding in findings
            if finding.get("rule_id") == "dependency-cve-match"]


def assert_retained(actual, findings):
    expected = [{**finding, "claim_evidence": {**finding["claim_evidence"],
                 "snapshot_check_status": "retained_not_reconfirmed"}} for finding in findings]
    assert len(actual) == len(expected)
    for current, previous in zip(actual, expected):
        # Keep every original fact and the saved recipe. Its active suggestion
        # must acknowledge that the failed refresh did not recheck candidates.
        assert {k: v for k, v in current.items() if k != "fix_hint"} == {
            k: v for k, v in previous.items() if k != "fix_hint"}
        if previous["claim_evidence"].get("remediation") is not None:
            assert "not been reconfirmed" in current["fix_hint"]
            assert "Advisory-fixed upgrade candidates:" not in current["fix_hint"]
        else:
            assert current["fix_hint"] == previous["fix_hint"]


@pytest.mark.parametrize("change", ["introduced", "withdrawn"])
@pytest.mark.asyncio
async def test_catalog_failure_keeps_latest_embedded_baseline_and_original_history(
    tmp_path, monkeypatch, change,
):
    from app.worker import main as worker

    def reject_network(*args, **kwargs):
        raise AssertionError("This baseline refresh must not contact a service")

    monkeypatch.setattr(socket.socket, "connect", reject_network)
    monkeypatch.setattr(socket, "create_connection", reject_network)
    catalog_path, receipt_path = tmp_path / "catalog.json", tmp_path / "catalog.sha256"
    monkeypatch.setattr(snapshot, "CATALOG_PATH", catalog_path)
    monkeypatch.setattr(snapshot, "CHECKSUM_PATH", receipt_path)

    def publish_catalog(*, includes_advisory):
        catalog = {**CATALOG, "packages": (
            {"PyPI:adyen": CATALOG["packages"]["PyPI:adyen"]} if includes_advisory else {})}
        raw = json.dumps(catalog).encode()
        catalog_path.write_bytes(raw)
        receipt_path.write_text(hashlib.sha256(raw).hexdigest())

    # A belongs to the standalone preview and remains immutable. B is only
    # represented by the paid report's refreshed, embedded free baseline.
    publish_catalog(includes_advisory=change == "withdrawn")
    raw = project("PyPI", "adyen", "2.2.0")
    repo = Repo()
    client = FakeLLM(response="[]")
    preview_a = await run_audit_job(raw, llm_client=client, audit_repo=repo)
    frozen_a = deepcopy(preview_a)
    publish_catalog(includes_advisory=change == "introduced")
    paid_b = await run_audit_job(raw, llm_client=client, audit_repo=repo, account_id="paid")
    frozen_b = deepcopy(paid_b)
    baseline_b = paid_b["score_json"]["free_baseline"]
    findings_b = dependency_findings(baseline_b["findings"])
    assert [finding["claim_evidence"]["advisory_id"] for finding in findings_b] == (
        [ADVISORY] if change == "introduced" else [])

    # C cannot reassess anything. Starting from A would either lose a newly
    # established advisory or resurrect a withdrawn one; the input must be B.
    catalog_path.write_bytes(b"corrupted catalog C")
    runner = AsyncMock(side_effect=AssertionError("Catalog refresh must not repeat model analysis"))
    monkeypatch.setattr(worker, "_run_scan_offthread", runner)
    paid_c = await run_audit_job(raw, llm_client=client, audit_repo=repo, account_id="paid")
    baseline_c = paid_c["score_json"]["free_baseline"]
    manifest_c = baseline_c["score"]["scan_manifest"]
    assert_retained(dependency_findings(baseline_c["findings"]), findings_b)
    assert manifest_c["dependency_cve"]["status"] == "unavailable"
    assert manifest_c["dependency_snapshot"].get("retained_findings", 0) == len(findings_b)
    assert baseline_c["source_audit_id"] == preview_a["id"]
    assert baseline_c["audit_id"] is None
    assert paid_c["score_json"]["preview_history"] == paid_b["score_json"]["preview_history"]
    assert preview_a == frozen_a
    assert paid_b == frozen_b
    assert snapshot.baseline_is_current(paid_c["score_json"])

    repeated = await run_audit_job(raw, llm_client=client, audit_repo=repo, account_id="paid")
    assert repeated["id"] == paid_c["id"]
    runner.assert_not_awaited()


@pytest.mark.asyncio
async def test_first_standalone_failure_preserves_prior_included_dependency_evidence(tmp_path, monkeypatch):
    from app.audit_history import refresh_cached_preview_history
    from app.worker import main as worker

    catalog_path, receipt_path = tmp_path / "catalog.json", tmp_path / "catalog.sha256"
    raw_catalog = json.dumps({**CATALOG, "packages": {"PyPI:adyen": CATALOG["packages"]["PyPI:adyen"]}}).encode()
    catalog_path.write_bytes(raw_catalog)
    receipt_path.write_text(hashlib.sha256(raw_catalog).hexdigest())
    monkeypatch.setattr(snapshot, "CATALOG_PATH", catalog_path)
    monkeypatch.setattr(snapshot, "CHECKSUM_PATH", receipt_path)
    raw = project("PyPI", "adyen", "2.2.0")
    repo, client = Repo(), FakeLLM(response="[]")
    paid_b = await run_audit_job(raw, llm_client=client, audit_repo=repo, account_id="paid")
    frozen_b = deepcopy(paid_b)
    baseline_b = paid_b["score_json"]["free_baseline"]
    assert baseline_b["origin"] == "included"
    old_findings = dependency_findings(baseline_b["findings"])
    assert len(old_findings) == 1

    catalog_path.write_bytes(b"corrupted catalog C")
    preview_c = await run_audit_job(raw, llm_client=client, audit_repo=repo)
    # Distinguish the newly performed code analysis from the earlier included
    # preview, so preservation cannot pass by reusing the whole old baseline.
    preview_c["score_json"]["scan_manifest"]["model"] = "new-preview-model"
    preview_c["findings_json"].append({"rule_id": "new-preview-observation", "source": "llm",
        "title": "New preview hypothesis", "severity": "low", "confidence": 0.8, "category": "Security"})
    frozen_c = deepcopy(preview_c)
    assert dependency_findings(preview_c["findings_json"]) == []
    assert await refresh_cached_preview_history(repo, paid_b) is paid_b, "Intake must defer reassessment"

    runner = AsyncMock(side_effect=AssertionError("Must reuse already performed code analysis"))
    monkeypatch.setattr(worker, "_run_scan_offthread", runner)
    paid_c = await run_audit_job(raw, llm_client=client, audit_repo=repo, account_id="paid")
    baseline_c = paid_c["score_json"]["free_baseline"]
    assert_retained(dependency_findings(baseline_c["findings"]), old_findings)
    assert [finding for finding in baseline_c["findings"]
            if finding.get("rule_id") != "dependency-cve-match"] == preview_c["findings_json"]
    assert baseline_c["score"]["scan_manifest"]["model"] == "new-preview-model"
    assert baseline_c["score"]["scan_manifest"]["dependency_snapshot"]["retained_findings"] == 1
    assert baseline_c["source_audit_id"] == preview_c["id"]
    history = paid_c["score_json"]["preview_history"]
    assert history["preview_audit_id"] == preview_c["id"]
    assert history["total"] == len(preview_c["findings_json"])
    assert dependency_findings(history["retained_findings"]) == []
    assert paid_b == frozen_b
    assert preview_c == frozen_c
    repeated = await run_audit_job(raw, llm_client=client, audit_repo=repo, account_id="paid")
    assert repeated["id"] == paid_c["id"]
    runner.assert_not_awaited()

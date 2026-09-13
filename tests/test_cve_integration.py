"""Official CVE context survives reports, outages and cached dependency refreshes."""
from copy import deepcopy
import json
from pathlib import Path

import httpx
import pytest

from app.llm.client import LLMClient
from app.report.cve import cve_rows, cve_notices
from app.report.evidence import manifest_rows, non_model_status_notices
from app.report.html import render_report
from app.report.sarif import build_sarif
from app.sca.cache import complete_cached_dependencies, needs_dependency_scan
from app.sca.cve import CveClient
from app.sca.osv import OsvClient
from app.sca.refresh import refresh_stale_dependency_audits
from app.sca.stage import run_sca_stage, sca_client_for
from app.scan.pipeline import run_scan, AUDIT_ENGINE_VERSION
from tests.test_cve_client import FIRST, published
from tests.test_sca_stage import FakeTransport, LODASH_ADVISORY, one_advisory, repo_with
from tests.test_sca_refresh import StoredRepo, stored_row, NOW


def client(status=200, *, rejected=False, max_records=20):
    record = published()
    if rejected:
        record["cveMetadata"]["state"] = "REJECTED"
        record["containers"]["cna"]["rejectedReasons"] = [
            {"lang": "en", "value": "Duplicate record; review replacement."}]
    return OsvClient(transport=one_advisory(), cve_client=CveClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(status, json=record)), max_records=max_records))


def scan(c):
    return run_scan(repo_with(), LLMClient(), sca_client=c)


def test_official_record_is_attributed_in_html_sarif_and_manifest():
    result = scan(client())
    cve = result["score"]["scan_manifest"]["sca_cve"]
    assert cve["status"] == "complete" and cve["resolved"] == 1
    finding = next(f for f in result["findings"] if f["rule_id"] == "dependency-known-vulnerability")
    assert "CNA English description" in finding["explanation"]
    assert "CWE-78" in finding["explanation"]
    assert "https://www.cve.org/CVERecord?id=" + FIRST in finding["fix_hint"]
    assert finding["severity"] == "high" and finding["confidence"] == 0.9
    html = render_report(result)
    assert "CVE Program" in html and "example-cna" in html and "PUBLISHED" in html
    sarif = build_sarif(result["findings"], engine_version=AUDIT_ENGINE_VERSION, score=result["score"])
    assert sarif["runs"][0]["invocations"][0]["properties"]["cveEvidence"] == cve


@pytest.mark.parametrize("status,cap", [(404, 20), (429, 20), (503, 20), (200, 0)])
def test_cve_failures_cannot_remove_or_downgrade_osv_findings(status, cap):
    baseline, _ = run_sca_stage(repo_with(), OsvClient(transport=one_advisory()))
    findings, stats = run_sca_stage(repo_with(), client(status, max_records=cap))
    assert [(f.title, f.severity, f.confidence) for f in findings] == [
        (f.title, f.severity, f.confidence) for f in baseline]
    assert stats["cve"]["status"] == "unavailable"
    assert stats["skipped_reason"] is None
    score = {"scan_manifest": {"sca_cve": stats["cve"]}}
    assert "CVE record lookup incomplete" in dict(non_model_status_notices(score))
    assert "unavailable" in dict(manifest_rows(score))["CVE Program"]


def test_rejected_record_surfaces_disagreement_without_changing_score():
    normal = scan(client())
    rejected = scan(client(rejected=True))
    assert rejected["score"]["total"] == normal["score"]["total"]
    assert "CVE source disagreement" in dict(non_model_status_notices(rejected["score"]))
    html = render_report(rejected)
    assert "REJECTED" in html and "Duplicate record" in html
    assert "CNA English description" not in html


def test_hostile_cna_text_is_escaped_in_html():
    c = client()
    record = published()
    record["containers"]["cna"]["descriptions"] = [{"lang": "en", "value": "<script>alert('CVE')</script>"}]
    c.cve_client.transport = httpx.MockTransport(lambda _: httpx.Response(200, json=record))
    html = render_report(scan(c))
    assert "<script>alert('CVE')</script>" not in html
    assert "&lt;script&gt;" in html


def test_factory_policy_and_no_match_make_no_cve_requests(monkeypatch):
    monkeypatch.delenv("CVE_ENABLED", raising=False)
    monkeypatch.delenv("SCA_ENABLED", raising=False)
    assert sca_client_for(paid=True).cve_client is not None
    assert sca_client_for(paid=False) is None
    assert sca_client_for(paid=True, opt_out=True) is None
    assert sca_client_for(paid=True, requested=False) is None
    monkeypatch.setenv("SCA_ENABLED", "0")
    assert sca_client_for(paid=True) is None
    assert sca_client_for(paid=True, requested=True).cve_client is not None
    monkeypatch.setenv("CVE_ENABLED", "0")
    assert sca_client_for(paid=True, requested=True).cve_client is None
    c = client()
    c.transport = FakeTransport([[{}]], {})
    c.cve_client.transport = httpx.MockTransport(lambda _: pytest.fail("No CVE request expected"))
    _, stats = run_sca_stage(repo_with(), c)
    assert stats["cve"]["status"] == "not_applicable"
    assert stats["cve"]["attempted"] == 0


def test_aliases_are_deduplicated_across_osv_records():
    other = {**LODASH_ADVISORY, "id": "GHSA-second", "aliases": [FIRST, FIRST, "CVE-2021-23337/../../secrets"]}
    c = client()
    c.transport = FakeTransport([[{"vulns": [{"id": LODASH_ADVISORY["id"]}, {"id": "GHSA-second"}]}]],
                                {LODASH_ADVISORY["id"]: LODASH_ADVISORY, "GHSA-second": other})
    findings, stats = run_sca_stage(repo_with(), c)
    assert stats["cve"]["attempted"] == 1
    assert len(findings) == 1


def test_paid_cache_completes_cve_without_model_and_keeps_evidence_on_outage(monkeypatch):
    monkeypatch.delenv("CVE_ENABLED", raising=False)
    monkeypatch.delenv("SCA_ENABLED", raising=False)
    old = stored_row(10)
    assert needs_dependency_scan(old)
    result = complete_cached_dependencies(old, repo_with(), client())
    assert result["llm_usage"]["calls"] == 0
    assert result["score"]["scan_manifest"]["sca_cve"]["resolved"] == 1
    cached = {**old, "score_json": result["score"], "findings_json": result["findings"],
              "dependency_inventory": result["dependency_inventory"]}
    failed = complete_cached_dependencies(cached, repo_with(), client(503))
    assert failed["score"] == cached["score_json"]
    assert failed["findings"] == cached["findings_json"]
    assert not needs_dependency_scan(cached)


@pytest.mark.asyncio
async def test_scheduled_refresh_records_cve_and_preserves_it_when_unavailable():
    old = stored_row(10)
    repo = StoredRepo([old])
    summary = await refresh_stale_dependency_audits(repo, client_factory=client, now=NOW)
    assert summary["refreshed"] == 1
    cve = repo.created[0]["score_json"]["scan_manifest"]["sca_cve"]
    assert cve["status"] == "complete"
    old_with_cve = deepcopy(old)
    old_with_cve["score_json"]["scan_manifest"]["sca_cve"] = cve
    repo = StoredRepo([old_with_cve])
    summary = await refresh_stale_dependency_audits(repo, client_factory=lambda: client(503), now=NOW)
    assert summary["unavailable"] == 1 and not repo.created
    assert repo.rows[0] == old_with_cve


def test_complete_osv_answer_can_retire_old_cve_evidence():
    old = stored_row(10)
    old["score_json"]["scan_manifest"]["sca_cve"] = client().cve_client.lookup([FIRST])
    c = client()
    c.transport = FakeTransport([[{}]], {})
    result = complete_cached_dependencies(old, repo_with(), c)
    assert result["score"]["scan_manifest"]["sca_cve"]["status"] == "not_applicable"
    assert not any(f["rule_id"] == "dependency-known-vulnerability" for f in result["findings"])


def test_shared_cve_report_contract():
    cases = json.loads((Path(__file__).parent / "fixtures/cve-report.json").read_text())
    for case in cases:
        assert [list(row) for row in cve_rows(case["value"])] == case["rows"], case["name"]
        assert [list(row) for row in cve_notices(case["value"])] == case["notices"], case["name"]

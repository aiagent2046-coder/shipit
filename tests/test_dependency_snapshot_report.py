"""Offline provenance and uncertainty survive HTML, web parity and SARIF export."""
from copy import deepcopy
from html import escape
import json
from pathlib import Path

import pytest

from app.report.dependency_snapshot import snapshot_coverage, snapshot_metadata, snapshot_notices, snapshot_rows
from app.report.evidence import claim_evidence_rows, evidence_label, manifest_rows, non_model_status_notices
from app.report.html import render_report
from app.report.sarif import build_sarif


CASES = json.loads((Path(__file__).parents[1] / "web/src/lib/fixtures/dependency_snapshot_cases.json").read_text())


def score_for(case):
    return {"basis": "static+preview", "categories": {}, "scan_manifest": {
        "model_calls": 1, "limitations": ["dependency_snapshot_scope", "dependency_runtime_reachability_not_checked"],
        "sca_skipped_reason": "no_client", "dependency_cve": deepcopy(case["coverage"]),
        "dependency_snapshot": deepcopy(case["metadata"]),
    }}


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_snapshot_report_parity(case):
    before = deepcopy(case)
    normalized = snapshot_coverage(case["coverage"])
    assert (normalized["status"] if normalized else None) == case["status"]
    rows = snapshot_rows(case["coverage"], case["metadata"])
    notices = snapshot_notices(case["coverage"], case["metadata"])
    assert [title for title, _ in notices] == case["notice_titles"]
    for fragment in case["fragments"]:
        assert fragment in json.dumps(rows)
    if case["name"] != "absent":
        score = score_for(case)
        assert all(row in manifest_rows(score) for row in rows)
        assert non_model_status_notices(score) == notices
        html = render_report({"score": score, "findings": []})
        assert "Not checked in this audit. This check is part of a paid audit." not in html
        assert 'aria-label="Dependency check not run"' not in html
        for title, detail in notices:
            assert html.index(f'aria-label="{escape(title)}"') < html.index("No issues found by the current checks")
            assert escape(detail) in html
        assert "private-cache-value" not in html
    assert case == before


def test_snapshot_success_keeps_remote_skip_separate():
    score = score_for(CASES[0])
    score["scan_manifest"]["limitations"].append("dependency_check_not_run")
    notices = dict(non_model_status_notices(score))
    assert set(notices) == {"Live OSV lookup not run"}
    assert "database was not queried" in notices["Live OSV lookup not run"]
    assert dict(manifest_rows(score))["Live OSV lookup"] == "Not run. Bundled snapshot results are recorded separately."


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_sarif_keeps_snapshot_metadata_without_private_fingerprint(case):
    score = score_for(case)
    sarif = build_sarif([], engine_version="test", score=score)
    invocation = sarif["runs"][0]["invocations"][0]
    metadata = snapshot_metadata(case["metadata"])
    assert invocation["properties"].get("dependencySnapshot") == metadata
    assert "private-cache-value" not in json.dumps(sarif)
    if case["status"] == "unavailable":
        assert invocation["executionSuccessful"] is False


@pytest.mark.parametrize("field,value", [
    ("version", True), ("mode", "network"), ("catalog_sha256", "bad"),
    ("checked_at", "2026-02-30T00:00:00Z"), ("retained_findings", True),
])
def test_invalid_snapshot_metadata_cannot_be_exported_as_valid(field, value):
    metadata = {**CASES[0]["metadata"], field: value}
    assert snapshot_metadata(metadata) is None
    score = score_for(CASES[0])
    score["scan_manifest"]["dependency_snapshot"] = metadata
    result = build_sarif([], engine_version="test", score=score)
    assert "dependencySnapshot" not in result["runs"][0]["invocations"][0]["properties"]


def test_retained_finding_shows_its_original_source_separately_from_new_catalog():
    old = {"name": "cvelist", **CASES[0]["coverage"]["sources"]["cvelist"], "commit": "d" * 40}
    finding = {"rule_id": "dependency-cve-match", "title": "Package version matches CVE",
               "severity": "high", "confidence": 0.9, "category": "Security", "file": "requirements.txt", "line": 1,
               "source": "dependency", "verification_method": "package_version_match",
               "verification_status": "unverified",
               "claim_evidence": {"version": 1, "snapshot_sources": [old]}}
    assert evidence_label(finding) == "Dependency version match — reachability unverified"
    assert "d" * 40 in json.dumps(claim_evidence_rows(finding))
    html = render_report({"score": score_for(CASES[0]), "findings": [finding]})
    assert "d" * 40 in html and "a" * 40 in html
    assert "Legacy finding" not in html
    assert "Application reachability was not checked." in html

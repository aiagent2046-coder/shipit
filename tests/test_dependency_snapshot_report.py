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


KEV_SNAPSHOT = {"feed": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                "catalog_version": "2026.11.03", "generated_at": "2026-11-03T20:00:24.8741Z", "sha256": "e" * 64}
UNREADABLE = "Recorded but unreadable; treat as not assessed."
KEV_LISTED = {"status": "listed", "source": "cisa-kev", "cve_id": "CVE-2025-12345", "date_added": "2026-10-01",
              "due_date": "2026-10-22", "ransomware": "Known", "snapshot": KEV_SNAPSHOT}


def dependency_finding(exploitation=..., severity="high"):
    evidence = {"version": 1, "snapshot_sources": [{"name": "cvelist", **CASES[0]["coverage"]["sources"]["cvelist"]}]}
    if exploitation is not ...:
        evidence["exploitation"] = exploitation
    return {"rule_id": "dependency-cve-match", "title": "widget 1.2.3 matches CVE-2025-12345",
            "severity": severity, "confidence": 0.9, "category": "Security", "file": "package-lock.json", "line": 1,
            "source": "dependency", "verification_method": "package_version_match",
            "verification_status": "unverified", "claim_evidence": evidence}


@pytest.mark.parametrize("exploitation,fragment", [
    (KEV_LISTED, "Listed in the CISA Known Exploited Vulnerabilities catalog as CVE-2025-12345; added 2026-10-01; "
                 "federal due date 2026-10-22; known ransomware campaign use: Known. KEV catalog version 2026.11.03."),
    ({"status": "not_listed", "source": "cisa-kev", "snapshot": KEV_SNAPSHOT},
     "Not listed in CISA KEV catalog version 2026.11.03. Absence does not establish"),
    ({"status": "not_assessed"}, "Not assessed; this finding's snapshot carried no exploitation source."),
    (..., "Not assessed; this finding's snapshot carried no exploitation source."),
    ({**KEV_LISTED, "ransomware": "Maybe"}, UNREADABLE),
    ({**KEV_LISTED, "snapshot": {**KEV_SNAPSHOT, "sha256": "short"}}, UNREADABLE),
    ({"status": "listed", "source": "cisa-kev", "snapshot": KEV_SNAPSHOT}, UNREADABLE),
    ({"status": "not_listed", "source": "other", "snapshot": KEV_SNAPSHOT}, UNREADABLE),
])
def test_known_exploitation_row_states_listing_without_claiming_application_exploitation(exploitation, fragment):
    finding = dependency_finding(exploitation)
    rows = dict(claim_evidence_rows(finding))
    assert fragment in rows["Known exploitation"]
    assert "Exploitation elsewhere does not establish exploitation of this application." in rows["Known exploitation"] \
        or exploitation is ... or exploitation.get("status") != "listed" or "unreadable" in rows["Known exploitation"]
    assert evidence_label(finding) == "Dependency version match — reachability unverified"
    html = render_report({"score": score_for(CASES[0]), "findings": [finding]})
    assert escape(fragment) in html or fragment in html


def test_sarif_marks_kev_listing_as_a_property_not_a_verification():
    listed = dependency_finding(KEV_LISTED, severity="critical")
    plain = dependency_finding({"status": "not_listed", "source": "cisa-kev", "snapshot": KEV_SNAPSHOT})
    legacy = dependency_finding()
    sarif = build_sarif([listed, plain, legacy], engine_version="test", score=score_for(CASES[0]))
    results = sarif["runs"][0]["results"]
    assert [r["properties"]["knownExploited"] for r in results] == [True, False, False]
    assert all(r["properties"]["verificationStatus"] == "unverified" for r in results)
    assert results[0]["properties"]["dependencyEvidence"]["exploitation"] == KEV_LISTED

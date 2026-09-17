"""A unique dependency assessment retains every recorded manifest in exports."""

from copy import deepcopy
from html import escape
import json
from pathlib import Path
from urllib.parse import urlsplit

import jsonschema
import pytest

from app.report.html import render_report
from app.report.plain_language import plain_fields
from app.report.sarif import build_sarif


DEPENDENCY_RULES = ("dependency-cve-match", "dependency-known-vulnerability")


@pytest.fixture(scope="module")
def schema():
    path = Path(__file__).parent / "fixtures" / "sarif-schema-2.1.0.json"
    return json.loads(path.read_text())


def finding(rule_id):
    occurrences = [
        {"manifest": "repo/email-worker/package-lock.json", "line": 0,
         "direct": False, "dependency_scope": "development", "dependency_groups": ["devDependencies"]},
        {"manifest": "repo/server/package-lock.json", "line": 12,
         "direct": True, "dependency_scope": "runtime", "dependency_groups": []},
        {"manifest": "repo/worker-r2/package-lock.json", "line": 0,
         "direct": False, "dependency_scope": "unknown", "dependency_groups": []},
    ]
    return {
        "rule_id": rule_id, "title": "widget 1.0.0 matches an advisory",
        "severity": "high", "confidence": 0.9, "category": "Security",
        "file": occurrences[1]["manifest"], "line": occurrences[1]["line"],
        "explanation": "The exact version is affected; reachability was not checked.",
        "fix_hint": "Review every recorded manifest and the advisory ranges.",
        "verification_status": "unverified", "verification_method": "package_version_match",
        "claim_evidence": {
            "version": 1, "ecosystem": "npm", "package": "widget", "installed_version": "1.0.0",
            "manifest": occurrences[1]["manifest"], "occurrences": occurrences,
            "occurrences_recorded": True,
        },
    }


def validate(document, schema):
    jsonschema.validate(document, schema, format_checker=jsonschema.FormatChecker())


@pytest.mark.parametrize("rule_id", DEPENDENCY_RULES)
def test_one_assessment_exports_all_origins_with_their_scope_and_directness(schema, rule_id):
    source = finding(rule_id)
    original = deepcopy(source)
    document = build_sarif([source], engine_version="test", archive_root="repo")
    validate(document, schema)
    result, = document["runs"][0]["results"]
    locations = [item["physicalLocation"] for item in result["locations"]]
    assert locations == [
        {"artifactLocation": {"uri": "server/package-lock.json"}, "region": {"startLine": 12}},
        {"artifactLocation": {"uri": "email-worker/package-lock.json"}},
        {"artifactLocation": {"uri": "worker-r2/package-lock.json"}},
    ]
    assert result["properties"]["dependencyEvidence"] == original["claim_evidence"]
    assert result["properties"]["verificationStatus"] == "unverified"
    assert result["properties"]["verificationMethod"] == "package_version_match"
    assert source == original


def test_multiple_advisories_keep_their_original_result_count(schema):
    sources = [finding("dependency-cve-match"), finding("dependency-cve-match")]
    for index, source in enumerate(sources):
        source["claim_evidence"]["advisory_id"] = f"CVE-2026-{10000 + index}"
        source["title"] = source["claim_evidence"]["advisory_id"]
    document = build_sarif(sources, engine_version="test")
    validate(document, schema)
    results = document["runs"][0]["results"]
    assert len(results) == 2
    assert [item["properties"]["dependencyEvidence"]["advisory_id"] for item in results] == [
        "CVE-2026-10000", "CVE-2026-10001",
    ]
    assert all(len(item["locations"]) == 3 for item in results)


@pytest.mark.parametrize("rule_id", DEPENDENCY_RULES)
@pytest.mark.parametrize("evidence", [None, {}, {"version": 1, "manifest": "package-lock.json"}])
def test_legacy_finding_keeps_its_only_recorded_location(schema, rule_id, evidence):
    source = finding(rule_id)
    source.update(file="package-lock.json", line=0, claim_evidence=evidence)
    document = build_sarif([source], engine_version="test")
    validate(document, schema)
    result, = document["runs"][0]["results"]
    assert len(result["locations"]) == 1
    assert result["locations"][0]["physicalLocation"] == {
        "artifactLocation": {"uri": "package-lock.json"},
    }
    assert result["properties"]["dependencyEvidence"] == (evidence or {})


@pytest.mark.parametrize("rule_id", DEPENDENCY_RULES)
def test_every_origin_uses_uri_escaping_and_explicit_wrapper_rules(schema, rule_id):
    source = finding(rule_id)
    paths = [
        'repo/modules/<svg onload="x">/package-lock.json',
        "repo/javascript:alert(1)/package-lock.json",
        "repo-other/space #?%/requirements.txt",
    ]
    for occurrence, path in zip(source["claim_evidence"]["occurrences"], paths):
        occurrence["manifest"] = path
    source.update(file=paths[1], line=12)
    source["claim_evidence"]["manifest"] = paths[1]
    document = build_sarif([source], engine_version="test", archive_root="repo")
    validate(document, schema)
    result, = document["runs"][0]["results"]
    uris = [item["physicalLocation"]["artifactLocation"]["uri"] for item in result["locations"]]
    assert uris == [
        "javascript%3Aalert%281%29/package-lock.json",
        "modules/%3Csvg%20onload%3D%22x%22%3E/package-lock.json",
        "repo-other/space%20%23%3F%25/requirements.txt",
    ]
    assert all(not urlsplit(uri).scheme and not urlsplit(uri).netloc for uri in uris)
    assert [item["manifest"] for item in result["properties"]["dependencyEvidence"]["occurrences"]] == paths


@pytest.mark.parametrize("rule_id", DEPENDENCY_RULES)
def test_human_report_keeps_and_escapes_the_producer_occurrence_summary(rule_id):
    source = finding(rule_id)
    origins = ["email-worker/package-lock.json", 'worker-<svg onload="x">/package-lock.json']
    summary = "Recorded manifests: " + "; ".join(origins) + "."
    source["explanation"] += " " + summary
    assert plain_fields(source)[1] == source["explanation"]
    html = render_report({"score": {}, "findings": [source]})
    assert escape(summary) in html
    assert '<svg onload="x">' not in html

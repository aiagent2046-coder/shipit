"""Partial static work stays visible even when no findings were produced."""
from copy import deepcopy
from html import escape
import json
from pathlib import Path

import pytest

from app.report.evidence import manifest_rows, non_model_status_notices
from app.report.html import render_report


CASES = json.loads((Path(__file__).parents[1] / "web/src/lib/fixtures/rule_coverage_cases.json").read_text())


def score_for(case):
    manifest = {"static_checks": [case["rule"]], "static_limits": {}, "limitations": []}
    if case["record"] is not None:
        manifest["rule_coverage"] = {case["rule"]: deepcopy(case["record"])}
    return {"basis": "static_only", "categories": {}, "scan_manifest": manifest}


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_file_accounting_and_legacy_states_match_browser(case):
    score = score_for(case)
    before = deepcopy(score)
    rows = dict(manifest_rows(score))
    label = case["label"]
    assert rows[f"File coverage: {label}"] == case["summary"]
    assert rows.get(f"Files excluded: {label}") == case["exclusions"]
    assert rows.get(f"Files not fully analyzed: {label}") == case["skips"]
    notices = non_model_status_notices(score)
    assert len(notices) == bool(case["notice"])
    html = render_report({"score": score, "findings": []})
    if case["notice"]:
        title, detail = notices[0]
        assert title == "Static checks incomplete"
        assert case["notice"] in detail
        assert "named rules only" in detail
        assert "does not establish safety" in detail
        assert escape(detail) in html
        assert html.index('aria-label="Static checks incomplete"') < html.index("No issues found by the current checks")
    else:
        assert 'aria-label="Static checks incomplete"' not in html
    assert escape(case["summary"]) in html
    assert score == before


def test_unknown_rule_metadata_never_reaches_report():
    score = score_for(CASES[0])
    private = "private/source/key.py <script>source-value</script>"
    coverage = score["scan_manifest"]["rule_coverage"]
    record = coverage[CASES[0]["rule"]]
    record["source"] = private
    record["exclusion_reasons"][private] = private
    record["skip_reasons"][private] = private
    coverage[private] = deepcopy(record)
    before = deepcopy(score)
    assert "private/source" not in json.dumps(manifest_rows(score))
    assert "private/source" not in json.dumps(non_model_status_notices(score))
    assert "private/source" not in render_report({"score": score, "findings": []})
    assert score == before


@pytest.mark.parametrize("field,value", [
    ("version", True), ("version", 2), ("eligible_files", True),
    ("attempted_files", -1), ("analyzed_files", "398"),
    ("skip_reasons", {"file_limit": "440"}),
])
def test_malformed_accounting_is_unknown_not_a_clean_result(field, value):
    score = score_for(CASES[0])
    score["scan_manifest"]["rule_coverage"][CASES[0]["rule"]][field] = value
    rows = dict(manifest_rows(score))
    assert rows["File coverage: Unsafe deserialization"] == "Not recorded for this audit"
    assert "Files not fully analyzed: Unsafe deserialization" not in rows
    assert non_model_status_notices(score) == []


def test_legacy_counts_are_not_inferred_from_secrets_or_archive_size():
    score = {"scan_manifest": {"archive_files": 840, "static_checks": [
        "outbound_url", "tls_verification", "unsafe_deserialization", "path_traversal",
    ], "secrets_coverage": {"files_scanned": 840}, "static_limits": {
        "tls_verification": "Bounded TLS checks",
    }}}
    coverage = [(label, value) for label, value in manifest_rows(score) if label.startswith("File coverage:")]
    assert len(coverage) == 4
    assert {value for _, value in coverage} == {"Not recorded for this audit"}

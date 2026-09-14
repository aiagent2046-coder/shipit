"""Partial static work stays visible even when no findings were produced."""
from copy import deepcopy
from html import escape
import io
import json
from pathlib import Path
import zipfile

import pytest

from app.report.evidence import manifest_rows, non_model_status_notices
from app.report.html import render_report
from app.scan.manifest import scan_manifest
from app.scan.xxe import scan_unsafe_xml_parse
from app.scan.archive_extraction import scan_archive_extraction


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


@pytest.mark.parametrize("signals", [1, 33])
@pytest.mark.parametrize("scanner,check,label,signal", [
    (scan_unsafe_xml_parse, "unsafe_xml_parse", "XML entity resolution",
     'from lxml import etree\netree.parse(source, etree.XMLParser(resolve_entities=True))\n'),
    (scan_archive_extraction, "archive_extraction", "Archive extraction",
     'import tarfile\ntarfile.open(source).extractall(dest, filter="fully_trusted")\n'),
])
def test_scanner_coverage_reaches_html_with_its_real_finding_limit(signals, scanner, check, label, signal):
    data = io.BytesIO()
    source = signal * signals
    with zipfile.ZipFile(data, "w") as archive:
        archive.writestr("app/feed.py", source)
    coverage = {}
    findings = scanner(io.BytesIO(data.getvalue()), coverage=coverage)
    assert len(findings) == min(signals, 32)
    manifest = scan_manifest(data.getvalue(), "test", {
        "checks_run": [check], "rule_coverage": {check: coverage},
    }, None, None)
    score = {"basis": "static_only", "categories": {}, "scan_manifest": manifest}
    rows = dict(manifest_rows(score))
    notices = non_model_status_notices(score)
    html = render_report({"score": score, "findings": [vars(finding) for finding in findings]})
    assert escape(rows[f"File coverage: {label}"]) in html
    if signals > 32:
        assert rows[f"Files not fully analyzed: {label}"] == "finding limit: 1"
        assert len(notices) == 1
        assert notices[0][0] == "Static checks incomplete"
        assert f"{label}: 0 of 1 eligible files analyzed" in notices[0][1]
        assert escape(notices[0][1]) in html
    else:
        assert rows[f"Files not fully analyzed: {label}"] == "None recorded"
        assert notices == []
        assert 'aria-label="Static checks incomplete"' not in html


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


def test_every_counted_rule_is_visible_in_report_coverage():
    from app.report.evidence import RULE_COVERAGE_LABELS
    from app.scan.rule_coverage import RULE_COVERAGE_KEYS
    assert set(RULE_COVERAGE_LABELS) == set(RULE_COVERAGE_KEYS)

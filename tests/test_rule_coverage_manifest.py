"""Real scan accounting reaches persisted reports without carrying source values."""

import copy
import io
import json
import zipfile

import pytest

from app.llm.client import LLMClient
from app.report.html import render_report
from app.report.sarif import build_sarif
from app.scan.manifest import scan_manifest
from app.scan.pipeline import run_scan
from app.scan.rule_coverage import RULE_COVERAGE_KEYS, normalize_rule_coverage


def archive(files):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as z:
        for name, content in files:
            z.writestr(name, content)
    return stream.getvalue()


def partial_record():
    return {
        "version": 1, "files_total": 842, "eligible_files": 840, "attempted_files": 400,
        "analyzed_files": 400, "excluded_files": 2, "skipped_files": 440,
        "exclusion_reasons": {"dependency_tree": 2}, "skip_reasons": {"file_limit": 440}, "partial": True,
    }


def test_real_scan_records_the_unread_tail_for_each_bounded_rule():
    data = archive([(f"project/app/module_{i}.py", "value = 1\n") for i in range(840)] + [
        ("project/.venv/pkg/a.py", "value = 1\n"), ("project/vendor/pkg/b.py", "value = 1\n"),
    ])
    scan = run_scan(data, LLMClient(providers=[]))
    counts = scan["score"]["scan_manifest"]["rule_coverage"]
    assert set(counts) == set(RULE_COVERAGE_KEYS)
    assert all(record == partial_record() for record in counts.values())
    # A report round-trip must retain the measured scope even with no findings
    # from these four rules. The visible notice is exercised by report tests.
    restored = json.loads(json.dumps(scan))
    assert restored["score"]["scan_manifest"]["rule_coverage"] == counts
    html = render_report(restored)
    assert "840" in html and "440" in html
    assert 'aria-label="Static checks incomplete"' in html


def test_manifest_exports_only_fixed_counts_and_known_reason_names():
    marker = "private-source-and-exception-text"
    extended = {**partial_record(), "file": marker, "exception": marker,
                "exclusion_reasons": {"dependency_tree": 2, marker: marker},
                "skip_reasons": {"file_limit": 440, marker: marker}}
    original = copy.deepcopy(extended)
    manifest = scan_manifest(archive([]), "test", {"rule_coverage": {
        "outbound_url": extended, marker: extended,
    }}, {}, None)
    assert manifest["rule_coverage"] == {"outbound_url": partial_record()}
    assert marker not in json.dumps(manifest)
    assert extended == original


@pytest.mark.parametrize("field,value", [
    ("eligible_files", -1), ("analyzed_files", True), ("attempted_files", 399),
    ("skipped_files", 0), ("version", 2), ("files_total", "842"),
    ("skip_reasons", {"file_limit": "440"}), ("exclusion_reasons", {"dependency_tree": 1}),
])
def test_invalid_accounting_stays_unknown(field, value):
    assert normalize_rule_coverage({"outbound_url": {**partial_record(), field: value}}) == {}


def test_partial_is_derived_from_recorded_counts_not_an_untrusted_flag():
    assert normalize_rule_coverage({"outbound_url": {**partial_record(), "partial": False}}) == {
        "outbound_url": partial_record(),
    }


def test_missing_accounting_does_not_become_a_zero_or_complete_record():
    manifest = scan_manifest(archive([]), "test", {}, {}, None)
    assert manifest["rule_coverage"] is None


def test_sarif_keeps_partial_scope_even_without_findings():
    record = partial_record()
    result = build_sarif([], engine_version="test", score={"scan_manifest": {
        "rule_coverage": {"outbound_url": {**record, "source": "not-exported"}},
    }})
    run = result["runs"][0]
    assert run["results"] == []
    assert run["invocations"][0]["properties"]["ruleCoverage"] == {"outbound_url": record}
    assert "not-exported" not in json.dumps(result)

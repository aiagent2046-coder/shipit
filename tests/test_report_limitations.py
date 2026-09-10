"""Stage-specific notices must not turn a skipped SCA query into a model outage."""
from copy import deepcopy
from html import escape
import json
from pathlib import Path

import pytest

from app.report.evidence import manifest_rows, model_status_notice, non_model_status_notices
from app.report.html import render_report
from app.scan.manifest import SCA_LIMITATIONS, scan_manifest
from tests.test_audit_llm_wiring import make_zip


# The browser helper reads the same scenarios, including legacy and mixed failures.
CASES = json.loads((Path(__file__).parents[1] / "web/src/lib/fixtures/report_limitation_cases.json").read_text())


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_model_dependency_and_unknown_limits_are_kept_separate(case):
    score = {"basis": case["basis"], "categories": {}}
    if not case.get("no_manifest"):
        score["scan_manifest"] = {"model_calls": case["calls"], "limitations": case["limitations"]}
    before = deepcopy(score)
    notice = model_status_notice(score)
    assert (notice[0] if notice else None) == case["model_title"]
    for detail in case["model_details"]:
        assert detail in notice[1]
    if notice:
        assert all(reason not in notice[1] for reason in case["other_reasons"])
    other_notices = non_model_status_notices(score)
    notices = dict(other_notices)
    expected_count = bool(case["dependency_reasons"]) + bool(case["other_reasons"])
    assert len(other_notices) == expected_count
    if case["dependency_reasons"]:
        assert case["dependency_detail"] in notices[case["dependency_title"]]
    if case["other_reasons"]:
        assert ", ".join(case["other_reasons"]) in notices["Additional audit limitations recorded"]
    if not case.get("no_manifest"):
        rows = dict(manifest_rows(score))
        for kind, reasons in (("Model", case["model_reasons"]), ("Dependency", case["dependency_reasons"]),
                              ("Other audit", case["other_reasons"])):
            assert rows.get(kind + " limits / skip reasons") == (
                ", ".join(reasons) if reasons else "None recorded" if kind == "Model" else None)
    html = render_report({"score": score, "findings": []})
    assert ('aria-label="Model review status"' in html) == bool(notice)
    for title, detail in other_notices:
        assert html.index(f'aria-label="{escape(title)}"') < html.index("No issues found by the current checks")
        assert escape(detail) in html
    assert score == before


def test_successful_empty_preview_with_unqueried_dependencies_is_not_a_model_failure():
    data = make_zip({"main.py": b"print('hello')"}).getvalue()
    manifest = scan_manifest(data, "test", {}, {
        "calls": 1, "model": "preview", "model_findings": [{
            "model": "preview", "responses": 1, "invalid_responses": 0, "empty_responses": 1,
            "received": 0, "accepted": 0, "rejected": 0, "merged": 0, "saved": 0, "rejection_reasons": {},
        }],
    }, None, {"skipped_reason": "no_client", "dependencies": 24})
    score = {"basis": "static+preview", "categories": {}, "scan_manifest": manifest}
    assert model_status_notice(score) is None
    assert non_model_status_notices(score)[0][0] == "Dependency check not run"
    html = render_report({"score": score, "findings": []})
    assert "Model review incomplete" not in html
    assert "valid empty: 1" in html
    assert "24 packages" in html and "vulnerability database was not queried" in html


def test_unknown_limit_text_is_escaped_in_the_report():
    reason = '<script>alert("audit")</script>'
    score = {"basis": "static+preview", "categories": {}, "scan_manifest": {
        "model_calls": 1, "limitations": [reason],
    }}
    html = render_report({"score": score, "findings": []})
    assert reason not in html and escape(reason) in html
    assert 'aria-label="Additional audit limitations recorded"' in html
    assert 'aria-label="Model review status"' not in html


def test_parity_cases_cover_each_dependency_producer_reason():
    assert {reason for case in CASES for reason in case["dependency_reasons"]} == SCA_LIMITATIONS

"""Related loader locations are a view, not deduplication or verification."""
from copy import deepcopy
import json

import pytest

from app.report.grouping import group_for_display, related_finding_groups
from app.report.html import render_report
from app.report.sarif import build_sarif
from app.scan.scoring import ScoredFinding, compute_scores


def finding(line: int, confidence: float = .8) -> dict:
    return {
        "rule_id": "unsafe-deserialization", "source": "static", "severity": "high",
        "confidence": confidence, "category": "Security", "file": "model/checkpoints.py", "line": line,
        "title": f"Pickle loader at {line}", "explanation": f"Original explanation {line}",
        "fix_hint": f"Original suggestion {line}", "verification_status": "unverified",
        "verification_method": "source_pattern", "context": "code",
        "claim_evidence": {
            "version": 1, "source_check": {"kind": "static_rule"}, "observation": None,
            "required_conditions": None, "conditions_status": "not_checked", "consequence_status": "not_checked",
            "deserialization_observation": {
                "version": 1, "method": "python_ast_import_resolved", "file": "model/checkpoints.py",
                "source_sha256": "a" * 64, "sink_line": line, "sink_span": [line, 8, line, 24],
                "sink_method": "load", "loader": "pickle.load", "input_control_status": "not_checked",
            },
        },
    }


def test_group_preserves_each_original_and_never_changes_score_or_exports():
    findings = [finding(77, .8), finding(128, .6)]
    original_json = json.dumps(findings)
    score = compute_scores([ScoredFinding(**{k: v for k, v in row.items()
                                            if k in ScoredFinding.__dataclass_fields__}) for row in findings])
    before_score = deepcopy(score)
    before_sarif = build_sarif(findings, engine_version="test")
    groups = related_finding_groups(findings)
    assert len(groups) == 1
    assert groups[0][0] is findings[0] and groups[0][1] is findings[1]
    # The API's existing RLS projection must not replace these with a representative.
    assert group_for_display(findings) == findings
    html = render_report({"score": score, "findings": findings})
    assert "Pickle file loading · 2 locations" in html
    assert "2 observations: 2 in source" in html
    for line in (77, 128):
        assert f"model/checkpoints.py:{line}" in html
        assert f"Original explanation {line}" in html
        assert f"Original suggestion {line}" in html
    assert json.dumps(findings) == original_json
    assert score == before_score
    assert build_sarif(findings, engine_version="test") == before_sarif
    assert [f["confidence"] for f in groups[0]] == [.8, .6]
    assert [f["verification_status"] for f in groups[0]] == ["unverified", "unverified"]


@pytest.mark.parametrize("field,value", [
    ("source", "llm"), ("context", "test_file"), ("severity", "medium"),
    ("verification_status", "verified"), ("verification_method", "model_review"),
    ("file", "another.py"), ("line", 129),
])
def test_different_claim_context_or_unbound_location_stays_separate(field, value):
    rows = [finding(77), finding(128)]
    rows[1][field] = value
    assert related_finding_groups(rows) == [[rows[0]], [rows[1]]]


@pytest.mark.parametrize("update", [
    {"source_sha256": "b" * 64}, {"loader": "pickle.loads", "sink_method": "loads"},
    {"method": "model_guess"}, {"sink_span": [128, 8, 128, 8]},
])
def test_different_snapshot_or_loader_and_invalid_trace_stays_separate(update):
    rows = [finding(77), finding(128)]
    rows[1]["claim_evidence"]["deserialization_observation"].update(update)
    assert related_finding_groups(rows) == [[rows[0]], [rows[1]]]


def test_historical_prose_and_distinct_source_context_are_not_grouped():
    rows = [finding(77), finding(128)]
    rows[1]["claim_evidence"].pop("deserialization_observation")
    rows[1]["explanation"] = "pickle.load with the same loader"
    assert related_finding_groups(rows) == [[rows[0]], [rows[1]]]
    rows[1] = finding(128)
    rows[1]["claim_evidence"]["source_context"] = {"kind": "doc_example"}
    assert related_finding_groups(rows) == [[rows[0]], [rows[1]]]


def test_duplicate_record_at_one_span_is_not_an_additional_location():
    rows = [finding(77), finding(77)]
    assert related_finding_groups(rows) == [[rows[0]], [rows[1]]]

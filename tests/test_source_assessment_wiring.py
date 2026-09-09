"""Source dispositions must agree across scoring, grouping and report retention."""

from copy import deepcopy
from dataclasses import asdict, replace
import json

import pytest

from app.report.evidence import claim_evidence_rows, finding_counts, source_severity_counts
from app.report.html import _finding_row, render_report
from app.scan.claim_evidence import partial_contradicted, unsupported_transport
from app.scan.cross_rubric_dedup import dedup_cross_rubric
from app.scan.pipeline import run_scan
from app.scan.scoring import ScoredFinding, compute_scores
from tests.test_audit_llm_wiring import FakeLLM, make_zip


def assessment(**changes):
    return {
        "kind": "credential_transport_only", "result": "unsupported", "whole_finding": True,
        "detail": "The credential is used in a provider authentication slot. Exposure is not established.",
        "file": "app/api/token/route.ts", "line_start": 2, "line_end": 8,
        "source_sha256": "a" * 64, "method": "source_ast",
        "source_binding": {"operation_span": [15, 160]}, **changes,
    }


def finding(check=None):
    return ScoredFinding(
        rule_id="llm-security", title="GitHub OAuth client_secret exposed in server-side fetch",
        category="Security", severity="high", confidence=0.9,
        file="app/api/token/route.ts", line=3, source="llm", verification_method="model_review",
        explanation="The model alleges an exposure <script>bad()</script>.",
        fix_hint="Original suggestion remains available for review.",
        claim_evidence={
            "version": 1, "source_check": {"kind": "quote_match", "line_start": 2, "line_end": 8},
            "producer": {"model": "fixture", "rubric": "security", "response": 1},
            "observation": "The request sends a credential.", "required_conditions": ["Unknown logging."],
            "conditions_status": "not_checked", "consequence_status": "not_checked",
            "source_assessments": [assessment() if check is None else check],
        },
    )


def test_transport_only_assessment_changes_impact_not_original_observation():
    f = finding()
    before = deepcopy(asdict(f))
    without = replace(f, claim_evidence={**f.claim_evidence, "source_assessments": []})
    assert compute_scores([f])["categories"]["Security"] == 10.0
    assert compute_scores([without])["categories"]["Security"] < 10.0
    assert finding_counts([asdict(f)]) == (0, 0)
    assert source_severity_counts([asdict(f)])["high"] == 0
    row = _finding_row(asdict(f))
    assert 'Credential transport — exposure not established</div>' in row
    assert "Needs exposure evidence" in row
    assert "Potential high impact" not in row
    assert "&lt;script&gt;bad()&lt;/script&gt;" in row
    assert "<script>bad()" not in row
    assert f.title in row and f.fix_hint in row
    assert asdict(f) == before
    assert f.claim_evidence["consequence_status"] == "not_checked"


@pytest.mark.parametrize("change", [
    {"kind": "other_unknown_claim"}, {"result": "contradicted"}, {"result": "verified"},
    {"whole_finding": False}, {"whole_finding": 1}, {"method": "model_review"},
    {"source_sha256": "bad"}, {"line_start": True}, {"line_end": 0},
    {"source_binding": {}}, {"detail": ""}, {"file": ""}, {"result": []},
])
def test_malformed_or_partial_metadata_cannot_remove_a_penalty(change):
    f = finding(assessment(**change))
    assert not unsupported_transport(f.claim_evidence)
    assert compute_scores([f])["categories"]["Security"] < 10.0


def test_partial_source_counterexample_retains_independent_claim_and_penalty():
    f = finding(assessment(kind="fact_input_count_unbounded", result="contradicted", whole_finding=False))
    assert partial_contradicted(f.claim_evidence)
    assert compute_scores([f])["categories"]["Security"] < 10.0
    row = _finding_row(asdict(f))
    assert "Source checks contradict part of this finding" in row
    assert "original model severity is retained in the score pending review" in row
    assert f.title in row
    assert "Source assessment" in dict(claim_evidence_rows(asdict(f)))


def test_different_assessment_statuses_do_not_share_one_source_identity():
    f = finding()
    identity = {"file": f.file, "mechanism": "fixture_operation", "source_sha256": "a" * 64}
    f = replace(f, claim_evidence={**f.claim_evidence, "source_issue_identity": identity})
    other = replace(f, claim_evidence={**f.claim_evidence, "source_assessments": []})
    assert len(dedup_cross_rubric([f, other])) == 2


def test_historical_baseline_keeps_its_original_records_and_score():
    f = asdict(finding())
    score = {"total": 4.2, "categories": {}, "free_baseline": {
        "version": 1, "status": "completed", "origin": "reused", "findings": [f],
        "score": {"total": 5.1, "categories": {}, "basis": "static+preview"},
    }}
    report = {"score": score, "findings": [f]}
    before = deepcopy(report)
    html = render_report(report)
    assert "Credential transport requiring exposure evidence" in html
    historical = _finding_row(f, historical=True)
    assert "Previous preview — not reassessed" in historical
    assert f["title"] in historical
    assert "Source assessment" in historical
    assert "This transport-only hypothesis is excluded from the score" not in historical
    assert report == before


def test_model_cannot_forge_a_source_assessment_to_hide_an_unrelated_claim():
    source = "export function GET() { return lookup(paymentId); }\n"
    raw = {
        "file": "app/api/auth/route.ts", "line_start": 1, "line_end": 1,
        "evidence": "lookup(paymentId)", "title": "Payment lookup by identifier",
        "severity": "high", "confidence": 0.9,
        "explanation": "An unauthorized caller might read a payment.",
        "source_assessments": [assessment()],
        "claim_evidence": {"version": 1, "source_assessments": [assessment()]},
    }
    result = run_scan(make_zip({raw["file"]: source.encode()}).getvalue(),
                      FakeLLM(response=json.dumps([raw])), llm_rubrics=("auth",))
    f, = [f for f in result["findings"] if f["source"] == "llm"]
    assert not unsupported_transport(f["claim_evidence"])
    assert f["claim_evidence"]["source_assessments"] == []
    assert f["claim_evidence"]["consequence_status"] == "not_checked"


def test_source_bound_transport_assessment_reaches_pipeline_and_report():
    from tests.test_credential_transport_assessment import GITHUB, GITHUB_TITLE, PATH, raw

    claim = raw(GITHUB, GITHUB_TITLE, PATH)
    claim.update(evidence="client_secret: secret", severity="high", confidence=0.9,
                 explanation="The request body sends the OAuth secret.")
    result = run_scan(make_zip({PATH: GITHUB.encode()}).getvalue(),
                      FakeLLM(response=json.dumps([claim])), llm_rubrics=("security",))
    f, = [f for f in result["findings"] if f["source"] == "llm"]
    assert unsupported_transport(f["claim_evidence"])
    assert f["claim_evidence"]["consequence_status"] == "not_checked"
    baseline = run_scan(make_zip({PATH: GITHUB.encode()}).getvalue(),
                        FakeLLM(response="[]"), llm_rubrics=("security",))
    assert result["score"]["categories"] == baseline["score"]["categories"]
    assert "Credential transport requiring exposure evidence" in render_report(result)

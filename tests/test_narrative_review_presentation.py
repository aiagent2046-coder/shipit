"""Unresolved source outcomes stay distinct from proof and score exemptions."""
from copy import deepcopy
from dataclasses import asdict, replace

import pytest

from app.report.evidence import claim_evidence_rows, evidence_label
from app.report.html import _finding_row, _free_baseline
from app.scan.claim_evidence import narrative_review_checks, partial_contradicted
from app.scan.cross_rubric_dedup import dedup_cross_rubric
from app.scan.scoring import compute_scores
from tests.test_source_assessment_wiring import assessment, finding


def review_finding():
    kind = "navigation_pending_outcome_unverified"
    check = assessment(kind=kind, result="observed", whole_finding=False,
                       narrative_review={"status": "required", "premise": kind,
                                         "reason": "Navigation outcome is unverified. <script>bad()</script>"})
    return replace(finding(check), title="The navigation permanently disables the button",
                   category="Frontend", severity="high")


def test_unresolved_outcome_is_neutral_but_retains_original_and_score():
    f = review_finding()
    before = deepcopy(asdict(f))
    assert narrative_review_checks(f.claim_evidence)
    assert not partial_contradicted(f.claim_evidence)
    assert compute_scores([f])["categories"]["Frontend"] == 9.1
    html = _finding_row(asdict(f))
    assert "Outcome needs review" in html
    assert "Source checks leave this outcome unresolved" in html
    assert "original model severity remains in the score" in html
    assert "Potential high impact" not in html
    assert f.title in html and f.fix_hint in html
    assert "&lt;script&gt;bad()&lt;/script&gt;" in html and "<script>bad()</script>" not in html
    assert asdict(f) == before


@pytest.mark.parametrize("change", [
    {"kind": "unknown"}, {"result": "not_checked"}, {"result": "contradicted"},
    {"whole_finding": True}, {"source_sha256": "bad"}, {"source_binding": {}},
    {"narrative_review": {"status": "required", "premise": "other", "reason": "Wrong premise"}},
    {"narrative_review": {"status": "required", "premise": "navigation_pending_outcome_unverified",
                          "reason": " "}},
    {"narrative_review": True},
])
def test_malformed_or_unregistered_review_metadata_does_not_change_disposition(change):
    f = review_finding()
    f.claim_evidence["source_assessments"][0].update(change)
    assert not narrative_review_checks(f.claim_evidence)


def test_historical_baseline_is_not_given_the_current_review_disposition():
    f = asdict(review_finding())
    baseline = {"free_baseline": {"version": 1, "status": "completed", "origin": "reused",
                                 "findings": [f], "score": {"total": 4.0, "categories": {}}}}
    before = deepcopy(baseline)
    html = _free_baseline(baseline)
    assert "Source checks leave this outcome unresolved" not in html
    assert "Original model claim and suggestion — outcome not established" not in html
    assert f["title"] in html
    assert "Outcome needs review" not in dict(claim_evidence_rows(f, historical=True))
    assert "Outcome not established" not in evidence_label(f, historical=True)
    assert baseline == before


def test_reviewed_and_unreviewed_source_observations_are_not_silently_grouped():
    f = review_finding()
    f.claim_evidence["source_issue_identity"] = {"file": f.file, "mechanism": "same_operation"}
    other = replace(f, claim_evidence=deepcopy(f.claim_evidence))
    other.claim_evidence["source_assessments"][0].pop("narrative_review")
    assert len(dedup_cross_rubric([f, other])) == 2

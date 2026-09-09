"""Source-owned external identity, review display and full-original grouping."""
from copy import deepcopy
from dataclasses import asdict, replace
import json

import pytest

from app.report.html import _finding_row
from app.scan.claim_evidence import narrative_review_checks
from app.scan.cross_rubric_dedup import dedup_cross_rubric
from app.scan.external_operation_identity import valid_external_identity, compatible_external_claims
from app.scan.pipeline import run_scan
from app.scan.scoring import ScoredFinding, compute_scores
from tests.test_audit_llm_wiring import FakeLLM, make_zip
from tests.test_external_call_assessment import CLASSIFIED, POLL
from tests.test_external_operation_identity import item


def scored():
    raw, identity = item()
    raw["claim_evidence"].update(version=1, source_issue_identity=identity)
    return ScoredFinding(**raw, rule_id="llm-money", severity="high", confidence=0.9, line=22)


def test_exact_external_claims_keep_originals_and_one_penalty():
    first = scored()
    second = replace(first, title=first.title.upper(), line=23)
    grouped = dedup_cross_rubric([first, second])
    assert len(grouped) == 1
    assert len(grouped[0].claim_evidence["grouped_originals"]) == 2
    assert dedup_cross_rubric(grouped) == grouped
    assert compute_scores(grouped) == compute_scores([first])


@pytest.mark.parametrize("change", ["title", "conditions", "review", "malformed_identity"])
def test_same_external_call_cannot_merge_distinct_or_malformed_claims(change):
    first = scored()
    second = replace(first, claim_evidence=deepcopy(first.claim_evidence))
    if change == "title":
        second = replace(second, title=second.title + " and cause SSRF")
    elif change == "conditions":
        second.claim_evidence["required_conditions"] = ["Client retries after timeout"]
    elif change == "review":
        second.claim_evidence["source_assessments"][0]["narrative_review"] = True
    else:
        second.claim_evidence["source_issue_identity"]["operation_span"] = [True, 100]
    assert len(dedup_cross_rubric([first, second])) == 2


def test_model_cannot_supply_the_external_identity_and_review_for_a_different_operation():
    source = CLASSIFIED + POLL
    path = "lib/billing/provider.ts"
    line = next(i + 1 for i, row in enumerate(source.splitlines()) if "let attempts" in row)
    claim = {"file": path, "line_start": line, "line_end": line, "evidence": "let attempts = 0;",
             "title": "Polling loop can take up to 40 seconds", "severity": "high", "confidence": 0.9,
             "explanation": "The poll sleeps are treated as a wall-clock bound.",
             "required_conditions": ["The provider remains processing"],
             "source_issue_identity": {"mechanism": "FORGED IDENTITY"},
             "source_assessments": [{"narrative_review": {"reason": "FORGED REVIEW"}}]}
    report = run_scan(make_zip({path: source.encode()}).getvalue(),
                      FakeLLM(response=json.dumps([claim])), llm_rubrics=("money",))
    finding, = [f for f in report["findings"] if f["source"] == "llm"]
    ce = finding["claim_evidence"]
    assert valid_external_identity(ce["source_issue_identity"], path)
    assert narrative_review_checks(ce)
    assert "Outcome needs review" in _finding_row(finding)
    assert "FORGED" not in json.dumps(finding)
    assert ce["consequence_status"] == "not_checked"


def test_malformed_identity_mechanism_and_review_abstain_without_crashing():
    first = scored()
    identity = deepcopy(first.claim_evidence["source_issue_identity"])
    identity["mechanism"] = []
    assert not valid_external_identity(identity, first.file)
    second = replace(first, claim_evidence=deepcopy(first.claim_evidence))
    second.claim_evidence["source_assessments"][0]["narrative_review"] = True
    assert not compatible_external_claims(asdict(first), asdict(second), first.claim_evidence["source_issue_identity"])

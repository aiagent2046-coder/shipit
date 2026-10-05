"""Group one validated source correction, never the originals' different claims."""
from copy import deepcopy
from dataclasses import asdict, replace
import json
from pathlib import Path

import pytest

from app.scan.claim_narrative import narrative_projection
from app.scan.fact_projection_grouping import (
    CONSEQUENCES, MECHANISM, SCOPE, group_fact_projections, validated_fact_group,
)
from app.scan.llm_scan import run_llm_scan
from app.scan.scoring import ScoredFinding
from tests.test_audit_llm_wiring import FakeLLM
from tests.test_source_claim_assessment import CALLER, HELPER, archive


PAIR = Path(__file__).parent / "fixtures/fact_projection_d8ae8860.json"


def pair():
    return [ScoredFinding(**row) for row in json.loads(PAIR.read_text())]


def test_saved_pair_groups_corrected_source_interpretation_and_retains_every_original_field():
    findings = pair()
    before = deepcopy(findings)
    assert all(narrative_projection(asdict(row)) for row in findings)
    grouped, = group_fact_projections(findings)
    assert findings == before
    assert grouped is not findings[0]
    assert grouped.confidence == 0.7
    assert grouped.claim_evidence["grouped_originals"] == [asdict(row) for row in before]
    assert grouped.claim_evidence["grouped_claim_scope"] == {
        "mechanism": MECHANISM, "scope": SCOPE, "consequences": CONSEQUENCES,
    }
    assert validated_fact_group(asdict(grouped))
    assert narrative_projection(asdict(grouped))
    assert grouped.title == findings[0].title
    assert grouped.explanation == findings[0].explanation
    originals = grouped.claim_evidence["grouped_originals"]
    assert (originals[0]["claim_evidence"]["required_conditions"]
            != originals[1]["claim_evidence"]["required_conditions"])
    assert "sanitizeFacts does not cap" in originals[1]["claim_evidence"]["required_conditions"][1]
    assert {row["claim_evidence"]["producer"]["response"] for row in originals} == {3, 7}


def test_input_order_does_not_choose_a_weaker_representative_and_position_is_preserved():
    first, second = pair()
    unrelated = ScoredFinding(rule_id="static-example", title="Independent", severity="low",
                              confidence=1, category="Testing")
    grouped, sentinel = group_fact_projections([second, unrelated, first])
    assert grouped.confidence == first.confidence
    assert grouped.claim_evidence["producer"] == first.claim_evidence["producer"]
    assert sentinel is unrelated
    assert grouped.claim_evidence["grouped_originals"] == [asdict(second), asdict(first)]


def test_equal_confidence_representative_is_stable_under_input_reversal():
    first, second = pair()
    second = replace(second, confidence=first.confidence)
    forward, = group_fact_projections([first, second])
    reverse, = group_fact_projections([second, first])
    a, b = asdict(forward), asdict(reverse)
    a["claim_evidence"].pop("grouped_originals")
    b["claim_evidence"].pop("grouped_originals")
    assert a == b


def test_singleton_policy_leaves_existing_groups_unchanged_and_is_idempotent():
    first, second = pair()
    grouped, = group_fact_projections([first, second])
    assert group_fact_projections([grouped])[0] is grouped
    # Incremental extension is deliberately outside this narrow pass.
    assert group_fact_projections([grouped, first]) == [grouped, first]
    old = deepcopy(first)
    old.claim_evidence["grouped_originals"] = [asdict(first), asdict(second)]
    assert group_fact_projections([old, second]) == [old, second]
    assert group_fact_projections([old, second])[0] is old
    assert not validated_fact_group(asdict(old))


@pytest.mark.parametrize("field,value", [
    ("severity", "medium"), ("verification_status", "verified"),
    ("verification_method", "not_run"), ("source", "static"),
    ("category", "Security"), ("origin_category", "Security"),
    ("context", "test_fixture"), ("masked", "different evidence"),
    ("rule_id", "llm-security"), ("line", 218),
    ("title", "All facts reach the prompt without a cap"),
    ("fix_hint", "Remove the existing count cap"),
])
def test_different_finding_semantics_never_group(field, value):
    first, second = pair()
    second = replace(second, **{field: value})
    assert group_fact_projections([first, second]) == [first, second]


@pytest.mark.parametrize("field,value", [
    ("source_issue_identity", {"mechanism": "different_source"}),
    ("conditions_status", "verified"), ("consequence_status", "verified"),
    ("syntax_check", {"result": "contradicted"}),
    ("premise_checks", [{"kind": "different", "result": "not_checked"}]),
    ("context_checks", [{"kind": "additional", "result": "observed"}]),
    ("recommendation_check", {"result": "superseded"}),
    ("future_metadata", {"must_remain_distinct": True}),
])
def test_different_evidence_and_future_fields_never_group(field, value):
    first, second = pair()
    second.claim_evidence[field] = value
    assert group_fact_projections([first, second]) == [first, second]


@pytest.mark.parametrize("mutate", [
    lambda e: e.pop("source_issue_identity"),
    lambda e: e.pop("narrative_projection"),
    lambda e: e["narrative_projection"].update(kind="retry_callback_scope"),
    lambda e: e["narrative_projection"].update(source_hashes={}),
    lambda e: e["narrative_projection"]["active"].update(observation="Unbounded facts"),
    lambda e: e["source_assessments"][0]["source_binding"].update(upper=41),
    lambda e: e["source_assessments"][0].update(result="not_checked"),
    lambda e: e["source_assessments"][0].update(whole_finding=True),
    lambda e: e["producer"].update(model="another-model"),
    lambda e: e["producer"].update(rubric="another-rubric"),
])
def test_missing_malformed_or_different_source_proof_never_groups(mutate):
    first, second = pair()
    mutate(second.claim_evidence)
    assert group_fact_projections([first, second]) == [first, second]


def test_individually_valid_projections_for_different_source_spans_do_not_group():
    first, second = pair()
    second.claim_evidence["source_assessments"][0]["source_binding"]["query_result"]["span"][0] += 1
    assert narrative_projection(asdict(first))
    assert narrative_projection(asdict(second))
    assert first.title == second.title and first.explanation == second.explanation
    assert group_fact_projections([first, second]) == [first, second]


@pytest.mark.parametrize("conditions", [None, "A textual condition", [3], {"condition": "unverified"}])
def test_malformed_conditions_cannot_qualify_even_when_both_inputs_match(conditions):
    findings = pair()
    for finding in findings:
        finding.claim_evidence["required_conditions"] = deepcopy(conditions)
    assert group_fact_projections(findings) == findings


@pytest.mark.parametrize("confidence", [True, -0.1, 1.1, float("inf"), "0.7"])
def test_invalid_confidence_cannot_be_used_to_select_a_representative(confidence):
    findings = [replace(row, confidence=confidence) for row in pair()]
    assert group_fact_projections(findings) == findings


@pytest.mark.parametrize("field", ["conditions_status", "consequence_status"])
def test_matching_nonpending_dispositions_still_do_not_qualify(field):
    findings = pair()
    for finding in findings:
        finding.claim_evidence[field] = "verified"
    assert group_fact_projections(findings) == findings


@pytest.mark.parametrize("mutate", [
    lambda f: f["claim_evidence"].pop("grouped_claim_scope"),
    lambda f: f["claim_evidence"]["grouped_claim_scope"].update(mechanism="unrelated"),
    lambda f: f["claim_evidence"].update(grouped_originals=[]),
    lambda f: f["claim_evidence"]["grouped_originals"].pop(),
    lambda f: f["claim_evidence"]["grouped_originals"][1].update(severity="critical"),
    lambda f: f["claim_evidence"]["grouped_originals"][1]["claim_evidence"].pop("narrative_projection"),
    lambda f: f.update(confidence=0.99),
])
def test_report_validator_does_not_endorse_malformed_or_unrelated_originals(mutate):
    grouped, = group_fact_projections(pair())
    saved = asdict(grouped)
    mutate(saved)
    assert not validated_fact_group(saved)


def test_fresh_scan_groups_distinct_original_prose_only_after_source_projection():
    raw = {
        "file": "app/auth.ts", "line_start": 3, "line_end": 3, "evidence": "{data: facts}",
        "title": "All facts are injected into every model prompt", "severity": "medium", "confidence": 0.8,
        "explanation": "Every saved fact increases the prompt and cost without any limit.",
        "observation": "All database facts reach the rendered prompt.",
        "fix_hint": "Limit the number of facts before rendering.",
        "required_conditions": ["Many saved facts exist."],
    }
    other = {**raw, "title": "Unbounded facts are prepended to every Claude prompt", "confidence": 0.7,
             "explanation": "The database facts have no row limit and all reach the model.",
             "required_conditions": ["The helper does not cap the number of facts."]}

    class TwoResponses(FakeLLM):
        def __init__(self):
            super().__init__(response="[]")
            self.responses = iter([raw, other])

        def complete(self, system, user, max_tokens=4096):
            self._response = json.dumps([next(self.responses)])
            return super().complete(system, user, max_tokens)

    findings, stats = run_llm_scan(archive({"app/auth.ts": CALLER, "app/helper.ts": HELPER}),
                                    TwoResponses(), rubrics=("auth",), passes=2)
    row, = findings
    assert validated_fact_group(asdict(row))
    originals = row.claim_evidence["grouped_originals"]
    assert len(originals) == 2
    assert all(narrative_projection(original) for original in originals)
    assert {o["claim_evidence"]["narrative_projection"]["original"]["title"] for o in originals} == {
        raw["title"], other["title"],
    }
    assert stats.model_findings[0]["accepted"] == 2
    assert stats.model_findings[0]["saved"] == 1
    assert stats.model_findings[0]["merged"] == 1


def test_boolean_evidence_version_cannot_establish_grouping():
    findings = pair()
    for finding in findings:
        finding.claim_evidence["version"] = True
    assert group_fact_projections(findings) == findings

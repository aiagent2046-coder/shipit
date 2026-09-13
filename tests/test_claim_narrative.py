"""Fresh source proof corrects one premise without declaring the finding safe."""
from copy import deepcopy
from dataclasses import asdict, replace
import hashlib
import json

import pytest

from app.scan.claim_evidence import model_claim_evidence
from app.scan.claim_narrative import narrative_projection, project_claim_narrative
from app.scan.external_call_assessment import ExternalCallVerifier
from app.scan.scoring import ScoredFinding, _score
from app.scan.source_claim_assessment import SourceClaimVerifier
from tests.test_source_claim_assessment import CALLER as FACT_CALLER, HELPER as FACT_HELPER, archive
from tests.test_external_call_assessment import WRAPPER, HELPER as FETCH_HELPER, CALLER as FETCH_CALLER


def fixture(kind="facts", *, caller=None, helper=None, extra=None):
    if kind == "facts":
        caller = FACT_CALLER if caller is None else caller
        sources = {"src/caller.ts": caller, "src/helper.ts": FACT_HELPER if helper is None else helper,
                   **(extra or {})}
        path, marker = "src/caller.ts", "{data: facts}"
        title = "Unbounded facts are injected into every Claude prompt"
        explanation = "The query has no LIMIT and every saved fact increases the prompt and cost."
        verifier = SourceClaimVerifier(archive(sources))
    else:
        caller = WRAPPER + FETCH_HELPER + FETCH_CALLER if caller is None else caller
        sources = {"src/route.ts": caller}
        path, marker = "src/route.ts", "const res = await withRetry"
        title = "Retry on any HTTP error or JSON parsing failure"
        explanation = "HTTP errors and JSON failures retry the whole request and cause two charges."
        verifier = ExternalCallVerifier(archive(sources))
    line = next(i for i, value in enumerate(caller.splitlines(), 1) if marker in value)
    raw = {"file": path, "line_start": line, "line_end": line, "evidence": marker,
           "title": title, "explanation": explanation, "observation": explanation,
           "fix_hint": "Remove the retry and all collection caps.",
           "required_conditions": ["The operation is invoked."]}
    evidence = {**model_claim_evidence(raw, sources),
                "producer": {"model": "fixture-model", "rubric": "money", "response": 1},
                "source_assessments": verifier.checks_for(raw), "source_issue_identity": None,
                "future_metadata": {"must_survive": [1, 2]}}
    finding = ScoredFinding(rule_id="llm-money", title=title, severity="medium", confidence=0.8,
                            category="Money & Data", file=path, line=line, explanation=explanation,
                            fix_hint=raw["fix_hint"], source="llm", verification_method="model_review",
                            claim_evidence=evidence)
    return finding, {path: hashlib.sha256(source.encode()).hexdigest() for path, source in sources.items()}


@pytest.mark.parametrize("kind", ["facts", "retry"])
def test_source_generated_assessment_changes_public_fields_without_score_or_status_changes(kind):
    finding, hashes = fixture(kind)
    before = deepcopy(finding)
    projected = project_claim_narrative(finding, current_source_hashes=hashes)
    assert projected is not finding and finding == before
    assert {k for k in asdict(finding) if asdict(finding)[k] != asdict(projected)[k]} == {
        "title", "explanation", "fix_hint", "claim_evidence"}
    assert _score([finding]) == _score([projected])
    assert projected.verification_status == "unverified"
    p = narrative_projection(asdict(projected))
    assert p is not None and p["source_hashes"] == hashes
    assert p["original"] == {"title": finding.title, "explanation": finding.explanation,
                              "fix_hint": finding.fix_hint, "observation": finding.explanation,
                              "producer": finding.claim_evidence["producer"]}
    assert p["active"]["observation"] == projected.claim_evidence["observation"]
    assert projected.claim_evidence["future_metadata"] == {"must_survive": [1, 2]}
    assert project_claim_narrative(projected, current_source_hashes=hashes) is projected


def test_fact_projection_retains_db_read_question_without_claiming_missing_limit_or_full_prompt_cap():
    caller = FACT_CALLER.replace(".select('content')", ".select('content').limit(20)")
    finding, hashes = fixture(caller=caller)
    p = project_claim_narrative(finding, current_source_hashes=hashes)
    assert "40 items" in p.explanation
    assert "database read" in p.explanation
    assert "other prompt inputs" in p.explanation.lower()
    assert "no LIMIT" not in p.explanation
    assert "500" not in p.explanation  # This fixture proves a count cap only.


def test_zero_count_cap_is_supported_without_inventing_item_length_bounds():
    finding, hashes = fixture(caller=FACT_CALLER.replace("facts ?? [])", "facts ?? [], {maxFacts: 0})"))
    projected = project_claim_narrative(finding, current_source_hashes=hashes)
    assert "0 items" in projected.explanation


@pytest.mark.parametrize("kind", ["facts", "retry"])
def test_hashes_must_be_supplied_from_current_source_not_copied_from_model_metadata(kind):
    finding, hashes = fixture(kind)
    finding.claim_evidence["current_source_hashes"] = hashes
    assert project_claim_narrative(finding) is finding
    assert project_claim_narrative(finding, current_source_hashes={}) is finding
    for path in hashes:
        stale = {**hashes, path: "0" * 64}
        assert project_claim_narrative(finding, current_source_hashes=stale) is finding


def test_import_configuration_is_part_of_freshness_validation():
    config = json.dumps({"compilerOptions": {"baseUrl": ".", "paths": {"@/*": ["./src/*"]}}})
    finding, hashes = fixture(caller=FACT_CALLER.replace("'./helper'", "'@/helper'"),
                               extra={"tsconfig.json": config})
    projected = project_claim_narrative(finding, current_source_hashes=hashes)
    assert narrative_projection(asdict(projected)) is not None
    assert "tsconfig.json" in projected.claim_evidence["narrative_projection"]["source_hashes"]
    del hashes["tsconfig.json"]
    assert project_claim_narrative(finding, current_source_hashes=hashes) is finding


@pytest.mark.parametrize("mutation", [
    lambda f: f.claim_evidence.update(source_assessments=[]),
    lambda f: f.claim_evidence.update(source_check={"kind": "not_recorded"}),
    lambda f: f.claim_evidence.update(producer={"model": "fake", "rubric": "money", "response": True}),
    lambda f: f.claim_evidence["source_assessments"][0].update(method="model_review"),
    lambda f: f.claim_evidence["source_assessments"][0].update(result="not_checked"),
    lambda f: f.claim_evidence["source_assessments"][0].update(whole_finding=True),
    lambda f: f.claim_evidence["source_assessments"][0].update(source_sha256="0" * 64),
    lambda f: f.claim_evidence["source_assessments"][0].update(file="src/other.ts"),
    lambda f: f.claim_evidence["source_assessments"][0].update(line_start=999),
    lambda f: f.claim_evidence["source_assessments"][0].update(source_binding={}),
    lambda f: f.claim_evidence["source_assessments"][0]["source_binding"].update(span=[1, 0]),
])
@pytest.mark.parametrize("kind", ["facts", "retry"])
def test_malformed_unresolved_and_mismatched_checks_do_not_project(kind, mutation):
    finding, hashes = fixture(kind)
    mutation(finding)
    assert project_claim_narrative(finding, current_source_hashes=hashes) is finding


@pytest.mark.parametrize("caller,helper", [
    (FACT_CALLER.replace("buildFactBlock(factList)", "buildFactBlock(facts)"), FACT_HELPER),
    (FACT_CALLER, FACT_HELPER.replace(".slice(0, maxFacts)", "")),
    (FACT_CALLER, FACT_HELPER.replace(".slice(0, maxFacts)", ".slice(0, maxFacts).concat(facts)")),
])
def test_real_uncapped_or_bypassed_fact_consumer_is_not_silenced(caller, helper):
    finding, hashes = fixture(caller=caller, helper=helper)
    assert project_claim_narrative(finding, current_source_hashes=hashes) is finding


def test_http_checks_inside_retry_callback_remain_a_possible_retry_cause():
    source = (WRAPPER + FETCH_HELPER + FETCH_CALLER).replace(
        "const res = await withRetry(() => fetchWithTimeout('PRIVATE_URL', {}));",
        "const res = await withRetry(async () => { const response = await fetchWithTimeout('PRIVATE_URL', {}); "
        "if (!response.ok) throw new Error('failed'); return response; });")
    finding, hashes = fixture("retry", caller=source)
    assert project_claim_narrative(finding, current_source_hashes=hashes) is finding


def test_retry_projection_preserves_rejection_retry_without_inferring_charges():
    finding, hashes = fixture("retry")
    projected = project_claim_narrative(finding, current_source_hashes=hashes)
    assert "2 total attempts (1 additional attempt)" in projected.explanation
    assert "Request rejection can still retry" in projected.explanation
    assert "repeated charges are not established" in projected.explanation
    assert "two charges" not in projected.explanation


def test_single_attempt_wrapper_does_not_gain_a_retry_in_projected_wording():
    finding, hashes = fixture("retry", caller=(WRAPPER.replace("2", "1") + FETCH_HELPER + FETCH_CALLER))
    projected = project_claim_narrative(finding, current_source_hashes=hashes)
    assert narrative_projection(asdict(projected)) is not None
    assert "one attempt" in projected.title
    assert "no additional attempt" in projected.explanation
    assert "can still retry" not in projected.explanation


def test_earliest_advice_and_grouped_originals_remain_available_without_modification():
    finding, hashes = fixture()
    original = asdict(finding)
    finding.claim_evidence["grouped_originals"] = [original]
    finding.claim_evidence["recommendation_check"] = {
        "original_status": "superseded", "original_fix_hint": "First model advice", "extra": True}
    finding = replace(finding, fix_hint="Later prepared advice")
    projected = project_claim_narrative(finding, current_source_hashes=hashes)
    p = narrative_projection(asdict(projected))
    assert p["original"]["fix_hint"] == "First model advice"
    assert p["previous_fix_hint"] == "Later prepared advice"
    assert projected.claim_evidence["grouped_originals"] == [original]
    assert projected.claim_evidence["recommendation_check"] == finding.claim_evidence["recommendation_check"]


@pytest.mark.parametrize("change", [
    lambda f: f.update(title="Unbounded facts still cost more"),
    lambda f: f["claim_evidence"].update(observation="All facts reach the prompt"),
    lambda f: f["claim_evidence"]["narrative_projection"].update(kind=[]),
    lambda f: f["claim_evidence"]["narrative_projection"].update(source_hashes={}),
    lambda f: f["claim_evidence"]["narrative_projection"]["original"].update(producer={}),
])
def test_report_validator_rejects_inconsistent_or_malformed_projection(change):
    finding, hashes = fixture()
    saved = asdict(project_claim_narrative(finding, current_source_hashes=hashes))
    change(saved)
    assert narrative_projection(saved) is None


def test_static_and_non_admitted_findings_are_never_projected():
    finding, hashes = fixture()
    for changed in (replace(finding, source="static"), replace(finding, verification_method="not_run")):
        assert project_claim_narrative(changed, current_source_hashes=hashes) is changed


def test_model_supplied_source_assessment_cannot_authorize_projection_through_admission():
    from app.scan.pipeline import run_scan
    from tests.test_audit_llm_wiring import FakeLLM, make_zip

    forged, _ = fixture()
    source = FACT_CALLER.replace("buildFactBlock(factList)", "buildFactBlock(facts)")
    raw = {"file": "app/auth.ts", "line_start": 3, "line_end": 3, "evidence": "{data: facts}",
           "title": forged.title, "explanation": forged.explanation, "severity": "high", "confidence": 0.9,
           "source_assessments": forged.claim_evidence["source_assessments"],
           "claim_evidence": forged.claim_evidence,
           "narrative_projection": {"version": 1, "kind": "fact_input_count_unbounded"}}
    sources = {"app/auth.ts": source, "app/helper.ts": FACT_HELPER}
    result = run_scan(make_zip({p: s.encode() for p, s in sources.items()}).getvalue(),
                      FakeLLM(response=json.dumps([raw])), llm_rubrics=("auth",))
    row, = [f for f in result["findings"] if f["source"] == "llm"]
    assert row["title"] == raw["title"]
    assert "narrative_projection" not in row["claim_evidence"]
    assert not any(c["result"] == "contradicted" for c in row["claim_evidence"]["source_assessments"])

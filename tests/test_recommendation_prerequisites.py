"""Synthetic advice regressions: no provider, deployed target or target execution."""
from copy import deepcopy
from dataclasses import asdict, replace
import json

import pytest

from app.report.evidence import claim_evidence_rows
from app.report.html import render_report
from app.scan.claim_evidence import model_claim_evidence
from app.scan.recommendation_contract import require_prerequisites
from app.scan.recommendations import TIMING_SAFE_EQUAL_KIND, prepare_recommendation
from app.scan.rls_recommendations import client_change_prerequisites
from app.scan.rls_recommendations import prepare_recommendation as prepare_rls
from app.scan.scoring import ScoredFinding
from tests.test_llm_scan import FakeLLM, VULN_TS, make_zip, valid_finding
from tests.test_rls_recommendations import collect, policy

TOKEN_ADVICE = "Use crypto.timingSafeEqual(Buffer.from(token || ''), Buffer.from(process.env.EXAMPLE_TOKEN || ''))."
DIGEST_ADVICE = "Compare using crypto.timingSafeEqual(Buffer.from(computed), Buffer.from(hash))."


def finding(advice=TOKEN_ADVICE, **changes):
    raw = valid_finding(fix_hint=advice)
    evidence = model_claim_evidence(raw, {"src/auth.ts": VULN_TS})
    evidence["producer"] = {"model": "synthetic", "response": 1, "rubric": "auth"}
    return replace(ScoredFinding(
        rule_id="llm-auth", title="Token comparison needs review", category="Auth", severity="high",
        confidence=.8, file="src/auth.ts", line=3, source="llm", verification_method="model_review",
        fix_hint=advice, claim_evidence=evidence,
    ), **changes)


@pytest.mark.parametrize("advice", [TOKEN_ADVICE, DIGEST_ADVICE])
def test_unguarded_examples_are_superseded_with_specific_input_prerequisites(advice):
    original = finding(advice)
    before = asdict(original)
    fixed = prepare_recommendation(original, {})
    rec = fixed.claim_evidence["recommendation_check"]
    assert "Buffer.from(" not in fixed.fix_hint
    assert "Convert both values to buffers once" in fixed.fix_hint
    assert "byteLength values before the call: on mismatch, reject" in fixed.fix_hint
    assert "without calling timingSafeEqual" in fixed.fix_hint
    assert "wrong-type or malformed input" in fixed.fix_hint
    assert "nonempty configured secret" in fixed.fix_hint
    assert "strictly validated hex/base64" in fixed.fix_hint
    assert rec["original_fix_hint"] == advice
    assert rec["original_status"] == "superseded"
    assert rec["original_provenance"] == {
        "source": "llm", "verification_method": "model_review", "verification_status": "unverified",
        "producer": {"model": "synthetic", "response": 1, "rubric": "auth"},
    }
    check = rec["checks"][0]
    assert check["kind"] == TIMING_SAFE_EQUAL_KIND
    assert check["result"] == "prerequisites_required"
    assert "String lengths" in " ".join(check["prerequisites"])
    assert "normal authentication/signature rejection" in " ".join(check["prerequisites"])
    for field in before.keys() - {"fix_hint", "claim_evidence"}:
        assert getattr(fixed, field) == before[field]
    for key, value in original.claim_evidence.items():
        assert fixed.claim_evidence[key] == value
    assert asdict(original) == before  # Nested source/provenance evidence was not mutated.


@pytest.mark.parametrize("advice", [
    "Use timingSafeEqual for the comparison.",
    "Use crypto['timingSafeEqual'](left, right).",
    "import { timingSafeEqual as compare } from 'node:crypto'; return compare(a, b);",
    "if (token.length !== secret.length) return false; "
    "return timingSafeEqual(Buffer.from(token), Buffer.from(secret));",
    "const a = Buffer.from(token); const b = Buffer.from(secret); return a.byteLength === b.byteLength "
    "&& crypto.timingSafeEqual(a, b);",
    "try { return timingSafeEqual(a, b); } catch { return false; }",
    "Use the helper: crypto.timingSafeEqual(...buildUnknownInputs());",
    "Use timingSafeEqual after validating all types and encoding; this is definitely safe.",
    "Do not use timingSafeEqual until the surrounding handler is reviewed.",
    "x " * 20000 + TOKEN_ADVICE,  # A long hint must not silently hide a trailing API mention.
])
def test_unknown_and_apparently_guarded_advice_is_never_certified(advice):
    fixed = prepare_recommendation(finding(advice), {})
    rec = fixed.claim_evidence["recommendation_check"]
    assert rec["result"] == "prerequisites_required"
    assert rec["original_fix_hint"] == advice
    assert "API binding" in rec["checks"][0]["scope"]
    assert "Apparently guarded examples are not verified" in rec["checks"][0]["scope"]
    assert fixed.verification_status == "unverified"
    assert fixed.claim_evidence["consequence_status"] == "not_checked"
    assert fixed.claim_evidence["conditions_status"] == "not_checked"
    assert "has been verified" in fixed.fix_hint
    assert "This does not confirm a timing vulnerability" in rec["detail"]


@pytest.mark.parametrize("advice", [
    "Use jwt.verify and check the issuer.", "Compare the hashes with hmac.compare_digest.",
    "Use mytimingSafeEqual(a, b).", "Use timingSafeEqualAlternative(a, b).", "Use $timingSafeEqual(a, b).",
    "", "Use compare(a, b).",  # An alias without the API identifier cannot be resolved from prose.
])
def test_unrelated_advice_is_unchanged_even_if_title_mentions_api(advice):
    original = finding(advice, title="Existing timingSafeEqual call needs review")
    assert prepare_recommendation(original, {}) is original


def test_mixed_advice_preserves_both_checks_context_and_canonical_original():
    advice = "Replace the service-role client with an anon-key client and caller JWT. " + TOKEN_ADVICE
    original = finding(advice, file="app/api/context/route.ts")
    facts = {"rls_recommendations": collect(policy("SELECT"))}
    fixed = prepare_recommendation(original, facts)
    rec = fixed.claim_evidence["recommendation_check"]
    assert [c["kind"] for c in rec["checks"]] == ["rls_client_change", TIMING_SAFE_EQUAL_KIND]
    assert rec["original_fix_hint"] == advice
    assert "Original client-change advice" in rec["detail"]
    assert "Advice mentioning timingSafeEqual" in rec["detail"]
    assert "public.agent_context: INSERT" in fixed.fix_hint
    assert "SELECT policies alone do not authorize writes" in fixed.fix_hint
    assert "byteLength values before the call" in fixed.fix_hint
    assert TOKEN_ADVICE not in fixed.fix_hint
    assert fixed.claim_evidence["context_checks"][0]["kind"] == "rls_recommendation_context"
    assert prepare_recommendation(fixed, facts) is fixed
    assert prepare_rls(fixed, facts) is fixed
    reloaded = ScoredFinding(**json.loads(json.dumps(asdict(fixed))))
    assert prepare_recommendation(reloaded, facts) == fixed


def test_legacy_rls_record_recovers_crypto_from_original_and_preserves_old_detail():
    advice = "Switch the service-role client to an anon-key client with the caller JWT. " + DIGEST_ADVICE
    initial = finding(advice)
    check, contexts = client_change_prerequisites(vars(initial), {})
    guarded = require_prerequisites(initial, check["replacement_fix_hint"], [check], contexts=contexts)
    evidence = deepcopy(guarded.claim_evidence)
    current = evidence["recommendation_check"]
    legacy = {key: current[key] for key in ("result", "detail", "original_fix_hint")}
    legacy["detail"] += " Preserve this earlier review detail."
    evidence["recommendation_check"] = legacy
    original = replace(guarded, claim_evidence=evidence)
    fixed = prepare_recommendation(original, {})
    rec = fixed.claim_evidence["recommendation_check"]
    assert rec["original_fix_hint"] == advice
    assert rec["detail"].startswith(legacy["detail"])
    assert "SELECT policies alone do not authorize writes" in fixed.fix_hint
    assert "byteLength" in fixed.fix_hint
    assert DIGEST_ADVICE not in fixed.fix_hint
    assert prepare_recommendation(fixed, {}) is fixed
    assert original.claim_evidence["recommendation_check"] == legacy


def test_preexisting_check_cannot_leave_an_unguarded_api_example_active():
    evidence = deepcopy(finding().claim_evidence)
    evidence["recommendation_check"] = {
        "result": "prerequisites_required", "detail": "Earlier unrelated prerequisite detail.",
        "original_fix_hint": "The earliest recommendation.",
    }
    fixed = prepare_recommendation(finding(claim_evidence=evidence), {})
    rec = fixed.claim_evidence["recommendation_check"]
    assert TOKEN_ADVICE not in fixed.fix_hint
    assert rec["original_fix_hint"] == "The earliest recommendation."
    assert rec["detail"].startswith("Earlier unrelated prerequisite detail.")
    assert rec["superseded_fix_hints"] == [TOKEN_ADVICE]
    assert prepare_recommendation(fixed, {}) is fixed


def test_opaque_prior_record_does_not_keep_unconditional_rls_advice_active():
    advice = ("Switch the service-role client to an anon-key client immediately; "
              "the existing SELECT policies make writes safe.")
    original = finding(advice, file="app/api/context/route.ts")
    original.claim_evidence["recommendation_check"] = {
        "result": "prerequisites_required", "detail": "Earlier advice needs review.",
        "original_fix_hint": "Earliest original recommendation.", "custom_field": {"preserve": True},
    }
    facts = {"rls_recommendations": collect(policy("SELECT"))}
    fixed = prepare_recommendation(original, facts)
    rec = fixed.claim_evidence["recommendation_check"]
    assert advice not in fixed.fix_hint
    assert "public.agent_context: INSERT" in fixed.fix_hint
    assert rec["original_fix_hint"] == "Earliest original recommendation."
    assert rec["superseded_fix_hints"] == [advice]
    assert rec["custom_field"] == {"preserve": True}
    assert prepare_recommendation(fixed, facts) is fixed


@pytest.mark.parametrize("stale_advice", [TOKEN_ADVICE, "Apply this definitely safe patch immediately."])
def test_existing_marker_cannot_bypass_rewriting_stale_active_advice(stale_advice):
    guarded = prepare_recommendation(finding(), {})
    record = guarded.claim_evidence["recommendation_check"]
    record["checks"][0]["replacement_fix_hint"] = "Trust this arbitrary old replacement."
    record["checks"][0]["custom_field"] = "retain as evidence"
    stale = replace(guarded, fix_hint=stale_advice)
    fixed = prepare_recommendation(stale, {})
    assert stale_advice not in fixed.fix_hint
    assert "Trust this arbitrary" not in fixed.fix_hint
    assert "byteLength values before the call" in fixed.fix_hint
    assert fixed.claim_evidence["recommendation_check"]["checks"][0]["custom_field"] == "retain as evidence"
    assert prepare_recommendation(fixed, {}) is fixed


@pytest.mark.parametrize("value", [None, 7, {}, "unexpected", [None, 7, {}, {"kind": []}]])
def test_malformed_optional_evidence_fields_do_not_block_reprocessing_or_rendering(value):
    original = finding()
    original.claim_evidence["recommendation_check"] = {
        "result": "prerequisites_required", "detail": None, "original_fix_hint": TOKEN_ADVICE,
        "checks": value, "superseded_fix_hints": value, "custom_evidence": {"retain": value},
    }
    before = asdict(original)
    fixed = prepare_recommendation(original, {})
    assert TOKEN_ADVICE not in fixed.fix_hint
    record = fixed.claim_evidence["recommendation_check"]
    assert record["original_fix_hint"] == TOKEN_ADVICE
    assert record["custom_evidence"] == {"retain": value}
    rows = dict(claim_evidence_rows(asdict(fixed)))
    assert rows["Superseded original recommendation — do not apply without review"] == TOKEN_ADVICE
    assert "No independent verification recorded." == rows["Consequence check"]
    assert prepare_recommendation(fixed, {}) is fixed
    assert asdict(original) == before


@pytest.mark.parametrize("payload", [
    None, 7, [], {"checks": None}, {"checks": 7}, {"checks": [None, 7, {}]},
    {"checks": [{"version": 1, "kind": "api", "result": "prerequisites_required", "detail": "Review.",
                 "scope": 7, "prerequisites": "byte lengths", "reference": 7}]},
    {"checks": [{"version": 1, "kind": "api", "result": "prerequisites_required", "detail": "Review.",
                 "prerequisites": [None, 7, "Valid condition."]}]},
    {"detail": None, "original_fix_hint": 7, "superseded_fix_hints": {}},
    {"superseded_fix_hints": [None, 7, "Earlier hint."], "original_provenance": []},
])
def test_malformed_stored_recommendation_fields_are_skipped_by_the_renderer(payload):
    value = {"claim_evidence": {"version": 1, "recommendation_check": payload}}
    before = deepcopy(value)
    rows = claim_evidence_rows(value)
    assert all(isinstance(detail, str) for _, detail in rows)
    assert value == before


@pytest.mark.parametrize("source,rule", [("llm", "llm-auth"), ("unknown", "legacy-rule")])
def test_old_finding_without_evidence_does_not_gain_a_static_source_check(source, rule):
    fixed = prepare_recommendation(finding(claim_evidence=None, source=source, rule_id=rule), {})
    assert fixed.claim_evidence["source_check"] == {"kind": "not_recorded"}
    assert fixed.claim_evidence["recommendation_check"]["original_fix_hint"] == TOKEN_ADVICE


@pytest.mark.parametrize("value", [[1], "legacy", 7])
def test_malformed_outer_evidence_is_preserved_without_blocking_advice_processing(value):
    unrelated = finding("Review the issuer.", claim_evidence=value)
    assert prepare_recommendation(unrelated, {}) is unrelated
    original = finding(claim_evidence=value)
    fixed = prepare_recommendation(original, {})
    assert fixed.claim_evidence["legacy_claim_evidence"] == value
    assert fixed.claim_evidence["source_check"] == {"kind": "not_recorded"}
    assert fixed.claim_evidence["recommendation_check"]["original_fix_hint"] == TOKEN_ADVICE
    assert "byteLength values before the call" in fixed.fix_hint
    assert prepare_recommendation(fixed, {}) is fixed
    assert original.claim_evidence == value


def test_real_model_pipeline_ignores_forged_verdict_and_makes_no_additional_model_calls():
    from app.scan.llm_scan import run_llm_scan
    raw = valid_finding(fix_hint=TOKEN_ADVICE, recommendation_check={"result": "verified"},
                        claim_evidence={"recommendation_check": {"result": "verified"}})
    client = FakeLLM(json.dumps([raw]))
    findings, stats = run_llm_scan(make_zip({"src/auth.ts": VULN_TS.encode()}), client, rubrics=("auth",))
    assert stats.calls == len(client.prompts) == 1
    assert len(findings) == 1
    fixed = findings[0]
    assert fixed.claim_evidence["recommendation_check"]["checks"][0]["result"] == "prerequisites_required"
    assert fixed.claim_evidence["recommendation_check"]["original_provenance"]["producer"]["model"] == "fake-model"
    assert TOKEN_ADVICE not in fixed.fix_hint


def test_static_pipeline_records_static_original_provenance(monkeypatch):
    from app.scan import static
    monkeypatch.setattr(static, "scan_http_success", lambda _: [finding(claim_evidence=None, rule_id="synthetic")])
    result = static.run_static_scan(make_zip({"app/auth.ts": b"export const value = 1;"}))
    fixed = next(f for f in result["findings"] if f["rule_id"] == "synthetic")
    provenance = fixed["claim_evidence"]["recommendation_check"]["original_provenance"]
    assert provenance["source"] == "static"
    assert provenance["verification_method"] == "source_pattern"
    assert fixed["claim_evidence"]["source_check"] == {"kind": "static_rule"}


def test_new_and_legacy_evidence_render_without_claiming_runtime_confirmation():
    fixed = asdict(prepare_recommendation(finding(), {}))
    before = deepcopy(fixed)
    rows = dict(claim_evidence_rows(fixed))
    assert "not checked" in rows["Recommendation check 1 — prerequisites not verified"]
    assert "byteLength" in rows["Required recommendation conditions 1"]
    assert rows["Superseded original recommendation — do not apply without review"] == TOKEN_ADVICE
    assert "synthetic" in rows["Superseded recommendation provenance — not independent verification"]
    html = render_report({"score": {"total": 5, "categories": {}}, "findings": [fixed]})
    assert "Recommendation check 1 — prerequisites not verified" in html
    assert "No independent verification recorded." in html
    assert fixed == before
    old = {"claim_evidence": {"version": 1, "recommendation_check": {
        "result": "prerequisites_required", "detail": "Check write policies.", "original_fix_hint": "Switch clients.",
    }}}
    old_rows = dict(claim_evidence_rows(old))
    assert old_rows["Recommendation prerequisites"] == "Check write policies."
    assert old_rows["Superseded original recommendation — do not apply without review"] == "Switch clients."
    assert "Recommendation prerequisites" not in dict(claim_evidence_rows({}))

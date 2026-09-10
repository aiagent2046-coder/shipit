"""Synthetic advice contracts: no target execution or provider requests."""
from copy import deepcopy
from dataclasses import asdict, replace
from html import escape
import json

import pytest

from app.report.evidence import claim_evidence_rows
from app.report.html import render_report
from app.scan.paid_operation_recommendations import (
    FOLLOWUPS_KIND, PAID_OPERATION_KIND, RETRY_BUDGET_KIND,
)
from app.scan.recommendations import TIMING_SAFE_EQUAL_KIND, prepare_recommendation
from app.scan.scoring import ScoredFinding
from tests.test_recommendation_prerequisites import TOKEN_ADVICE, finding


def operation(advice, **changes):
    return finding(advice, **{
        "title": "Concurrent requests may invoke the LLM twice",
        "explanation": "The read-then-act path may issue duplicate external calls before storing a result.",
        **changes,
    })


def kinds(value):
    return [c["kind"] for c in value.claim_evidence["recommendation_check"]["checks"]]


@pytest.mark.parametrize("advice", [
    "Add a unique partial index on results(event_id) so the second insert fails silently.",
    "Alternatively, check for an existing reply before calling Claude.",
    "Use upsert with ignoreDuplicates to prevent two Claude calls.",
    "Use a database advisory lock around the final insert.",
    "Add an idempotency key to the final saved result.",
    "x " * 20000 + "Check for an existing result before calling Claude.",
])
def test_final_insert_and_read_then_act_advice_requires_a_claim_before_dispatch(advice):
    original = operation(advice)
    before = asdict(original)
    fixed = prepare_recommendation(original, {})
    record = fixed.claim_evidence["recommendation_check"]
    assert kinds(fixed) == [PAID_OPERATION_KIND]
    assert "Before issuing the external call, acquire and commit a durable atomic claim" in fixed.fix_hint
    assert "only its confirmed owner may dispatch" in fixed.fix_hint
    assert "does not prevent external calls already issued" in fixed.fix_hint
    assert "crash recovery" in fixed.fix_hint
    assert "lease expiry or timeout is not proof" in fixed.fix_hint
    assert "reconcile uncertain completion before another dispatch" in fixed.fix_hint
    assert "do not promise exactly-once" in fixed.fix_hint
    assert record["original_fix_hint"] == advice
    assert record["original_status"] == "superseded"
    assert record["original_provenance"]["producer"] == original.claim_evidence["producer"]
    assert record["checks"][0]["result"] == "prerequisites_required"
    assert "Source bindings" in record["checks"][0]["scope"]
    for field in before.keys() - {"fix_hint", "claim_evidence"}:
        assert getattr(fixed, field) == before[field]
    for field in original.claim_evidence:
        assert fixed.claim_evidence[field] == original.claim_evidence[field]
    assert asdict(original) == before
    # Generated retry wording must not create a second check on the next run.
    assert prepare_recommendation(fixed, {}) is fixed


def test_apparently_correct_claim_advice_is_not_certified_by_prose():
    original = operation(
        "Use an atomic claim before the LLM call and an idempotency key for safe retries; "
        "this guarantees exactly-once billing."
    )
    fixed = prepare_recommendation(original, {})
    assert kinds(fixed) == [PAID_OPERATION_KIND, RETRY_BUDGET_KIND]
    assert "guarantees exactly-once billing" not in fixed.fix_hint
    assert fixed.verification_status == original.verification_status == "unverified"
    assert fixed.claim_evidence["conditions_status"] == "not_checked"
    assert fixed.claim_evidence["consequence_status"] == "not_checked"
    assert "verify the provider's idempotency contract" in fixed.fix_hint
    assert prepare_recommendation(fixed, {}) is fixed


def test_same_operation_wording_gets_the_same_contract_without_a_named_provider():
    variants = [
        ("Concurrent Claude calls", "Two concurrent callbacks may each call Claude."),
        ("Duplicate generated replies", "Concurrent callbacks each trigger a duplicate "
         "AI-generated message and consume API credits."),
        ("Racy first-message check", "Concurrent requests can both trigger an AI auto-reply, "
         "resulting in two AI responses."),
    ]
    advice = "Use a unique partial index on results(event_id) to prevent duplicates."
    prepared = [prepare_recommendation(operation(advice, title=title, explanation=explanation), {})
                for title, explanation in variants]
    assert all(kinds(value) == [PAID_OPERATION_KIND] for value in prepared)
    # Equivalent context wording must not create different active advice/check
    # metadata and split a group solely because one reviewer named a provider.
    assert len({value.fix_hint for value in prepared}) == 1
    assert all(value.claim_evidence["recommendation_check"]["checks"]
               == prepared[0].claim_evidence["recommendation_check"]["checks"] for value in prepared)
    for value, (title, explanation) in zip(prepared, variants):
        assert (value.title, value.explanation) == (title, explanation)
        assert value.claim_evidence["recommendation_check"]["original_fix_hint"] == advice
        assert value.claim_evidence["consequence_status"] == "not_checked"
        assert prepare_recommendation(value, {}) is value


@pytest.mark.parametrize("title,explanation,advice", [
    ("Duplicate local rows", "Concurrent database inserts.", "Use a unique constraint on emails."),
    ("LLM request validation", "Invalid usernames are sent to the model.",
     "Use a unique constraint on emails."),
    ("Concurrent Claude calls", "A duplicate request may occur.", "Validate the request schema."),
    ("Concurrent Claude calls", "A duplicate request may occur.", "Review the cache TTL."),
    ("Local request handler", "A web request takes too long.", "Add a request timeout."),
    ("Database replication", "Replicate rows into the backup.", "Retry failed backup transfers."),
    ("Billing unknown", "Replicate API billing needs review.", "Verify whether polling GETs are billed."),
    ("Concurrent LLM calls", "Repeated responses need review.", "Use myuniqueconstraint helper."),
    ("AI dashboard duplicates", "Concurrent local inserts duplicate saved display labels.",
     "Use a unique constraint on labels."),
    ("AI-generated messages", "The display may contain repeated messages.", "Review the CSS layout."),
    ("AI response costs", "Billing has not been verified.", "Verify whether responses consume API credits."),
])
def test_unrelated_or_out_of_scope_advice_is_retained(title, explanation, advice):
    original = operation(advice, title=title, explanation=explanation)
    assert prepare_recommendation(original, {}) is original


@pytest.mark.parametrize("advice", [
    "Reduce max poll attempts to 8 for a 10-second deadline.",
    "Reduce maxAttempts to 2 to guarantee that the operation ends within 20 seconds.",
    "Cancel the prediction before retrying to avoid any further charge.",
    "Raise the timeout to 160 seconds because four retries always occur.",
])
def test_poll_and_retry_advice_distinguishes_attempts_time_and_unknown_remote_outcomes(advice):
    original = operation(advice, title="Replicate prediction polling and timeout budget",
                         explanation="A model prediction is polled and may fail.")
    fixed = prepare_recommendation(original, {})
    assert kinds(fixed) == [RETRY_BUDGET_KIND]
    assert advice not in fixed.fix_hint
    assert "ordinary terminal errors need not be retried" in fixed.fix_hint
    assert "maximum may count attempts rather than retries" in fixed.fix_hint
    assert "poll count multiplied by a sleep interval is not a wall-clock bound" in fixed.fix_hint
    assert "request durations, setup and backoff" in fixed.fix_hint
    assert "check remaining time before dispatch" in fixed.fix_hint
    assert "cancellation request does not establish that remote work stopped" in fixed.fix_hint
    assert "no numeric runtime limit, retry multiplier" in fixed.fix_hint
    assert fixed.claim_evidence["recommendation_check"]["original_fix_hint"] == advice
    # Generated idempotency wording must not induce a new deduplication check.
    assert prepare_recommendation(fixed, {}) is fixed


def test_polling_alternatives_and_separate_billing_question_survive_replacement():
    advice = ("Verify whether Replicate meters polling GET requests. Reduce polls to 8 for a 10s "
              "function, or use a webhook instead of polling. Also add rate limiting.")
    fixed = prepare_recommendation(operation(advice), {})
    assert kinds(fixed) == [RETRY_BUDGET_KIND, FOLLOWUPS_KIND]
    assert "Reduce polls to 8" not in fixed.fix_hint
    assert "If replacing polling with a webhook, verify provider support" in fixed.fix_hint
    assert "duplicate delivery handling and recovery for missing callbacks" in fixed.fix_hint
    assert "Verify the provider's actual billing terms" in fixed.fix_hint
    assert "Review rate limiting separately" in fixed.fix_hint
    assert fixed.claim_evidence["recommendation_check"]["original_fix_hint"] == advice
    assert prepare_recommendation(fixed, {}) is fixed


def test_crypto_rate_limit_goal_is_retained_without_inventing_a_paid_operation():
    advice = TOKEN_ADVICE + " Also add rate limiting before expensive work."
    fixed = prepare_recommendation(finding(advice), {})
    assert kinds(fixed) == [TIMING_SAFE_EQUAL_KIND, FOLLOWUPS_KIND]
    assert "byteLength values before the call" in fixed.fix_hint
    assert "Review rate limiting separately" in fixed.fix_hint
    assert prepare_recommendation(fixed, {}) is fixed


def test_mixed_rls_crypto_dedup_retry_and_followups_keep_one_original_and_round_trip():
    advice = ("Replace the service-role client with an anon-key client and caller JWT. " + TOKEN_ADVICE
              + " Use a unique partial index to stop duplicate Claude calls. Retry with maxAttempts=2. "
              "Add rate limiting and verify whether retries are billed.")
    original = operation(advice)
    fixed = prepare_recommendation(original, {})
    assert kinds(fixed) == ["rls_client_change", TIMING_SAFE_EQUAL_KIND, PAID_OPERATION_KIND,
                           RETRY_BUDGET_KIND, FOLLOWUPS_KIND]
    assert "SELECT policies alone do not authorize writes" in fixed.fix_hint
    assert "byteLength values before the call" in fixed.fix_hint
    assert "durable atomic claim" in fixed.fix_hint
    assert "overall deadline" in fixed.fix_hint
    assert "Review rate limiting separately" in fixed.fix_hint
    assert "Verify the provider's actual billing terms" in fixed.fix_hint
    assert fixed.claim_evidence["recommendation_check"]["original_fix_hint"] == advice
    assert prepare_recommendation(fixed, {}) is fixed
    reloaded = ScoredFinding(**json.loads(json.dumps(asdict(fixed))))
    assert prepare_recommendation(reloaded, {}) == fixed


@pytest.mark.parametrize("kind,advice", [
    (PAID_OPERATION_KIND, "Use an upsert to prevent duplicate LLM calls."),
    (RETRY_BUDGET_KIND, "Limit Claude retries to two attempts."),
])
def test_stale_record_cannot_certify_replacement_and_no_generated_checks_accumulate(kind, advice):
    fixed = prepare_recommendation(operation(advice), {})
    before = deepcopy(fixed.claim_evidence)
    before["recommendation_check"]["checks"][0]["replacement_fix_hint"] = "This guarantees no charges."
    before["recommendation_check"]["checks"][0]["custom_field"] = {"retained": True}
    stale = replace(fixed, fix_hint="This guarantees no charges.", claim_evidence=before)
    repaired = prepare_recommendation(stale, {})
    assert kinds(repaired) == [kind]
    assert "This guarantees no charges." not in repaired.fix_hint
    assert repaired.claim_evidence["recommendation_check"]["checks"][0]["custom_field"] == {"retained": True}
    assert repaired.claim_evidence["recommendation_check"]["superseded_fix_hints"] == [stale.fix_hint]
    assert prepare_recommendation(repaired, {}) is repaired


def test_original_and_provenance_are_rendered_as_superseded_without_mutating_report():
    advice = "Use a unique partial index on results(event_id) WHERE state='done'; then ignore conflicts."
    fixed = asdict(prepare_recommendation(operation(advice), {}))
    before = deepcopy(fixed)
    rows = dict(claim_evidence_rows(fixed))
    assert rows["Superseded original recommendation — do not apply without review"] == advice
    assert "synthetic" in rows["Superseded recommendation provenance — not independent verification"]
    assert "durable atomic claim" in rows["Required recommendation conditions 1"]
    html = render_report({"score": {"total": 5, "categories": {}}, "findings": [fixed]})
    assert escape(advice) in html
    assert "Superseded original recommendation" in html
    assert "No independent verification recorded." in html
    assert fixed == before


def test_model_pipeline_does_not_trust_forged_check_or_add_another_model_call():
    from app.scan.llm_scan import run_llm_scan
    from tests.test_llm_scan import FakeLLM, VULN_TS, make_zip, valid_finding

    advice = "Use a unique partial index to prevent duplicate Claude calls."
    raw = valid_finding(title="Concurrent Claude calls", fix_hint=advice,
                        claim_evidence={"recommendation_check": {"result": "verified"}})
    client = FakeLLM(json.dumps([raw]))
    values, stats = run_llm_scan(make_zip({"src/auth.ts": VULN_TS.encode()}), client, rubrics=("auth",))
    assert stats.calls == len(client.prompts) == 1
    assert len(values) == 1
    assert kinds(values[0]) == [PAID_OPERATION_KIND]
    record = values[0].claim_evidence["recommendation_check"]
    assert record["result"] == "prerequisites_required"
    assert record["original_fix_hint"] == advice
    assert record["original_provenance"]["producer"]["model"] == "fake-model"


@pytest.mark.parametrize(
    "advice",
    [
        "Retry only on 429 (rate limit), 5xx and transport failures.",
        "Treat HTTP 429 (rate limit) as retryable.",
        "Check the response status for 429 (rate limit).",
        "Add retries for 429 (rate limit) responses.",
    ],
)
def test_provider_rate_limit_status_does_not_invent_a_local_limiter_goal(advice):
    from app.scan.paid_operation_recommendations import operational_followups

    assert operational_followups(advice) is None


@pytest.mark.parametrize(
    "advice",
    [
        "Add rate limiting before expensive work.",
        "Review the per-tenant rate limiter.",
        "Apply a shared rate limit.",
        "Consider rate limiting separately.",
    ],
)
def test_explicit_local_limiter_action_remains_a_followup(advice):
    from app.scan.paid_operation_recommendations import operational_followups

    assert "Review rate limiting separately" in operational_followups(advice)["replacement_fix_hint"]

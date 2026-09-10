"""A shared operation cannot erase distinct external/concurrency conditions."""
from copy import deepcopy

import pytest

from app.scan.external_operation_identity import (
    compatible_external_claims, identity_from_assessments, valid_external_identity,
)
from tests.test_external_call_assessment import CLASSIFIED, POLL, check


def item(title="Polling loop can take up to 40 seconds"):
    assessments = check(CLASSIFIED + POLL, "let attempts", title)
    raw = {"file": "src/route.ts", "title": title, "source": "llm", "verification_method": "model_review",
           "verification_status": "unverified", "category": "Money & Data", "origin_category": None,
           "explanation": "The poll sleeps are treated as a wall-clock bound.",
           "claim_evidence": {"observation": "The callback has poll waits and an awaited request.",
                              "required_conditions": ["The provider remains processing"],
                              "conditions_status": "not_checked", "consequence_status": "not_checked",
                              "source_assessments": assessments}}
    identity = identity_from_assessments(assessments, raw["file"])
    assert identity is not None
    return raw, identity


def test_source_operation_and_equal_proposition_can_group_spelling_variations():
    first, identity = item()
    second = deepcopy(first)
    second["title"] = "POLLING  loop can take up to 40 seconds"
    assert compatible_external_claims(first, second, identity)
    second["claim_evidence"]["required_conditions"] = ["The client retries after a function timeout"]
    assert not compatible_external_claims(first, second, identity)


@pytest.mark.parametrize("field,value", [
    ("required_conditions", ["The provider remains processing", "A retryable error occurs"]),
    ("required_conditions", None),
    ("observation", "Every request is billed separately"),
    ("conditions_status", "verified"),
    ("consequence_status", "verified"),
])
def test_distinct_assumptions_observations_or_verification_never_group(field, value):
    first, identity = item()
    second = deepcopy(first)
    second["claim_evidence"][field] = value
    assert not compatible_external_claims(first, second, identity)


def test_unrelated_title_or_added_cost_consequence_is_not_swallowed():
    first, identity = item()
    second = deepcopy(first)
    second["title"] = "Prediction URL permits an SSRF redirect"
    assert not compatible_external_claims(first, second, identity)
    second = deepcopy(first)
    second["explanation"] += " This also proves every GET is charged."
    assert not compatible_external_claims(first, second, identity)


@pytest.mark.parametrize("title", ["Polling loop can take up to 160 seconds",
                                  "Polling loop can take up to 40 seconds and cause SSRF"])
def test_title_only_numeric_or_additional_consequence_cannot_merge(title):
    first, identity = item()
    second = deepcopy(first)
    second["title"] = title
    second["claim_evidence"]["source_assessments"] = check(CLASSIFIED + POLL, "let attempts", title)
    assert not compatible_external_claims(first, second, identity)


def test_identity_must_match_bound_operation_source_and_supported_mechanism():
    first, identity = item()
    assert valid_external_identity(identity, first["file"])
    for key, value in [("source_sha256", "a" * 64), ("operation_span", [1, 2]),
                       ("mechanism", "whole_external_function")]:
        records = deepcopy(first["claim_evidence"]["source_assessments"])
        for record in records:
            record["operation_identity"][key] = value
        assert identity_from_assessments(records, first["file"]) is None
    records = deepcopy(first["claim_evidence"]["source_assessments"])
    records[0]["operation_identity"]["extra_model_metadata"] = "untrusted"
    assert identity_from_assessments(records, first["file"]) is None


def test_same_helper_different_invocation_is_not_same_source_operation():
    first, identity = item()
    records = check(CLASSIFIED + POLL.replace(" let result", " await prepareOtherOperation();\n let result"),
                    "let attempts", first["title"])
    second_identity = identity_from_assessments(records, first["file"])
    assert second_identity is not None and second_identity != identity

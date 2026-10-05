"""Validate pilot controls against production source analysis, without model calls."""

import io
import zipfile

import pytest

from app.scan.issue_identity import SourceIssueResolver
from app.scan.source_claim_assessment import FACT_KIND, SourceClaimVerifier
from scripts.luna_pilot_cases import supplemental_cases


def _case(case_id):
    return next(case for case in supplemental_cases() if case["id"] == case_id)


def _archive(case):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for path, source in case["files"].items():
            archive.writestr(path, source)
    stream.seek(0)
    return stream


@pytest.mark.parametrize("case_id, has_identity", [
    ("pagination-control", False),
    ("pagination-unbounded", True),
])
def test_query_identity_distinguishes_explicit_limit_from_timestamp_filter(case_id, has_identity):
    finding = {
        "file": "src/messages.ts",
        "title": "Messages query fetches all messages for a match with no pagination limit",
        "line_start": 2,
        "line_end": 7,
        "premises": [{"kind": "query_limit_unbounded", "target": "query",
                      "line_start": 2, "line_end": 7}],
    }
    identity = SourceIssueResolver(_archive(_case(case_id))).identity(finding)
    assert (identity is not None) is has_identity
    if has_identity:
        assert identity["version"] == 2
        assert identity["mechanism"] == "query_read_volume"


@pytest.mark.parametrize("case_id, has_cap", [("facts-control", True), ("facts-unbounded", False)])
def test_fact_control_proves_only_rendered_count_not_read_prompt_or_cost(case_id, has_cap):
    records = SourceClaimVerifier(_archive(_case(case_id))).checks_for({
        "file": "src/agent_context.ts",
        "line_start": 3,
        "line_end": 3,
        "title": "All facts are injected into every model prompt without a count cap",
    })
    contradictions = [record for record in records
                      if record["kind"] == FACT_KIND and record["result"] == "contradicted"]
    assert bool(contradictions) is has_cap
    if has_cap:
        (record,) = contradictions
        assert record["whole_finding"] is False
        binding = record["source_binding"]
        assert binding["upper"] == 40
        assert binding["database_read_bound"] == "not_checked"
        assert binding["total_prompt_bound"] == "not_checked"


def test_trial_inputs_are_independent_of_evaluator_metadata_and_prior_mutations():
    cases = supplemental_cases()
    assert len({case["id"] for case in cases}) == 4
    for case in cases:
        assert case["rubric"] == "money"
        assert case["review_expectation"]
        assert all(case["review_expectation"] not in source for source in case["files"].values())
    cases[0]["files"].clear()
    cases[0]["review_expectation"] = "changed by consumer"
    assert supplemental_cases()[0]["files"]
    assert supplemental_cases()[0]["review_expectation"] != "changed by consumer"

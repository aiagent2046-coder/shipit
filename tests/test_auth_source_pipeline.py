"""Admission must compute Auth review metadata from uploaded source only."""

import json

import pytest

from app.report.html import _finding_row
from app.scan.claim_evidence import narrative_review_checks
from app.scan.pipeline import run_scan
from tests.test_audit_llm_wiring import FakeLLM, make_zip
from tests.test_auth_source_assessment import PATH, SERVICE, raw


@pytest.mark.parametrize("guarded", [True, False])
def test_source_owned_auth_review_reaches_current_report_without_trusting_model_metadata(guarded):
    source = SERVICE if guarded else SERVICE.replace(".eq('user_id', user.id)", "")
    claim = raw(source, needle="db =")
    claim.update(
        evidence="const db = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);",
        severity="high", confidence=0.9,
        explanation="A future query omitting the ownership filter would expose rows.",
        source_assessments=[{"kind": "verified_user_operation_scope", "result": "observed",
                             "narrative_review": {"status": "required", "reason": "MODEL FORGED REVIEW"}}],
    )
    claim["claim_evidence"] = {"version": 1, "source_assessments": claim["source_assessments"]}
    report = run_scan(make_zip({PATH: source.encode()}).getvalue(),
                      FakeLLM(response=json.dumps([claim])), llm_rubrics=("auth",))
    finding, = [f for f in report["findings"] if f["source"] == "llm"]
    checks = narrative_review_checks(finding["claim_evidence"])
    assert bool(checks) is guarded
    assert "MODEL FORGED REVIEW" not in json.dumps(finding)
    assert ("Outcome needs review" in _finding_row(finding)) is guarded
    assert finding["severity"] == "high"
    assert finding["claim_evidence"]["consequence_status"] == "not_checked"

"""Source counterevidence reaches current reports without dismissing mixed claims."""
import json

import pytest

from app.report.html import _finding_row
from app.scan.claim_evidence import partial_contradicted, unsupported_transport
from app.scan.pipeline import run_scan
from tests.test_audit_llm_wiring import FakeLLM, make_zip
from tests.test_source_claim_assessment import CALLER, HELPER, TIMEZONE, finding


@pytest.mark.parametrize("source,marker,title,expected", [
    (CALLER, "{data: facts", "All facts are injected into every model prompt",
     {"fact_input_count_unbounded"}),
    (TIMEZONE, "if (parsed.data.time_zone", "Intl timezone validation has no error handling; empty string passes",
     {"local_intl_error_handling_absent", "empty_string_schema_guard_absent"}),
])
def test_partial_assessment_crosses_model_admission_scoring_and_rendering(source, marker, title, expected):
    raw = finding(source, marker=marker, title=title)
    raw.update(file="app/auth.ts", evidence=marker, severity="high", confidence=0.9,
               explanation="Review this source claim and separate validation or cost concerns.")
    result = run_scan(make_zip({"app/auth.ts": source.encode(), "app/helper.ts": HELPER.encode()}).getvalue(),
                      FakeLLM(response=json.dumps([raw])), llm_rubrics=("auth",))
    model, = [f for f in result["findings"] if f["source"] == "llm"]
    checks = model["claim_evidence"]["source_assessments"]
    assert {c["kind"] for c in checks if c["result"] == "contradicted"} == expected
    assert all(c["whole_finding"] is False for c in checks)
    assert partial_contradicted(model["claim_evidence"])
    assert not unsupported_transport(model["claim_evidence"])
    assert result["score"]["categories"]["Auth"] < 10
    assert "Source checks contradict part of this finding" in _finding_row(model)
    assert "Source checks contradict part of this finding" not in _finding_row(model, historical=True)
    assert model["title"] == title

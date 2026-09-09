"""Conditional database context cannot become a source-proven contradiction."""
import json

import pytest

from app.report.html import _finding_row
from app.scan.claim_evidence import partial_contradicted, unsupported_transport
from app.scan.pipeline import run_scan
from tests.test_audit_llm_wiring import FakeLLM, make_zip
from tests.test_external_call_assessment import CALLER, COUNT, HELPER, WRAPPER, finding


@pytest.mark.parametrize("source,marker,title,kind,partial", [
    (WRAPPER + HELPER + CALLER, "const res = await withRetry", "Retry on any error or JSON parsing failure",
     "retry_callback_scope", True),
    (COUNT, "after(async", "Both concurrent requests see count one and call Claude",
     "insert_before_count_schedule", False),
])
def test_external_source_assessment_keeps_original_and_mixed_penalty(source, marker, title, kind, partial):
    raw = finding(source, marker, title)
    raw.update(file="app/auth.ts", evidence=marker, severity="high", confidence=0.9,
               explanation="The external call's outcome and billing need separate verification.")
    result = run_scan(make_zip({"app/auth.ts": source.encode()}).getvalue(),
                      FakeLLM(response=json.dumps([raw])), llm_rubrics=("auth",))
    model, = [f for f in result["findings"] if f["source"] == "llm"]
    assessment, = [c for c in model["claim_evidence"]["source_assessments"] if c["kind"] == kind]
    assert assessment["whole_finding"] is False
    assert partial_contradicted(model["claim_evidence"]) is partial
    assert not unsupported_transport(model["claim_evidence"])
    assert result["score"]["categories"]["Auth"] < 10
    assert ("Source checks contradict part of this finding" in _finding_row(model)) is partial
    assert model["title"] == title

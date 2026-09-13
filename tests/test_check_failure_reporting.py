"""A detector failure must survive the scan-to-report boundary as a tool error."""

import json
from pathlib import Path

import jsonschema
import pytest

from app.llm.client import LLMClient
from app.report.evidence import non_model_status_notices
from app.report.html import render_report
from app.report.sarif import build_sarif
from app.scan import static
from app.scan.pipeline import AUDIT_ENGINE_VERSION, run_scan
from tests.test_check_isolation import LEAKING_MESSAGE, explode, make_zip


@pytest.mark.parametrize("target,check", [
    ("scan_cookie_flags", "session_cookie"),
    ("scan_error_boundary", "error_boundary"),
])
def test_detector_failure_reaches_html_and_valid_sarif(monkeypatch, target, check):
    monkeypatch.setattr(static, target, explode)
    scan = run_scan(make_zip().getvalue(), LLMClient(), llm_skip_reason="free_tier")
    # Simulate persistence: report exports receive plain stored data.
    scan = json.loads(json.dumps(scan))
    expected = [{"check": check, "reason": "check_error: RuntimeError"}]
    assert scan["score"]["scan_manifest"]["static_checks_not_run"] == expected
    assert any(f["rule_id"] == "github-pat" for f in scan["findings"])

    html = render_report(scan)
    assert 'aria-label="Static checks failed"' in html
    assert f"{check}: check_error: RuntimeError" in html
    assert f"Static check failed: {check}" in html
    assert "cannot be used for comparison" in html
    assert "affected check is not classified" not in html

    sarif = build_sarif(scan["findings"], engine_version=AUDIT_ENGINE_VERSION, score=scan["score"])
    schema = json.loads((Path(__file__).parent / "fixtures/sarif-schema-2.1.0.json").read_text())
    jsonschema.Draft7Validator(schema, format_checker=jsonschema.FormatChecker()).validate(sarif)
    invocation = sarif["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is False
    assert invocation["properties"]["staticChecksNotRun"] == expected
    notices = invocation["toolExecutionNotifications"]
    assert len(notices) == 1 and notices[0]["level"] == "error"
    assert notices[0]["properties"] == expected[0]
    assert check in notices[0]["message"]["text"]
    assert len(sarif["runs"][0]["results"]) == len(scan["findings"])
    assert LEAKING_MESSAGE not in html + json.dumps(sarif)


def test_successful_scan_keeps_successful_invocation_and_no_failure_notice():
    scan = run_scan(make_zip().getvalue(), LLMClient(), llm_skip_reason="free_tier")
    sarif = build_sarif(scan["findings"], engine_version=AUDIT_ENGINE_VERSION, score=scan["score"])
    invocation = sarif["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is True
    assert "toolExecutionNotifications" not in invocation
    assert not any(title == "Static checks failed" for title, _ in non_model_status_notices(scan["score"]))


@pytest.mark.parametrize("record", [
    {"check": "session_cookie", "reason": "check_error: RuntimeError: " + LEAKING_MESSAGE},
    {"check": LEAKING_MESSAGE, "reason": LEAKING_MESSAGE, "message": LEAKING_MESSAGE},
    "broken_record",
])
def test_malformed_saved_failure_stays_visible_without_exception_text(record):
    score = {"scan_manifest": {"static_checks_not_run": [record]}}
    sarif = build_sarif([], engine_version=AUDIT_ENGINE_VERSION, score=score)
    assert sarif["runs"][0]["invocations"][0]["executionSuccessful"] is False
    notices = non_model_status_notices(score)
    assert notices[0][0] == "Static checks failed"
    assert "reason_not_recorded" in notices[0][1]
    assert LEAKING_MESSAGE not in json.dumps(sarif) + json.dumps(notices)

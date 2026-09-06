"""Scan passport records available facts and explicit gaps, including failures."""
import hashlib

import pytest

from app.llm.client import LLMClient
from app.report.evidence import coverage_rows, finding_counts, manifest_rows
from app.report.evidence import model_status_notice, source_severity_counts
from app.report.html import render_report
from app.report.plain_language import plain_fields
from app.scan.manifest import scan_manifest
from app.scan.pipeline import AUDIT_ENGINE_VERSION, run_scan
from tests.test_audit_llm_wiring import AUTH_ZIP, FakeLLM, make_zip


def test_static_scan_records_input_and_skip_without_inventing_a_git_commit():
    data = make_zip({"repo-1907721/app.py": b"print('hello')",
                     "repo-1907721/deploy/api.service": b"[Service]"}).getvalue()
    score = run_scan(data, LLMClient(providers=[]))["score"]
    m = score["scan_manifest"]
    assert m["archive_sha256"] == hashlib.sha256(data).hexdigest()
    assert m["commit_sha"] is None
    assert m["engine_version"] == AUDIT_ENGINE_VERSION
    assert m["archive_files"] == 2
    assert m["inventory"]["systemd units"] == ["repo-1907721/deploy/api.service"]
    assert m["runtime_verified"] is False
    assert m["model_calls"] == 0
    assert "no_providers_configured" in m["limitations"]
    assert "broader auth not checked" in dict(coverage_rows(score, []))["Auth"]
    assert dict(manifest_rows({}))["Scan record"] == "Not recorded for this older audit"


def test_model_submission_counts_and_limit_reasons_are_preserved():
    data = make_zip(AUTH_ZIP).getvalue()
    score = run_scan(data, FakeLLM(response="[]"), llm_rubrics=("auth",))["score"]
    m = score["scan_manifest"]
    assert m["model_calls"] == 1
    assert m["llm_submitted_files"] > 0
    assert m["llm_candidate_files"] >= m["llm_submitted_files"]
    assert m["llm_files_not_submitted"] == m["llm_candidate_files"] - m["llm_submitted_files"]
    limited = scan_manifest(data, "test", {}, {
        "candidate_files": 5, "submitted_files": ["a.py", "b.py"],
        "calls": 1, "cost_cap_exceeded": True, "failed_rubric": "money",
    }, "provider_failure")
    assert limited["llm_files_not_submitted"] == 3
    assert limited["limitations"] == ["provider_failure", "cost_cap_exceeded", "rubric_failed: money"]


def test_fixture_counts_and_old_credential_claims_cannot_inflate_the_headline():
    fixture = {"rule_id": "aws-access-key-id", "category": "Security", "severity": "high",
               "file": "tests/key.py", "context": "test_file", "source": "static",
               "explanation": "An attacker controls your AWS account", "fix_hint": "Rotate everything"}
    source = {**fixture, "file": "app/key.py", "context": None}
    assert finding_counts([source, fixture]) == (1, 1)
    what, risk, fix = plain_fields(fixture)
    assert "matches" in what
    assert "alone cannot authenticate" in risk
    assert "test, example or comment" in risk
    assert "Rotate everything" not in fix
    html = render_report({"score": {"basis": "static_only", "categories": {}},
                          "findings": [source, fixture]})
    assert "An attacker controls" not in html
    assert "1 test/example observations" in html
    assert "Not recorded for this older audit" in html


def test_display_grouping_preserves_source_and_example_counts():
    from app.report.grouping import group_for_display
    from app.scan.rls import RULE_ID
    common = {"rule_id": RULE_ID, "severity": "medium", "category": "Security", "title": "RLS"}
    findings = [{**common, "file": "schema/a.sql"}, {**common, "file": "schema/b.sql"},
                {**common, "file": "tests/schema.sql"}]
    grouped = group_for_display(findings)
    assert len(grouped) == 2
    assert finding_counts(grouped) == finding_counts(findings) == (2, 1)


def test_mixed_severity_display_group_retains_the_original_source_summary():
    from app.report.grouping import group_for_display
    from app.scan.rls import RULE_ID
    common = {"rule_id": RULE_ID, "category": "Security", "title": "RLS", "file": "schema.sql"}
    findings = [{**common, "severity": "high"}, {**common, "severity": "medium"},
                {**common, "severity": "critical", "file": "tests/schema.sql"}]
    grouped = group_for_display(findings)
    assert source_severity_counts(grouped) == source_severity_counts(findings) == {
        "critical": 0, "high": 1, "medium": 1, "low": 0,
    }


@pytest.mark.parametrize("reason,calls,basis,title,detail", [
    ("billing", 0, "static_only", "Model review unavailable", "billing or quota"),
    ("provider", 2, "static+partial", "Model review incomplete", "request failed"),
    ("cost_cap_exceeded", 1, "static+llm", "Model review incomplete", "spending limit"),
    ("input_truncated", 1, "static+llm", "Model review incomplete", "truncated input"),
    ("no_providers_configured", 0, "static_only", "Model review unavailable", "No model response"),
])
def test_limited_model_status_is_visible_before_findings(reason, calls, basis, title, detail):
    score = {"basis": basis, "categories": {}, "scan_manifest": {"model_calls": calls, "limitations": [reason]}}
    notice = model_status_notice(score)
    assert notice[0] == title
    assert detail in notice[1]
    html = render_report({"score": score, "findings": []})
    assert html.index('aria-label="Model review status"') < html.index("No issues found by the current checks")
    assert detail in html


def test_successful_preview_and_full_reviews_have_no_failure_notice():
    for basis in ("static+preview", "static+llm"):
        assert model_status_notice({"basis": basis, "scan_manifest": {"model_calls": 1, "limitations": []}}) is None
    assert model_status_notice({}) is None
    assert "details were not recorded" in model_status_notice({"basis": "static+partial"})[1]


@pytest.mark.parametrize("flag", ["cost_cap_exceeded", "input_truncated"])
def test_limited_model_review_cannot_be_cached_as_full(monkeypatch, flag):
    from app.scan import pipeline
    from app.scan.llm_scan import LLMScanStats

    def limited(*args, **kwargs):
        return [], LLMScanStats(calls=1, rubrics_ran=("auth",), **{flag: True})

    monkeypatch.setattr(pipeline, "run_llm_scan", limited)
    scan = run_scan(make_zip(AUTH_ZIP).getvalue(), FakeLLM(response="[]"))
    assert scan["score"]["basis"] == "static+partial"
    assert flag in scan["score"]["scan_manifest"]["limitations"]

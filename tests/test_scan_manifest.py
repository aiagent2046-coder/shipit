"""Scan passport records available facts and explicit gaps, including failures."""
import hashlib

from app.llm.client import LLMClient
from app.report.evidence import coverage_rows, finding_counts, manifest_rows
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
    assert "local Python route comparison" in dict(coverage_rows(score, []))["Auth"]
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

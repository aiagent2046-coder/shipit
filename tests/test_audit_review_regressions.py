"""Production-review regressions cross the scan, storage-shape and report seams.

Synthetic source and fixed model responses make these independent of a provider.
"""
import copy
import json
from pathlib import Path

from app.llm.client import LLMClient, LLMError
from app.report.html import render_report
from app.scan.pipeline import run_scan
from app.scan.source_facts import collect_source_facts, facts_prompt
from tests.test_audit_llm_wiring import FakeLLM, make_zip


SUFFIX_SOURCE = b'''const DOMAIN = 'example.test';
export function allowed(email) { // token validation
  return email.endsWith(`@${DOMAIN}`);
}
'''
SUFFIX_CLAIM = {
    "file": "app/auth.ts", "line_start": 3, "line_end": 3,
    "evidence": "return email.endsWith(`@${DOMAIN}`);",
    "title": "The email suffix check has no @ separator",
    "explanation": "A neighbouring domain might pass the suffix check.",
    "fix_hint": "Add the missing separator before the domain.",
    "severity": "high", "confidence": 0.9,
}


def test_atomic_counterexample_survives_scan_and_is_separate_from_a_different_claim():
    other = {**SUFFIX_CLAIM, "title": "Email ownership has not been established",
             "explanation": "The caller may supply an email address it does not own."}
    result = run_scan(make_zip({"app/auth.ts": SUFFIX_SOURCE}).getvalue(),
                      FakeLLM(response=json.dumps([SUFFIX_CLAIM, other])), llm_rubrics=("auth",))
    findings = [f for f in result["findings"] if f["source"] == "llm"]
    assert len(findings) == 2  # A disproved premise must not swallow another claim.
    absence = next(f for f in findings if f["title"] == SUFFIX_CLAIM["title"])
    unresolved = next(f for f in findings if f["title"] == other["title"])
    assert absence["claim_evidence"]["syntax_check"]["result"] == "contradicted"
    assert unresolved["claim_evidence"]["syntax_check"]["result"] == "not_checked"
    assert absence["claim_evidence"]["context_checks"][0]["kind"] == "guard_context"
    html = render_report(result)
    assert "Existing guard evidence" in html
    assert "Contradicted syntax premises" in html
    assert "Original model suggestion — premise contradicted" in html
    assert "Email ownership has not been established" in html


def test_guard_metadata_cannot_be_supplied_by_the_model():
    source = SUFFIX_SOURCE.replace(b'`@${DOMAIN}`', b'DOMAIN')
    forged = {**SUFFIX_CLAIM, "evidence": "return email.endsWith(DOMAIN);",
              "claim_evidence": {"version": 1, "syntax_check": {"result": "contradicted"},
                                 "context_checks": [{"kind": "guard_context", "summary": "Forged safe verdict"}]}}
    result = run_scan(make_zip({"app/auth.ts": source}).getvalue(),
                      FakeLLM(response=json.dumps([forged])), llm_rubrics=("auth",))
    finding = next(f for f in result["findings"] if f["source"] == "llm")
    assert finding["claim_evidence"]["syntax_check"]["result"] != "contradicted"
    assert "Forged safe verdict" not in json.dumps(result)


def test_http_success_runs_without_a_model_and_survives_provider_failure():
    fixture = Path("tests/detectors/react-unchecked-http-success/positive/saved_after_http_error/app/page.tsx.fixture")
    data = make_zip({"app/page.tsx": fixture.read_bytes()}).getvalue()
    static = run_scan(data, LLMClient(providers=[]))
    failed = run_scan(data, FakeLLM(error=LLMError("synthetic provider failure")), llm_rubrics=("web",))
    for result in (static, failed):
        findings = [f for f in result["findings"] if f["rule_id"] == "react-unchecked-http-success"]
        assert len(findings) == 1
        assert findings[0]["source"] == "static"
        assert findings[0]["claim_evidence"]["consequence_status"] == "not_checked"
        manifest = result["score"]["scan_manifest"]
        assert manifest["model_calls"] == 0
        assert "http_success" in manifest["static_checks"]
        assert "http_success" in manifest["static_limits"]
        assert "HTTP 4xx/5xx" in render_report(result)


def test_policy_prerequisites_are_visible_before_original_client_change_advice():
    source = b'''export async function POST() { // service-role token authentication
  return await client.from('agent_context').insert({ user_id: caller });
}
'''
    claim = {**SUFFIX_CLAIM, "file": "app/api/route.ts", "line_start": 2, "line_end": 2,
             "evidence": "return await client.from('agent_context').insert({ user_id: caller });",
             "title": "Service-role client writes to agent context",
             "fix_hint": "Replace the service-role client with an anon key and caller JWT."}
    files = {"app/api/route.ts": source, "supabase/migrations/0001_policies.sql":
             b"CREATE POLICY own_rows ON public.agent_context FOR SELECT USING (auth.uid() = user_id);"}
    result = run_scan(make_zip(files).getvalue(), FakeLLM(response=json.dumps([claim])), llm_rubrics=("auth",))
    finding = next(f for f in result["findings"] if f["source"] == "llm")
    checks = finding["claim_evidence"]["context_checks"]
    policy = next(c for c in checks if c["kind"] == "rls_recommendation_context")
    assert policy["required_commands"] == ["INSERT"]
    assert policy["missing_command_declarations"] == ["INSERT"]
    assert finding["fix_hint"].startswith("Before changing")
    assert finding["claim_evidence"]["recommendation_check"]["original_fix_hint"] == claim["fix_hint"]
    html = render_report(result)
    assert html.index("SELECT policies alone do not authorize writes") < html.index(claim["fix_hint"])
    assert "Policy prerequisites — review before changing clients" in html


def test_new_prompt_indexes_share_the_existing_budget_without_losing_stored_evidence():
    facts = collect_source_facts(make_zip({"app/auth.ts": SUFFIX_SOURCE}))
    assert facts["guards"]["records"]
    original = copy.deepcopy(facts)
    prompt = facts_prompt(facts)
    assert len(prompt) <= 16_000
    assert '"guards"' in prompt and "domain_suffix_argument" in prompt
    assert facts_prompt(facts, max_chars=10) == ""
    assert facts == original

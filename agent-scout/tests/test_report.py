"""Report tests: what the rights holder sees, and what they never see.

The full report must carry the engine's limitations verbatim and lead with
KEV; the outreach letter must prove without teaching exploitation.
"""
from __future__ import annotations

from scout.engine import ScanResult, rank
from scout.report import render_deep_report, render_outreach, render_report


def finding(advisory, package="pkg", version="1.0.0", exploitation="not_listed",
            severity="high"):
    return {
        "rule_id": "dependency-cve-match",
        "title": f"{package} {version} matches {advisory}",
        "severity": severity,
        "confidence": 0.9,
        "explanation": "The resolved npm package version is listed as affected.",
        "claim_evidence": {
            "advisory_id": advisory,
            "advisory_ids": [advisory],
            "package": package,
            "installed_version": version,
            "dependency_scope": "runtime",
            "exploitation": {"status": exploitation, "source": "cisa-kev"},
        },
    }


LIMITATIONS = [
    "A package/version match does not establish reachable or exploitable application code.",
    "Absence from the snapshot, unsupported ranges, and no matches do not establish a clean or safe project.",
]


def result(*findings):
    return ScanResult(
        findings=rank(list(findings)),
        coverage={"dependencies_found": 2, "dependencies_checked": 2,
                  "manifests": ["package-lock.json"], "kev_listed_findings": 1},
        limitations=LIMITATIONS,
        engine_commit="abc1234",
        catalog_digest="d" * 64,
        target="fixture/project",
        artifacts=["package-lock.json"],
    )


def test_report_leads_with_kev_section():
    text = render_report(result(
        finding("CVE-2026-1", exploitation="listed"),
        finding("CVE-2026-2", package="other")))
    kev_at = text.index("CISA KEV: exploitation confirmed in the wild")
    other_at = text.index("Other matched advisories")
    assert kev_at < other_at
    assert "CVE-2026-1" in text[kev_at:other_at]
    assert "CVE-2026-2" not in text[kev_at:other_at]


def test_report_summary_counts():
    text = render_report(result(
        finding("CVE-2026-1", exploitation="listed"),
        finding("CVE-2026-2", package="other")))
    assert "- Findings total: 2" in text
    assert "- CISA KEV-listed (actively exploited in the wild): 1" in text
    assert "- Effective critical (incl. KEV escalation): 1" in text


def test_report_carries_engine_limitations_verbatim():
    text = render_report(result(finding("CVE-2026-1")))
    for item in LIMITATIONS:
        assert f"- {item}" in text


def test_report_records_provenance():
    text = render_report(result(finding("CVE-2026-1")))
    assert "abc1234" in text
    assert "d" * 16 in text
    assert "package-lock.json" in text


def test_report_states_unknown_engine_commit_honestly():
    # git unavailable -> no SHA: the report must say 'unknown', never guess.
    res = result(finding("CVE-2026-1"))
    res.engine_commit = None
    assert "(shipit) @ unknown" in render_report(res)


def test_report_states_stack_hints_as_signals_not_proof():
    res = result(finding("CVE-2026-1"))
    res.stack_hints = ["nginx", "next.js"]
    text = render_report(res)
    assert "Stack hints (passive signals, not proof): nginx, next.js" in text
    assert "Stack hints" not in render_report(result(finding("CVE-2026-1")))


def test_report_states_disclosure_timeline():
    assert "90 days" in render_report(result(finding("CVE-2026-1")))


def test_outreach_addresses_contact_and_offers_contract():
    text = render_outreach(result(finding("CVE-2026-1", exploitation="listed")),
                           "mailto:sec@example.test")
    assert text.startswith("To: mailto:sec@example.test")
    assert "KEV-listed (actively exploited) findings: 1" in text
    assert "contract" in text
    assert "CVE-2026-1" in text


def test_outreach_without_contact_stays_actionable():
    text = render_outreach(result(finding("CVE-2026-1")), None)
    assert "contact not published" in text
    assert "Subject: Security finding in fixture/project" in text


def test_outreach_proves_without_teaching():
    text = render_outreach(result(finding("CVE-2026-1", exploitation="listed")), None)
    # Proof: counts and advisory identifiers. No evidence table, no engine internals.
    assert "| Advisory |" not in text
    assert "The resolved npm package version" not in text
    assert "have not attempted exploitation" in text


def deep_audit(*findings):
    return {
        "contract_id": "c-9",
        "target": "github.com/o/r",
        "engine_commit": "abc1234",
        "result": {
            "findings": list(findings),
            "score": {"total": 6.5, "basis": "static_only",
                      "categories": {"Security": 7.0},
                      "scan_manifest": {"threat_context": {
                          "limitations": [
                              "known_exploitation_elsewhere_not_project_compromise"]}}},
            "llm": {"skipped_reason": "no_providers_configured",
                    "prompts": 0, "verified": 0},
            "sca": {"skipped_reason": "no_client", "advisories": 0,
                    "asked_at": None},
        },
    }


def test_deep_report_states_basis_and_llm_honestly():
    text = render_deep_report(deep_audit(finding("CVE-2026-1")))
    assert "Assessment basis: static_only" in text
    assert "LLM stage: skipped (no_providers_configured)" in text
    assert "not asked (inventory never sent)" in text


def test_deep_report_lists_findings_kev_first_with_evidence():
    text = render_deep_report(deep_audit(
        finding("CVE-plain", severity="medium"),
        finding("CVE-kev", exploitation="listed"),
    ))
    assert text.index("CVE-kev") < text.index("CVE-plain")  # KEV leads
    assert "CISA KEV-listed (actively exploited in the wild): 1" in text
    assert "installed_version: 1.0.0" in text  # root cause carries the evidence


def test_deep_report_carries_engine_limitations_verbatim():
    text = render_deep_report(deep_audit())
    assert "known_exploitation_elsewhere_not_project_compromise" in text
    assert "llm stage skipped: no_providers_configured" in text
    assert "dependency advisories were not queried" in text


def test_deep_report_db_section_honest_when_not_examined():
    text = render_deep_report(deep_audit())
    assert "Not examined in this engagement" in text
    assert "Absence of evidence is not evidence of safety" in text


def test_deep_report_renders_db_evidence():
    text = render_deep_report(deep_audit(), db_evidence=[
        {"label": "table inventory", "observation": "42 tables, RLS enabled on 3"}])
    assert "table inventory: 42 tables, RLS enabled on 3" in text
    assert "audit-logged per query" in text


def test_deep_report_carries_llm_failure_verbatim():
    audit = deep_audit()
    audit["result"]["llm"] = {
        "prompts": 2, "verified": 0,
        "failure": "openai_compat@https://openrouter.ai/api/v1: model returned "
                   "no answer text (finish_reason='length')"}
    text = render_deep_report(audit)
    assert "LLM stage: partial - openai_compat" in text
    assert "finish_reason='length'" in text  # the failure travels verbatim
    assert "llm stage incomplete: openai_compat" in text

"""Complete a paid audit's dependency check without repeating its code analysis."""
from __future__ import annotations

from app.sca.osv import OsvClient
from app.sca.refresh import inventory_payload, refreshed_findings, refreshed_score
from app.sca.stage import RULE_ID, run_sca_stage, sca_enabled, cve_enabled, loses_cve_evidence
from app.scan.cve_evidence import normalize_cve_summary


def needs_dependency_scan(cached: dict) -> bool:
    """Whether a paid cache hit still needs an enabled dependency lookup.

    Code depth and dependency coverage are independent. A full code audit from
    monitoring or a disabled deployment must not prevent a later paid lookup.
    Unresolvable lockfiles cannot improve without changed bytes or a new engine.
    """
    if not sca_enabled():
        return False
    manifest = (cached.get("score_json") or {}).get("scan_manifest") or {}
    reason = str(manifest.get("sca_skipped_reason") or "")
    cve = normalize_cve_summary(manifest.get("sca_cve"))
    missing_cve = (cve_enabled() and bool(manifest.get("sca_advisories"))
                   and (not cve or cve["status"] in {"disabled", "not_run", "partial", "unavailable"}))
    return (not manifest.get("sca_checks") or reason == "no_client"
            or reason.startswith("osv_unavailable")
            or bool(manifest.get("sca_unreadable_advisories")) or missing_cve)


def complete_cached_dependencies(cached: dict, raw: bytes, client: OsvClient) -> dict:
    """Return scan-shaped data using the stored static/model work and fresh SCA.

    Run on the worker's thread pool: only OSV and CVE may perform network calls here.
    An incomplete answer cannot discard previously established vulnerabilities.
    """
    score = cached.get("score_json") or {}
    findings = cached.get("findings_json") or []
    inventory = cached.get("dependency_inventory")
    sca_findings, stats = run_sca_stage(raw, client)
    incomplete = (loses_cve_evidence(score, stats.get("cve"))
                  or bool(stats.get("skipped_reason"))
                  or bool(stats.get("coverage_incomplete"))
                  or bool(stats.get("unreadable_advisories"))
                  or bool(stats.get("truncated"))
                  or stats.get("dependencies_found", 0) > stats.get("dependencies", 0))
    if not (incomplete and (inventory or any(f.get("rule_id") == RULE_ID for f in findings))):
        findings = refreshed_findings(findings, sca_findings)
        score = refreshed_score(score, findings, stats, previous_audit_id=str(cached["id"]))
        inventory = inventory_payload(raw, stats.get("asked_at"))
    return {"score": score, "findings": findings, "llm": {},
            "llm_usage": {"calls": 0}, "dependency_inventory": inventory}

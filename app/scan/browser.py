"""Local ZIP scanning entry point for a Python Web Worker runtime.

This imports only deterministic scanning/reporting code. It never imports the
server pipeline, calls an external service, or executes submitted source code.
Native parsers are optional; unavailable checks remain explicit failures.
"""
from __future__ import annotations

import io
import hashlib
from copy import deepcopy
from dataclasses import replace

from app.report.sarif import build_sarif
from app.scan.manifest import scan_manifest
from app.scan.static import run_static_scan
from app.scan.security_agent import agent_record, attach_security_agent
from app.scan.version import AUDIT_ENGINE_VERSION


def scan_archive(data: bytes, catalog: dict | None = None) -> dict:
    """Return JSON-serializable findings and SARIF; validation errors propagate.

    The shared static stage enforces the upload contract, including the 50 MiB
    archive cap, expansion/entry limits, duplicate paths and path traversal.
    No numeric readiness score is exposed by this browser report.
    """
    if not isinstance(data, bytes):
        raise TypeError("scan_archive expects bytes")
    static = run_static_scan(io.BytesIO(data), allow_missing_native=True)
    return _result(data, static, _dependencies(data, catalog))


def _dependencies(data: bytes, catalog: dict | None) -> dict | None:
    if catalog is None:
        return None
    from app.scan.cve_match import match_archive
    try:
        return match_archive(data, catalog)
    except (ValueError, TypeError, KeyError, RecursionError):
        return {"findings": [], "coverage": {"status": "unavailable",
                "limitations": ["cve_catalog_invalid"]}}


def _result(data: bytes, static: dict, dependencies: dict | None = None) -> dict:
    manifest = scan_manifest(
        data, AUDIT_ENGINE_VERSION, static,
        {"skipped_reason": "llm_not_run_browser"}, None,
    )
    # Matching uses a preloaded public snapshot; no package query leaves the worker.
    dependency_coverage = dependencies["coverage"] if dependencies else None
    dependency_ran = dependency_coverage and dependency_coverage.get("status") != "unavailable"
    findings = [*static["findings"], *(dependencies["findings"] if dependencies else [])]
    limitations = list(dict.fromkeys([
        *manifest["limitations"], *static.get("limitations", []),
        *([] if dependency_ran else ["dependency_check_not_run"]),
        *(["dependency_snapshot_scope", "dependency_runtime_reachability_not_checked"] if dependency_ran else []),
        "runtime_tests_not_run", "static_source_only",
        *(["native_parsers_unavailable"] if any(
            failure["reason"] == "check_error: ImportError"
            for failure in static["checks_not_run"]
        ) else []),
    ]))
    manifest["limitations"] = limitations
    manifest["dependency_cve"] = dependency_coverage
    coverage = dict(static["coverage"])
    if dependency_coverage:
        coverage["dependency_cve"] = (
            "Local CVE snapshot matching of resolved npm/PyPI dependencies. "
            "Only explicit package identities and supported version ranges are evaluated. "
            "Snapshot exclusions, unlisted packages and unknown ranges cannot establish safety. "
            f"Status: {dependency_coverage.get('status', 'unavailable')}."
        )
    for failure in static["checks_not_run"]:
        coverage[failure["check"]] = f"Did not run ({failure['reason']}). No coverage established."
    sarif = build_sarif(
        findings, engine_version=AUDIT_ENGINE_VERSION,
        score={**static["score"], "basis": "static_only", "scan_manifest": manifest},
    )
    if "recommendation_enrichment_unavailable" in limitations:
        # plain_fields normally fills missing advice from the rule dictionary.
        # That fallback must not reintroduce advice whose guards never ran.
        for rule in sarif["runs"][0]["tool"]["driver"]["rules"]:
            rule["help"] = {"text": "Advice omitted: recommendation prerequisite checks were unavailable."}
    return {
        "report": {
            "engine_version": AUDIT_ENGINE_VERSION,
            "findings": findings,
            "checks_run": static["checks_run"],
            "checks_not_run": static["checks_not_run"],
            "coverage": coverage,
            "rule_coverage": static["rule_coverage"],
            "limitations": limitations,
            "runtime_verified": False,
            "security_agent": agent_record(static.get("security_agent")),
            **({"dependency_cve": dependency_coverage} if dependency_coverage else {}),
        },
        "sarif": sarif,
    }


class ScanSession:
    """In-memory browser session; no source or continuation token leaves the worker.

    Each continuation reads at most another 400 eligible files per bounded rule.
    Findings, parse failures and the per-rule finding cap persist across batches.
    Checks without file accounting are never claimed to be resumable.
    """

    def __init__(self, data: bytes, catalog: dict | None = None):
        if not isinstance(data, bytes):
            raise TypeError("ScanSession expects bytes")
        self.data = data
        self.static = run_static_scan(io.BytesIO(data), allow_missing_native=True)
        self.dependencies = _dependencies(data, catalog)

    def result(self) -> dict:
        failed = {item["check"] for item in self.static["checks_not_run"]}
        result = _result(self.data, self.static, self.dependencies)
        result["can_continue"] = any(
            record.get("skip_reasons", {}).get("file_limit", 0) and name not in failed
            for name, record in self.static["rule_coverage"].items()
        )
        return result

    def continue_scan(self) -> dict:
        from app.scan import static as stage
        from app.scan.rule_coverage import resume_rule
        from app.scan.scoring import ScoredFinding, compute_scores
        from app.scan.claim_evidence import static_claim_evidence
        from app.scan.check_failure_scoring import failed_check_categories

        scanners = {
            "sql_injection": stage.scan_sql_injection,
            "sql_injection_js": stage.scan_sql_injection_js,
            "outbound_url": stage.scan_outbound_url,
            "tls_verification": stage.scan_tls_verification,
            "unsafe_deserialization": stage.scan_unsafe_deserialization,
            "unsafe_xml_parse": stage.scan_unsafe_xml_parse,
            "path_traversal": stage.scan_path_traversal,
            "xss": stage.scan_xss,
            "open_redirect": stage.scan_open_redirect,
            "insecure_randomness": stage.scan_insecure_randomness,
            "command_injection": stage.scan_command_injection,
            "archive_extraction": stage.scan_archive_extraction,
        }
        updated = {**self.static, **deepcopy({key: self.static[key] for key in (
            "findings", "rule_coverage", "check_finding_counts", "checks_not_run", "checks_run", "coverage",
        )})}
        failed = {item["check"] for item in updated["checks_not_run"]}
        for name, scanner in scanners.items():
            previous = self.static["rule_coverage"].get(name, {})
            if name in failed or not previous.get("skip_reasons", {}).get("file_limit"):
                continue
            coverage = {}
            count = updated["check_finding_counts"][name]
            try:
                with resume_rule(previous, count):
                    candidates = scanner(io.BytesIO(self.data), coverage=coverage)
                added = []
                for candidate in candidates:
                    finding = ScoredFinding(
                        rule_id=candidate.rule_id, title=candidate.title, severity=candidate.severity,
                        confidence=candidate.confidence, category=candidate.category,
                        file=candidate.file, line=candidate.line, explanation=candidate.explanation,
                        fix_hint=candidate.fix_hint, source="static", verification_method="source_pattern",
                        claim_evidence=getattr(candidate, "claim_evidence", None) or static_claim_evidence(),
                    )
                    if "recommendation_enrichment_unavailable" in updated["limitations"]:
                        finding = replace(finding, fix_hint="")
                    else:
                        finding = stage.prepare_recommendation(finding, updated["source_facts"])
                    added.append(vars(finding))
                updated["findings"].extend(added)
                updated["check_finding_counts"][name] = count + len(added)
                updated["rule_coverage"][name] = coverage
                prefix = "Continued in local batches; the file limit below applies to each batch. "
                if not updated["coverage"][name].startswith(prefix):
                    updated["coverage"][name] = prefix + updated["coverage"][name]
            except Exception as exc:  # Same fail-closed boundary as the initial static stage.
                updated["checks_not_run"].append({"check": name, "reason": f"check_error: {type(exc).__name__}"})
                updated["checks_run"] = [check for check in updated["checks_run"] if check != name]
                # Preserve previous findings/counts: the failed batch establishes no new coverage.
        frontend = updated["score"].get("frontend_scan")
        updated["score"] = compute_scores(
            [ScoredFinding(**finding) for finding in updated["findings"]], llm_ran=False,
            failed_static=failed_check_categories(updated["checks_not_run"]),
        )
        updated["score"]["frontend_scan"] = frontend
        attach_security_agent(updated, archive_sha256=hashlib.sha256(self.data).hexdigest(),
                              engine_version=AUDIT_ENGINE_VERSION, source_archive=io.BytesIO(self.data))
        self.static = updated
        return self.result()

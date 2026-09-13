"""Local ZIP scanning entry point for a Python Web Worker runtime.

This imports only deterministic scanning/reporting code. It never imports the
server pipeline, calls an external service, or executes submitted source code.
Native parsers are optional; unavailable checks remain explicit failures.
"""
from __future__ import annotations

import io

from app.report.sarif import build_sarif
from app.scan.manifest import scan_manifest
from app.scan.static import run_static_scan
from app.scan.version import AUDIT_ENGINE_VERSION


def scan_archive(data: bytes) -> dict:
    """Return JSON-serializable findings and SARIF; validation errors propagate.

    The shared static stage enforces the upload contract, including the 50 MiB
    archive cap, expansion/entry limits, duplicate paths and path traversal.
    No numeric readiness score is exposed by this browser report.
    """
    if not isinstance(data, bytes):
        raise TypeError("scan_archive expects bytes")
    static = run_static_scan(io.BytesIO(data), allow_missing_native=True)
    manifest = scan_manifest(
        data, AUDIT_ENGINE_VERSION, static,
        {"skipped_reason": "llm_not_run_browser"}, None,
    )
    # No advisory lookup occurs, whether or not the archive has a lockfile.
    limitations = list(dict.fromkeys([
        *manifest["limitations"], *static.get("limitations", []),
        "dependency_check_not_run", "runtime_tests_not_run", "static_source_only",
        *(["native_parsers_unavailable"] if any(
            failure["reason"] == "check_error: ImportError"
            for failure in static["checks_not_run"]
        ) else []),
    ]))
    manifest["limitations"] = limitations
    coverage = dict(static["coverage"])
    for failure in static["checks_not_run"]:
        coverage[failure["check"]] = f"Did not run ({failure['reason']}). No coverage established."
    sarif = build_sarif(
        static["findings"], engine_version=AUDIT_ENGINE_VERSION,
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
            "findings": static["findings"],
            "checks_run": static["checks_run"],
            "checks_not_run": static["checks_not_run"],
            "coverage": coverage,
            "rule_coverage": static["rule_coverage"],
            "limitations": limitations,
            "runtime_verified": False,
        },
        "sarif": sarif,
    }

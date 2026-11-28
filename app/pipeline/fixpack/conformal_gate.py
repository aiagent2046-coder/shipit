"""Conformal Risk Control eligibility gate for Fix Pack autonomous rewrites.

A finding whose nonconformity score s(x) exceeds its stratum's calibrated
finite-sample threshold lambda_fix (at risk level alpha_fix = 0.05) stays in
the customer report in full, but is refused autonomous source modification in
Fix Pack so low-certainty detections never silently rewrite application code.
"""

from __future__ import annotations

from typing import Any

from app.scan.core.secrets import RULES as _SECRET_RULES
from app.scan.reporting.conformal.strata_thresholds import (
    ALPHA_FIX,
    ZONE_AUTO_FIX,
    classify_finding_risk,
)

_CANONICAL_SECRET_CONFIDENCE = {r.id: r.confidence for r in _SECRET_RULES}

CONFORMAL_SKIP_REASON = (
    "Needs human review — confidence is below the calibrated 5% false-positive "
    "risk bound for unattended code modification:"
)


def _normalize_for_gate(finding: dict[str, Any]) -> dict[str, Any]:
    """Normalize legacy persisted dicts while keeping pipeline findings exact.

    1. Historical audits predating confidence persistence have no `confidence`
       key and default to 0.9.
    2. Raw `SecretFinding` projections (`source` absent, `source_context`
       present) with `context=None` represent pre-classification secret hits
       whose pre-damping confidence is the rule's canonical `rule.confidence`.
    """
    if "confidence" not in finding or finding["confidence"] is None:
        return {**finding, "confidence": 0.9}
    rule_id = str(finding.get("rule_id", ""))
    if (
        "source" not in finding
        and "source_context" in finding
        and finding.get("context") is None
        and rule_id in _CANONICAL_SECRET_CONFIDENCE
    ):
        return {**finding, "confidence": _CANONICAL_SECRET_CONFIDENCE[rule_id]}
    return finding


def passes_conformal_fixpack_gate(finding: dict[str, Any]) -> bool:
    """True when the finding sits inside the calibrated `auto_fix_eligible` zone."""
    verdict = classify_finding_risk(_normalize_for_gate(finding))
    return verdict["zone"] == ZONE_AUTO_FIX


def conformal_rejection_metadata(finding: dict[str, Any]) -> dict[str, Any]:
    """Structured audit stamp explaining why CRC withheld autonomous patching."""
    verdict = classify_finding_risk(_normalize_for_gate(finding))
    return {
        "alpha_fix": ALPHA_FIX,
        "stratum": verdict["stratum"],
        "nonconformity": verdict["nonconformity"],
        "lambda_fix": verdict["lambda_fix"],
        "zone": verdict["zone"],
    }

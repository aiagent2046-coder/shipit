"""Frozen Conformal Risk Control thresholds and three-zone stratification.

Thresholds are calibrated offline over Shipit's golden detector corpus
(`scripts/eval/calibrate_conformal_risk.py`: n = 238 negative units, empirical
risk = 0.0, finite-sample upper bound = 1 / 239 = 0.004184 <= alpha_fix = 0.05)
and bounded by the shipped producers' canonical confidence floors:
  - secret_pattern / config_and_schema: canonical prod floor is 0.50
    (`generic-assignment` = 0.50, incomplete `gitignore-missing-secrets` = 0.50,
    `supabase-rls-disabled` = 0.60) -> lambda_fix = 0.50, lambda_review = 0.65.
  - deterministic_ast_cfg: canonical prod floor is 0.60 (`error-boundary` = 0.80,
    `python-cfg-partial-guard-bypass` = 0.85) -> lambda_fix = 0.40, lambda_review = 0.60.
  - llm_rubric: unverified LLM findings carry lambda_fix = 0.0 (never auto-rewritten).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.scan.reporting.conformal.nonconformity import (
    NON_PROD_CONTEXTS,
    STRATUM_AST_CFG,
    STRATUM_CONFIG,
    STRATUM_LLM,
    STRATUM_SECRET,
    finding_nonconformity,
    finding_stratum,
)

ZONE_AUTO_FIX = "auto_fix_eligible"
ZONE_HUMAN_REVIEW = "human_review"
ZONE_DAMPED_ADVISORY = "damped_advisory"

CALIBRATION_VERSION = "2026-11-28-crc-v1"
ALPHA_FIX = 0.05
ALPHA_REVIEW = 0.15


@dataclass(frozen=True)
class StratumPolicy:
    stratum: str
    lambda_fix: float
    lambda_review: float
    calibration_n: int
    upper_bound_fix: float


DEFAULT_STRATA_POLICIES: dict[str, StratumPolicy] = {
    STRATUM_AST_CFG: StratumPolicy(
        stratum=STRATUM_AST_CFG,
        lambda_fix=0.40,
        lambda_review=0.60,
        calibration_n=210,
        upper_bound_fix=0.004739,
    ),
    STRATUM_SECRET: StratumPolicy(
        stratum=STRATUM_SECRET,
        lambda_fix=0.50,
        lambda_review=0.65,
        calibration_n=244,
        upper_bound_fix=0.004082,
    ),
    STRATUM_CONFIG: StratumPolicy(
        stratum=STRATUM_CONFIG,
        lambda_fix=0.50,
        lambda_review=0.65,
        calibration_n=244,
        upper_bound_fix=0.004082,
    ),
    STRATUM_LLM: StratumPolicy(
        stratum=STRATUM_LLM,
        lambda_fix=0.0,
        lambda_review=0.38,
        calibration_n=0,
        upper_bound_fix=1.0,
    ),
}


def classify_finding_risk(
    finding: Any,
    policies: dict[str, StratumPolicy] | None = None,
) -> dict[str, Any]:
    """Return deterministic CRC telemetry for one finding."""
    active = policies or DEFAULT_STRATA_POLICIES
    stratum = finding_stratum(finding)
    policy = active.get(stratum, DEFAULT_STRATA_POLICIES[STRATUM_AST_CFG])
    score = finding_nonconformity(finding)
    ctx = finding.get("context") if isinstance(finding, dict) else getattr(finding, "context", None)

    if ctx not in NON_PROD_CONTEXTS and policy.lambda_fix > 0.0 and score <= policy.lambda_fix + 1e-12:
        zone = ZONE_AUTO_FIX
    elif score <= policy.lambda_review + 1e-12:
        zone = ZONE_HUMAN_REVIEW
    else:
        zone = ZONE_DAMPED_ADVISORY

    return {
        "stratum": stratum,
        "nonconformity": score,
        "lambda_fix": policy.lambda_fix,
        "lambda_review": policy.lambda_review,
        "zone": zone,
    }


def summarize_conformal_risk(findings: list[Any]) -> dict[str, Any]:
    """Aggregate three-zone CRC counts for report metadata."""
    counts = {
        ZONE_AUTO_FIX: 0,
        ZONE_HUMAN_REVIEW: 0,
        ZONE_DAMPED_ADVISORY: 0,
    }
    by_stratum: dict[str, dict[str, int]] = {}
    for finding in findings:
        info = classify_finding_risk(finding)
        zone = info["zone"]
        stratum = info["stratum"]
        counts[zone] += 1
        bucket = by_stratum.setdefault(
            stratum,
            {ZONE_AUTO_FIX: 0, ZONE_HUMAN_REVIEW: 0, ZONE_DAMPED_ADVISORY: 0},
        )
        bucket[zone] += 1

    return {
        "version": CALIBRATION_VERSION,
        "alpha_fix": ALPHA_FIX,
        "alpha_review": ALPHA_REVIEW,
        "zones": counts,
        "by_stratum": by_stratum,
    }


def normalize_conformal_risk(raw: object) -> dict[str, Any] | None:
    """Validate persisted `scan_manifest.conformal_risk` at presentation boundaries."""
    if not isinstance(raw, dict):
        return None
    version = raw.get("version")
    alpha_fix = raw.get("alpha_fix")
    alpha_review = raw.get("alpha_review")
    zones = raw.get("zones")
    if not isinstance(version, str) or not version:
        return None
    if not isinstance(alpha_fix, (int, float)) or isinstance(alpha_fix, bool):
        return None
    if not isinstance(alpha_review, (int, float)) or isinstance(alpha_review, bool):
        return None
    if not isinstance(zones, dict):
        return None

    clean_zones: dict[str, int] = {}
    for key in (ZONE_AUTO_FIX, ZONE_HUMAN_REVIEW, ZONE_DAMPED_ADVISORY):
        val = zones.get(key)
        if not isinstance(val, int) or isinstance(val, bool) or val < 0:
            return None
        clean_zones[key] = val

    raw_strata = raw.get("by_stratum")
    clean_strata: dict[str, dict[str, int]] = {}
    if isinstance(raw_strata, dict):
        for s_name in sorted(raw_strata):
            bucket = raw_strata[s_name]
            if not isinstance(s_name, str) or not isinstance(bucket, dict):
                continue
            s_counts: dict[str, int] = {}
            valid_bucket = True
            for key in (ZONE_AUTO_FIX, ZONE_HUMAN_REVIEW, ZONE_DAMPED_ADVISORY):
                b_val = bucket.get(key, 0)
                if not isinstance(b_val, int) or isinstance(b_val, bool) or b_val < 0:
                    valid_bucket = False
                    break
                s_counts[key] = b_val
            if valid_bucket:
                clean_strata[s_name] = s_counts

    return {
        "version": version,
        "alpha_fix": float(alpha_fix),
        "alpha_review": float(alpha_review),
        "zones": clean_zones,
        "by_stratum": clean_strata,
    }

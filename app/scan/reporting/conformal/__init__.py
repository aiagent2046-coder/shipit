"""Conformal Risk Control (CRC) calibration and stratification package."""

from app.scan.reporting.conformal.nonconformity import (
    compute_nonconformity_score,
    finding_nonconformity,
    finding_stratum,
    producer_stratum,
)
from app.scan.reporting.conformal.risk_control import (
    CalibrationSample,
    ConformalCalibrationResult,
    calibrate_conformal_threshold,
    finite_sample_risk_bound,
)
from app.scan.reporting.conformal.strata_thresholds import (
    ALPHA_FIX,
    ALPHA_REVIEW,
    CALIBRATION_VERSION,
    DEFAULT_STRATA_POLICIES,
    ZONE_AUTO_FIX,
    ZONE_DAMPED_ADVISORY,
    ZONE_HUMAN_REVIEW,
    StratumPolicy,
    classify_finding_risk,
    normalize_conformal_risk,
    summarize_conformal_risk,
)

__all__ = [
    "ALPHA_FIX",
    "ALPHA_REVIEW",
    "CALIBRATION_VERSION",
    "CalibrationSample",
    "ConformalCalibrationResult",
    "DEFAULT_STRATA_POLICIES",
    "StratumPolicy",
    "ZONE_AUTO_FIX",
    "ZONE_DAMPED_ADVISORY",
    "ZONE_HUMAN_REVIEW",
    "calibrate_conformal_threshold",
    "classify_finding_risk",
    "compute_nonconformity_score",
    "finding_nonconformity",
    "finding_stratum",
    "finite_sample_risk_bound",
    "normalize_conformal_risk",
    "producer_stratum",
    "summarize_conformal_risk",
]

"""Finite-sample Conformal Risk Control (Angelopoulos et al., ICLR 2024).

Given n exchangeable calibration units with monotone non-decreasing loss
functions L_i(lambda) in [0, B] for lambda in [0, 1], the finite-sample
conservative risk bound at threshold lambda is:

    R_hat_plus(lambda) = (sum_{i=1..n} L_i(lambda) + B) / (n + 1)

Choosing lambda_hat_alpha = sup { lambda in Grid : R_hat_plus(lambda) <= alpha }
guarantees E[L_{n+1}(lambda_hat_alpha)] <= alpha without distributional
assumptions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence


@dataclass(frozen=True)
class CalibrationSample:
    """One exchangeable repository/fixture calibration unit.

    `min_spurious_nonconformity` is the minimum s(x) among false-positive
    (forbidden or unverified spurious) findings emitted on this unit, or None
    when the unit stayed clean (zero false positives for all lambda in [0, 1]).
    For monotone loss L_i(lambda) = 1[min_spurious_s <= lambda] * weight,
    L_i(lambda) is guaranteed non-decreasing in lambda and bounded by B = 1.0.
    """

    sample_id: str
    stratum: str
    min_spurious_nonconformity: float | None
    loss_weight: float = 1.0

    def loss_at(self, lam: float) -> float:
        if self.min_spurious_nonconformity is None:
            return 0.0
        if self.min_spurious_nonconformity <= lam + 1e-12:
            return min(1.0, max(0.0, self.loss_weight))
        return 0.0


@dataclass(frozen=True)
class ConformalCalibrationResult:
    stratum: str
    alpha: float
    sample_size: int
    bound_b: float
    lambda_hat: float
    empirical_risk: float
    finite_sample_upper_bound: float
    feasible: bool


def finite_sample_risk_bound(
    losses: Sequence[float],
    *,
    bound_b: float = 1.0,
) -> float:
    """Compute (sum_{i=1}^n L_i + B) / (n + 1)."""
    if bound_b <= 0.0:
        raise ValueError("bound_b must be positive")
    n = len(losses)
    total = sum(min(bound_b, max(0.0, float(x))) for x in losses)
    return (total + bound_b) / (n + 1)


def calibrate_conformal_threshold(
    samples: Sequence[CalibrationSample],
    alpha: float,
    *,
    stratum: str = "global",
    bound_b: float = 1.0,
    grid_steps: int = 1000,
) -> ConformalCalibrationResult:
    """Find sup { lambda in [0, 1] : (sum L_i(lambda) + B) / (n + 1) <= alpha }.

    If B / (n + 1) > alpha, no threshold can satisfy the finite-sample bound
    with n data points; returns feasible=False and lambda_hat=0.0 honestly.
    """
    if not (0.0 < alpha < bound_b):
        raise ValueError("alpha must lie strictly between 0 and bound_b")
    if grid_steps < 10:
        raise ValueError("grid_steps must be >= 10")

    n = len(samples)
    if bound_b / (n + 1) > alpha + 1e-12:
        emp0 = (sum(s.loss_at(0.0) for s in samples) / n) if n else 0.0
        return ConformalCalibrationResult(
            stratum=stratum,
            alpha=alpha,
            sample_size=n,
            bound_b=bound_b,
            lambda_hat=0.0,
            empirical_risk=round(emp0, 6),
            finite_sample_upper_bound=round(
                finite_sample_risk_bound([s.loss_at(0.0) for s in samples], bound_b=bound_b),
                6,
            ),
            feasible=False,
        )

    # Candidate grid combines uniform grid with exact jump points of L_i.
    jump_points = {
        round(max(0.0, min(1.0, s.min_spurious_nonconformity - 1e-6)), 6)
        for s in samples
        if s.min_spurious_nonconformity is not None
    }
    grid = sorted(
        {round(i / grid_steps, 6) for i in range(grid_steps + 1)} | jump_points
    )

    best_lambda: float | None = None
    best_losses: list[float] = []

    for lam in grid:
        losses = [s.loss_at(lam) for s in samples]
        ub = finite_sample_risk_bound(losses, bound_b=bound_b)
        if ub <= alpha + 1e-12:
            best_lambda = lam
            best_losses = losses
        else:
            # Because L_i(lambda) is non-decreasing, first exceedance ends the valid prefix.
            break

    if best_lambda is None:
        losses0 = [s.loss_at(0.0) for s in samples]
        return ConformalCalibrationResult(
            stratum=stratum,
            alpha=alpha,
            sample_size=n,
            bound_b=bound_b,
            lambda_hat=0.0,
            empirical_risk=round(sum(losses0) / n if n else 0.0, 6),
            finite_sample_upper_bound=round(
                finite_sample_risk_bound(losses0, bound_b=bound_b), 6
            ),
            feasible=False,
        )

    emp = sum(best_losses) / n if n else 0.0
    ub = finite_sample_risk_bound(best_losses, bound_b=bound_b)
    return ConformalCalibrationResult(
        stratum=stratum,
        alpha=alpha,
        sample_size=n,
        bound_b=bound_b,
        lambda_hat=round(best_lambda, 6),
        empirical_risk=round(emp, 6),
        finite_sample_upper_bound=round(ub, 6),
        feasible=True,
    )

"""Algebraic and finite-sample distribution-free guarantees for CRC."""

from __future__ import annotations

import random

import pytest

from app.scan.reporting.conformal.nonconformity import compute_nonconformity_score
from app.scan.reporting.conformal.risk_control import (
    CalibrationSample,
    calibrate_conformal_threshold,
    finite_sample_risk_bound,
)


def test_loss_is_monotone_non_decreasing_in_lambda() -> None:
    rng = random.Random(20261128)
    samples = [
        CalibrationSample(
            sample_id=f"u-{i}",
            stratum="deterministic_ast_cfg",
            min_spurious_nonconformity=(rng.uniform(0.0, 1.0) if rng.random() < 0.4 else None),
        )
        for i in range(60)
    ]
    grid = [i / 100.0 for i in range(101)]
    bounds = [
        finite_sample_risk_bound([s.loss_at(lam) for s in samples])
        for lam in grid
    ]
    for prev, curr in zip(bounds, bounds[1:]):
        assert curr >= prev - 1e-12


def test_insufficient_sample_size_returns_infeasible_honestly() -> None:
    # With n = 10 and B = 1.0, minimum bound is 1 / 11 = 0.0909 > alpha = 0.05.
    samples = [
        CalibrationSample(sample_id=f"clean-{i}", stratum="s", min_spurious_nonconformity=None)
        for i in range(10)
    ]
    res = calibrate_conformal_threshold(samples, alpha=0.05, stratum="s")
    assert res.feasible is False
    assert res.lambda_hat == 0.0
    assert res.finite_sample_upper_bound == pytest.approx(1.0 / 11.0, abs=1e-5)


@pytest.mark.parametrize("alpha", [0.05, 0.10, 0.20])
def test_finite_sample_marginal_risk_guarantee_on_exchangeable_draws(alpha: float) -> None:
    """Verify E[L_{n+1}(lambda_hat_alpha)] <= alpha across Monte Carlo exchangeable splits."""
    rng = random.Random(9001 + int(alpha * 1000))
    # Adversarial heavy-tailed spurious nonconformity distribution:
    # 35% of negative repos emit a false positive concentrated in [0.12, 0.65].
    trials = 400
    n_cal = 55
    test_losses: list[float] = []

    for _ in range(trials):
        population: list[CalibrationSample] = []
        for j in range(n_cal + 1):
            spurious = rng.betavariate(2.0, 3.0) * 0.7 + 0.10 if rng.random() < 0.35 else None
            population.append(
                CalibrationSample(
                    sample_id=f"item-{j}",
                    stratum="deterministic_ast_cfg",
                    min_spurious_nonconformity=spurious,
                )
            )
        cal, test_point = population[:n_cal], population[n_cal]
        cal_res = calibrate_conformal_threshold(cal, alpha=alpha, grid_steps=500)
        assert cal_res.feasible is True
        assert cal_res.finite_sample_upper_bound <= alpha + 1e-9
        test_losses.append(test_point.loss_at(cal_res.lambda_hat))

    marginal_risk = sum(test_losses) / len(test_losses)
    # Finite-sample CRC guarantees marginal expectation <= alpha; allow tiny MC slack.
    assert marginal_risk <= alpha + 0.02


def test_structural_proof_lowers_nonconformity_and_non_prod_raises_it() -> None:
    plain = compute_nonconformity_score(confidence=0.80, source="static")
    proven = compute_nonconformity_score(
        confidence=0.80,
        source="static",
        claim_evidence={
            "source_type": "static_cfg_dominator",
            "optimal_cut_lines": [12],
        },
    )
    fixture = compute_nonconformity_score(
        confidence=0.80,
        context="test_fixture",
        source="static",
    )
    llm_unverified = compute_nonconformity_score(
        confidence=0.80,
        source="llm",
        verification_status="unverified",
    )
    assert proven < plain < llm_unverified < fixture

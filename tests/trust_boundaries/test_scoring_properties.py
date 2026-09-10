"""Property tests for the scoring core, run without any LLM and without
hypothesis (seeded random, matching the existing suite's style).

These are the invariants that make the headline number safe to print:
bounded, monotone in the findings set, and unable to present a passing
score over a confident critical. A violation of any of them means a worse
repository can read as a better one.
"""

from __future__ import annotations

import random

from tests.detector_samples import SAMPLES as CREDENTIAL_SAMPLES

from app.scan.scoring import (
    CATEGORIES,
    GATED_CATEGORIES,
    SEVERITY_WEIGHT,
    ScoredFinding,
    compute_scores,
)
from app.scan.static import run_static_scan

from .conftest import make_zip

SEED = 20260908  # fixed: a failing draw must be reproducible
SAMPLES = 4000


def _random_finding(rng: random.Random) -> ScoredFinding:
    return ScoredFinding(
        rule_id=rng.choice(["r1", "r2", "r3"]),
        title="t",
        severity=rng.choice(list(SEVERITY_WEIGHT)),
        confidence=round(rng.uniform(0.3, 1.0), 2),
        category=rng.choice(CATEGORIES),
        file="f.ts",
        source="static",
    )


def test_scores_stay_within_bounds():
    rng = random.Random(SEED)
    for _ in range(SAMPLES):
        fs = [_random_finding(rng) for _ in range(rng.randint(0, 8))]
        out = compute_scores(fs)
        assert 0.0 <= out["total"] <= 10.0
        assert all(0.0 <= v <= 10.0 for v in out["categories"].values())


def test_removing_a_finding_never_lowers_the_total():
    """The score is a measure of findings: deleting evidence must not make
    a repository look worse."""
    rng = random.Random(SEED)
    for _ in range(SAMPLES):
        fs = [_random_finding(rng) for _ in range(rng.randint(1, 8))]
        full = compute_scores(list(fs))["total"]
        subset = compute_scores(fs[: len(fs) // 2])["total"]
        assert subset >= full, (
            f"removing findings lowered the total: {full} -> {subset}"
        )


def test_one_confident_critical_caps_the_headline():
    """GATE_ON_CRITICAL: whatever else is true of the repo, a confident
    critical in a gated category caps the total at GATED_MAX."""
    rng = random.Random(SEED)
    for _ in range(SAMPLES):
        fs = [_random_finding(rng) for _ in range(rng.randint(0, 8))]
        for cat in GATED_CATEGORIES:
            crit = ScoredFinding(
                rule_id="c", title="t", severity="critical",
                confidence=0.9, category=cat,
            )
            assert compute_scores(fs + [crit])["total"] <= 6.9


def test_a_critical_its_producer_is_unsure_of_cannot_gate_alone():
    """CRITICAL_GATE_MIN_CONFIDENCE: 'critical if real, but guessing' is a
    penalty inside the category, not a disqualifier of the headline."""
    out = compute_scores([ScoredFinding(
        rule_id="c", title="t", severity="critical",
        confidence=0.5, category="Security",
    )])
    assert "critical" not in {g["kind"] for g in out["gated_by"]}


def test_perfect_ten_requires_an_empty_findings_list():
    rng = random.Random(SEED)
    for _ in range(SAMPLES):
        fs = [_random_finding(rng) for _ in range(rng.randint(1, 6))]
        assert compute_scores(fs)["total"] < 10.0


def test_unexamined_llm_categories_neither_vote_nor_gate():
    """On a static-only audit, Auth and Money & Data sit at 10.0 because
    nothing looked -- that 10.0 must not prop up the mean and must not be
    able to clear or fail a gate (issues #22 / #181)."""
    fs = [ScoredFinding(rule_id="r", title="t", severity="high",
                        confidence=0.9, category="Security")]
    full = compute_scores(fs, llm_ran=True)
    static_only = compute_scores(fs, llm_ran=False)
    assert set(static_only["unexamined"]) >= {"Auth", "Money & Data"}
    assert static_only["total"] <= full["total"]


def test_committed_env_credentials_gate_the_end_to_end_score():
    """The product's flagship finding, through the real static stage:
    a committed .env with credentials never presents a passing headline."""
    out = run_static_scan(make_zip({
        ".env": f"DATABASE_URL={CREDENTIAL_SAMPLES['REMOTE_DSN']}\n",
        "package.json": '{"dependencies": {"next": "14.0.0"}}',
    }))
    assert out["score"]["total"] <= 6.9
    kinds = {g["kind"] for g in out["score"]["gated_by"]}
    assert kinds & {"critical", "subscore"}

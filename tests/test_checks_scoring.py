"""Tests for presence checks and the score formula."""

import io
import zipfile

import pytest

from app.scan.checks import run_checks
from app.scan.scoring import (
    CATEGORIES,
    GATE_THRESHOLD,
    GATED_CATEGORIES,
    GATED_MAX,
    ScoredFinding,
    compute_scores,
)
from app.scan.static import run_static_scan


def make_zip(entries: dict[str, bytes]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    buf.seek(0)
    return buf


def test_committed_env_detected_even_inside_root_folder():
    buf = make_zip({"my-app/.env": b"KEY=value", "my-app/app.py": b""})
    ids = {f.rule_id for f in run_checks(buf)}
    assert "env-file-committed" in ids


def test_env_example_is_allowed():
    buf = make_zip({".env.example": b"KEY=", ".gitignore": b".env\n",
                    "tests/test_x.py": b"", "Dockerfile": b"",
                    ".github/workflows/ci.yml": b""})
    assert run_checks(buf) == []


def test_gitignore_missing_entirely_is_flagged():
    buf = make_zip({"app.py": b"", ".env.example": b"KEY="})
    ids = {f.rule_id for f in run_checks(buf)}
    assert "gitignore-missing-secrets" in ids


def test_gitignore_without_env_coverage_is_flagged():
    buf = make_zip({".gitignore": b"node_modules/\ndist/\n", "app.py": b""})
    findings = run_checks(buf)
    f = next(f for f in findings if f.rule_id == "gitignore-missing-secrets")
    assert f.severity == "high"
    assert f.category == "Security"


def test_gitignore_covering_env_is_not_flagged():
    buf = make_zip({".gitignore": b"node_modules/\n.env\n*.pem\n", "app.py": b""})
    ids = {f.rule_id for f in run_checks(buf)}
    assert "gitignore-missing-secrets" not in ids


def test_gitignore_env_glob_coverage_is_accepted():
    buf = make_zip({".gitignore": b".env*\n", "app.py": b""})
    ids = {f.rule_id for f in run_checks(buf)}
    assert "gitignore-missing-secrets" not in ids


def test_gitignore_coverage_detected_inside_root_folder():
    buf = make_zip({"my-app/.gitignore": b".env\n", "my-app/app.py": b""})
    ids = {f.rule_id for f in run_checks(buf)}
    assert "gitignore-missing-secrets" not in ids


def test_missing_tests_dockerfile_ci_reported():
    buf = make_zip({"app.py": b""})
    ids = {f.rule_id for f in run_checks(buf)}
    assert {"no-tests", "no-dockerfile", "no-ci"} <= ids


def _f(sev: str, conf: float, cat: str = "Security") -> ScoredFinding:
    return ScoredFinding(
        rule_id="r", title="t", severity=sev, confidence=conf, category=cat
    )


def test_score_v2_total_is_weighted_mean_of_categories():
    # Security: 10 − (2.0×1.0 + 1.0×0.5) = 7.5; Testing: 10 − 0.4 = 9.6
    findings = [_f("critical", 1.0), _f("high", 0.5), _f("medium", 1.0, "Testing")]
    scores = compute_scores(findings)
    assert scores["categories"]["Security"] == 7.5
    assert scores["categories"]["Testing"] == 9.6
    assert scores["categories"]["Deploy"] == 10.0
    # Weights are the raw values normalised over their own sum:
    # (7.5×.25 + 10×.20 + 9.6×.15 + 10×.15 + 10×.20) / .95 = 9.3
    # Not gated: Security 7.5 clears GATE_THRESHOLD, so the mean stands.
    assert scores["total"] == 9.3


def test_saturated_category_does_not_zero_total():
    # v1 regression: 10 criticals in ONE category zeroed the whole
    # score; v2 floors the damage at that category's weight.
    findings = [_f("critical", 1.0)] * 10  # all Security
    scores = compute_scores(findings)
    assert scores["categories"]["Security"] == 0.0
    # Everything except Security intact. The number has moved twice since:
    # to 6.7 when the two producer-less categories were dropped (issue #181),
    # and to 5.1 once a failing safety category began compressing the mean
    # into the sub-threshold band. The property under test is unchanged and
    # is the point -- a single saturated category must not zero the total.
    assert scores["total"] == 5.1
    assert scores["total"] > 0.0


def test_findings_across_all_categories_still_reach_zero():
    # Driven off CATEGORIES itself so this cannot quietly stop covering a
    # category the way it did when the tuple was written out by hand.
    findings = [_f("critical", 1.0, cat) for cat in CATEGORIES] * 10
    assert compute_scores(findings)["total"] == 0.0


# --- safety gate: a failing category keeps the headline out of passing range ---

def test_failing_safety_category_keeps_total_below_threshold():
    # The motivating real case, audit 0a043539
    # (vercel/nextjs-subscription-payments): an open redirect, a service-role
    # client that silently no-ops when misconfigured, and a subscriptions
    # table with no write RLS policies put Security at 5.9 -- while Testing
    # 9.7 and Deploy 9.8 carried the weighted mean to a reassuring 8.1.
    # Security: 10 − (2.0×1.0 + 2.0×1.0) = 6.0, while every other category
    # stays at 10.0 -- the weighted mean alone would read 8.9.
    findings = [_f("critical", 1.0), _f("critical", 1.0)]
    scores = compute_scores(findings)

    assert scores["categories"]["Security"] < GATE_THRESHOLD
    assert scores["total"] < GATE_THRESHOLD
    assert scores["total"] <= GATED_MAX


@pytest.mark.parametrize("category", ["Security", "Auth", "Money & Data"])
def test_either_safety_category_alone_triggers_the_gate(category: str) -> None:
    """Both halves gate independently.

    A repo can be clean on Security and still be unsafe to ship on Auth, and
    the headline must say so either way. The category names are written out
    rather than driven off GATED_CATEGORIES: parametrizing off the tuple
    means dropping a category from it silently deletes its own test case
    instead of failing, which is how this stops guarding what it claims to.
    """
    assert category in GATED_CATEGORIES, f"{category} is no longer gated"
    findings = [_f("critical", 1.0, category), _f("critical", 1.0, category)]
    scores = compute_scores(findings)

    assert scores["categories"][category] < GATE_THRESHOLD
    assert scores["total"] < GATE_THRESHOLD
    assert scores["total"] <= GATED_MAX


def test_gate_does_not_fire_on_hygiene_only_findings():
    # Missing tests and no Dockerfile are real findings but say nothing about
    # whether a visitor can break in. A repo whose only problems are hygiene
    # must keep its averaged score -- the gate is a ceiling on the misleading
    # case, not a blanket penalty.
    findings = [_f("medium", 0.8, "Testing"), _f("low", 0.9, "Deploy")]
    scores = compute_scores(findings)

    assert scores["categories"]["Security"] == 10.0
    assert scores["categories"]["Auth"] == 10.0
    assert scores["categories"]["Money & Data"] == 10.0
    assert scores["total"] > GATE_THRESHOLD


def test_gate_preserves_ordering_among_failing_repos():
    """The gate must not flatten the bottom of the scale.

    Replacing the total with the failing subscore was tried first and
    collapsed every repo whose Security penalty saturated to 0.0 down to
    exactly 0.0 -- on the real audit set, 10 of the 72 carrying category
    data. That re-creates for these two categories the v1 flattening the
    module docstring exists to describe. A ceiling leaves the weighted mean
    intact below it, so worse repos still score worse.
    """
    saturated_only = [_f("critical", 1.0)] * 10                      # Security 0.0
    saturated_plus = saturated_only + [_f("critical", 1.0, "Auth")]  # Auth also hit

    worse = compute_scores(saturated_plus)["total"]
    bad = compute_scores(saturated_only)["total"]

    assert compute_scores(saturated_only)["categories"]["Security"] == 0.0
    assert worse < bad, "a repo failing both safety categories must score lower"
    assert worse > 0.0, "the gate must not collapse the scale to zero"


def test_gate_never_raises_a_score():
    # min() by construction, pinned because a future edit that turns the
    # ceiling into an assignment would silently start inflating clean repos.
    clean = compute_scores([])
    assert clean["total"] == 10.0


def test_static_scan_end_to_end():
    buf = make_zip({
        "src/config.ts": b"const k = 'AKIA" + b"A" * 16 + b"'",
        "app.py": b"",
    })
    result = run_static_scan(buf)
    ids = {f["rule_id"] for f in result["findings"]}
    assert "aws-access-key-id" in ids and "no-tests" in ids
    assert result["score"]["total"] < 10.0
    assert result["score"]["categories"]["Security"] < 10.0


def test_static_findings_carry_context_field():
    # The structured context field must survive serialization into the
    # finding dicts stored in findings_json / returned by the API.
    buf = make_zip({
        "src/config.ts": b"const k = 'AKIA" + b"A" * 16 + b"'",
        "app.py": b"",
    })
    result = run_static_scan(buf)
    aws = next(f for f in result["findings"] if f["rule_id"] == "aws-access-key-id")
    assert "context" in aws
    assert aws["context"] is None


def test_perfect_total_impossible_with_findings():
    # weighted mean can round up to 10.0 past one tiny finding
    assert compute_scores([_f("low", 0.1, "Deploy")])["total"] == 9.9
    assert compute_scores([])["total"] == 10.0


def test_score_is_deterministic_regardless_of_finding_order():
    """The core reproducibility invariant: the SAME findings must always
    produce the SAME score, independent of the order they arrive in. The
    score formula has no LLM call and no randomness -- so if the finding
    set is fixed, the number is fixed. (The prod 8.9/9.9/9.9 variance came
    from the LLM producing a *different* finding set each run, not from
    this formula; see app/scan/scoring.py and app/scan/llm_scan.py.)"""
    import random

    findings = [
        _f("critical", 1.0, "Security"), _f("high", 0.5, "Auth"),
        _f("medium", 0.7, "Testing"), _f("low", 0.3, "Deploy"),
        _f("high", 0.9, "Testing"), _f("medium", 0.4, "Deploy"),
        _f("low", 0.2, "Security"), _f("high", 0.6, "Auth"),
    ]
    baseline = compute_scores(findings)
    for _ in range(100):
        shuffled = findings[:]
        random.shuffle(shuffled)
        assert compute_scores(shuffled) == baseline


def test_finding_in_a_category_we_no_longer_score_is_ignored_not_fatal():
    """A finding whose category is not in CATEGORIES must neither raise nor move
    the total.

    Not hypothetical: "Correctness" and "Config" were dropped in #181, stored
    audits still carry findings labelled with them, and a future producer could
    emit a name before the constant learns about it. compute_scores filters by
    CATEGORIES, so such a finding is silently absent from the score while still
    being listed in the report -- which is the tolerable behaviour, but only if
    it is deliberate rather than discovered in production.
    """
    baseline = compute_scores([_f("high", 0.5, "Auth")])
    with_ghost = compute_scores([
        _f("high", 0.5, "Auth"), _f("critical", 1.0, "Correctness"),
    ])
    assert with_ghost == baseline
    assert "Correctness" not in with_ghost["categories"]


def test_gate_scales_rather_than_clamping():
    """Two repos failing the gate by different amounts must not print the same
    number.

    A flat ceiling (total = min(mean, GATED_MAX)) was the first design. It
    stopped the flattering headline but flattened the failing range, because a
    repo's mean sits well above 6.9 even when one category fails: on the 42
    real full audits, 17 of them -- 40% -- would have printed exactly 6.9,
    making one failing category indistinguishable from three.

    Both fixtures here fail only on Security and are strong everywhere else,
    so both means land above GATED_MAX -- which is exactly where a clamp
    erases the difference between them and a scale keeps it.
    """
    mild = [_f("critical", 1.0), _f("high", 1.0), _f("medium", 1.0)]   # Security 6.6
    worse = [_f("critical", 1.0), _f("critical", 1.0), _f("high", 1.0)]  # Security 5.0

    mild_scores = compute_scores(mild)
    worse_scores = compute_scores(worse)

    # Precondition: an unscaled mean above the band top, or a clamp would be
    # indistinguishable from a scale here and the test would prove nothing.
    assert mild_scores["categories"]["Security"] < GATE_THRESHOLD
    assert worse_scores["categories"]["Security"] < GATE_THRESHOLD

    assert worse_scores["total"] < mild_scores["total"], (
        f'gate flattened {worse_scores["total"]} == {mild_scores["total"]}')
    assert mild_scores["total"] < GATE_THRESHOLD


def test_no_gated_repo_can_present_a_passing_score():
    """The one invariant the gate exists for, over the whole input space."""
    import random

    random.seed(20260808)
    for _ in range(3000):
        findings = [
            _f(random.choice(["critical", "high", "medium", "low"]),
               random.random(), cat)
            for cat in CATEGORIES
            for _ in range(random.randint(0, 4))
        ]
        scores = compute_scores(findings)
        failing = [c for c in GATED_CATEGORIES
                   if scores["categories"][c] < GATE_THRESHOLD]
        if failing:
            assert scores["total"] < GATE_THRESHOLD, (failing, scores)


# --- basis-aware weighting ---

def test_static_only_audit_does_not_count_categories_nothing_examined():
    """Auth and Money & Data have no static producer.

    On a static-only audit their 10.0 means "not examined", not "clean", and
    letting it vote is how the free tier came to average 8.99 against 7.79 for
    full audits -- with Auth reading exactly 10.0 in 25 of 25 of them. The
    subscores are still reported; they just no longer carry weight.
    """
    findings = [_f("critical", 0.9), _f("medium", 0.8, "Testing")]

    full = compute_scores(findings, llm_ran=True)
    static_only = compute_scores(findings, llm_ran=False)

    assert static_only["categories"]["Auth"] == 10.0        # still shown
    assert static_only["categories"]["Money & Data"] == 10.0
    assert static_only["total"] < full["total"], (
        "unexamined categories must not prop up a static-only total")


def test_unexamined_category_cannot_trigger_the_gate():
    # The mirror of the above: an Auth of 10.0 that nothing looked at must not
    # clear the gate, and an unexamined category must not fail it either.
    hygiene_only = [_f("medium", 0.8, "Testing"), _f("low", 0.9, "Deploy")]

    scores = compute_scores(hygiene_only, llm_ran=False)

    assert scores["total"] > GATE_THRESHOLD

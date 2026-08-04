"""Tests for presence checks and the score formula."""

import io
import zipfile

from app.scan.checks import run_checks
from app.scan.scoring import CATEGORIES, ScoredFinding, compute_scores
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
    # Weights are the raw 0.25/0.20/0.15/0.15 normalised over their own sum:
    # total = (7.5×.25 + 10×.20 + 9.6×.15 + 10×.15) / .75 = 9.1
    assert scores["total"] == 9.1


def test_saturated_category_does_not_zero_total():
    # v1 regression: 10 criticals in ONE category zeroed the whole
    # score; v2 floors the damage at that category's weight.
    findings = [_f("critical", 1.0)] * 10  # all Security
    scores = compute_scores(findings)
    assert scores["categories"]["Security"] == 0.0
    # Everything except Security intact. This is the floor of the scale for a
    # single failed category, and it moved from 7.5 to 6.7 when the two
    # producer-less categories were dropped (issue #181) -- 25% of the weight
    # was previously a constant 10.0 propping every total up.
    assert scores["total"] == 6.7


def test_findings_across_all_categories_still_reach_zero():
    # Driven off CATEGORIES itself so this cannot quietly stop covering a
    # category the way it did when the tuple was written out by hand.
    findings = [_f("critical", 1.0, cat) for cat in CATEGORIES] * 10
    assert compute_scores(findings)["total"] == 0.0


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

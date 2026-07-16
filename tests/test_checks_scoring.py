"""Tests for presence checks and the score formula."""

import io
import zipfile

from app.scan.checks import run_checks
from app.scan.scoring import ScoredFinding, compute_scores
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
    # total = 7.5×.25 + 10×.20 + 10×.15 + 10×.10 + 9.6×.15 + 10×.15 = 9.3
    assert scores["total"] == 9.3


def test_saturated_category_does_not_zero_total():
    # v1 regression: 10 criticals in ONE category zeroed the whole
    # score; v2 floors the damage at that category's weight.
    findings = [_f("critical", 1.0)] * 10  # all Security
    scores = compute_scores(findings)
    assert scores["categories"]["Security"] == 0.0
    assert scores["total"] == 7.5  # everything except Security intact


def test_findings_across_all_categories_still_reach_zero():
    findings = [
        _f("critical", 1.0, cat) for cat in
        ("Security", "Auth", "Correctness", "Config", "Testing", "Deploy")
    ] * 10
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

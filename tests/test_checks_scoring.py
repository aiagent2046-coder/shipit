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
    buf = make_zip({".env.example": b"KEY=", "tests/test_x.py": b"",
                    "Dockerfile": b"", ".github/workflows/ci.yml": b""})
    assert run_checks(buf) == []


def test_missing_tests_dockerfile_ci_reported():
    buf = make_zip({"app.py": b""})
    ids = {f.rule_id for f in run_checks(buf)}
    assert {"no-tests", "no-dockerfile", "no-ci"} <= ids


def _f(sev: str, conf: float, cat: str = "Security") -> ScoredFinding:
    return ScoredFinding(
        rule_id="r", title="t", severity=sev, confidence=conf, category=cat
    )


def test_score_formula_matches_architecture():
    # 10 − (2.0×1.0 + 1.0×0.5 + 0.4×1.0) = 7.1
    findings = [_f("critical", 1.0), _f("high", 0.5), _f("medium", 1.0, "Testing")]
    scores = compute_scores(findings)
    assert scores["total"] == 7.1
    assert scores["categories"]["Security"] == 7.5
    assert scores["categories"]["Testing"] == 9.6
    assert scores["categories"]["Deploy"] == 10.0


def test_score_clamped_at_zero():
    findings = [_f("critical", 1.0)] * 10
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

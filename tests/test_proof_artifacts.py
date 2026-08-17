"""Tests for proof log/storyboard artifacts."""

from __future__ import annotations

from app.proof.artifacts import (
    artifacts_to_json,
    build_artifacts,
    render_artifacts_markdown,
)
from app.proof.types import ExploitAttempt, ProofReport


def _report(*, verified: bool = True) -> ProofReport:
    before = ExploitAttempt(
        template_id="secrets_leak",
        status="success",
        success=True,
        detail="found 1",
        evidence={
            "finding_count": 1,
            "samples": [{
                "file": "cfg.py", "line": 1,
                "rule_id": "stripe-live-key",
                "masked": "sk_l****(32 chars)",
            }],
        },
        duration_ms=4,
    )
    after = ExploitAttempt(
        template_id="secrets_leak",
        status="failure",
        success=False,
        detail="none",
        evidence={"finding_count": 0, "samples": []},
        duration_ms=3,
    )
    return ProofReport(
        template_id="secrets_leak",
        before=before,
        after=after,
        verified=verified,
        informational=False,
        detail=(
            "verified (secrets_leak): exploit succeeded before, failed after"
            if verified else "not verified"
        ),
    )


def test_build_artifacts_log_and_storyboard() -> None:
    arts = build_artifacts(_report())
    kinds = {a.kind for a in arts}
    assert kinds == {"log", "storyboard"}
    log = next(a for a in arts if a.kind == "log")
    assert "BEFORE" in log.content
    assert "AFTER" in log.content
    assert "stripe-live-key" in log.content
    assert "sk_l****" in log.content
    assert log.content_sha256
    board = next(a for a in arts if a.kind == "storyboard")
    assert "VERIFIED" in board.content
    assert "EXPLOIT OK" in board.content
    assert "BLOCKED" in board.content


def test_render_artifacts_markdown_has_details() -> None:
    md = render_artifacts_markdown(build_artifacts(_report()))
    assert "<details>" in md
    assert "Proof log" in md
    assert "Storyboard" in md


def test_artifacts_json_truncates() -> None:
    arts = build_artifacts(_report())
    rows = artifacts_to_json(arts, max_content_chars=50)
    assert any(r["truncated"] for r in rows)
    assert all("content_sha256" in r for r in rows)


def test_not_verified_storyboard() -> None:
    board = next(
        a for a in build_artifacts(_report(verified=False)) if a.kind == "storyboard"
    )
    assert "NOT VERIFIED" in board.content

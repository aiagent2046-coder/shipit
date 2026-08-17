"""Unit tests for Proof-of-Exploit soft/hard delivery gate."""

from __future__ import annotations

import pytest

from app.proof.gate import decide_proof_gate, proof_gate_mode
from app.proof.types import ExploitAttempt, ProofReport


def _attempt(
    *,
    success: bool,
    status: str = "success",
    template_id: str = "secrets_leak",
    detail: str = "test",
) -> ExploitAttempt:
    return ExploitAttempt(
        template_id=template_id,  # type: ignore[arg-type]
        status=status,  # type: ignore[arg-type]
        success=success,
        detail=detail,
        evidence={},
        duration_ms=1,
    )


def _report(
    *,
    before_success: bool,
    after_success: bool,
    before_status: str = "success",
    after_status: str = "failure",
    verified: bool | None = None,
    informational: bool = False,
) -> ProofReport:
    before = _attempt(success=before_success, status=before_status)
    after = _attempt(success=after_success, status=after_status)
    if verified is None:
        verified = (
            before_success
            and before_status == "success"
            and not after_success
            and after_status == "failure"
        )
    return ProofReport(
        template_id="secrets_leak",
        before=before,
        after=after,
        verified=verified,
        informational=informational,
        detail="test report",
    )


def test_mode_defaults_to_soft(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PROOF_GATE_MODE", raising=False)
    assert proof_gate_mode() == "soft"


def test_mode_accepts_valid_values(monkeypatch: pytest.MonkeyPatch) -> None:
    for mode in ("off", "soft", "hard"):
        monkeypatch.setenv("PROOF_GATE_MODE", mode)
        assert proof_gate_mode() == mode


def test_mode_unknown_falls_back_to_soft(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PROOF_GATE_MODE", "aggressive")
    assert proof_gate_mode() == "soft"


def test_none_report_is_pass() -> None:
    assert decide_proof_gate(None) == "pass"


def test_verified_is_always_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PROOF_GATE_MODE", "hard")
    report = _report(before_success=True, after_success=False)
    assert report.verified is True
    assert decide_proof_gate(report) == "pass"


def test_no_reproduction_is_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    """Static finding that never reproduced must not gate delivery."""
    monkeypatch.setenv("PROOF_GATE_MODE", "hard")
    report = _report(
        before_success=False,
        after_success=False,
        before_status="failure",
        after_status="failure",
        verified=False,
    )
    assert decide_proof_gate(report) == "pass"


def test_error_is_fail_open(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PROOF_GATE_MODE", "hard")
    report = _report(
        before_success=True,
        after_success=False,
        before_status="success",
        after_status="error",
        verified=False,
    )
    assert decide_proof_gate(report) == "pass"


def test_soft_mode_soft_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PROOF_GATE_MODE", "soft")
    report = _report(
        before_success=True,
        after_success=True,
        before_status="success",
        after_status="success",
        verified=False,
    )
    assert decide_proof_gate(report) == "soft_fail"


def test_hard_mode_hard_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PROOF_GATE_MODE", "hard")
    report = _report(
        before_success=True,
        after_success=True,
        before_status="success",
        after_status="success",
        verified=False,
    )
    assert decide_proof_gate(report) == "hard_fail"


def test_off_mode_never_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PROOF_GATE_MODE", "off")
    report = _report(
        before_success=True,
        after_success=True,
        before_status="success",
        after_status="success",
        verified=False,
    )
    assert decide_proof_gate(report) == "pass"

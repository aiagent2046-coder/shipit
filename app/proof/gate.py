"""Proof-of-Exploit delivery gate.

Controls whether a non-verified proof blocks Fix Pack delivery.

Mode is read from ``PROOF_GATE_MODE`` (default ``soft``):

* ``off``  — record + render only; never influence delivery (original MVP).
* ``soft`` — still deliver, but the PR and job detail carry a clear warning
  when the exploit still succeeds after the proposed fix.
* ``hard`` — same condition becomes a ``blocked`` outcome (withheld PR),
  identical in shape to a semantic-check regression.

Infrastructure failures and skipped templates never block (fail-open).
A report is only actionable when the original workspace actually
reproduced the exploit (``before.success``).

When multiple reports are present (stage routing), the strongest decision
wins: hard_fail > soft_fail > pass.
"""

from __future__ import annotations

import os
from typing import Literal

from app.proof.types import ProofReport

GateMode = Literal["off", "soft", "hard"]
GateDecision = Literal["pass", "soft_fail", "hard_fail"]

_VALID_MODES: frozenset[str] = frozenset({"off", "soft", "hard"})


def proof_gate_mode() -> GateMode:
    """Current gate mode. Unknown / empty values fall back to soft."""
    raw = (os.environ.get("PROOF_GATE_MODE") or "soft").strip().lower()
    if raw not in _VALID_MODES:
        return "soft"
    return raw  # type: ignore[return-value]


def decide_proof_gate(
    report: ProofReport | None,
    reports: list[ProofReport] | None = None,
) -> GateDecision:
    """Map proof report(s) onto a delivery decision.

    ``report`` is the primary (legacy). When ``reports`` is provided, every
    report is evaluated and the strongest failure wins.
    """
    candidates: list[ProofReport] = []
    if reports:
        candidates.extend(reports)
    elif report is not None:
        candidates.append(report)

    if not candidates:
        return "pass"

    decisions = [_decide_one(r) for r in candidates]
    if "hard_fail" in decisions:
        return "hard_fail"
    if "soft_fail" in decisions:
        return "soft_fail"
    return "pass"


def _decide_one(report: ProofReport) -> GateDecision:
    if not report.before.success or report.before.status != "success":
        return "pass"

    if report.verified:
        return "pass"

    if report.before.status in ("error", "skipped") or report.after.status in (
        "error",
        "skipped",
    ):
        return "pass"

    mode = proof_gate_mode()
    if mode == "off":
        return "pass"
    if mode == "hard":
        return "hard_fail"
    return "soft_fail"

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


def decide_proof_gate(report: ProofReport | None) -> GateDecision:
    """Map a (possibly missing) ProofReport onto a delivery decision.

    Returns:
        ``pass``      — deliver normally
        ``soft_fail`` — deliver with a strong warning
        ``hard_fail`` — withhold the PR (status=blocked)
    """
    if report is None:
        return "pass"

    # Only actionable when the original workspace actually reproduced the
    # exploit. A static finding that never reproduced is not a delivery gate.
    if not report.before.success or report.before.status != "success":
        return "pass"

    if report.verified:
        return "pass"

    # Infrastructure / skip on either side → fail-open.
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

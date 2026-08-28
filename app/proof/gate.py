"""Proof-of-Exploit delivery gate.

Controls whether a non-verified proof blocks Fix Pack delivery.

Mode is read from ``PROOF_GATE_MODE`` (default ``hard``):

* ``off``  — record + render only; never influence delivery (original MVP).
* ``soft`` — still deliver, but the PR and job detail carry a clear warning
  when the exploit still succeeds after the proposed fix.
* ``hard`` — same condition becomes a ``blocked`` outcome (withheld PR),
  identical in shape to a semantic-check regression.

WHY THE DEFAULT IS ``hard`` (changed 2026-08-28, a product decision). The
thing being sold is a repair, and this is the only place that can tell a
repair from a plausible-looking patch. Under ``soft`` a Fix Pack whose own
proof showed the exploit still working was delivered with a warning attached
-- charging for work we had just measured as not working, and asking the
customer to read a caveat to find that out.

WHAT THAT DOES AND DOES NOT COVER, because the distinction is the whole
design. This gate blocks exactly one state: the exploit reproduced BEFORE the
patch, the same check ran AFTER it, and it still succeeded. That is "we proved
we did not fix it". It is not "we could not prove anything" -- no template
routed, a probe that errored, an exploit that never reproduced -- and those
still deliver, in every mode. Refusing delivery on absent evidence is a
separate and much larger decision (see app/proof/routing.py: a template is
selected only when the plan touches secrets or a changed path matches the sqli
/ cors patterns, so "no evidence" is the common case, not the exception).
Making that call needs a measurement of how many jobs it would stop, which
does not exist yet.

An unrecognised value falls back to ``hard`` rather than ``soft``. A typo
means the operator does not know which mode is in force, and shipping unproven
repairs from that state is precisely what this default exists to stop.

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


DEFAULT_MODE: GateMode = "hard"


def proof_gate_mode() -> GateMode:
    """Current gate mode. Unknown / empty values fall back to DEFAULT_MODE."""
    raw = (os.environ.get("PROOF_GATE_MODE") or DEFAULT_MODE).strip().lower()
    if raw not in _VALID_MODES:
        return DEFAULT_MODE
    return raw  # type: ignore[return-value]


def decide_proof_gate(
    report: ProofReport | None | object,
    reports: list[ProofReport] | None = None,
) -> GateDecision:
    """Map proof report(s) onto a delivery decision.

    ``report`` is the primary (legacy). When ``reports`` is provided, every
    report is evaluated and the strongest failure wins.

    Also accepts a ``ProofStageResult`` (has ``.primary`` / ``.reports``) so
    callers that still do ``decide_proof_gate(await run_proof_stage(...))``
    keep working after stage routing.
    """
    if report is not None and hasattr(report, "primary") and hasattr(report, "reports"):
        if reports is None:
            reports = list(getattr(report, "reports") or [])
        report = getattr(report, "primary")

    candidates: list[ProofReport] = []
    if reports:
        candidates.extend(reports)
    elif report is not None:
        candidates.append(report)  # type: ignore[arg-type]

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

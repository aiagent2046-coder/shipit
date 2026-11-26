"""Stable data contract for Proof-of-Exploit results.

Mirrors the VerificationReport pattern in app/fixpack/verification.py:
define the shape first so storage, PR rendering, and a future blocking
gate share one type instead of growing ad-hoc dicts.

SECURITY: evidence must never carry raw secret values — only masks,
paths, line numbers, and counts. Templates that touch credentials are
responsible for masking before constructing an ExploitAttempt.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Literal

TemplateId = Literal[
    "secrets_leak", "sqli", "cors_open", "cors_open_runtime",
    "rls_open_runtime",
]

# The same tuple the validators below check against, named once so a new id
# cannot be accepted in one function and rejected in the other.
#
# `cors_open_runtime` is deliberately a SEPARATE id from `cors_open` rather
# than a flag on it. proof_json is stored and later read by people deciding
# whether to trust a fix, and the two are different kinds of evidence: one is
# a regex over the source, the other is a booted application answering a real
# cross-origin request. A single id would make a stored row ambiguous forever
# — nobody reading it a month later could tell which claim it carried.
#
# Note that being in this contract is not the same as being in
# app/proof/registry.py, which is what the product actually offers. This id is
# storable and renderable before the runtime probe is wired into routing.
# `rls_open_runtime` is likewise its own id: an anon `select` that came back
# with rows is a different claim from a regex over migrations, and a stored
# proof_json row has to stay unambiguous about which one it carried.
VALID_TEMPLATE_IDS: tuple[str, ...] = (
    "secrets_leak", "sqli", "cors_open", "cors_open_runtime",
    "rls_open_runtime",
)

AttemptStatus = Literal[
    "success",      # attack worked (exploit confirmed)
    "failure",      # attack did not work
    "skipped",      # template not applicable / not implemented
    "error",        # runner/infrastructure failure
]


@dataclass(frozen=True)
class ExploitAttempt:
    """One run of a template against one workspace snapshot."""

    template_id: TemplateId
    status: AttemptStatus
    success: bool
    detail: str
    evidence: dict[str, Any]
    duration_ms: int = 0


@dataclass(frozen=True)
class ProofReport:
    """Before/after comparison for one template.

    ``verified`` is true only when the exploit succeeded on the original
    workspace and failed on the patched one.

    ``informational`` controls the PR footer note. When the delivery gate
    is ``soft`` or ``hard`` we pass ``informational=False`` so the section
    does not claim the report is non-blocking. The actual block decision
    lives in ``app.proof.gate.decide_proof_gate``.
    """

    template_id: TemplateId
    before: ExploitAttempt
    after: ExploitAttempt
    verified: bool
    informational: bool
    detail: str


def proof_report_to_json(report: ProofReport) -> dict[str, Any]:
    """Serialize for fixpack_jobs.proof_json (jsonb)."""
    return asdict(report)


def proof_report_from_json(value: object) -> ProofReport:
    """Rebuild a ProofReport from stored jsonb. Raises ValueError on junk."""
    if not isinstance(value, dict):
        raise ValueError("proof_json must be an object")

    template_id = value.get("template_id")
    if template_id not in VALID_TEMPLATE_IDS:
        raise ValueError("proof_json.template_id is invalid")

    before = _attempt_from_json(value.get("before"), "before")
    after = _attempt_from_json(value.get("after"), "after")

    verified = value.get("verified")
    informational = value.get("informational")
    detail = value.get("detail")

    if not isinstance(verified, bool):
        raise ValueError("proof_json.verified must be boolean")
    if not isinstance(informational, bool):
        raise ValueError("proof_json.informational must be boolean")
    if not isinstance(detail, str) or not detail.strip():
        raise ValueError("proof_json.detail must be a non-empty string")

    return ProofReport(
        template_id=template_id,
        before=before,
        after=after,
        verified=verified,
        informational=informational,
        detail=detail,
    )


def _attempt_from_json(value: object, field: str) -> ExploitAttempt:
    if not isinstance(value, dict):
        raise ValueError(f"proof_json.{field} must be an object")

    template_id = value.get("template_id")
    status = value.get("status")
    success = value.get("success")
    detail = value.get("detail")
    evidence = value.get("evidence")
    duration_ms = value.get("duration_ms", 0)

    if template_id not in VALID_TEMPLATE_IDS:
        raise ValueError(f"proof_json.{field}.template_id is invalid")
    if status not in ("success", "failure", "skipped", "error"):
        raise ValueError(f"proof_json.{field}.status is invalid")
    if not isinstance(success, bool):
        raise ValueError(f"proof_json.{field}.success must be boolean")
    if not isinstance(detail, str):
        raise ValueError(f"proof_json.{field}.detail must be a string")
    if not isinstance(evidence, dict):
        raise ValueError(f"proof_json.{field}.evidence must be an object")
    if isinstance(duration_ms, bool) or not isinstance(duration_ms, int) or duration_ms < 0:
        raise ValueError(f"proof_json.{field}.duration_ms is invalid")

    return ExploitAttempt(
        template_id=template_id,
        status=status,
        success=success,
        detail=detail,
        evidence=evidence,
        duration_ms=duration_ms,
    )

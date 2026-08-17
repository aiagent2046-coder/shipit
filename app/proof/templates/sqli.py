"""SQLi proof template — stub.

Runtime HTTP probe against a sandboxed app is out of scope for the
informational MVP. Registered so the registry is complete; always returns
skipped.
"""

from __future__ import annotations

from app.proof.types import ExploitAttempt


def run(zip_bytes: bytes, **_: object) -> ExploitAttempt:
    return ExploitAttempt(
        template_id="sqli",
        status="skipped",
        success=False,
        detail="sqli template not implemented (runtime HTTP probe pending)",
        evidence={"reason": "not_implemented"},
    )

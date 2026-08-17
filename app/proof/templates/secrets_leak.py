"""Static secrets-leak proof template.

Reuses ``app.scan.secrets.scan_secrets`` so proof and audit share one
definition of "what counts as a leaked secret". No raw values are kept
in evidence — only masks, paths, and counts.

``success`` means at least one high/critical finding remains in the
workspace (excluding known non-production contexts). After a working
secrets Fix Pack that count should drop to zero.
"""

from __future__ import annotations

import io
import time

from app.proof.types import ExploitAttempt
from app.scan.secrets import NON_PRODUCTION_CONTEXTS, scan_secrets

# Findings at or above this severity count as a successful "exploit"
# for proof purposes. Low/informational (anon keys, dev DSN defaults)
do not.
_PROOF_SEVERITIES = frozenset({"critical", "high"})


def run(zip_bytes: bytes, **_: object) -> ExploitAttempt:
    started = time.monotonic()
    try:
        findings = scan_secrets(io.BytesIO(zip_bytes))
    except Exception as exc:  # noqa: BLE001 — surface as attempt error
        return ExploitAttempt(
            template_id="secrets_leak",
            status="error",
            success=False,
            detail=f"secrets scan failed: {type(exc).__name__}",
            evidence={},
            duration_ms=_ms(started),
        )

    actionable = [
        f
        for f in findings
        if f.severity in _PROOF_SEVERITIES
        and f.context not in NON_PRODUCTION_CONTEXTS
    ]

    samples = [
        {
            "file": f.file,
            "line": f.line,
            "rule_id": f.rule_id,
            "severity": f.severity,
            "masked": f.masked,
        }
        for f in actionable[:5]
    ]

    success = len(actionable) > 0
    if success:
        detail = (
            f"found {len(actionable)} high/critical secret(s) in workspace"
        )
        status = "success"
    else:
        detail = "no high/critical production secrets found"
        status = "failure"

    return ExploitAttempt(
        template_id="secrets_leak",
        status=status,  # type: ignore[arg-type]
        success=success,
        detail=detail,
        evidence={
            "finding_count": len(actionable),
            "total_scanned_findings": len(findings),
            "samples": samples,
        },
        duration_ms=_ms(started),
    )


def _ms(started: float) -> int:
    return max(0, int((time.monotonic() - started) * 1000))

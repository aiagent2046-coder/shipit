"""Proof stage for Fix Pack delivery.

Runs after semantic check succeeds. Fail-open on infrastructure errors.
Gate decision (off/soft/hard) is applied by the caller via decide_proof_gate.
"""

from __future__ import annotations

import functools
import logging
from typing import Any

from starlette.concurrency import run_in_threadpool

from app.proof.compare import run_proof_pair
from app.proof.types import ProofReport, proof_report_to_json
from app.proof.workspace import apply_plan_to_zip

logger = logging.getLogger(__name__)


async def run_proof_stage(
    *,
    job_id: str,
    zip_bytes: bytes,
    plan: Any,
    fixpack_repo: Any,
) -> ProofReport | None:
    """Build patched zip, run secrets_leak pair, persist proof_json.

    Returns the ProofReport on success, or None on any failure (fail-open).
    """
    try:
        patched_zip = apply_plan_to_zip(
            zip_bytes, plan.files, plan.deletions,
        )
        proof_report = await run_in_threadpool(
            functools.partial(
                run_proof_pair, "secrets_leak", zip_bytes, patched_zip,
                informational=False,
            )
        )
        await fixpack_repo.set_proof_json(
            job_id, proof_report_to_json(proof_report),
        )
        return proof_report
    except Exception:  # noqa: BLE001 — proof must never kill delivery
        logger.exception(
            "Fix Pack job %s: proof stage failed, continuing without it",
            job_id,
            extra={"step": "proof"},
        )
        return None

"""Proof stage for Fix Pack delivery.

Runs after semantic check succeeds. Selects templates via routing, runs
before/after pairs, persists proof_json, returns a stage result for the
gate and PR body. Fail-open on infrastructure errors.
"""

from __future__ import annotations

import functools
import logging
from dataclasses import dataclass, field
from typing import Any

from starlette.concurrency import run_in_threadpool

from app.proof.compare import run_proof_pair
from app.proof.routing import select_templates
from app.proof.types import ProofReport, proof_report_to_json
from app.proof.workspace import apply_plan_to_zip

logger = logging.getLogger(__name__)


@dataclass
class ProofStageResult:
    """Outcome of the proof stage for one Fix Pack job.

    ``primary`` is the report the gate / legacy callers focus on (first
    verified, else first actionable, else first). ``reports`` is the full
    ordered list for multi-section PR bodies and aggregate gating.
    """

    primary: ProofReport | None = None
    reports: list[ProofReport] = field(default_factory=list)

    @property
    def detail(self) -> str:
        if self.primary is not None:
            return self.primary.detail
        if self.reports:
            return self.reports[0].detail
        return "no proof report"


async def run_proof_stage(
    *,
    job_id: str,
    zip_bytes: bytes,
    plan: Any,
    fixpack_repo: Any,
) -> ProofStageResult:
    """Build patched zip, run selected template pairs, persist proof_json.

    Returns an empty result (primary=None, reports=[]) on failure so callers
    stay fail-open.
    """
    try:
        templates = select_templates(plan, zip_bytes)
        if not templates:
            logger.info(
                "Fix Pack job %s: proof stage skipped (no templates selected)",
                job_id,
                extra={"step": "proof"},
            )
            return ProofStageResult()

        patched_zip = apply_plan_to_zip(
            zip_bytes, plan.files, plan.deletions,
        )

        reports: list[ProofReport] = []
        for template_id in templates:
            report = await run_in_threadpool(
                functools.partial(
                    run_proof_pair, template_id, zip_bytes, patched_zip,
                    informational=False,
                )
            )
            reports.append(report)

        primary = _pick_primary(reports)
        payload = _proof_json_payload(primary, reports)
        await fixpack_repo.set_proof_json(job_id, payload)
        return ProofStageResult(primary=primary, reports=reports)
    except Exception:  # noqa: BLE001 — proof must never kill delivery
        logger.exception(
            "Fix Pack job %s: proof stage failed, continuing without it",
            job_id,
            extra={"step": "proof"},
        )
        return ProofStageResult()


def _pick_primary(reports: list[ProofReport]) -> ProofReport | None:
    if not reports:
        return None
    for r in reports:
        if r.verified:
            return r
    for r in reports:
        if r.before.success and r.before.status == "success":
            return r
    return reports[0]


def _proof_json_payload(
    primary: ProofReport | None,
    reports: list[ProofReport],
) -> dict[str, Any]:
    """Backward-compatible jsonb: primary fields at top level + reports[]."""
    if primary is None:
        return {
            "template_id": None,
            "verified": False,
            "reports": [proof_report_to_json(r) for r in reports],
        }
    payload = proof_report_to_json(primary)
    payload["reports"] = [proof_report_to_json(r) for r in reports]
    return payload

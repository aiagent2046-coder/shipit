"""Proof stage for Fix Pack delivery.

Runs after semantic check succeeds. Selects templates via routing, runs
before/after pairs, persists proof_json, returns a stage result for the
gate and PR body. Fail-open on infrastructure errors.
"""

from __future__ import annotations

import functools
import logging
import random
from dataclasses import dataclass, field
from typing import Any

from starlette.concurrency import run_in_threadpool

from app import sandbox_client
from app.proof.compare import build_proof_report, run_proof_pair
from app.proof.routing import select_templates
from app.proof.runtime_cors import PROBE_PORT_RANGE, runtime_cors_applicable
from app.proof.artifacts import artifacts_to_json, build_artifacts
from app.proof.types import ProofReport, proof_report_to_json
from app.proof.workspace import apply_plan_to_zip

logger = logging.getLogger(__name__)

# The port the probe container is expected to serve on. 8000 matches what the
# Deploy Pack's generated images expose and what verify_deploy_pack's callers
# already assume; a repo that serves elsewhere simply never answers 200 and
# comes back as `error`, which is the correct outcome rather than a guess.
_CONTAINER_PORT = 8000


@dataclass
class ProofStageResult:
    """Outcome of the proof stage for one Fix Pack job.

    ``primary`` is the report the gate / legacy callers focus on (first
    verified, else first actionable, else first). ``reports`` is the full
    ordered list for multi-section PR bodies and aggregate gating.
    ``artifacts`` holds log/storyboard blobs for PR rendering.
    """

    primary: ProofReport | None = None
    reports: list[ProofReport] = field(default_factory=list)
    artifacts: list = field(default_factory=list)

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

        runtime = await _maybe_runtime_cors(job_id, reports, zip_bytes,
                                            patched_zip)
        if runtime is not None:
            # APPENDED, never substituted. If the scanner found a pattern and
            # the booted app did not reproduce it, the reader gets both: the
            # code says one thing, the running application another, and that
            # disagreement is the finding. Dropping the static half here would
            # publish the quieter of two claims — see app/proof/runtime_cors.py.
            reports.append(runtime)

        primary = _pick_primary(reports)
        artifacts = []
        for report in reports:
            artifacts.extend(build_artifacts(report))
        payload = _proof_json_payload(primary, reports, artifacts)
        await fixpack_repo.set_proof_json(job_id, payload)
        return ProofStageResult(
            primary=primary, reports=reports, artifacts=artifacts,
        )
    except Exception:  # noqa: BLE001 — proof must never kill delivery
        logger.exception(
            "Fix Pack job %s: proof stage failed, continuing without it",
            job_id,
            extra={"step": "proof"},
        )
        return ProofStageResult()


async def _maybe_runtime_cors(
    job_id: str,
    static_reports: list[ProofReport],
    original_zip: bytes,
    patched_zip: bytes,
) -> ProofReport | None:
    """Two container boots, or nothing. Never raises.

    Off unless PROOF_RUNTIME_CORS says otherwise, and gated further by
    runtime_cors_applicable. A runner outage, a build failure or a probe that
    could not connect all arrive here as `error` attempts, which
    build_proof_report can never mark verified — the honest outcome for "we
    did not manage to check".
    """
    applicable, reason = runtime_cors_applicable(static_reports, original_zip)
    if not applicable:
        logger.info(
            "Fix Pack job %s: runtime CORS probe not run (%s)", job_id, reason,
            extra={"step": "proof_runtime"},
        )
        return None

    port = random.choice(PROBE_PORT_RANGE)
    try:
        before = await run_in_threadpool(functools.partial(
            sandbox_client.run_cors_probe, original_zip,
            host_port=port, container_port=_CONTAINER_PORT,
        ))
        after = await run_in_threadpool(functools.partial(
            sandbox_client.run_cors_probe, patched_zip,
            host_port=port, container_port=_CONTAINER_PORT,
        ))
    except Exception as exc:  # noqa: BLE001 — runner outage is not a verdict
        logger.warning(
            "Fix Pack job %s: runtime CORS probe unavailable (%s)",
            job_id, type(exc).__name__, extra={"step": "proof_runtime"},
        )
        return None

    return build_proof_report(before, after, informational=False)


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
    artifacts: list | None = None,
) -> dict[str, Any]:
    """Backward-compatible jsonb: primary fields at top level + reports[]."""
    if primary is None:
        payload: dict[str, Any] = {
            "template_id": None,
            "verified": False,
            "reports": [proof_report_to_json(r) for r in reports],
        }
    else:
        payload = proof_report_to_json(primary)
        payload["reports"] = [proof_report_to_json(r) for r in reports]
    payload["artifacts"] = artifacts_to_json(artifacts or [])
    return payload

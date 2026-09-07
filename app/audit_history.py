"""Preserve a same-content, same-engine preview without rerunning its model.

History is not current evidence and never changes scores or fix eligibility.
Matching is deliberately exact: changed wording is not a verified resolution.
"""

from copy import deepcopy
import json
import asyncio

from app.llm import pricing
from app.scan import llm_scan
from app.scan.pipeline import FREE_TIER_MODEL, FREE_TIER_MODEL_BY_KIND, FREE_TIER_RUBRICS

from app.scan.pipeline import BASIS_PREVIEW
from app.db import DatabaseNotConfigured


def _observation_key(finding: dict) -> str:
    # Do not silently discard changed evidence, grouped occurrences or advice.
    return json.dumps(finding, sort_keys=True, ensure_ascii=False)


async def score_with_preview_history(repo, score: dict, findings: list[dict],
                                     digest: str, engine_version: str) -> dict:
    """Called only for full-depth requests, including their failed/partial scans."""
    preview = await repo.get_by_content_hash(digest, engine_version, BASIS_PREVIEW)
    if (not preview or not preview.get("id")
            or preview.get("status") != "completed"
            or preview.get("content_hash") != digest
            or preview.get("engine_version") != engine_version
            or (preview.get("score_json") or {}).get("basis") != BASIS_PREVIEW):
        return score
    previous = preview.get("findings_json") or []
    keys = {_observation_key(f) for f in findings}
    retained = [deepcopy(f) for f in previous if _observation_key(f) not in keys]
    history = {
        "version": 1,
        "preview_audit_id": str(preview["id"]),
        "content_hash": digest,
        "engine_version": engine_version,
        "model": ((preview.get("score_json") or {}).get("scan_manifest") or {}).get("model"),
        "total": len(previous),
        "matched_count": len(previous) - len(retained),
        "retained_findings": retained,
        "status": "not_reassessed",
    }
    if score.get("preview_history") == history and score.get("free_baseline"):
        return score
    return {**score, "preview_history": history,
            "free_baseline": baseline_snapshot(preview["score_json"], previous, "reused", str(preview["id"]))}


async def refresh_cached_preview_history(repo, cached: dict) -> dict | None:
    """Create a new snapshot when history changes; leave the original untouched.

No scan or LLM call is needed. Keep the original analysis id so copied model
coverage is not mistaken for newly performed work. The new row gets its own
access token through the normal repository create path.
"""
    digest, engine = cached.get("content_hash"), cached.get("engine_version")
    if not digest or not engine:
        return cached
    original_score = cached.get("score_json") or {}
    findings = cached.get("findings_json") or []
    score = await score_with_preview_history(repo, original_score, findings, digest, engine)
    if score is original_score:
        return cached
    score["analysis_reused_from"] = original_score.get("analysis_reused_from") or str(cached["id"])
    persisted = await repo.create(
        stack=cached["stack"], file_count=cached["file_count"],
        score_total=cached["score_total"], score_json=score, findings_json=findings,
        repo_url=cached.get("repo_url"), content_hash=digest, engine_version=engine,
    )
    if persisted is None:
        raise DatabaseNotConfigured("Could not persist the audit history snapshot")
    return persisted


def baseline_snapshot(score, findings, origin, audit_id=None):
    """Keep the complete free result, with no access tokens or nested history."""
    clean_score = {k: deepcopy(v) for k, v in score.items()
                   if k not in {"free_baseline", "preview_history", "analysis_reused_from"}}
    return {"version": 1, "origin": origin, "audit_id": audit_id,
            "status": "completed" if score.get("basis") == BASIS_PREVIEW else "incomplete",
            "score": clean_score, "findings": deepcopy(findings)}


async def ensure_paid_baseline(repo, scan, raw, client, digest, engine, *, runner, record_usage):
    """One preview inside paid entitlement; reuse exact content/engine first.

    This is not an anonymous request and does not consume its quota. The
    remaining paid-job spend budget bounds subsequent preview calls. Like the
    existing cap, one provider response may overshoot; no hard dollar reservation.
    """
    score = await score_with_preview_history(repo, scan["score"], scan["findings"], digest, engine)
    if score.get("free_baseline"):
        return score
    usage = scan.get("llm_usage") or {}
    remaining = llm_scan.JOB_COST_CAP_USD - pricing.cost_usd(
        usage.get("model"), usage.get("input_tokens", 0), usage.get("output_tokens", 0))
    if not client.providers or remaining <= 0:
        return {**score, "free_baseline": {"version": 1, "origin": "included",
                "status": "unavailable", "reason": "no_providers_configured" if not client.providers
                else "paid_job_cost_cap", "findings": [], "score": None}}
    preview = await runner(raw, client.with_model(FREE_TIER_MODEL, by_kind=FREE_TIER_MODEL_BY_KIND),
                           llm_passes=1, llm_rubrics=FREE_TIER_RUBRICS, depth=BASIS_PREVIEW,
                           llm_cost_cap=remaining)
    # Record this model separately: the paid and free models have different
    # prices. Do this before persisting any report, also on later DB failure.
    await asyncio.shield(record_usage(preview["llm_usage"]))
    return {**score, "free_baseline": baseline_snapshot(preview["score"], preview["findings"], "included")}

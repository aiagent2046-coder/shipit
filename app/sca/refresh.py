"""Re-ask about an audit's dependencies once its answer has aged.

WHY A REFRESH EXISTS AT ALL. Every other finding an audit produces describes
the bytes it was given, so it stays true for as long as those bytes exist. The
dependency answer is the exception: it describes what a database said on a
date, and advisory data changes while the repository does not. Without this,
"no known vulnerabilities" silently becomes false in a cached row that keeps
its cache key.

WHY IT NEEDS STORED INPUT. Re-asking requires the resolved versions, and this
deployment deliberately keeps no archive bytes (migrations/0001). So the
inventory is stored beside the audit (migration 0039) and the refresh is a
query about a list -- never a re-read of a repository we no longer have.

WHY IT WRITES A NEW ROW INSTEAD OF UPDATING. An audit is a record of what was
reported, and `get_by_content_hash` returns the most recent row for the same
content, engine and basis. A refreshed row therefore becomes the row a repeat
audit reuses, while the earlier one keeps saying what it said. Rewriting
history would make a customer's stored report change under them.

THE COST OF BEING WRONG IS ONE-SIDED. A database that cannot be reached leaves
the older answer in place instead of replacing it with nothing; the row simply
stays stale and keeps saying so.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from app.scan.checks import CheckFinding
from app.sca.lockfiles import Dependency, collect_dependencies
from app.sca.stage import (RULE_ID, SCA_FRESHNESS_TTL_DAYS, findings_for,
                           freshness, query_dependencies)
from app.sca.osv import OsvClient
from app.scan.pipeline import RUBRICS, BASIS_STATIC_ONLY, score_findings

INVENTORY_VERSION = 1


def inventory_payload(data: bytes, asked_at: str | None) -> dict | None:
    """What to store beside an audit so its answer can be re-asked later.

    None when the stage never asked: an inventory is only useful for re-asking,
    and storing dependencies we never queried would turn an audit that skipped
    the check into one that looks like it performed it.

    Stored data is the resolved identity of each dependency -- never source, a
    snippet or a path outside the lockfile that declared it.
    """
    if not asked_at:
        return None
    dependencies, manifests, found = collect_dependencies(data)
    if not dependencies:
        return None
    return {
        "version": INVENTORY_VERSION,
        "asked_at": asked_at,
        "lockfiles": manifests,
        "found": found,
        "dependencies": [
            {"ecosystem": d.ecosystem, "name": d.name, "version": d.version,
             "manifest": d.manifest, "line": d.line, "direct": d.direct,
             "development": d.development}
            for d in dependencies
        ],
    }


def with_asked_at(payload: dict, asked_at: str) -> dict:
    """The same inventory, dated by the answer that used it."""
    return {**payload, "version": INVENTORY_VERSION, "asked_at": asked_at}


def dependencies_from_payload(payload: object) -> list[Dependency]:
    """Read a stored inventory back, ignoring anything malformed.

    A row stored by a future version, or a partially written one, yields the
    entries that are readable rather than raising inside a sweep: a refresh
    that cannot read one audit must not stop the others.
    """
    if not isinstance(payload, dict):
        return []
    stored = payload.get("dependencies")
    if not isinstance(stored, list):
        return []
    out: list[Dependency] = []
    for entry in stored:
        if not isinstance(entry, dict):
            continue
        ecosystem, name, version = (entry.get("ecosystem"), entry.get("name"),
                                    entry.get("version"))
        if not all(isinstance(v, str) and v for v in (ecosystem, name, version)):
            continue
        development = entry.get("development")
        out.append(Dependency(
            ecosystem=ecosystem, name=name, version=version,
            manifest=str(entry.get("manifest") or ""),
            line=int(entry.get("line") or 0),
            direct=bool(entry.get("direct")),
            development=development if isinstance(development, bool) else None,
        ))
    return out


def refreshed_findings(stored_findings: list[dict],
                       sca_findings: list[CheckFinding]) -> list[dict]:
    """The stored findings with every dependency row replaced by today's.

    Replaced wholesale, not merged: a refreshed answer can drop an advisory
    that was withdrawn or found to be mis-scoped, and merging would leave the
    withdrawn row behind forever.
    """
    kept = [f for f in stored_findings if f.get("rule_id") != RULE_ID]
    return kept + [vars(finding) for finding in sca_findings]


def score_inputs_from_stored(score: dict) -> dict:
    """The inputs run_scan would have passed to the scorer for this row.

    Read back from the stored facts rather than recomputed from the bytes:
    `basis` says whether a model stage ran, the manifest says which rubrics
    answered, and the static limits say whether an analyzer ran out of budget.
    """
    manifest = score.get("scan_manifest") or {}
    basis = score.get("basis")
    llm_ran = bool(basis) and basis != BASIS_STATIC_ONLY
    # Mirrors run_scan: a scan with no LLM stage passed the full rubric list,
    # which scores identically because llm_ran is False; a scan that ran a
    # subset passes the subset it actually ran.
    ran = (tuple(manifest.get("rubrics_completed") or ()) if llm_ran
           else tuple(RUBRICS))
    limits = manifest.get("static_limits") or {}
    return {
        "llm_ran": llm_ran,
        "llm_categories": frozenset(RUBRICS[r]["category"] for r in ran if r in RUBRICS),
        "incomplete_static": frozenset(
            {"Frontend"} if limits.get("error_boundary") == "budget_exhausted" else set()),
    }


def refreshed_score(stored_score: dict, findings: list[dict], stats: dict,
                    previous_audit_id: str | None = None) -> dict:
    """The stored score with its computed numbers recomputed for `findings`.

    Keys the scorer does not produce (`basis`, `frontend_scan`, `free_baseline`,
    preview history) are carried over untouched: they describe facts about the
    scan, and this refresh only changed one rule's rows.
    """
    manifest = dict(stored_score.get("scan_manifest") or {})
    manifest.update({
        "sca_checks": stats.get("checks_run", []),
        "sca_dependencies": stats.get("dependencies"),
        "sca_dependencies_found": stats.get("dependencies_found"),
        "sca_asked_at": stats.get("asked_at"),
        "sca_findings": stats.get("findings"),
        "sca_skipped_reason": stats.get("skipped_reason") or None,
    })
    refreshed = {**stored_score,
                 **score_findings(findings, **score_inputs_from_stored(stored_score)),
                 "scan_manifest": manifest}
    if previous_audit_id:
        # Provenance, for anyone comparing two rows for the same content: this
        # one did not scan the repository again, it re-asked about its
        # dependencies.
        refreshed["dependency_refreshed_from"] = previous_audit_id
    return refreshed


@dataclass
class RefreshSummary:
    """What one sweep did, in the numbers a log line can carry."""
    considered: int = 0
    refreshed: int = 0
    skipped: int = 0
    unavailable: int = 0
    failed: int = 0
    reasons: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"considered": self.considered, "refreshed": self.refreshed,
                "skipped": self.skipped, "unavailable": self.unavailable,
                "failed": self.failed, "reasons": self.reasons}


def _empty_stats() -> dict:
    """The same counters the stage produces, without the archive to collect."""
    return {"checks_run": ["sca_dependencies"], "lockfiles": [], "dependencies": 0,
            "dependencies_found": 0, "advisories": 0, "reported_advisories": 0,
            "packages_reported": 0, "below_severity_floor": 0,
            "unreadable_advisories": 0, "requests": 0, "findings": 0,
            "truncated": 0, "asked_at": None, "skipped_reason": None}


async def refresh_stale_dependency_audits(
    repo, *, client_factory, now: datetime | None = None, limit: int = 20,
) -> dict:
    """Re-ask about the dependencies of audits whose answer has aged.

    `client_factory` is asked for a client PER ROW, so the entitlement policy
    is consulted again on every refresh rather than frozen at sweep start: an
    account that opted out since the audit was written must not be asked about
    again because the sweep had already decided otherwise.
    """
    reference = now or datetime.now(timezone.utc)
    cutoff = reference - timedelta(days=SCA_FRESHNESS_TTL_DAYS)
    summary = RefreshSummary()
    stored_audits = await repo.stale_dependency_audits(
        created_before=cutoff, limit=limit)

    for stored in stored_audits:
        summary.considered += 1
        score = stored.get("score_json") or {}
        manifest = score.get("scan_manifest") or {}
        # The SQL filter is coarse (created_at < cutoff); the exact age policy
        # lives here, and only here.
        if freshness(manifest.get("sca_asked_at"), reference) != "stale":
            summary.skipped += 1
            continue
        payload = stored.get("dependency_inventory") or {}
        dependencies = dependencies_from_payload(payload)
        if not dependencies:
            summary.skipped += 1
            summary.reasons["empty_inventory"] = summary.reasons.get("empty_inventory", 0) + 1
            continue
        client = client_factory()
        if client is None:
            summary.skipped += 1
            summary.reasons["no_client"] = summary.reasons.get("no_client", 0) + 1
            continue

        hits, records, unreadable, reason = await _ask(dependencies, client)
        if reason is not None:
            # The older answer stays. Replacing it with nothing would turn a
            # database outage into a clean dependency report.
            summary.unavailable += 1
            summary.reasons[reason.split(":")[0]] = (
                summary.reasons.get(reason.split(":")[0], 0) + 1)
            continue
        if not records and unreadable:
            # The batch answered and every detail lookup failed. The stage
            # reports that as "nothing was established"; a REFRESH has a better
            # option -- leaving the older, detailed answer in place rather than
            # overwriting it with rows that know less.
            summary.unavailable += 1
            summary.reasons["details_unavailable"] = (
                summary.reasons.get("details_unavailable", 0) + 1)
            continue

        stats = _empty_stats()
        stats["lockfiles"] = list(payload.get("lockfiles") or [])
        stats["dependencies"] = len(dependencies)
        stats["dependencies_found"] = int(payload.get("found") or len(dependencies))
        stats["asked_at"] = reference.isoformat(timespec="seconds")
        findings = findings_for(dependencies, hits, records, stats)
        stats["requests"] = getattr(client, "requests_made", 0)

        new_findings = refreshed_findings(stored.get("findings_json") or [], findings)
        new_score = refreshed_score(score, new_findings, stats,
                                    previous_audit_id=str(stored.get("id") or "") or None)
        created = await repo.create(
            stack=stored.get("stack") or "", file_count=stored.get("file_count") or 0,
            score_total=new_score.get("total"), score_json=new_score,
            findings_json=new_findings, repo_url=stored.get("repo_url"),
            content_hash=stored.get("content_hash"),
            engine_version=stored.get("engine_version"),
            dependency_inventory=with_asked_at(payload, stats["asked_at"]),
        )
        if created is None:
            summary.failed += 1
            continue
        summary.refreshed += 1

    return summary.as_dict()


async def _ask(dependencies: list[Dependency], client: OsvClient):
    """query_dependencies, on the threadpool-agnostic path.

    Kept as one awaitable so the sweep's shape does not depend on whether the
    client is blocking: the stage's own callers run inside a thread, and this
    one runs in the worker's event loop, where a blocking transport would stall
    every other slot.
    """
    return await asyncio.get_running_loop().run_in_executor(
        None, query_dependencies, dependencies, client)

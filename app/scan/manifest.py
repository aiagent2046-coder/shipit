"""Recorded scan inputs and execution facts; no inferred production status."""
from __future__ import annotations

import hashlib
import io
import zipfile

from app.scan.rejection_diagnostics import acceptance_summary, diagnostics_manifest
from app.scan.rule_coverage import normalize_rule_coverage
from app.sca.lockfiles import OSV_ECOSYSTEM


SCA_LIMITATIONS = frozenset({
    "dependency_check_not_run", "dependency_database_unavailable",
    "dependency_lockfile_unreadable", "dependency_coverage_incomplete",
})


def sca_limitations(sca: dict) -> list[str]:
    """Dependency coverage facts shared by initial scans and cached refreshes."""
    reasons = []
    skipped = str(sca.get("skipped_reason") or "")
    if skipped == "no_client" and sca.get("dependencies"):
        reasons.append("dependency_check_not_run")
    elif skipped.startswith("osv_unavailable"):
        reasons.append("dependency_database_unavailable")
    elif skipped.startswith("lockfile_unreadable"):
        reasons.append("dependency_lockfile_unreadable")
    if sca.get("coverage_incomplete") or skipped == "no_resolvable_lockfile":
        reasons.append("dependency_coverage_incomplete")
    return reasons


def sca_manifest_fields(sca: dict) -> dict:
    """Public dependency facts, excluding the private package inventory."""
    fields = {"sca_" + name: sca.get(name) for name in (
        "dependencies", "dependencies_found", "asked_at", "findings", "advisories",
        "unreadable_advisories", "unusable_lockfiles", "incomplete_lockfiles",
        "coverage_incomplete", "below_severity_floor",
    )}
    fields.update({"sca_checks": sca.get("checks_run", []),
                   "sca_findings_truncated": sca.get("truncated", 0),
                   "sca_skipped_reason": sca.get("skipped_reason") or None})
    return fields


def _file_counts(coverage: object) -> dict | None:
    """Persist a fixed numeric schema, never opaque scanner metadata.

    These are public file counts. No source value, path or extra dictionary
    field may travel through this channel into JSON, HTML or CLI output.
    """
    if not isinstance(coverage, dict):
        return None
    counts = {name: int(coverage.get(name, 0)) for name in (
        "files_total", "files_read", "files_scanned", "lossy_decoded_files",
    )}
    excluded = coverage.get("exclusions", {})
    counts["exclusions"] = {reason: int(excluded[reason]) for reason in (
        "file_size_limit", "symlink", "excluded_directory", "excluded_extension", "binary_content",
    ) if reason in excluded}
    return counts


def scan_manifest(data: bytes, engine: str, static: dict, llm: object,
                  failure_kind: str | None, sca: object = None) -> dict:
    """Recorded inputs, execution facts and what was NOT examined.

    `sca` is the dependency stage's stats when it ran, or its reason for not
    running. It is carried here rather than only in the findings because a
    reader must be able to tell "no known vulnerabilities" from "the database
    was never asked", and because the answer is only true of the day it was
    asked -- see `asked_at`.
    """
    stats = llm if isinstance(llm, dict) else {}
    sca = sca if isinstance(sca, dict) else {}
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        names = [i.filename for i in archive.infolist() if not i.is_dir()]
    inventory = {
        "Python manifests": [n for n in names if n.rsplit("/", 1)[-1] in ("pyproject.toml", "requirements.txt")],
        "JavaScript manifests": [n for n in names if n.rsplit("/", 1)[-1] == "package.json"],
        # The lockfiles the dependency stage actually read, so a repository
        # whose dependencies were resolved elsewhere can be told apart from one
        # that was never asked about.
        "Lockfiles": [n for n in names if n.rsplit("/", 1)[-1] in OSV_ECOSYSTEM],
        "CI workflows": [n for n in names if ".github/workflows/" in n and n.endswith((".yml", ".yaml"))],
        "systemd units": [n for n in names if n.endswith((".service", ".timer"))],
        "Dockerfiles": [n for n in names if n.rsplit("/", 1)[-1] == "Dockerfile"],
    }
    submitted = stats.get("submitted_files")
    candidates = stats.get("candidate_files")
    reasons = []
    if stats.get("skipped_reason"):
        reasons.append(str(stats["skipped_reason"]))
    if failure_kind:
        reasons.append(failure_kind)
    for flag in ("cost_cap_exceeded", "input_truncated", "invalid_responses"):
        if stats.get(flag):
            reasons.append(flag)
    if stats.get("failed_rubric"):
        reasons.append("rubric_failed: " + str(stats["failed_rubric"]))
    # A dependency check that did not happen is a limitation of THIS audit, not
    # an absence of problems. The two reasons are kept apart: one is a policy
    # boundary (the check is not part of this entitlement), the other is a
    # failure that could be retried.
    reasons.extend(sca_limitations(sca))
    return {
        "archive_sha256": hashlib.sha256(data).hexdigest(),
        "engine_version": engine,
        "archive_files": len(names),
        # The archive digest identifies the exact input. A filename's short
        # SHA is not a verified Git commit, so do not promote it to one.
        "commit_sha": None,
        "inventory": inventory,
        "static_checks": static.get("checks_run", []),
        **sca_manifest_fields(sca),
        "static_limits": static.get("coverage", {}),
        "secrets_coverage": _file_counts(static.get("secrets_coverage")),
        "rule_coverage": normalize_rule_coverage(static.get("rule_coverage")),
        "source_facts": static.get("source_facts"),
        "model": stats.get("model"),
        "model_calls": stats.get("calls", 0),
        "model_findings": stats.get("model_findings"),
        "model_acceptance": acceptance_summary(stats.get("model_findings")),
        "rejection_diagnostics": diagnostics_manifest(stats),
        "rubrics_completed": list(stats.get("rubrics_ran", ())),
        "llm_candidate_files": candidates,
        "llm_submitted_files": len(submitted) if submitted is not None else None,
        "llm_files_not_submitted": max(0, candidates - len(submitted))
        if candidates is not None and submitted is not None else None,
        "llm_selection_exclusions": stats.get("selection_exclusions"),
        "limitations": reasons,
        "runtime_verified": False,
    }

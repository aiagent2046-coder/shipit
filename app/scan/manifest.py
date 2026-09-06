"""Recorded scan inputs and execution facts; no inferred production status."""
from __future__ import annotations

import hashlib
import io
import zipfile


def scan_manifest(data: bytes, engine: str, static: dict, llm: object, failure_kind: str | None) -> dict:
    stats = llm if isinstance(llm, dict) else {}
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        names = [i.filename for i in archive.infolist() if not i.is_dir()]
    inventory = {
        "Python manifests": [n for n in names if n.rsplit("/", 1)[-1] in ("pyproject.toml", "requirements.txt")],
        "JavaScript manifests": [n for n in names if n.rsplit("/", 1)[-1] == "package.json"],
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
    for flag in ("cost_cap_exceeded", "input_truncated"):
        if stats.get(flag):
            reasons.append(flag)
    if stats.get("failed_rubric"):
        reasons.append("rubric_failed: " + str(stats["failed_rubric"]))
    return {
        "archive_sha256": hashlib.sha256(data).hexdigest(),
        "engine_version": engine,
        "archive_files": len(names),
        # The archive digest identifies the exact input. A filename's short
        # SHA is not a verified Git commit, so do not promote it to one.
        "commit_sha": None,
        "inventory": inventory,
        "static_checks": static.get("checks_run", []),
        "static_limits": static.get("coverage", {}),
        "model": stats.get("model"),
        "model_calls": stats.get("calls", 0),
        "rubrics_completed": list(stats.get("rubrics_ran", ())),
        "llm_candidate_files": candidates,
        "llm_submitted_files": len(submitted) if submitted is not None else None,
        "llm_files_not_submitted": max(0, candidates - len(submitted))
        if candidates is not None and submitted is not None else None,
        "limitations": reasons,
        "runtime_verified": False,
    }

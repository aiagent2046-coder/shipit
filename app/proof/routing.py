"""Select which proof templates to run for a Fix Pack delivery.

Routing is driven by the plan, not by scanning the whole product surface:

* ``secrets_leak`` — when the plan rewrites secrets / untracks leaked env files.
* ``sqli`` / ``cors_open`` — only when the template reproduces on the original
  workspace **and** at least one of its evidence files is in the plan's
  changed path set (files rewritten or deleted).

That keeps residual SQLi in an untouched module from soft-failing a pure
secrets Fix Pack.
"""

from __future__ import annotations

from typing import Any

from app.proof.registry import get_template
from app.proof.types import TemplateId


def select_templates(plan: Any, original_zip: bytes) -> list[TemplateId]:
    """Return ordered template ids to run for this plan + workspace."""
    selected: list[TemplateId] = []

    if _plan_touches_secrets(plan):
        selected.append("secrets_leak")

    changed = _changed_paths(plan)
    if changed:
        for tid in ("sqli", "cors_open"):
            if _template_hits_changed_paths(tid, original_zip, changed):
                selected.append(tid)  # type: ignore[arg-type]

    # De-dupe, preserve order.
    return list(dict.fromkeys(selected))


def _plan_touches_secrets(plan: Any) -> bool:
    if getattr(plan, "secret_fixes", None):
        return True
    if getattr(plan, "leaked_env_files", None):
        return True
    if getattr(plan, "leaked_env_vars", None):
        return True
    return False


def _changed_paths(plan: Any) -> set[str]:
    paths: set[str] = set()
    files = getattr(plan, "files", None) or {}
    for p in files:
        paths.add(_normalize_path(str(p)))
    for p in getattr(plan, "deletions", None) or []:
        paths.add(_normalize_path(str(p)))
    return {p for p in paths if p}


def _template_hits_changed_paths(
    template_id: str,
    original_zip: bytes,
    changed: set[str],
) -> bool:
    try:
        attempt = get_template(template_id)(original_zip)
    except Exception:  # noqa: BLE001 — routing must not break delivery
        return False
    if not attempt.success or attempt.status != "success":
        return False
    samples = (attempt.evidence or {}).get("samples") or []
    for sample in samples:
        if not isinstance(sample, dict):
            continue
        path = _normalize_path(str(sample.get("file") or ""))
        if path and _path_intersects(path, changed):
            return True
    return False


def _normalize_path(path: str) -> str:
    """Strip archive root wrappers and leading ./ so plan and evidence agree."""
    path = path.replace("\\", "/").lstrip("./")
    parts = path.split("/")
    if len(parts) >= 2 and parts[0] not in {
        "app", "src", "lib", "api", "pages", "server", "backend", "apps",
    }:
        if parts[1] in {
            "app", "src", "lib", "api", "pages", "server", "backend",
            "apps", "config", "cmd", "internal",
        }:
            return "/".join(parts[1:])
    return path


def _path_intersects(evidence_path: str, changed: set[str]) -> bool:
    if evidence_path in changed:
        return True
    for c in changed:
        if evidence_path.endswith(c) or c.endswith(evidence_path):
            return True
        if evidence_path.split("/")[-1] and evidence_path.split("/")[-1] == c.split("/")[-1]:
            if evidence_path.endswith("/" + c) or c.endswith("/" + evidence_path):
                return True
    return False

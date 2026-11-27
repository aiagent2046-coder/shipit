"""Dependency-snapshot manifest section: the validated record shape.

Used by both the SARIF builder (app.scan.sarif_format) and the report
renderers via app.dependency_snapshot; extracted during the import-cycles
fix phase so scan never imports the report/dependency domain above it.
"""
from __future__ import annotations

import re
from datetime import datetime


def snapshot_metadata(value: object) -> dict | None:
    """Public fields only; cache fingerprints and unknown fields are not exported."""
    if (not isinstance(value, dict) or type(value.get("version")) is not int or value["version"] != 1
            or value.get("mode") != "bundled"):
        return None
    digest, checked = value.get("catalog_sha256"), value.get("checked_at")
    if digest is not None and (not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)):
        return None
    if checked is not None and _date(checked) is None:
        return None
    result = {"version": 1, "mode": "bundled", "catalog_sha256": digest, "checked_at": checked}
    if "retained_findings" in value:
        if not _count(value["retained_findings"]):
            return None
        result["retained_findings"] = value["retained_findings"]
    return result


def _count(value: object) -> bool:
    return type(value) is int and 0 <= value <= 9_007_199_254_740_991


def _date(value: object) -> datetime | None:
    if not isinstance(value, str) or len(value) > 64 or not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
            r"(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})", value):
        return None
    if value[-6] in {"+", "-"} and (int(value[-5:-3]) >= 24 or int(value[-2:]) >= 60):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None

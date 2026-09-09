"""Bounded processing facts; neither rejection nor acceptance proves a claim.

Never retain rejected model text, quotes, suggested paths, or quote hashes.
A known source path is represented only by its SHA-256 for local correlation.
"""
from __future__ import annotations

import hashlib
import re

MAX_REJECTION_ITEMS = 200
_MAX_COUNT = 2 ** 53 - 1
_REASONS = frozenset({
    "not_an_object", "missing_fields", "invalid_severity", "invalid_confidence",
    "invalid_text", "source_quote_or_location_mismatch", "self_cancelled",
})
_DETAILS = _REASONS | {"unknown_file", "invalid_line_range", "quote_missing_or_short", "quote_mismatch"}
_RUBRICS = frozenset({"auth", "security", "money", "web"})


def _count(value: object) -> bool:
    return type(value) is int and 0 <= value <= _MAX_COUNT


def _code(value: object, allowed: frozenset | set) -> bool:
    return isinstance(value, str) and value in allowed


def acceptance_summary(processing: object) -> dict | None:
    """Derive counts for new and historical reports without inventing coverage."""
    if not isinstance(processing, list) or not processing:
        return None
    received = accepted = rejected = source_rejected = withdrawn = 0
    for row in processing:
        if not isinstance(row, dict) or not all(_count(row.get(k)) for k in ("received", "accepted", "rejected")):
            return None
        if row["received"] != row["accepted"] + row["rejected"]:
            return None
        reasons = row.get("rejection_reasons")
        if not isinstance(reasons, dict) or not all(_count(v) for v in reasons.values()):
            return None
        if sum(reasons.values()) != row["rejected"]:
            return None
        received += row["received"]
        accepted += row["accepted"]
        rejected += row["rejected"]
        source_rejected += reasons.get("source_quote_or_location_mismatch", 0)
        withdrawn += reasons.get("self_cancelled", 0)
    if not all(_count(v) for v in (received, accepted, rejected)):
        return None
    state = ("no_candidates" if not received else "none_accepted" if not accepted
             else "partially_accepted" if rejected else "all_accepted")
    return dict(version=1, state=state, received=received, accepted=accepted, rejected=rejected,
                source_rejected=source_rejected, withdrawn=withdrawn,
                other_rejected=rejected - source_rejected - withdrawn)


def _line(value: object) -> int | None:
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return number if not isinstance(value, bool) and 1 <= number <= 2 ** 31 - 1 else None


def rejected_item(finding: object, files: dict[str, str], *, response: int,
                  rubric: str, item: int, reason: str) -> dict:
    """Explain an existing rejection; never relax or replace the admission gate."""
    f = finding if isinstance(finding, dict) else {}
    path = f.get("file")
    known = isinstance(path, str) and path in files
    start, end = _line(f.get("line_start")), _line(f.get("line_end"))
    detail = reason
    if reason == "source_quote_or_location_mismatch":
        if not known:
            detail = "unknown_file"
        elif start is None or end is None or not 1 <= start <= end <= len(files[path].splitlines()):
            detail = "invalid_line_range"
        elif len(str(f.get("evidence", "")).strip()) < 4:
            detail = "quote_missing_or_short"
        else:
            detail = "quote_mismatch"
    return dict(response=response, rubric=rubric, item=item, reason=reason, detail=detail,
                file_ref="sha256:" + hashlib.sha256(path.encode("utf-8")).hexdigest() if known else None,
                line_start=start, line_end=end)


def diagnostics_manifest(stats: dict) -> dict | None:
    """Persist a fixed allowlist even when a caller supplies extra metadata."""
    raw = stats.get("rejected_items")
    if not isinstance(raw, list):
        return None
    omitted = stats.get("rejected_items_omitted", 0)
    omitted = omitted if _count(omitted) else 0
    items = []
    for record in raw:
        if (len(items) >= MAX_REJECTION_ITEMS or not isinstance(record, dict)
                or not _code(record.get("reason"), _REASONS) or not _code(record.get("detail"), _DETAILS)
                or not _code(record.get("rubric"), _RUBRICS)
                or not all(_count(record.get(k)) and record[k] > 0 for k in ("response", "item"))):
            omitted = min(_MAX_COUNT, omitted + 1)
            continue
        ref = record.get("file_ref")
        items.append(dict(response=record["response"], rubric=record["rubric"], item=record["item"],
                          reason=record["reason"], detail=record["detail"],
                          file_ref=ref if isinstance(ref, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", ref) else None,
                          line_start=_line(record.get("line_start")), line_end=_line(record.get("line_end"))))
    return dict(version=1, items=items, omitted=omitted)

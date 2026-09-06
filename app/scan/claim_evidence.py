"""Execution evidence is set by the scanner, never accepted from model JSON.

A matching excerpt proves that text exists in a source window. It does not
prove the model's interpretation, a reachable path, or a harmful consequence.
Do not persist the excerpt: it can contain an unmasked credential.
"""
from __future__ import annotations


def quote_match_window(finding: dict, files: dict[str, str]) -> tuple[int, int] | None:
    path = finding.get("file")
    if not isinstance(path, str) or path not in files:
        return None
    lines = files[path].splitlines()
    try:
        start, end = int(finding["line_start"]), int(finding["line_end"])
    except (KeyError, TypeError, ValueError, OverflowError):
        return None
    if not 1 <= start <= end <= len(lines):
        return None
    excerpt = str(finding.get("evidence", "")).strip()
    lo, hi = max(0, start - 3), min(len(lines), end + 2)
    if len(excerpt) < 4 or excerpt not in "\n".join(lines[lo:hi]):
        return None
    return lo + 1, hi


def model_claim_evidence(finding: dict, files: dict[str, str]) -> dict:
    window = quote_match_window(finding, files)
    observation = finding.get("observation")
    conditions = finding.get("required_conditions")
    # Older/incomplete responses remain readable; missing conditions do not
    # mean that no conditions are needed. No arbitrary nested model metadata.
    conditions = ([c.strip() for c in conditions if isinstance(c, str) and c.strip()]
                  if isinstance(conditions, list) else [])
    return {
        "version": 1,
        "source_check": ({"kind": "quote_match", "line_start": window[0], "line_end": window[1]}
                         if window else {"kind": "not_recorded"}),
        "observation": observation.strip() if isinstance(observation, str) and observation.strip() else None,
        "required_conditions": conditions or None,
        "conditions_status": "not_checked",
        "consequence_status": "not_checked",
    }


def static_claim_evidence() -> dict:
    return {
        "version": 1, "source_check": {"kind": "static_rule"},
        "observation": None, "required_conditions": None,
        "conditions_status": "not_checked", "consequence_status": "not_checked",
    }

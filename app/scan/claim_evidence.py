"""Execution evidence is set by the scanner, never accepted from model JSON.

A matching excerpt proves that text exists in a source window. It does not
prove the model's interpretation, a reachable path, or a harmful consequence.
Do not persist the excerpt: it can contain an unmasked credential.
"""
from __future__ import annotations

import re


# Only scanner-owned, source-bound checks may request this display disposition.
# Unlike a contradiction, an unresolved outcome does not assert the opposite
# claim and never removes its score contribution.
NARRATIVE_REVIEW_KINDS = frozenset({"navigation_pending_outcome_unverified"})


def source_assessments(record: dict | None) -> list[dict]:
    """Read only well-formed scanner assessments; old records stay unchanged.

    These fields are constructed after model admission, never copied from its
    JSON. A source binding identifies the scope of a check, not runtime proof.
    Malformed saved metadata cannot grant score relief or a new disposition.
    """
    if not isinstance(record, dict) or type(record.get("version")) is not int or record["version"] != 1:
        return []
    checks = record.get("source_assessments")
    if not isinstance(checks, list):
        return []
    valid = []
    for check in checks:
        if not isinstance(check, dict):
            continue
        start, end = check.get("line_start"), check.get("line_end")
        if (check.get("method") != "source_ast"
                or not isinstance(check.get("result"), str)
                or check.get("result") not in {"unsupported", "contradicted", "observed", "not_checked"}
                or type(check.get("whole_finding")) is not bool
                or not isinstance(check.get("kind"), str) or not check["kind"]
                or not isinstance(check.get("detail"), str) or not check["detail"]
                or not isinstance(check.get("file"), str) or not check["file"]
                or not isinstance(check.get("source_sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", check["source_sha256"])
                or type(start) is not int or type(end) is not int or not 1 <= start <= end <= 2**53 - 1
                or not isinstance(check.get("source_binding"), dict) or not check["source_binding"]):
            continue
        valid.append(check)
    return valid


def unsupported_transport(record: dict | None) -> bool:
    """A narrow transport-only hypothesis lacks evidence of credential exposure.

    This excludes only that hypothesis's penalty. It does not verify routing,
    logging, proxy configuration, credential validity or application safety.
    Other unsupported/partial claims deliberately receive no score relief.
    """
    return any(check["kind"] == "credential_transport_only"
               and check["result"] == "unsupported" and check["whole_finding"]
               for check in source_assessments(record))


def narrative_review_checks(record: dict | None) -> list[dict]:
    """Validated source observations whose claimed outcome still needs review."""
    result = []
    for check in source_assessments(record):
        review = check.get("narrative_review")
        if (check["kind"] not in NARRATIVE_REVIEW_KINDS
                or check["result"] != "observed" or check["whole_finding"]
                or not isinstance(review, dict)
                or review.get("status") != "required"
                or review.get("premise") != check["kind"]
                or not isinstance(review.get("reason"), str)
                or not review["reason"].strip()):
            continue
        result.append(check)
    return result


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


def syntax_contradicted(record: dict | None) -> bool:
    return bool(record and record.get("version") == 1
                and (record.get("syntax_check") or {}).get("result") == "contradicted")


def partial_contradicted(record: dict | None) -> bool:
    """A source counterexample does not settle a compound finding's other claims.

    Only scanner-owned premise results count. Model observations and words such
    as 'actually safe' never determine this disposition or the score.
    """
    return bool(record and record.get("version") == 1 and not syntax_contradicted(record)
                and not unsupported_transport(record)
                and (any(isinstance(check, dict) and check.get("result") == "contradicted"
                         for check in (record.get("premise_checks") or []))
                     or any(check["result"] == "contradicted" for check in source_assessments(record))))

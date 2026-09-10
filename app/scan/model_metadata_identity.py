"""Small, fail-closed claim scopes for model metadata source operations.

A GET identifies an operation, not whether its version selection or repeated
request is the alleged problem. Only complete, short supported statements can
select a scope. Unknown prose, negation, qualifiers and compound claims are not
discarded. This deliberately leaves most free-form prose exact-repeat-only;
it neither verifies provider billing nor proves a cache/version defect.
"""
from __future__ import annotations

import re
from pathlib import PurePosixPath

MECHANISM = "model_metadata_request"
VERSION = 2
SCOPES = {"version_selection", "repeated_request"}

_MODEL = r"(?:the )?(?:replicate )?model version"
_EACH = r"(?:on every|for each) (?:embedding computation|computation|recompute)"
# Full matches, never keyword searches. Qualifiers remain distinct even when
# two statements select the same scope (for example paid vs extra requests).
_CLAIMS = [
    ("version_selection", (), _MODEL + r" (?:is |is fetched |fetched )?dynamically without pinning"),
    ("version_selection", (), _MODEL + r" (?:is not pinned|is unpinned|lookup uses an unpinned version)"),
    ("repeated_request", ("per_computation",), _MODEL + r" (?:is )?fetched " + _EACH),
    ("repeated_request", ("per_computation",), _MODEL + r" lookup (?:runs|is called) " + _EACH),
    ("repeated_request", ("per_computation", "paid_request_asserted"),
     _MODEL + r" lookup makes a paid api call " + _EACH),
    ("repeated_request", ("per_computation", "extra_request_asserted"),
     _MODEL + r" lookup adds an extra metadata request " + _EACH),
    ("repeated_request", ("cache_absent",), _MODEL + r" (?:lookup is not cached|is fetched without caching)"),
]
_FIXES = {
    "version_selection": r"pin the model version(?: id)?(?: in configuration)?",
    "repeated_request": r"cache the model version(?: id)?(?: with a ttl)?",
}
_CONDITIONS = {
    "version_selection": r"the (?:model owner publishes a new version|upstream model version changes)",
    "repeated_request": r"(?:multiple users trigger embedding recomputation in the same process lifetime|"
                        r"the provider charges for model metadata get requests|"
                        r"the metadata get request is billable)",
}


def _text(value, limit=2000):
    if not isinstance(value, str) or len(value) > limit:
        return None  # Never classify a truncated prefix of a compound claim.
    return re.sub(r"\s+", " ", re.sub(r"[-‐‑‒–—]", " ", value)).strip().casefold().removesuffix(".")


def _claim(value):
    text = _text(value)
    matches = [(scope, qualifiers) for scope, qualifiers, pattern in _CLAIMS
               if text is not None and re.fullmatch(pattern, text)]
    return matches[0] if len(matches) == 1 else None


def model_metadata_title(value):
    """Rejection routing only: a mixed metadata title cannot pick another cause."""
    text = _text(value[:2000]) if isinstance(value, str) else None
    return text is not None and re.search(r"\bmodel version\b|\bversion lookup\b", text) is not None


def model_metadata_claim(finding):
    """Select one complete supported hypothesis; model-provided scopes are ignored.

    Narrative fields may restate short claims within the selected scope. Free
    prose and compound narrative are outside this contract. Conditions are
    recognized here but compared literally during grouping, never paraphrased.
    """
    title = _claim(finding.get("title"))
    if title is None:
        return None
    scope, qualifiers = title
    qualifiers = set(qualifiers)
    for key in ("observation", "explanation"):
        value = finding.get(key, "")
        if value in (None, ""):
            continue
        claim = _claim(value)
        if claim is None or claim[0] != scope:
            return None
        qualifiers.update(claim[1])
    fix = _text(finding.get("fix_hint", ""))
    if fix is None or (fix and not re.fullmatch(_FIXES[scope], fix)):
        return None
    conditions = finding.get("required_conditions", [])
    if conditions is None:
        conditions = []  # model_claim_evidence persists absent conditions as null.
    if not isinstance(conditions, list) or len(conditions) > 16:
        return None
    for condition in conditions:
        text = _text(condition)
        if text is None or not re.fullmatch(_CONDITIONS[scope], text):
            return None
    # A model's additional premise request could concern another mechanism.
    if finding.get("premises") not in (None, []):
        return None
    return {"claim_scope": scope, "claim_qualifiers": sorted(qualifiers)}


def valid_model_metadata_identity(identity, path, *, legacy=False):
    """Legacy broad identities are valid only for payload-exact repetition."""
    if (not isinstance(path, str) or not path.strip() or len(path) > 512
            or PurePosixPath(path).is_absolute() or ".." in PurePosixPath(path).parts
            or not isinstance(identity, dict) or type(identity.get("version")) is not int
            or identity["version"] not in ({1, VERSION} if legacy else {VERSION})
            or identity.get("method") != "source_ast" or identity.get("mechanism") != MECHANISM
            or identity.get("file") != path or not isinstance(identity.get("source_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", identity["source_sha256"])):
        return False
    if identity["version"] == VERSION:
        if not isinstance(identity.get("claim_scope"), str) or identity["claim_scope"] not in SCOPES:
            return False
        qualifiers = identity.get("claim_qualifiers")
        known = {value for _, values, _ in _CLAIMS for value in values}
        if (not isinstance(qualifiers, list) or any(not isinstance(q, str) or q not in known for q in qualifiers)
                or qualifiers != sorted(set(qualifiers))):
            return False
    for key in ("function_span", "operation_span"):
        span = identity.get(key)
        if (not isinstance(span, list) or len(span) != 2 or any(type(n) is not int for n in span)
                or not 0 <= span[0] < span[1]):
            return False
    function, operation = identity["function_span"], identity["operation_span"]
    start, end = identity.get("operation_line_start"), identity.get("operation_line_end")
    return (function[0] <= operation[0] < operation[1] <= function[1]
            and type(start) is int and type(end) is int and 1 <= start <= end)


def compatible_model_metadata_claims(left, right, identity):
    """Same scope plus exact ancillary meaning; status checks run in dedup too."""
    for finding in (left, right):
        evidence = finding.claim_evidence or {}
        check, producer = evidence.get("source_check"), evidence.get("producer")
        if not isinstance(check, dict) or not isinstance(producer, dict):
            return False
        start, end = check.get("line_start"), check.get("line_end")
        if (check.get("kind") != "quote_match" or type(start) is not int or type(end) is not int
                or type(finding.line) is not int or not 1 <= start <= finding.line <= end
                or check.get("source_sha256", identity["source_sha256"]) != identity["source_sha256"]
                or check.get("file", finding.file) != finding.file
                or any(not isinstance(producer.get(key), str) or not producer[key].strip()
                       for key in ("model", "rubric"))
                or type(producer.get("response")) is not int or producer["response"] < 1):
            return False
        claim = model_metadata_claim({"title": finding.title, "explanation": finding.explanation,
                                      "fix_hint": finding.fix_hint,
                                      "observation": evidence.get("observation", ""),
                                      "required_conditions": evidence.get("required_conditions", [])})
        if claim is None or any(identity.get(key) != value for key, value in claim.items()):
            return False
    # Do not reinterpret conditional/qualified prose or recommendations. Title
    # paraphrases alone are allowed; all ancillary content must stay identical.
    for key in ("explanation", "fix_hint", "context", "source", "verification_method",
                "verification_status", "category", "origin_category"):
        if getattr(left, key) != getattr(right, key):
            return False
    if left.source != "llm" or left.verification_method != "model_review":
        return False
    # Evidence other than citation/producer coordinates is compared in full;
    # matching not_checked labels cannot erase different conditions or targets.
    def evidence_key(finding):
        record = finding.claim_evidence
        return {**{k: v for k, v in record.items() if k != "source_issue_identity"},
                "source_check": {k: v for k, v in record["source_check"].items()
                                 if k not in {"line_start", "line_end"}},
                "producer": {k: v for k, v in record["producer"].items()
                             if k not in {"model", "rubric", "response"}}}
    return evidence_key(left) == evidence_key(right)

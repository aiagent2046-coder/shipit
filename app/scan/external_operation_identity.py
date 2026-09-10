"""Exact bound-operation identities with conservative claim compatibility.

The AST operation alone does not establish equal findings. In particular,
different retry causes, client versus server effects, and database assumptions
must keep their separate interpretations. No title-similarity matching is used.
"""
from __future__ import annotations

from copy import deepcopy
import re

MECHANISMS = frozenset({"retry_poll_execution", "insert_count_schedule", "duplicate_key_dispatch"})
KINDS = frozenset({"retry_callback_scope", "retry_classifier_terminal_error", "poll_wait_not_deadline",
                   "duplicate_key_before_external_call", "insert_before_count_schedule",
                   "request_role_billing_boundary"})


def valid_external_identity(identity, path):
    if not isinstance(identity, dict) or set(identity) != {
            "version", "mechanism", "file", "source_sha256", "operation_span"}:
        return False
    span = identity.get("operation_span")
    return (type(identity.get("version")) is int and identity["version"] == 1
            and isinstance(identity.get("mechanism"), str) and identity["mechanism"] in MECHANISMS
            and identity.get("file") == path
            and isinstance(path, str) and 0 < len(path) <= 512 and not path.startswith("/")
            and "\\" not in path and all(p not in {"", ".", ".."} for p in path.split("/"))
            and isinstance(identity.get("source_sha256"), str)
            and re.fullmatch(r"[0-9a-f]{64}", identity["source_sha256"]) is not None
            and isinstance(span, list) and len(span) == 2 and all(type(n) is int for n in span)
            and 0 <= span[0] < span[1] <= 256000)


def identity_from_assessments(assessments, path):
    """Consume scanner-generated assessments; not arbitrary model metadata."""
    identities = []
    for record in assessments if isinstance(assessments, list) else []:
        if (not isinstance(record, dict) or not isinstance(record.get("kind"), str)
                or record["kind"] not in KINDS):
            continue
        identity = record.get("operation_identity")
        if identity is None:
            continue
        source = record.get("source_binding")
        if (not valid_external_identity(identity, path) or record.get("method") != "source_ast"
                or record.get("whole_finding") is not False
                or record.get("result") not in {"observed", "contradicted"}
                or record.get("file") != path or record.get("source_sha256") != identity["source_sha256"]
                or not isinstance(source, dict) or source.get("file") != path
                or source.get("source_sha256") != identity["source_sha256"]):
            return None
        key = {"retry_poll_execution": "retry_call", "insert_count_schedule": "registration",
               "duplicate_key_dispatch": "later_call"}[identity["mechanism"]]
        operation = source.get(key)
        if not isinstance(operation, dict) or operation.get("span") != identity["operation_span"]:
            return None
        identities.append(identity)
    if not identities or any(identity != identities[0] for identity in identities[1:]):
        return None
    return deepcopy(identities[0])


def _field(finding, key):
    return finding.get(key) if isinstance(finding, dict) else getattr(finding, key, None)


def _text(value):
    return " ".join(value.casefold().split()) if isinstance(value, str) else None


def _conditions(record):
    values = record.get("required_conditions")
    if not isinstance(values, list) or not values or any(not _text(v) for v in values):
        return None
    return tuple(sorted(_text(value) for value in values))


def _title_mechanism(title, mechanism):
    text = _text(title) or ""
    if re.search(r"\b(?:not|never|whether|no evidence)\b", text):
        return False
    if mechanism == "retry_poll_execution":
        return bool(re.search(r"\bpoll(?:ing)?\b", text) and re.search(r"\b(?:loop|retry|retries|seconds)\b", text))
    if mechanism == "insert_count_schedule":
        return bool(re.search(r"\b(?:auto.reply|Claude|AI)\b", text, re.I)
                    and re.search(r"\b(?:count|first.message|insert)\b", text)
                    and re.search(r"\b(?:race|duplicate|twice|concurrent)\b", text))
    return bool(re.search(r"\b(?:auto.reply|Claude)\b", text, re.I)
                and re.search(r"\b(?:deduplication|unconditional|every mutual match|fires again)\b", text))


def compatible_external_claims(first, second, identity):
    """Same bound operation plus retained proposition/conditions, never only a title.

Only spelling whitespace/case is normalized. Paraphrased conditions are not
treated as equal without a separate semantic proof. This deliberately refuses
to merge a duplicate-key error hypothesis with a hypothetical successful upsert,
or a retryable provider failure with a client retry after a function timeout.
"""
    path = _field(first, "file")
    if not valid_external_identity(identity, path) or _field(second, "file") != path:
        return False
    for field in ("source", "verification_method", "verification_status", "category", "origin_category"):
        if _field(first, field) != _field(second, field):
            return False
    if _field(first, "source") != "llm" or _field(first, "verification_method") != "model_review":
        return False
    records = [_field(item, "claim_evidence") for item in (first, second)]
    if not all(isinstance(record, dict) for record in records):
        return False
    a, b = records
    for record in records:
        if identity_from_assessments(record.get("source_assessments"), path) != identity:
            return False
    if not all(_title_mechanism(_field(item, "title"), identity["mechanism"]) for item in (first, second)):
        return False
    if _text(_field(first, "title")) != _text(_field(second, "title")):
        return False  # Additional/numeric title claims need a separate semantic proof.
    if _conditions(a) is None or _conditions(a) != _conditions(b):
        return False
    # An exact stated observation and explanation form a conservative proposition
    # boundary; a shared call must not swallow an additional numeric/cost claim.
    if not _text(a.get("observation")) or _text(a.get("observation")) != _text(b.get("observation")):
        return False
    if (not _text(_field(first, "explanation"))
            or _text(_field(first, "explanation")) != _text(_field(second, "explanation"))):
        return False
    for key in ("conditions_status", "consequence_status"):
        if a.get(key) != b.get(key):
            return False

    def disposition(record):
        records = record.get("source_assessments", [])
        if any(not isinstance(r, dict) or ("narrative_review" in r
               and not isinstance(r["narrative_review"], dict)) for r in records):
            return None
        return sorted((str(r.get("kind", "")), str(r.get("result", "")), r.get("whole_finding") is True,
                       str(r.get("narrative_review", {}).get("premise", ""))) for r in records)

    return disposition(a) is not None and disposition(a) == disposition(b)

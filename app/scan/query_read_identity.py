"""Group one source SELECT/pagination hypothesis without equating its outcomes.

Titles select a narrow read-volume scope. The archive AST, not a title or a
model-supplied target, identifies the fluent SELECT. Original conditions,
retention assumptions, fixes and consequences are preserved independently.
This is not a proof of missing runtime limits or expensive database work.
"""
from __future__ import annotations

from hashlib import sha256
import re

MECHANISM = "query_read_volume"
CLAIM_SCOPE = "select_pagination_bound"
_TITLE = re.compile(
    r"(?:GET /[\w/{}-]+|[a-z][\w-]* GET endpoint|[a-z][\w-]* query) "
    r"fetches all (?P<table>[a-z][a-z0-9_]*)"
    r"(?: for (?:a|each) (?:match|conversation|user))? with no (?:pagination )?limit", re.I)
_OTHER = re.compile(
    r"\b(?:auth(?:entication|orization)?|unauthenticated|ownership|owner|RLS|race|concurren\w*|"
    r"atomic|idempot\w*|duplicate|LLM|Claude|Anthropic|prompt|tokens?|reasoning|injection|"
    r"secrets?|credentials?|passwords?|encrypt\w*|SSRF|XSS|leak\w*|breach|delete[sd]?|"
    r"corrupt\w*)\b|rate[ -]limit|\b(?:already|does|has|uses) (?:a )?(?:row )?limit\b|"
    r"\b(?:not|never) (?:unbounded|unlimited)\b", re.I)


def _text(value, limit=16000):
    if value is None:
        return ""
    if not isinstance(value, str) or len(value) > limit:
        return None
    return " ".join(value.replace("`", "").split()).removesuffix(".")


def query_read_title(title):
    text = _text(title, 2000)
    return _TITLE.fullmatch(text) if text is not None else None


def query_read_related_title(title):
    """Rejection routing only; an unsupported suffix cannot invoke legacy grouping."""
    text = _text(title[:2000], 2000) if isinstance(title, str) else None
    return text is not None and re.match(
        r"(?:GET /[\w/{}-]+|[a-z][\w-]* GET endpoint|[a-z][\w-]* query) fetches all\b", text, re.I) is not None


def query_read_claim(finding):
    """Select only the common pagination observation, never its claimed damage."""
    match = query_read_title(finding.get("title"))
    if match is None:
        return None
    table = match["table"]
    # Read-load/retention explanations can differ, but cannot hide another
    # recognized security, concurrency or prompt-size hypothesis in the group.
    for key in ("observation", "explanation", "fix_hint"):
        text = _text(finding.get(key))
        if text is None or _OTHER.search(text):
            return None
    conditions = finding.get("required_conditions")
    if conditions is None:
        conditions = []
    if not isinstance(conditions, list) or len(conditions) > 16:
        return None
    if any(not isinstance(item, str) or not item.strip() or _text(item, 2000) is None
           or _OTHER.search(_text(item, 2000)) for item in conditions):
        return None
    premises = finding.get("premises")
    if premises is None:
        premises = []
    if not isinstance(premises, list) or len(premises) > 1:
        return None
    start, end = finding.get("line_start"), finding.get("line_end")
    if premises and (type(start) is not int or type(end) is not int or not 1 <= start <= end):
        return None
    for premise in premises:
        if (not isinstance(premise, dict) or premise.get("kind") != "query_limit_unbounded"
                or premise.get("target") != table
                or type(premise.get("line_start")) is not int
                or type(premise.get("line_end")) is not int
                or not start <= premise["line_start"] <= premise["line_end"] <= end):
            return None
    return {"claim_scope": CLAIM_SCOPE, "table_sha256": sha256(table.encode()).hexdigest()}


def query_read_candidates(nodes, claim):
    """Only a literal, full-row read chain; counts, writes and helpers abstain."""
    # Report consumers validate saved identities without native parsers,
    # including the browser runtime. Load AST helpers only when resolving.
    from app.scan import guard_context as g

    result = []
    for node in nodes:
        if node.type != "call_expression":
            continue
        parent = node.parent
        if (parent and parent.type == "member_expression"
                and parent.child_by_field_name("object") == node):
            continue  # Select the outermost fluent call once.
        current, names, table = node, [], None
        while current is not None and current.type == "call_expression":
            function = current.child_by_field_name("function")
            if function is None or function.type != "member_expression":
                break
            name = g._text(function.child_by_field_name("property"))
            args = g._children(current.child_by_field_name("arguments"))
            names.append(name)
            if name == "select" and (len(args) != 1 or g._literal(args[0]) != "*"):
                break  # count/head options describe a different operation.
            if name == "from":
                if len(args) == 1:
                    table = g._literal(args[0])
                break
            if name not in {"select", "eq", "neq", "gt", "gte", "lt", "lte", "order"}:
                break  # Limits, RPC, aliases and unknown transforms stay unresolved.
            current = function.child_by_field_name("object")
        if (isinstance(table, str) and names.count("select") == 1
                and names[-1] == "from" and sha256(table.encode()).hexdigest() == claim["table_sha256"]):
            result.append(node)
    return result


def valid_query_read_identity(identity, path):
    if not isinstance(identity, dict) or set(identity) != {
            "version", "method", "mechanism", "claim_scope", "table_sha256", "file", "source_sha256",
            "function_span", "operation_span", "operation_line_start", "operation_line_end"}:
        return False
    if (type(identity["version"]) is not int or identity["version"] != 1
            or identity["method"] != "source_ast" or identity["mechanism"] != MECHANISM
            or identity["claim_scope"] != CLAIM_SCOPE or identity["file"] != path
            or not isinstance(path, str) or not 0 < len(path) <= 512 or "\\" in path
            or any(part in {"", ".", ".."} for part in path.split("/"))):
        return False
    for key in ("table_sha256", "source_sha256"):
        if not isinstance(identity[key], str) or not re.fullmatch(r"[0-9a-f]{64}", identity[key]):
            return False
    for key in ("function_span", "operation_span"):
        span = identity[key]
        if (not isinstance(span, list) or len(span) != 2 or any(type(n) is not int for n in span)
                or not 0 <= span[0] < span[1] <= 256000):
            return False
    function, operation = identity["function_span"], identity["operation_span"]
    start, end = identity["operation_line_start"], identity["operation_line_end"]
    return (function[0] <= operation[0] < operation[1] <= function[1]
            and type(start) is int and type(end) is int and 1 <= start <= end <= 256000)


def compatible_query_read_claims(left, right, identity):
    """Compare only the supported source scope; retain separate interpretation."""
    if not valid_query_read_identity(identity, left.file):
        return False
    for key in ("source", "verification_method", "verification_status", "category", "origin_category", "context"):
        if getattr(left, key) != getattr(right, key):
            return False
    if left.source != "llm" or left.verification_method != "model_review":
        return False
    for finding in (left, right):
        record = finding.claim_evidence or {}
        check, producer = record.get("source_check"), record.get("producer")
        if not isinstance(check, dict) or not isinstance(producer, dict):
            return False
        start, end = check.get("line_start"), check.get("line_end")
        if (check.get("kind") != "quote_match" or check.get("result") not in (None, "observed")
                or type(start) is not int or type(end) is not int or type(finding.line) is not int
                or not 1 <= start <= finding.line <= end
                or not start <= identity["operation_line_end"] or not identity["operation_line_start"] <= end
                or check.get("file", finding.file) != identity["file"]
                or check.get("source_sha256", identity["source_sha256"]) != identity["source_sha256"]
                or any(not isinstance(producer.get(key), str) or not producer[key].strip()
                       for key in ("model", "rubric"))
                or type(producer.get("response")) is not int or producer["response"] < 1):
            return False
        claim = query_read_claim({"title": finding.title, "explanation": finding.explanation,
                                  "fix_hint": finding.fix_hint, "observation": record.get("observation"),
                                  "required_conditions": record.get("required_conditions")})
        if claim is None or any(identity.get(key) != value for key, value in claim.items()):
            return False
        premises = record.get("premise_checks")
        if premises is None:
            premises = []
        if not isinstance(premises, list) or any(
                not isinstance(p, dict) or p.get("kind") != "query_limit_unbounded"
                or not isinstance(p.get("target"), str)
                or sha256(p["target"].encode()).hexdigest() != identity["table_sha256"] for p in premises):
            return False
    # Cross-rubric dedup additionally compares all scanner dispositions. The
    # hypotheses may describe different read-volume conditions; grouping must
    # never promote those conditions or consequences to verified facts.
    return all((finding.claim_evidence or {}).get(key) == "not_checked"
               for finding in (left, right) for key in ("conditions_status", "consequence_status"))

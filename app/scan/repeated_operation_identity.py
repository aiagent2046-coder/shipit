"""Narrow repeated operation hypotheses, with all interpretations retained.

A supported title and observation select a claim scope. Only the archive AST
selects the operation. This is grouping, not proof of runtime harm or missing
protection. Unknown or compound observations remain separate.
"""
from __future__ import annotations

import re

HOST = "forwarded_host_authenticated_request"
TIMER = "scheduled_retry_cleanup"
MECHANISMS = frozenset({HOST, TIMER})
SCOPES = {HOST: "header_derived_authorized_fetch", TIMER: "discarded_self_retry_timer"}


def _text(value, limit=16000):
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        return None
    return " ".join(value.replace("`", "").split()).rstrip(".")


def repeated_operation_claim(finding):
    title = _text(finding.get("title"), 2000)
    observation = _text(finding.get("observation"))
    premises = finding.get("premises", [])
    if (title is None or observation is None
            or premises is not None and (not isinstance(premises, list) or premises)):
        return None
    if re.fullmatch(r"Forwarded host controls an authenticated server(?:-side)? request", title, re.I):
        # Both statements assert exactly one header-derived, authorized fetch.
        if not re.fullmatch(
            r"The route (?:derives|builds) (?P<name>[A-Za-z_$][\w$]*) from x-forwarded-host "
            r"and uses it (?:as the destination for|for) a server-side fetch that includes "
            r"(?:the caller’s|the request’s|the caller's|the request's) bearer token", observation, re.I):
            return None
        kind = HOST
    elif re.fullmatch(r"(?:A )?scheduled retry is not cancel(?:l)?ed when leaving (?:onboarding|the page)",
                      title, re.I):
        if not re.fullmatch(
            r"(?:The rate-limit branch schedules a retry with setTimeout and returns without retaining "
            r"a timer handle for cleanup|The retry is scheduled with setTimeout; this callback does not "
            r"retain or cancel the timer on page exit)", observation, re.I):
            return None
        kind = TIMER
    else:
        return None
    # Other interpretations remain in originals, but an additional mechanism
    # must not disappear inside the common operation's displayed hypothesis.
    forbidden = (r"\b(?:SQL|XSS|RLS|injection|race|idempotency|deadlock|password|"
                 r"payment|billing|double.charge|corrupt\w*|delete[sd]?)\b|"
                 r"(?:missing|without|no) (?:authentication|authorization)")
    fields = [finding.get(key, "") for key in ("explanation", "fix_hint")]
    conditions = finding.get("required_conditions", [])
    if not isinstance(conditions, list) or len(conditions) > 16:
        return None
    fields += conditions
    if any(_text(value) is None or re.search(forbidden, _text(value), re.I) for value in fields):
        return None
    return {"mechanism": kind, "claim_scope": SCOPES[kind]}


def retry_timer_candidates(scope, own):
    from app.scan import guard_context as g
    name = g._name(scope.child_by_field_name("name"))
    if not name and scope.parent and scope.parent.type == "variable_declarator":
        name = g._name(scope.parent.child_by_field_name("name"))
    if not name:
        return []
    result = []
    for node in own:
        if (node.type != "call_expression" or g._name(node.child_by_field_name("function")) != "setTimeout"
                or node.parent.type != "expression_statement"):
            continue
        args = g._children(node.child_by_field_name("arguments"))
        if len(args) != 2 or args[0].type != "arrow_function":
            continue
        callback = args[0]
        params = callback.child_by_field_name("parameters")
        body = callback.child_by_field_name("body")
        if (params is None or params.named_child_count or body is None or body.type != "call_expression"
                or g._name(body.child_by_field_name("function")) != name):
            continue
        # Shadowed timer/handler names cannot establish a known retry operation.
        if any(n.type == "identifier" and g._text(n) in {"setTimeout", name}
               and n.parent.type in {"required_parameter", "optional_parameter", "variable_declarator"}
               and n != scope.parent.child_by_field_name("name") for n in g._walk(scope)):
            continue
        result.append(node)
    return result


def authorized_fetch(node):
    from app.scan import guard_context as g
    args = g._children(node.child_by_field_name("arguments"))
    if len(args) != 2 or args[1].type != "object":
        return False
    headers = [p.child_by_field_name("value") for p in args[1].named_children
               if p.type == "pair" and g._text(p.child_by_field_name("key")) == "headers"]
    if len(headers) != 1 or headers[0].type != "object":
        return False
    auth = [p.child_by_field_name("value") for p in headers[0].named_children
            if p.type == "pair" and g._text(p.child_by_field_name("key")) == "Authorization"]
    return (len(auth) == 1 and auth[0].type == "template_string"
            and re.fullmatch(r"`Bearer \$\{[A-Za-z_$][\w$]*\}`", g._text(auth[0])) is not None)


def host_target_matches(finding, operation, scope):
    """Require the observation's local URL binding, with no opaque guard use."""
    from app.scan import guard_context as g
    text = _text(finding.get("observation")) or ""
    match = re.match(r"The route (?:derives|builds) ([A-Za-z_$][\w$]*) from ", text, re.I)
    args = g._children(operation.child_by_field_name("arguments"))
    if not match or not args or args[0].type != "template_string":
        return False
    name = match[1]
    uses = [n for n in g._walk(args[0]) if n.type == "identifier"]
    if len(uses) != 1 or g._name(uses[0]) != name:
        return False
    # A guarded or transformed host is outside this single direct-flow scope.
    # Absence of these forms is not a claim that deployment protection is absent.
    for node in g._walk(scope):
        if node.type == "if_statement":
            condition = node.child_by_field_name("condition")
            if condition and any(g._name(n) == name for n in g._walk(condition)):
                return False
    return True


def valid_repeated_identity(identity, path):
    keys = {"version", "method", "mechanism", "claim_scope", "file", "source_sha256",
            "function_span", "operation_span", "operation_line_start", "operation_line_end"}
    if not isinstance(identity, dict) or set(identity) != keys:
        return False
    if (type(identity["version"]) is not int or identity["version"] != 1
            or identity["method"] != "source_ast" or not isinstance(identity["mechanism"], str)
            or identity["mechanism"] not in MECHANISMS
            or identity["claim_scope"] != SCOPES[identity["mechanism"]] or identity["file"] != path
            or not isinstance(path, str) or len(path) > 512 or "\\" in path
            or any(p in {"", ".", ".."} for p in path.split("/"))
            or not isinstance(identity["source_sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", identity["source_sha256"])):
        return False
    for key in ("function_span", "operation_span"):
        value = identity[key]
        if (not isinstance(value, list) or len(value) != 2 or any(type(n) is not int for n in value)
                or not 0 <= value[0] < value[1] <= 256000):
            return False
    a, b = identity["function_span"], identity["operation_span"]
    start, end = identity["operation_line_start"], identity["operation_line_end"]
    return a[0] <= b[0] < b[1] <= a[1] and type(start) is int and type(end) is int and 1 <= start <= end


def compatible_repeated_claims(left, right, identity):
    if not valid_repeated_identity(identity, left.file):
        return False
    if any(getattr(left, key) != getattr(right, key) for key in (
            "source", "verification_method", "verification_status", "category", "origin_category", "context")):
        return False
    if left.source != "llm" or left.verification_method != "model_review":
        return False
    for finding in (left, right):
        record = finding.claim_evidence or {}
        if not isinstance(record, dict):
            return False
        check = record.get("source_check") or {}
        if not isinstance(check, dict):
            return False
        start, end = check.get("line_start"), check.get("line_end")
        if (check.get("kind") != "quote_match" or check.get("result") not in (None, "observed")
                or type(start) is not int or type(end) is not int or type(finding.line) is not int
                or not 1 <= start <= finding.line <= end
                or not start <= identity["operation_line_end"] or not identity["operation_line_start"] <= end
                or check.get("source_sha256", identity["source_sha256"]) != identity["source_sha256"]
                or check.get("file", finding.file) != identity["file"] or record.get("premise_checks")):
            return False
        claim = repeated_operation_claim({"title": finding.title, "observation": record.get("observation"),
                    "explanation": finding.explanation, "fix_hint": finding.fix_hint,
                    "required_conditions": record.get("required_conditions", [])})
        if claim != {"mechanism": identity["mechanism"], "claim_scope": identity["claim_scope"]}:
            return False
    return True

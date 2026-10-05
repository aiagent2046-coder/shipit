"""Source-bound grouping of projected database reads, not prompt-size claims.

A downstream sanitizer can cap material consumed by a model without bounding
an earlier database read. This identity names only that read's literal fluent
syntax; runtime database caps, reachability and harmful outcomes stay unchecked.
"""
from hashlib import sha256
import re
import zipfile

MECHANISM = "projected_query_read_volume"
CLAIM_SCOPE = "projected_select_read_bound"
_TITLE = re.compile(r"(?:Agent chats read all matching saved facts|Could growing history reads be capped\?)", re.I)
_RELATED = re.compile(r"(?:Agent chats read all matching saved facts|Could growing history reads be capped)", re.I)
_OTHER = re.compile(
    r"\b(?:auth(?:entication|orization)?|unauthenticated|ownership|RLS|race|concurren\w*|"
    r"atomic|idempot\w*|injection|secrets?|credentials?|passwords?|SSRF|XSS|leak\w*|"
    r"breach|delete[sd]?|corrupt\w*|LLM|Claude|Anthropic|tokens?|reasoning)\b|rate[ -]limit|"
    r"\bprompt\b|\bsanitiz\w*\b", re.I)
_OBSERVATION = re.compile(
    r"(?:The route selects saved-fact content for the current user and orders the results "
    r"without specifying a limit|The (?P<table>[a-z][a-z0-9_]*) query selects content, "
    r"filters by user, and orders the results; no limit or pagination is specified in this query)", re.I)


def _text(value, limit=16000):
    if not isinstance(value, str) or len(value) > limit:
        return None
    return " ".join(value.replace("`", "").split()).removesuffix(".")


def projected_read_related_title(title):
    text = _text(title, 2000)
    return text is not None and _RELATED.match(text) is not None


def projected_read_claim(finding):
    """Accept only read-volume language; a quote alone does not select a claim."""
    title, observation = _text(finding.get("title"), 2000), _text(finding.get("observation"))
    if title is None or not _TITLE.fullmatch(title) or observation is None:
        return None
    match = _OBSERVATION.fullmatch(observation)
    if match is None:
        return None
    explanation, fix = _text(finding.get("explanation")), _text(finding.get("fix_hint"))
    # A recommendation to retain facts for a prompt is not a claim that the
    # whole prompt is unbounded. No other prompt/sanitizer language is admitted.
    if (explanation is None or fix is None or _OTHER.search(explanation)
            or _OTHER.search(fix.replace("retain only facts needed for the prompt", "retain facts"))):
        return None
    conditions = finding.get("required_conditions")
    if not isinstance(conditions, list) or not 1 <= len(conditions) <= 16:
        return None
    if any(_text(c, 2000) is None or not _text(c, 2000) or _OTHER.search(_text(c, 2000)) for c in conditions):
        return None
    return {"table": match["table"].lower() if match["table"] else None}


def _operation_binding(operation, scope_nodes):
    from app.scan import guard_context as g

    awaited = operation.parent
    declaration = awaited.parent if awaited and awaited.type == "await_expression" else None
    if (declaration is None or declaration.type != "variable_declarator"
            or declaration.child_by_field_name("value") != awaited):
        return None
    statement, pattern = declaration.parent, declaration.child_by_field_name("name")
    if (statement is None or statement.type != "lexical_declaration"
            or not any(c.type == "const" for c in statement.children)
            or pattern is None or pattern.type != "object_pattern"):
        return None
    # Bind only a single direct `data: local` property. Rest/default/computed
    # patterns are intentionally unsupported; other result keys are irrelevant.
    properties = g._children(pattern)
    if len(properties) != 1 or properties[0].type != "pair_pattern":
        return None
    prop = properties[0]
    key, value = prop.child_by_field_name("key"), prop.child_by_field_name("value")
    name = g._name(value)
    if g._text(key) != "data" or not name or "\\" in name:
        return None
    if (g._bindings(scope_nodes)[name] != 1
            or any("identifier" in n.type and "\\" in g._text(n) for n in scope_nodes)
            or any(n.type == "with_statement" or n.type == "call_expression"
                   and g._name(n.child_by_field_name("function")) == "eval" for n in scope_nodes)):
        return None
    return name, [value.start_byte, value.end_byte]


def _candidate(node):
    from app.scan import guard_context as g

    if node.type != "call_expression" or node.parent is None or node.parent.type != "await_expression":
        return None
    if any(n.type == "optional_chain" or any(c.type == "?." for c in n.children) for n in g._walk(node)):
        return None
    current, names, table, columns = node, [], None, None
    while current is not None and current.type == "call_expression":
        fn = current.child_by_field_name("function")
        if fn is None or fn.type != "member_expression":
            return None
        name = g._text(fn.child_by_field_name("property"))
        args = g._children(current.child_by_field_name("arguments"))
        names.append(name)
        if name == "from":
            table = g._literal(args[0]) if len(args) == 1 else None
            break
        if name == "select":
            columns = g._literal(args[0]) if len(args) == 1 else None
            if not isinstance(columns, str) or not re.fullmatch(r"[a-z][a-z0-9_]*(?:,\s*[a-z][a-z0-9_]*)*", columns):
                return None
        elif (name not in {"eq", "neq", "gt", "gte", "lt", "lte", "order"}
              or len(args) != 2 or not isinstance(g._literal(args[0]), str)):
            return None
        current = fn.child_by_field_name("object")
    if not isinstance(table, str) or names.count("select") != 1 or names[-1] != "from" or columns != "content":
        return None
    return table, columns


def projected_read_identity(finding, resolver):
    """Use the existing resolver's bounded document cache and work counters."""
    try:
        return _resolve(finding, resolver)
    except (UnicodeError, ValueError, TypeError, RecursionError, RuntimeError, ImportError,
            OSError, zipfile.BadZipFile):
        return None


def _resolve(finding, resolver):
    from app.scan import guard_context as g
    from app.scan.issue_identity import MAX_CHECKS, _lines, _owning_scope, _span

    claim = projected_read_claim(finding)
    start, end, path = finding.get("line_start"), finding.get("line_end"), finding.get("file")
    if (claim is None or not isinstance(path, str) or not 0 < len(path) <= 512 or "\\" in path
            or any(part in {"", ".", ".."} for part in path.split("/"))
            or not path.endswith((".ts", ".tsx", ".js", ".jsx"))
            or type(start) is not int or type(end) is not int or not 1 <= start <= end
            or resolver.checks >= MAX_CHECKS):
        return None
    resolver.checks += 1
    document = resolver._document(path)
    if document is None:
        return None
    root, nodes, digest = document
    scope = _owning_scope(root, nodes, start)
    if scope == root or end > _lines(scope)[1]:
        return None
    scope_nodes = list(g._walk(scope))
    if len(scope_nodes) > resolver.remaining_nodes:
        return None
    resolver.remaining_nodes -= len(scope_nodes)
    own = list(g._walk(scope, skip=g._FUNCTIONS))
    candidates = [(n, _candidate(n)) for n in own if _lines(n)[0] <= end and start <= _lines(n)[1]]
    candidates = [(n, c) for n, c in candidates if c is not None]
    if len(candidates) != 1:
        return None
    operation, (table, _) = candidates[0]
    binding = _operation_binding(operation, scope_nodes)
    if binding is None or claim["table"] not in (None, table):
        return None
    name, span = binding
    premises = finding.get("premises")
    if not isinstance(premises, list) or len(premises) != 1:
        return None
    identity = {"version": 1, "method": "source_ast", "mechanism": MECHANISM, "claim_scope": CLAIM_SCOPE,
                "file": path, "source_sha256": digest, "function_span": _span(scope),
                "operation_span": _span(operation), "operation_line_start": _lines(operation)[0],
                "operation_line_end": _lines(operation)[1], "relation_sha256": sha256(table.encode()).hexdigest(),
                "binding": {"name_sha256": sha256(name.encode()).hexdigest(), "span": span}}
    if valid_projected_read_identity(identity, path) and _premise(premises[0], identity, start, end):
        return identity
    return None


def valid_projected_read_identity(identity, path):
    # Re-use byte/span/path validation without accepting a legacy read identity.
    from app.scan.query_read_identity import valid_query_read_identity

    if (not isinstance(identity, dict) or type(identity.get("version")) is not int or identity["version"] != 1
            or identity.get("mechanism") != MECHANISM or identity.get("claim_scope") != CLAIM_SCOPE
            or "relation_sha256" not in identity):
        return False
    legacy = {**identity, "version": 2, "mechanism": "query_read_volume", "claim_scope": "select_pagination_bound",
              "table_sha256": identity["relation_sha256"]}
    del legacy["relation_sha256"]
    return valid_query_read_identity(legacy, path)


def _premise(premise, identity, start, end):
    if (not isinstance(premise, dict) or premise.get("kind") != "query_limit_unbounded"
            or not isinstance(premise.get("target"), str)
            or sha256(premise["target"].encode()).hexdigest() != identity["binding"]["name_sha256"]):
        return False
    for first, last in (("line_start", "line_end"), ("anchor_line_start", "anchor_line_end")):
        if first.startswith("anchor") and first not in premise and last not in premise:
            continue
        a, b = premise.get(first), premise.get(last)
        if (type(a) is not int or type(b) is not int or not start <= a <= b <= end
                or a > identity["operation_line_end"] or identity["operation_line_start"] > b):
            return False
    return True


def compatible_projected_read_claims(left, right, identity):
    if not valid_projected_read_identity(identity, left.file):
        return False
    for key in ("source", "verification_method", "verification_status", "category", "origin_category", "context"):
        if getattr(left, key) != getattr(right, key):
            return False
    if left.source != "llm" or left.verification_method != "model_review":
        return False
    for item in (left, right):
        evidence = item.claim_evidence or {}
        check, producer = evidence.get("source_check"), evidence.get("producer")
        if not isinstance(check, dict) or not isinstance(producer, dict):
            return False
        start, end = check.get("line_start"), check.get("line_end")
        if (check.get("kind") != "quote_match" or check.get("result") not in (None, "observed")
                or type(start) is not int or type(end) is not int or type(item.line) is not int
                or not 1 <= start <= item.line <= end
                or check.get("file", item.file) != identity["file"]
                or check.get("source_sha256", identity["source_sha256"]) != identity["source_sha256"]
                or any(not isinstance(producer.get(k), str) or not producer[k].strip() for k in ("model", "rubric"))
                or type(producer.get("response")) is not int or producer["response"] < 1):
            return False
        claim = projected_read_claim({"title": item.title, "explanation": item.explanation, "fix_hint": item.fix_hint,
                                      "observation": evidence.get("observation"),
                                      "required_conditions": evidence.get("required_conditions")})
        if (claim is None or claim["table"] is not None
                and sha256(claim["table"].encode()).hexdigest() != identity["relation_sha256"]):
            return False
        premises = evidence.get("premise_checks")
        if (not isinstance(premises, list) or len(premises) != 1 or not _premise(premises[0], identity, start, end)
                or premises[0].get("result") != "not_checked"
                or any(evidence.get(k) != "not_checked" for k in ("conditions_status", "consequence_status"))):
            return False
    return True

"""Check bounded source premises separately from a finding's narrative.

Model fields select a supported check and coordinates, never its result. Only
literal, single-premise titles can deactivate a whole finding. A counterexample
to one premise of a compound finding remains visible alongside that finding.
"""
import re
from collections import Counter

from tree_sitter import Language, Parser
import tree_sitter_typescript

from app.scan import guard_context as g

MAX_PREMISES = 6
KINDS = {
    "http_status_guard_absent": "The response has no local HTTP status guard before its JSON body is parsed.",
    "json_rejection_uncaught": "The JSON parsing promise has no local rejection fallback or safe enclosing catch.",
    "intl_catch_absent": "The Intl.DateTimeFormat constructor has no enclosing catch.",
    "required_nested_objects_absent": "The parsed Zod schema does not require its nested objects.",
    "query_limit_unbounded": "The query receives the raw limit without a finite bounded clamp.",
    "sql_update_where": "The cited PostgreSQL UPDATE has no WHERE clause of its own.",
    "ownership_guard_absent": "The cited write has no local ownership guard for its target.",
}
# These complete titles state one premise. Broad risk/validation titles only
# request a partial check below; their other interpretations are not dismissed.
_ATOMIC = {
    "http_status_guard_absent": r"(?:Missing HTTP status (?:check|validation)(?: before parsing (?:the )?"
                                r"(?:API |OAuth token )?response| in [\w ()'-]{1,160})?|"
                                r"[\w ()'-]{1,120} (?:does not|fails to) (?:check|validate) HTTP status"
                                r" before (?:JSON parsing|parsing (?:the )?(?:JSON|response)))",
    "json_rejection_uncaught": r"(?:The )?(?:response )?JSON parsing promise has no (?:catch|rejection fallback)",
    "intl_catch_absent": r"Time zone validation relies on Intl API without error handling",
    "required_nested_objects_absent": r"Zod schema validation does not enforce required nested object structure",
    "query_limit_unbounded": r"The query receives an unclamped limit",
}
_PARTIAL = {
    "http_status_guard_absent": r"(?:Incomplete error handling for .{0,120}API response|"
                                r"\b(?:missing|absent|unvalidated|unchecked|no)\b.{0,100}\bHTTP (?:status|response)|"
                                r"\b(?:does not|fails to|not) (?:check(?:ed)?|validat(?:e|ed))\b"
                                r".{0,100}\bHTTP (?:status|errors)|"
                                r"\bHTTP (?:status|response)\b.{0,100}\b"
                                r"(?:unchecked|unvalidated|not checked|not validated))",
    "json_rejection_uncaught": r"(?:JSON|parsing).{0,160}(?:throw|reject|uncaught|crash|try.catch)|"
                              r"(?:uncaught|unhandled)\b.{0,80}\bJSON",
    "intl_catch_absent": r"(?:time.?zone|Intl).*(?:without error handling|no catch|uncaught)",
    "required_nested_objects_absent": r"Zod.*required nested object",
    "query_limit_unbounded": r"(?:Integer overflow risk in limit parameter parsing|negative.*limit|limit.*negative)",
    "sql_update_where": r"\bupdate\b.{0,200}\b(?:without|missing|no)\b.{0,80}\b(?:where|guard|row filter)\b",
    "ownership_guard_absent": r"\b(?:insert|write|update|delete)\b.{0,120}\b(?:does not|without|missing|no)\b"
                              r".{0,100}\b(?:ownership|membership|participant)\b|"
                              r"\b(?:missing|absent|no)\b.{0,80}\b(?:ownership|membership) "
                              r"(?:check|guard|validation)\b",
}


def title_kind(title):
    if re.search(r"\b(?:and|or|also|separately|additionally)\b|[;\n]", title, re.I):
        return None
    return next((kind for kind, pattern in _ATOMIC.items()
                 if re.fullmatch(pattern + r"[.]?", title, re.I)), None)


def requests(finding):
    """Normalize only selector fields; never copy model-supplied evidence/status."""
    title = str(finding.get("title", ""))[:2000]
    atomic = title_kind(title)
    found = []
    raw = finding.get("premises")
    for item in raw[:MAX_PREMISES] if isinstance(raw, list) else []:
        if not isinstance(item, dict) or not isinstance(item.get("kind"), str) or item["kind"] not in KINDS:
            continue
        target = item.get("target", "")
        start, end = item.get("line_start"), item.get("line_end")
        if (not isinstance(target, str) or not re.fullmatch(r"[A-Za-z_$][\w$]{0,127}|", target)
                or type(start) is not int or type(end) is not int or not 1 <= start <= end):
            continue
        found.append({"kind": item["kind"], "target": target, "line_start": start, "line_end": end})
    # Legacy answers still get a check. No inferred targets from quoted prose.
    narrative = title + "\n" + str(finding.get("explanation", ""))[:8000]
    kinds = [kind for kind, pattern in _PARTIAL.items() if re.search(pattern, narrative, re.I)]
    if atomic and atomic not in kinds:
        kinds.insert(0, atomic)
    for kind in kinds:
        if len(found) >= MAX_PREMISES or any(item["kind"] == kind for item in found):
            continue
        found.append({"kind": kind, "target": "", "line_start": finding.get("line_start"),
                      "line_end": finding.get("line_end")})
    return found


def unknown(request, detail="No unambiguous source counterexample found within this check's scope."):
    return {**request, "claim": KINDS[request["kind"]], "result": "not_checked", "detail": detail}


def _member_name(node, property_name):
    member = g._member(node, property_name)
    return g._name(member.child_by_field_name("object")) if member else ""


def _direct_statement(node, block):
    while node and node.parent != block:
        if node.type in g._FUNCTIONS:
            return None
        node = node.parent
    return node


def _returns_on_not_ok(stmt, name):
    if stmt.type != "if_statement" or stmt.child_by_field_name("alternative"):
        return False
    condition = g._unwrap(stmt.child_by_field_name("condition"))
    if (not condition or condition.type != "unary_expression"
            or g._text(condition.child_by_field_name("operator")) != "!"
            or _member_name(condition.child_by_field_name("argument"), "ok") != name):
        return False
    body = stmt.child_by_field_name("consequence")
    parts = g._children(body) if body.type == "statement_block" else [body]
    # Prefix expressions may reject/throw, but cannot continue to the later
    # parse. Nested control flow and catches/finally are deliberately unknown.
    return bool(parts and parts[-1].type == "return_statement" and all(
        n.type in {"expression_statement", "lexical_declaration"} for n in parts[:-1]))


def _inside(node, ancestor):
    return ancestor is not None and ancestor.start_byte <= node.start_byte and node.end_byte <= ancestor.end_byte


def _positive_ok_branch(node, block, name):
    """The JSON call must execute inside this response's positive branch."""
    parent = node.parent
    while parent and parent != block:
        if parent.type in g._FUNCTIONS:
            return False
        if (parent.type == "if_statement"
                and _member_name(g._unwrap(parent.child_by_field_name("condition")), "ok") == name
                and _inside(node, parent.child_by_field_name("consequence"))):
            return True
        parent = parent.parent
    return False


def _literal_value(value):
    return value is not None and all(n.type in {
        "object", "pair", "property_identifier", "string", "string_fragment", "number", "null", "true", "false"
    } for n in g._walk(g._unwrap(value)))


def _safe_enclosing_catch(node):
    # Only an awaited promise is caught by the surrounding synchronous try.
    awaited = node.parent
    while awaited and awaited.type == "parenthesized_expression":
        awaited = awaited.parent
    if not awaited or awaited.type != "await_expression":
        return False
    parent = awaited.parent
    while parent and parent.type not in g._FUNCTIONS:
        if parent.type == "try_statement" and _inside(node, parent.child_by_field_name("body")):
            catch = parent.child_by_field_name("handler")
            if not catch or parent.child_by_field_name("finalizer"):
                return False
            parameter = catch.child_by_field_name("parameter")
            if parameter and parameter.type != "identifier":
                return False  # destructuring/defaults may throw before the handler
            statements = g._children(catch.child_by_field_name("body"))
            if not statements:
                return True
            if len(statements) == 1 and statements[0].type == "return_statement":
                values = g._children(statements[0])
                return not values or (len(values) == 1 and _literal_value(values[0]))
            return False  # calls, rethrows and conditional effects are not proved safe
        parent = parent.parent
    return False


def _http(own, bindings, target, kind, start, end):
    candidates = []
    for node in own:
        receiver, args = g._method(node, "json")
        name = g._name(receiver)
        if not name or args or (target and target != name):
            continue
        declarations = [n for n in own if n.type == "variable_declarator"
                        and g._name(n.child_by_field_name("name")) == name]
        dec = declarations[0] if len(declarations) == 1 else None
        selected = any(g._line(n) <= end and n.end_point[0] + 1 >= start for n in (node, dec) if n)
        unresolved = (name, node, False, "The response binding or control flow is unresolved.", selected)
        if bindings[name] != 1:
            candidates.append(unresolved)
            continue
        if kind == "json_rejection_uncaught":
            obj, handlers = g._method(node.parent, "catch")
            # Call's parent is a member expression, then a call expression.
            if node.parent and node.parent.type == "member_expression":
                obj, handlers = g._method(node.parent.parent, "catch")
            handler = handlers[0] if obj == node and len(handlers) == 1 else None
            value = (g._unwrap(handler.child_by_field_name("body"))
                     if handler and handler.type == "arrow_function" else None)
            simple_parameters = (handler is not None and
                                 not g._children(handler.child_by_field_name("parameters")) and
                                 handler.child_by_field_name("parameter") is None)
            harmless = simple_parameters and _literal_value(value)
            enclosing = _safe_enclosing_catch(node)
            detail = ("The awaited JSON promise is inside a try with an empty or literal-return catch. "
                      if enclosing else "The same JSON promise has a local literal fallback. ")
            candidates.append((name, node, bool(harmless or enclosing), detail +
                               "This does not prove response shape, transport handling or UI reset.", selected))
            continue
        # A same-spelling response factory (NextResponse.json) is not the
        # response binding. Require one immutable local awaited initializer.
        if dec is None:
            candidates.append(unresolved)
            continue
        value = g._unwrap(dec.child_by_field_name("value"))
        if not value or value.type != "await_expression" or dec.end_byte >= node.start_byte:
            candidates.append(unresolved)
            continue
        block = dec.parent.parent
        if block.type != "statement_block" or dec not in g._consts(block).values():
            candidates.append(unresolved)
            continue
        use = _direct_statement(node, block)
        guarded = bool(use and (any(dec.end_byte < guard.start_byte < guard.end_byte < use.start_byte
                                    and _returns_on_not_ok(guard, name) for guard in g._children(block))
                                or _positive_ok_branch(node, block, name)))
        candidates.append((name, node, guarded, "The same immutable local response has a !ok return before "
                           "its JSON parse, or the parse is inside its positive .ok branch. Response factories "
                           "are separate calls. Response shape, transport failures and runtime bindings remain "
                           "unverified.", selected))
    # Coordinates may distinguish separate response operations in one function.
    # A selected binding with two parses stays ambiguous even if one parse is safe.
    if not target and len(candidates) > 1:
        selected_names = {name for name, _, _, _, selected in candidates if selected}
        if len(selected_names) == 1:
            candidates = [candidate for candidate in candidates if candidate[0] in selected_names]
    # Never select the safe call while ignoring an unsafe call in the same scope.
    if len(candidates) != 1:
        return None
    name, node, contradicted, detail, _ = candidates[0]
    return (node, detail, name) if contradicted else None


def _nested_schema(root, own, fn, constants, bindings, file_bindings, target):
    globals_ = g._consts(root)
    zod, imported = set(), Counter()
    for stmt in root.named_children:
        if stmt.type == "import_statement":
            for spec in g._walk(stmt):
                if spec.type == "import_specifier":
                    imported[g._name(spec.child_by_field_name("alias") or spec.child_by_field_name("name"))] += 1
                elif spec.type == "identifier" and spec.parent.type in {"import_clause", "namespace_import"}:
                    imported[g._name(spec)] += 1
        if stmt.type == "import_statement" and g._literal(stmt.child_by_field_name("source")) == "zod":
            for spec in g._walk(stmt):
                if (spec.type == "import_specifier" and g._name(spec.child_by_field_name("name")) == "z"
                        and not any(n.type == "type" for n in [*stmt.children, *spec.children])):
                    zod.add(g._name(spec.child_by_field_name("alias") or spec.child_by_field_name("name")))
    zod = {name for name in zod if not file_bindings[name] and imported[name] == 1}
    candidates = []
    for dec in constants.values():
        schema, args = g._method(dec.child_by_field_name("value"), "safeParse")
        name = g._name(schema)
        if not name or (target and target != name) or len(args) != 1:
            continue
        schema_dec = (constants.get(name) if bindings[name] == 1 else
                      globals_.get(name) if not bindings[name] and file_bindings[name] == 1 else None)
        obj, fields = g._method(schema_dec.child_by_field_name("value") if schema_dec else None, "object")
        if g._name(obj) not in zod or len(fields) != 1 or fields[0].type != "object":
            candidates.append(None)
            continue
        nested, unsupported = 0, False
        field_names = set()
        for field in g._children(fields[0]):
            if field.type != "pair":
                unsupported = True
                continue
            key = field.child_by_field_name("key")
            if key.type != "property_identifier" or g._text(key) in field_names:
                unsupported = True
            field_names.add(g._text(key))
            value = field.child_by_field_name("value")
            receiver, child_args = g._method(value, "object")
            if g._name(receiver) in zod and len(child_args) == 1 and child_args[0].type == "object":
                nested += 1
            elif any(g._name(g._method(n, "object")[0]) in zod for n in g._walk(value)):
                unsupported = True  # optional/default/catch/transform or indirect shape
        checks = g._schema(g._children(fn.child_by_field_name("body")), own, constants, bindings,
                           globals_, file_bindings, zod)
        matching = [c for c in checks if c["schema_line"] == g._line(dec)
                    and c["mandatory_object_schema"] and c["data_accesses_after_guard"]]
        candidates.append((dec, "The same parsed Zod object declares its nested objects without optional/default "
                           "wrappers, and !success returns before parsed.data use. This checks the declared "
                           "shape and local order, not deployed Zod behavior or every field constraint.", name)
                          if nested and not unsupported and len(matching) == 1 else None)
    return candidates[0] if len(candidates) == 1 else None


def _limit(own, constants, bindings, free, target):
    candidates = []
    all_sinks = [n for n in own if any(g._method(n, method)[0] is not None for method in ("limit", "rpc"))]
    # An unqualified title cannot select one safe query and ignore another.
    if not target and len(all_sinks) != 1:
        return None
    for name, dec in constants.items():
        clamp = g._clamp(dec, bindings, constants, free)
        if not clamp or (target and target != name):
            continue
        value = g._unwrap(dec.child_by_field_name("value"))
        bounds = g._native(value.child_by_field_name("consequence"), "Math", "min")
        raw = g._name(g._native(value.child_by_field_name("condition"), "Number", "isFinite")[0])
        sinks = []
        for node in own:
            receiver, args = g._method(node, "limit")
            if receiver and len(args) == 1 and g._name(args[0]) == name:
                sinks.append(node)
            receiver, args = g._method(node, "rpc")
            if receiver and len(args) == 2 and args[1].type == "object":
                pairs = [p for p in g._children(args[1]) if p.type == "pair"
                         and g._text(p.child_by_field_name("key")) == "match_count"
                         and g._name(p.child_by_field_name("value")) == name]
                if len(pairs) == 1 and all(p.type == "pair" for p in g._children(args[1])):
                    sinks.append(node)
        raw_elsewhere = any(n.type in {"identifier", "shorthand_property_identifier"} and g._text(n) == raw
                            and n.start_byte > dec.end_byte for n in own)
        safe = (clamp["nonnegative_lower_bound"] and clamp["fallback_within_bounds"]
                and g._number(bounds[0]) <= 2**53 - 1 and len(sinks) == 1
                and dec.end_byte < sinks[0].start_byte and not raw_elsewhere)
        candidates.append((dec, "A finite clamp with a nonnegative lower bound, safe numeric upper bound "
                           "and in-range fallback feeds the recorded limit/RPC argument through the same "
                           "immutable binding. This does not prove RPC semantics or workload safety.", name)
                          if safe else None)
    return candidates[0] if len(candidates) == 1 else None


def check_source(data, path, request):
    if request["kind"] == "ownership_guard_absent":
        from app.scan.ownership_claims import check_source as check_ownership
        return check_ownership(data, path, request)
    result = unknown(request)
    start, end = request.get("line_start"), request.get("line_end")
    if type(start) is not int or type(end) is not int or not 1 <= start <= end <= len(data.splitlines()):
        return result
    if request["kind"] == "sql_update_where":
        if not path.endswith(".sql"):
            return result
        from pglast.parser import ParseError
        from app.scan.syntax_claims import _sql
        try:
            proof = _sql(data.decode("utf-8"), start, end, target=request.get("target", ""))
        except (ParseError, UnicodeError, ValueError):
            return result
        anchor_start, anchor_end = request.get("anchor_line_start", start), request.get("anchor_line_end", end)
        if (type(anchor_start) is not int or type(anchor_end) is not int
                or not proof.get("line_start", 0) <= anchor_start <= anchor_end <= proof.get("line_end", 0)):
            return unknown(request, "The selected UPDATE does not contain the cited finding's range.")
        result.update(result=proof["result"], detail=proof["detail"],
                      source_line_start=proof["line_start"], source_line_end=proof["line_end"])
        return result
    if not path.endswith((".ts", ".tsx", ".js", ".jsx")):
        return result
    parser = Parser(Language(tree_sitter_typescript.language_tsx() if path.endswith((".tsx", ".jsx"))
                             else tree_sitter_typescript.language_typescript()))
    root = parser.parse(data).root_node
    if root.has_error:
        return result
    nodes = []
    for node in g._walk(root):
        nodes.append(node)
        if len(nodes) > g.MAX_NODES:
            return result
    functions = [n for n in nodes if n.type in g._FUNCTIONS
                 and n.child_by_field_name("body") is not None
                 and n.child_by_field_name("body").type == "statement_block"]
    matches = [n for n in functions if g._line(n) <= start <= end <= n.end_point[0] + 1]
    if not matches:
        return result
    fn = min(matches, key=lambda n: n.end_byte - n.start_byte)
    anchor_start, anchor_end = request.get("anchor_line_start", start), request.get("anchor_line_end", end)
    if (type(anchor_start) is not int or type(anchor_end) is not int
            or not g._line(fn) <= anchor_start <= anchor_end <= fn.end_point[0] + 1):
        return unknown(request, "The selected premise is outside the cited finding's function.")
    # Adjacent/nested functions sharing selected lines make the target ambiguous.
    if any(n != fn and not (n.start_byte <= fn.start_byte and n.end_byte >= fn.end_byte)
           and g._line(n) <= end and n.end_point[0] + 1 >= start for n in functions):
        return result
    body = fn.child_by_field_name("body")
    if not body or body.type != "statement_block":
        return result
    fn_nodes = list(g._walk(fn))
    if len(fn_nodes) > g.MAX_FUNCTION_NODES:
        return result
    own = list(g._walk(body, g._SKIP))
    bindings, file_bindings = g._bindings(fn_nodes), g._bindings(nodes)
    constants = g._consts(body)
    imported = {g._text(n) for stmt in root.named_children if stmt.type == "import_statement"
                for n in g._walk(stmt) if n.type == "identifier"}
    free = {name for name in ("Math", "Number", "Intl") if not file_bindings[name] and name not in imported}
    kind, target = request["kind"], request.get("target", "")
    proof = None
    if kind in {"http_status_guard_absent", "json_rejection_uncaught"}:
        proof = _http(own, bindings, target, kind, start, end)
        if proof and (target or (start, end) != (anchor_start, anchor_end)):
            anchored = _http(own, bindings, "", kind, anchor_start, anchor_end)
            if not anchored or anchored[2] != proof[2]:
                return unknown(request, "The selected response is not the unique operation at the cited finding.")
    elif kind == "intl_catch_absent":
        calls = [n for n in own if n.type in {"new_expression", "call_expression"}
                 and g._callee_name(n) in {"DateTimeFormat", "computed_unknown"}]
        if len(calls) == 1 and target in {"", "Intl", "DateTimeFormat"}:
            check = g._intl(calls[0], fn, free)
            if check and check["catch_returns_false"]:
                proof = calls[0], check["summary"], "Intl"
    elif kind == "required_nested_objects_absent":
        proof = _nested_schema(root, own, fn, constants, bindings, file_bindings, target)
    elif kind == "query_limit_unbounded":
        proof = _limit(own, constants, bindings, free, target)
    if proof:
        node, detail, selected = proof
        result.update(result="contradicted", target=selected, detail=detail,
                      source_line_start=g._line(node), source_line_end=node.end_point[0] + 1)
    return result

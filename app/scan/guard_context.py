"""Bounded JS/TS counterevidence for validation claims, without code execution.

Only source syntax and a few immutable local bindings are linked. Observing a
guard does not establish its completeness, runtime enforcement or safety.
"""
from collections import Counter
import math
from pathlib import PurePosixPath
import re
import stat
import zipfile

from tree_sitter import Language, Parser
import tree_sitter_typescript

from app.scan.secrets import is_non_production_path

MAX_FILE_BYTES = 512_000
MAX_TOTAL_BYTES = 4_000_000
MAX_FILES = 200
MAX_NODES = 80_000
MAX_RECORDS = 64
MAX_CHECKS = 8
MAX_FUNCTIONS = 256
MAX_FUNCTION_NODES = 16_000
MAX_WORK_NODES = 160_000
MAX_LOCALS = 128
SCOPE = (
    "Bounded JS/TS syntax observations for state comparisons, domain suffix arguments, finite limit clamps, "
    "Intl try/catch and JSON/schema return guards. Collected before model review, without executing source. "
    "Only same-function source order and unambiguous local/constant spellings are linked; aliases, callbacks "
    "and cross-file execution are not resolved. Guard presence does not prove validation completeness, "
    "runtime bindings, reachability or prevention of a harmful outcome. Source literal values are redacted; "
    "test, documentation and vendor files are excluded. Missing observations do not establish missing guards."
)
_FUNCTIONS = {"function_declaration", "function_expression", "arrow_function", "method_definition",
              "generator_function_declaration", "generator_function"}
_SKIP = _FUNCTIONS | {"class_declaration", "class", "comment"}


def _walk(root, skip=()):
    todo = [root]
    while todo:
        node = todo.pop()
        yield node
        if node == root or node.type not in skip:
            todo.extend(reversed(node.named_children))


def _text(node):
    return node.text.decode("utf-8") if node else ""


def _name(node):
    return _text(node) if node and node.type == "identifier" and len(node.text) <= 128 else ""


def _children(node):
    return [n for n in node.named_children if n.type != "comment"] if node else []


def _line(node):
    # tree-sitter 0.26 Point.row has a borrowed-reference bug; use indexing.
    return node.start_point[0] + 1


def _unwrap(node):
    while node and node.type == "parenthesized_expression" and len(_children(node)) == 1:
        node = _children(node)[0]
    return node


def _bound(pattern):
    if not pattern:
        return []
    if pattern.type in {"identifier", "shorthand_property_identifier_pattern"}:
        return [_text(pattern)]
    if pattern.type in {"required_parameter", "optional_parameter"}:
        return _bound(pattern.child_by_field_name("pattern"))
    if pattern.type in {"assignment_pattern", "object_assignment_pattern"}:
        return _bound(pattern.child_by_field_name("left"))
    if pattern.type == "pair_pattern":
        return _bound(pattern.child_by_field_name("value"))
    if pattern.type in {"array_pattern", "object_pattern", "formal_parameters", "rest_pattern"}:
        return [name for child in _children(pattern) for name in _bound(child)]
    return []


def _bindings(nodes):
    names = []
    for node in nodes:
        if node.type in _FUNCTIONS | {"variable_declarator", "class_declaration"}:
            names.extend(_bound(node.child_by_field_name("name")))
        if node.type in _FUNCTIONS:
            names.extend(_bound(node.child_by_field_name("parameters") or node.child_by_field_name("parameter")))
        if node.type == "catch_clause":
            names.extend(_bound(node.child_by_field_name("parameter")))
        if node.type in {"assignment_expression", "augmented_assignment_expression", "update_expression",
                         "for_in_statement"}:
            target = node.child_by_field_name("left") or node.child_by_field_name("argument")
            while target and target.type in {"member_expression", "subscript_expression"}:
                target = target.child_by_field_name("object")
            names.extend(_bound(target))
    return Counter(names)


def _consts(body):
    found = {}
    for stmt in _children(body):
        if stmt.type == "export_statement":
            stmt = stmt.child_by_field_name("declaration")
        if not stmt or stmt.type != "lexical_declaration" or not any(c.type == "const" for c in stmt.children):
            continue
        for dec in _children(stmt):
            name = _name(dec.child_by_field_name("name"))
            if name:
                found[name] = dec
    return found


def _member(node, name=None):
    node = _unwrap(node)
    if not node or node.type != "member_expression" or node.child_by_field_name("optional_chain"):
        return None
    return node if name is None or _text(node.child_by_field_name("property")) == name else None


def _method(node, name):
    node = _unwrap(node)
    if not node or node.type != "call_expression" or node.child_by_field_name("optional_chain"):
        return None, []
    fn = _member(node.child_by_field_name("function"), name)
    return (fn.child_by_field_name("object"), _children(node.child_by_field_name("arguments"))) if fn else (None, [])


def _native(node, namespace, method):
    obj, args = _method(node, method)
    return args if _name(obj) == namespace else None


def _exit(guard):
    if guard.type != "if_statement" or guard.child_by_field_name("alternative"):
        return False
    consequence = guard.child_by_field_name("consequence")
    parts = _children(consequence) if consequence and consequence.type == "statement_block" else [consequence]
    return len(parts) == 1 and parts[0] is not None and parts[0].type == "return_statement"


def _check(kind, node, summary, **details):
    return {"kind": kind, "result": "observed", "line": _line(node), "line_end": node.end_point[0] + 1,
            "summary": summary, **details}


def _literal(node):
    # Do not interpret escapes/templates as literal values or emit their text.
    if node and node.type == "string" and all(n.type == "string_fragment" for n in node.named_children):
        return _text(node)[1:-1]
    return None


def _number(node):
    node = _unwrap(node)
    if not node:
        return None
    sign = 1
    if node.type == "unary_expression" and _text(node.child_by_field_name("operator")) == "-":
        sign, node = -1, node.child_by_field_name("argument")
    if not node or node.type != "number" or not re.fullmatch(r"\d+(?:\.\d+)?", _text(node)):
        return None
    value = sign * float(_text(node))
    return value if math.isfinite(value) else None


def _suffix(node, constants, bindings, global_consts, file_bindings):
    obj, args = _method(node, "endsWith")
    if obj is None or len(args) != 1:
        return None
    arg = _unwrap(args[0])
    separator, domain = None, None
    literal = _literal(arg)
    if literal is not None:
        separator = literal.startswith("@") and len(literal) > 1
    elif arg.type == "binary_expression" and _text(arg.child_by_field_name("operator")) == "+":
        if _literal(arg.child_by_field_name("left")) == "@":
            separator, domain = True, _name(arg.child_by_field_name("right"))
    elif arg.type == "template_string":
        parts = _children(arg)
        if (len(parts) == 2 and parts[0].type == "string_fragment" and _text(parts[0]) == "@"
                and parts[1].type == "template_substitution" and len(_children(parts[1])) == 1):
            separator, domain = True, _name(_children(parts[1])[0])
    elif _name(arg):
        separator, domain = False, _name(arg)
    resolved = literal is not None
    if domain:
        dec = constants.get(domain) if bindings[domain] == 1 else None
        if dec is None and not bindings[domain] and file_bindings[domain] == 1:
            dec = global_consts.get(domain)
        value = _literal(dec.child_by_field_name("value")) if dec and dec.end_byte < node.start_byte else None
        resolved = value is not None and bool(value)
        if separator is False and resolved:
            separator = value.startswith("@") and len(value) > 1
    shape = "present" if separator is True else "absent" if separator is False else "unresolved"
    return _check("domain_suffix_argument", node,
                  f"endsWith argument at line {_line(node)} has an @ separator shape: {shape}. "
                  + ("The domain operand is an unambiguous literal/constant. " if resolved else
                     "The domain operand is unresolved. ")
                  + "Reconsider claims that omit this separator; receiver type, domain policy, case handling "
                  "and runtime method behavior are not verified.",
                  separator=shape, domain_binding="constant" if resolved else "unresolved")


def _clamp(dec, bindings, constants, globals_free):
    value = _unwrap(dec.child_by_field_name("value"))
    if not value or value.type != "ternary_expression" or not {"Number", "Math"} <= globals_free:
        return None
    condition = _native(value.child_by_field_name("condition"), "Number", "isFinite")
    if not condition or len(condition) != 1 or not _name(condition[0]):
        return None
    raw = _name(condition[0])
    raw_dec = constants.get(raw)
    if bindings[raw] != 1 or not raw_dec or raw_dec.end_byte >= dec.start_byte:
        return None
    outer = _native(value.child_by_field_name("consequence"), "Math", "min")
    if not outer or len(outer) != 2:
        return None
    upper = _number(outer[0])
    inner = _native(outer[1], "Math", "max")
    if upper is None or not inner or len(inner) != 2 or _name(inner[1]) != raw:
        return None
    lower, fallback = _number(inner[0]), _number(value.child_by_field_name("alternative"))
    if lower is None or fallback is None or lower > upper:
        return None
    result = _name(dec.child_by_field_name("name"))
    if not result or bindings[result] != 1:
        return None
    nonnegative, bounded_fallback = lower >= 0, lower <= fallback <= upper
    return _check("finite_limit_clamp", dec,
                  f"At line {_line(dec)}, Number.isFinite selects a nested Math.min/Math.max clamp; "
                  f"its lower bound is {'nonnegative' if nonnegative else 'negative'}, and the literal fallback "
                  f"is {'inside' if bounded_fallback else 'outside'} those bounds. "
                  "Reconsider a missing-negative-limit-check premise. Later use, integer policy, builtin "
                  "runtime mutation and workload limits are not verified.",
                  nonnegative_lower_bound=nonnegative, fallback_within_bounds=bounded_fallback)


def _intl(node, fn, globals_free):
    if node.type != "new_expression" or "Intl" not in globals_free:
        return None
    ctor = _member(node.child_by_field_name("constructor"), "DateTimeFormat")
    if not ctor or _name(ctor.child_by_field_name("object")) != "Intl":
        return None
    caught, ancestor = None, node.parent
    while ancestor and ancestor != fn:
        if ancestor.type in _FUNCTIONS:
            break
        if ancestor.type == "try_statement":
            body, handler = ancestor.child_by_field_name("body"), ancestor.child_by_field_name("handler")
            if handler and body.start_byte <= node.start_byte < body.end_byte:
                caught = handler
                break
        ancestor = ancestor.parent
    parts = _children(caught.child_by_field_name("body")) if caught else []
    returns_false = bool(len(parts) == 1 and parts[0].type == "return_statement"
                         and len(_children(parts[0])) == 1 and _children(parts[0])[0].type == "false")
    return _check("intl_try_catch", node,
                  f"Intl.DateTimeFormat at line {_line(node)} "
                  + (f"is inside a try with catch at line {_line(caught)}. " if caught else
                     "has no same-function enclosing try/catch observed. ")
                  + ("That catch directly returns false. " if returns_false else "")
                  + "This is counterevidence to absent exception handling only; accepted timezone values, "
                  "caller enforcement and runtime Intl behavior are not verified.",
                  catch_line=_line(caught) if caught else None, catch_returns_false=returns_false)


def _query_value(dec, key):
    value = dec.child_by_field_name("value")
    obj, args = _method(value, "get")
    return bool(obj and len(args) == 1 and _literal(args[0]) == key)


def _or_terms(node):
    node = _unwrap(node)
    if node and node.type == "binary_expression" and _text(node.child_by_field_name("operator")) == "||":
        return _or_terms(node.child_by_field_name("left")) + _or_terms(node.child_by_field_name("right"))
    return [node]


def _oauth(stmts, nodes, constants, bindings, globals_free):
    if "fetch" not in globals_free:
        return []
    exchanges = []
    for node in nodes:
        if node.type != "call_expression" or _name(node.child_by_field_name("function")) != "fetch":
            continue
        args = _children(node.child_by_field_name("arguments"))
        if len(args) < 2 or _literal(args[0]) != "https://github.com/login/oauth/access_token":
            continue
        # Query code must be the same immutable local binding appearing in the
        # request expression, not an unrelated request elsewhere in the file.
        used = {_text(n) for n in _walk(args[1], _SKIP)
                if n.type in {"identifier", "shorthand_property_identifier"}}
        if any(bindings[name] == 1 and dec.end_byte < node.start_byte and _query_value(dec, "code")
               for name, dec in constants.items() if name in used):
            exchanges.append(node)
    checks = []
    for guard in stmts:
        if not _exit(guard):
            continue
        terms = _or_terms(guard.child_by_field_name("condition"))
        missing = {_name(t.child_by_field_name("argument")) for t in terms if t and t.type == "unary_expression"
                   and _text(t.child_by_field_name("operator")) == "!"}
        for term in terms:
            if not term or term.type != "binary_expression" or _text(term.child_by_field_name("operator")) != "!==":
                continue
            left, right = _name(term.child_by_field_name("left")), _name(term.child_by_field_name("right"))
            if not left or left == right or not {left, right} <= missing:
                continue
            pair = [constants.get(left), constants.get(right)]
            if (any(dec is None or dec.end_byte >= guard.start_byte for dec in pair)
                    or bindings[left] != 1 or bindings[right] != 1
                    or not any(_query_value(dec, "state") for dec in pair)):
                continue
            if not exchanges:
                continue
            before = all(guard.end_byte < call.start_byte for call in exchanges)
            checks.append(_check("oauth_state_return_guard", guard,
                                 f"At line {_line(guard)}, a direct return branch checks missing state values "
                                 "and strict inequality of the same two local bindings. "
                                 + ("It precedes the recorded GitHub token request. " if before else
                                    "It does not precede every recorded GitHub token request. ")
                                 + "Reconsider a missing-state-comparison premise. Cookie origin, return-expression "
                                 "effects, replay protection, runtime bindings and OAuth safety are not verified.",
                                 exchange_lines=[_line(n) for n in exchanges[:MAX_CHECKS]],
                                 before_exchange=before))
    return checks


def _json_fallback(dec, bindings):
    value = dec.child_by_field_name("value")
    if not value or value.type != "await_expression" or len(_children(value)) != 1:
        return False
    obj, args = _method(_children(value)[0], "catch")
    request, json_args = _method(obj, "json")
    if not request or not _name(request) or bindings[_name(request)] != 1 or json_args or len(args) != 1:
        return False
    handler = args[0]
    if handler.type != "arrow_function" or _children(handler.child_by_field_name("parameters")):
        return False
    body = handler.child_by_field_name("body")
    return body is not None and body.type == "null"


def _mandatory_object(schema, constants, globals_, file_bindings, local_bindings, zod_names):
    dec = constants.get(schema) if local_bindings[schema] == 1 else None
    if dec is None and not local_bindings[schema] and file_bindings[schema] == 1:
        dec = globals_.get(schema)
    if dec is None:
        return False
    value = dec.child_by_field_name("value")
    # These refinements do not add nullish acceptance. Optional/default/catch/
    # preprocess/transform/pipe and arbitrary schema factories stay unresolved.
    for _ in range(8):
        obj, args = _method(value, "object")
        if _name(obj) in zod_names and len(args) == 1 and args[0].type == "object":
            return True
        member = _member(value.child_by_field_name("function")) if value and value.type == "call_expression" else None
        if (not member
                or _text(member.child_by_field_name("property")) not in {"refine", "superRefine", "strict", "strip"}):
            return False
        value = member.child_by_field_name("object")
    return False


def _schema(stmts, nodes, constants, bindings, globals_, file_bindings, zod_names):
    checks = []
    for body_name, body_dec in constants.items():
        if bindings[body_name] != 1 or not _json_fallback(body_dec, bindings):
            continue
        for parsed_name, parsed_dec in constants.items():
            if bindings[parsed_name] != 1 or parsed_dec.start_byte <= body_dec.end_byte:
                continue
            schema, args = _method(parsed_dec.child_by_field_name("value"), "safeParse")
            if not _name(schema) or len(args) != 1:
                continue
            arg = _unwrap(args[0])
            if arg.type == "member_expression":
                # Only one optional field access: null?.field becomes undefined.
                arg = arg.child_by_field_name("object") if arg.child_by_field_name("optional_chain") else None
            if _name(arg) != body_name:
                continue
            guard = None
            for stmt in stmts:
                if stmt.start_byte <= parsed_dec.end_byte or not _exit(stmt):
                    continue
                condition = _unwrap(stmt.child_by_field_name("condition"))
                negated = (condition and condition.type == "unary_expression"
                           and _text(condition.child_by_field_name("operator")) == "!")
                member = _member(condition.child_by_field_name("argument"), "success") if negated else None
                if member and _name(member.child_by_field_name("object")) == parsed_name:
                    guard = stmt
                    break
            if not guard:
                continue
            data_uses = [n for n in nodes if _member(n, "data")
                         and _name(n.child_by_field_name("object")) == parsed_name]
            ordered = bool(data_uses and all(n.start_byte > guard.end_byte for n in data_uses))
            mandatory = _mandatory_object(_name(schema), constants, globals_, file_bindings, bindings, zod_names)
            checks.append(_check("json_schema_return_guard", body_dec,
                                 f"JSON rejection maps to null at line {_line(body_dec)}; that local result "
                                 f"feeds safeParse at line {_line(parsed_dec)}, followed by a !success return "
                                 f"at line {_line(guard)}. "
                                 + ("The indexed schema is a mandatory Zod object shape. " if mandatory else
                                    "Schema acceptance is unresolved. ")
                                 + ("Recorded parsed.data accesses follow that return branch. " if ordered else
                                    "Ordering before all parsed.data accesses is not established. ")
                                 + "Reconsider treating the null fallback alone as acceptance of invalid JSON. "
                                 "Field coverage, response status, indirect effects and runtime schema behavior "
                                 "are not verified.",
                                 schema_line=_line(parsed_dec), guard_line=_line(guard),
                                 mandatory_object_schema=mandatory, data_accesses_after_guard=ordered))
    return checks


def _callee_name(node):
    """Spelling only, deliberately including unsupported/optional/computed calls."""
    target = _unwrap(node.child_by_field_name("function") or node.child_by_field_name("constructor"))
    if not target:
        return ""
    if target.type == "member_expression":
        return _text(target.child_by_field_name("property"))
    if target.type == "subscript_expression":
        # An unresolved computed member could be any of the checked methods.
        return _literal(target.child_by_field_name("index")) or "computed_unknown"
    return _name(target)


def _atomic_candidates(nodes, fn):
    """Inventory targets before selecting supported counterexamples.

    Counting only successful checks would let a checked safe expression dismiss
    an unsupported expression sharing its line. Candidate names are syntax,
    not resolved bindings or evidence that a custom callee implements a clamp.
    """
    candidates = {kind: {} for kind in ("domain_suffix_argument", "finite_limit_clamp", "intl_try_catch")}
    for node in nodes:
        name = _callee_name(node) if node.type in {"call_expression", "new_expression"} else ""
        kind = ("domain_suffix_argument" if name in {"endsWith", "computed_unknown"} else
                "intl_try_catch" if name == "DateTimeFormat" else None)
        if kind:
            candidates[kind][(node.start_byte, node.end_byte)] = node
        if name == "computed_unknown":
            candidates["intl_try_catch"][(node.start_byte, node.end_byte)] = node
        if (node.type != "ternary_expression" and name not in {"min", "max", "computed_unknown"}
                and not re.search(r"clamp", name, re.I)):
            continue
        # One initializer is one candidate: nested min/max calls form a single
        # clamp. An unsupported neighboring initializer remains a second target.
        owner = node
        while owner.parent and owner.parent != fn and owner.type not in {
                "variable_declarator", "expression_statement", "return_statement"}:
            if owner.parent.type in _FUNCTIONS:
                break
            owner = owner.parent
        candidates["finite_limit_clamp"][(owner.start_byte, owner.end_byte)] = owner
    return candidates


def _target_unambiguous(check, fn, candidates, functions):
    start, end = check["line"], check["line_end"]
    matches = [n for n in candidates[check["kind"]].values()
               if _line(n) <= end and n.end_point[0] + 1 >= start]
    if len(matches) != 1:
        return False
    # A sibling/nested function on the same line is ambiguous even when it has
    # no supported guard and therefore would not produce its own record.
    return not any(other != fn and not (
        other.start_byte <= fn.start_byte and fn.end_byte <= other.end_byte)
        and _line(other) <= end and other.end_point[0] + 1 >= start for other in functions)


def _file_records(root, nodes, path, limits):
    file_bindings, globals_ = _bindings(nodes), _consts(root)
    imported = Counter()
    zod_names = set()
    for stmt in root.named_children:
        if stmt.type != "import_statement":
            continue
        for n in _walk(stmt):
            if n.type == "identifier" and n.parent.type in {"import_clause", "namespace_import"}:
                imported[_name(n)] += 1
            if n.type == "import_specifier":
                local = _name(n.child_by_field_name("alias") or n.child_by_field_name("name"))
                imported[local] += 1
                if (_literal(stmt.child_by_field_name("source")) == "zod"
                        and _name(n.child_by_field_name("name")) == "z"
                        and not any(c.type == "type" for c in [*stmt.children, *n.children])):
                    zod_names.add(local)
    zod_names = {n for n in zod_names if imported[n] == 1 and not file_bindings[n]}
    globals_free = {n for n in ("Math", "Number", "Intl", "fetch") if not file_bindings[n] and not imported[n]}
    attempted = work = 0
    functions = [n for n in nodes if n.type in _FUNCTIONS]
    for fn in functions:
        attempted += 1
        if attempted > MAX_FUNCTIONS:
            limits.add("function_limit_reached")
            break
        body = fn.child_by_field_name("body")
        if not body:
            continue
        all_fn_nodes = []
        for node in _walk(fn):
            work += 1
            all_fn_nodes.append(node)
            if len(all_fn_nodes) > MAX_FUNCTION_NODES or work > MAX_WORK_NODES:
                break
        if work > MAX_WORK_NODES:
            limits.add("function_work_limit_reached")
            break
        if len(all_fn_nodes) > MAX_FUNCTION_NODES:
            limits.add("function_node_limit_reached")
            continue
        own = list(_walk(body, _SKIP))
        bindings, constants = _bindings(all_fn_nodes), _consts(body)
        if len(constants) > MAX_LOCALS:
            limits.add("local_binding_limit_reached")
            continue
        stmts = _children(body) if body.type == "statement_block" else []
        checks = _oauth(stmts, own, constants, bindings, globals_free)
        checks.extend(_schema(stmts, own, constants, bindings, globals_, file_bindings, zod_names))
        for dec in constants.values():
            check = _clamp(dec, bindings, constants, globals_free)
            if check:
                checks.append(check)
        for node in own:
            if len(checks) > MAX_CHECKS:
                break
            check = (_suffix(node, constants, bindings, globals_, file_bindings)
                     if node.type == "call_expression" else _intl(node, fn, globals_free))
            if check:
                checks.append(check)
        if not checks:
            continue
        candidates = _atomic_candidates(own, fn)
        for check in checks:
            if check["kind"] in candidates:
                check["syntax_target_unambiguous"] = _target_unambiguous(check, fn, candidates, functions)
        name = _name(fn.child_by_field_name("name"))
        if not name and fn.parent.type == "variable_declarator":
            name = _name(fn.parent.child_by_field_name("name"))
        if len(checks) > MAX_CHECKS:
            limits.add("checks_per_function_limit")
        yield {"file": path, "line": _line(fn), "line_end": fn.end_point[0] + 1,
               "scope": name or f"anonymous_at_line_{_line(fn)}", "checks": checks[:MAX_CHECKS]}


def collect_guard_context(fileobj):
    records, limits = [], set()
    parsed = attempted = used = excluded = 0
    with zipfile.ZipFile(fileobj) as archive:
        infos = archive.infolist()
        canonical = Counter(str(PurePosixPath(i.filename.replace("\\", "/"))) for i in infos)
        for info in sorted(infos, key=lambda i: i.filename):
            path = info.filename
            if info.is_dir() or not path.endswith((".js", ".jsx", ".ts", ".tsx")):
                continue
            normalized = PurePosixPath(path.replace("\\", "/"))
            if (normalized.is_absolute() or ".." in normalized.parts or str(normalized) != path
                    or (len(path) >= 2 and path[1] == ":")):
                limits.add("unsafe_or_noncanonical_path")
                continue
            if canonical[str(normalized)] != 1:
                limits.add("ambiguous_archive_path")
                continue
            if (is_non_production_path(path) or stat.S_ISLNK(info.external_attr >> 16)
                    or any(p in path.split("/") for p in ("vendor", "node_modules", ".next", "dist"))):
                excluded += 1
                continue
            if info.file_size > MAX_FILE_BYTES or len(path) > 512:
                limits.add("file_size_or_path_limit")
                continue
            if attempted >= MAX_FILES or used + info.file_size > MAX_TOTAL_BYTES:
                limits.add("scan_budget_reached")
                break
            attempted += 1
            used += info.file_size
            try:
                data = archive.read(info)
                data.decode("utf-8", errors="strict")
                grammar = (tree_sitter_typescript.language_typescript if path.endswith(".ts")
                           else tree_sitter_typescript.language_tsx)
                root = Parser(Language(grammar())).parse(data).root_node
                if root.has_error:
                    limits.add("unparseable_js_ts")
                    continue
                nodes = []
                for node in _walk(root):
                    nodes.append(node)
                    if len(nodes) > MAX_NODES:
                        break
                if len(nodes) > MAX_NODES:
                    limits.add("node_limit_reached")
                    continue
                parsed += 1
                for record in _file_records(root, nodes, path, limits):
                    if len(records) >= MAX_RECORDS:
                        limits.add("record_limit_reached")
                        break
                    records.append(record)
            except (UnicodeError, ValueError, RecursionError, RuntimeError, OSError, zipfile.BadZipFile):
                limits.add("unparseable_js_ts")
            if "record_limit_reached" in limits:
                break
    return {"scope": SCOPE, "records": records, "limitations": sorted(limits),
            "parsed_files": parsed, "excluded_files": excluded}


def guard_finding_context(finding, source_facts):
    start, end = finding.get("line_start"), finding.get("line_end")
    if type(start) is not int or type(end) is not int or not 1 <= start <= end:
        return []
    matches = [r for r in ((source_facts or {}).get("guards") or {}).get("records", [])
               if r["file"] == finding.get("file") and r["line"] <= start <= end <= r["line_end"]]
    if not matches:
        return []
    matches.sort(key=lambda r: r["line_end"] - r["line"])
    if len(matches) > 1 and matches[0]["line_end"] - matches[0]["line"] == matches[1]["line_end"] - matches[1]["line"]:
        return []
    record = matches[0]
    return [{"kind": "guard_context", "result": "observed", **record,
             "summary": " ".join(c["summary"] for c in record["checks"]), "detail": SCOPE}]


def guard_syntax_check(finding, source_facts):
    """Atomic syntax absence only; original broad security titles stay unknown."""
    title = str(finding.get("title", ""))
    patterns = {
        "domain_suffix_argument": r"(?:The |This )?(?:email |domain )?suffix (?:check|comparison|argument) "
                                  r"(?:has no|omits the|is missing the) @ separator[.]?",
        "finite_limit_clamp": r"(?:The |This )?(?:limit |numeric )?clamp "
                              r"(?:has no|is missing a) nonnegative lower bound[.]?",
        "intl_try_catch": r"(?:The |This )?(?:cited )?Intl\.DateTimeFormat (?:call|constructor) "
                          r"(?:is outside (?:any|a) try/catch|has no enclosing try/catch)[.]?",
    }
    kind = next((k for k, pattern in patterns.items() if re.fullmatch(pattern, title, re.I)), None)
    if kind is None:
        return None
    result = {"kind": kind, "result": "not_checked", "claim": title,
              "detail": "No unambiguous matching syntax counterexample observed; absence is not established."}
    contexts = guard_finding_context(finding, source_facts)
    if not contexts:
        return result
    start, end = finding["line_start"], finding["line_end"]
    checks = [c for c in contexts[0]["checks"] if c["kind"] == kind and c["line"] <= start <= end <= c["line_end"]]
    # A single line can contain multiple calls/clamps. Do not guess the target.
    if len(checks) != 1:
        return result
    check = checks[0]
    if not check.get("syntax_target_unambiguous"):
        result["detail"] = "The cited lines also contain another possible target or function; no target is guessed."
        return result
    contradicted = ((kind == "domain_suffix_argument" and check["separator"] == "present"
                     and check["domain_binding"] == "constant")
                    or (kind == "finite_limit_clamp" and check["nonnegative_lower_bound"])
                    or (kind == "intl_try_catch" and check["catch_line"] is not None))
    if contradicted:
        result.update(result="contradicted", line_start=check["line"], line_end=check["line_end"],
                      detail=check["summary"] + " Only the atomic syntax premise is contradicted.")
    return result

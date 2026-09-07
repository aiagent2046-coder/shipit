"""Bounded React async syntax inventory, independent of model calls/titles.

Only direct, named handlers and useState bindings in top-level components are
linked. This is source evidence, not a control-flow or concurrency proof.
Never execute uploaded code or retain its string literals.
"""
from collections import Counter
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
MAX_ITEMS = 16
MAX_HANDLERS = 128
MAX_BUTTONS = 128
MAX_STATES = 64
SCOPE = (
    "React async syntax, collected without LLM or code execution. Direct named async handlers in "
    "top-level named components; direct imported useState bindings; literal boolean setters, "
    "empty-string setters, simple state/empty-input return guards and native button onClick/disabled syntax only. "
    "Source order and finally placement are observations, not full control-flow proofs. "
    "Indirect handlers, custom hooks/components, refs, all event entry points, runtime bindings, "
    "request idempotency and harmful outcomes are not verified. Missing observations do not prove "
    "missing protection. String values redacted; tests/vendor files excluded."
)
_FUNCTIONS = {"function_declaration", "function_expression", "arrow_function", "method_definition"}
_SKIP = _FUNCTIONS | {"class_declaration", "class"}


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


def _line(node):
    # Point.row in tree-sitter 0.26.0 has a borrowed-reference bug.
    return node.start_point[0] + 1


def _children(node):
    return [n for n in node.named_children if n.type != "comment"] if node else []


def _bound_names(pattern):
    if not pattern:
        return []
    if pattern.type in {"identifier", "shorthand_property_identifier_pattern"}:
        return [_text(pattern)]
    if pattern.type in {"required_parameter", "optional_parameter"}:
        return _bound_names(pattern.child_by_field_name("pattern"))
    if pattern.type in {"assignment_pattern", "object_assignment_pattern"}:
        return _bound_names(pattern.child_by_field_name("left"))
    if pattern.type == "pair_pattern":
        return _bound_names(pattern.child_by_field_name("value"))
    if pattern.type in {"array_pattern", "object_pattern", "formal_parameters", "rest_pattern"}:
        return [name for child in _children(pattern) for name in _bound_names(child)]
    return []


def _bindings(nodes):
    names = []
    for node in nodes:
        if node.type in {"variable_declarator", "function_declaration", "function_expression", "class_declaration"}:
            names.extend(_bound_names(node.child_by_field_name("name")))
        if node.type in _FUNCTIONS:
            names.extend(_bound_names(node.child_by_field_name("parameters")
                                      or node.child_by_field_name("parameter")))
        if node.type == "catch_clause":
            names.extend(_bound_names(node.child_by_field_name("parameter")))
        if node.type in {"assignment_expression", "augmented_assignment_expression", "update_expression"}:
            target = node.child_by_field_name("left") or node.child_by_field_name("argument")
            # An assignment (including a namespace member write) makes linking unsafe.
            while target and target.type in {"member_expression", "subscript_expression"}:
                target = target.child_by_field_name("object")
            names.extend(_bound_names(target))
    return Counter(names)


def _imports(root, bindings):
    hooks, namespaces = set(), set()
    imported_names = Counter()
    for node in root.named_children:
        if node.type != "import_statement":
            continue
        react = (_text(node.child_by_field_name("source")) in {"'react'", '"react"'}
                 and not any(c.type == "type" for c in node.children))
        for clause in _children(node):
            if clause.type != "import_clause":
                continue
            for child in _children(clause):
                if child.type == "identifier":
                    imported_names[_name(child)] += 1
                    if react:
                        namespaces.add(_name(child))
                elif child.type == "namespace_import":
                    for n in _children(child):
                        imported_names[_name(n)] += 1
                        if react:
                            namespaces.add(_name(n))
                elif child.type == "named_imports":
                    for spec in _children(child):
                        local = _name(spec.child_by_field_name("alias") or spec.child_by_field_name("name"))
                        imported_names[local] += 1
                        if (react and _text(spec.child_by_field_name("name")) == "useState"
                                and not any(c.type == "type" for c in spec.children)):
                            hooks.add(local)
    return ({n for n in hooks if n and not bindings[n] and imported_names[n] == 1},
            {n for n in namespaces if n and not bindings[n] and imported_names[n] == 1})


def _definitions(body):
    for stmt in _children(body):
        if stmt.type == "export_statement":
            stmt = stmt.child_by_field_name("declaration")
            if stmt is None:
                continue
        if stmt.type == "function_declaration":
            yield _name(stmt.child_by_field_name("name")), stmt
        elif stmt.type == "lexical_declaration":
            for dec in _children(stmt):
                value = dec.child_by_field_name("value")
                if value and value.type in {"arrow_function", "function_expression"}:
                    yield _name(dec.child_by_field_name("name")), value


def _call(node):
    if node.type == "expression_statement":
        children = _children(node)
        node = children[0] if len(children) == 1 else node
    if node.type != "call_expression" or node.child_by_field_name("optional_chain"):
        return "", []
    return _name(node.child_by_field_name("function")), _children(node.child_by_field_name("arguments"))


def _literal_setter(stmt, setter, value):
    name, args = _call(stmt)
    return name == setter and len(args) == 1 and args[0].type == value


def _disabled_state(node):
    """Return only a small vocabulary of expression shapes, never source text."""
    if _name(node):
        return _name(node), "state_truthy"
    if not node or node.type != "unary_expression" or _text(node.child_by_field_name("operator")) != "!":
        return "", "not_checked"
    arg = node.child_by_field_name("argument")
    if _name(arg):
        return _name(arg), "state_empty"
    if arg and arg.type == "call_expression" and not arg.child_by_field_name("optional_chain"):
        fn = arg.child_by_field_name("function")
        if (fn and fn.type == "member_expression" and not fn.child_by_field_name("optional_chain")
                and _text(fn.child_by_field_name("property")) == "trim"
                and not _children(arg.child_by_field_name("arguments"))):
            return _name(fn.child_by_field_name("object")), "trimmed_state_empty"
    return "", "not_checked"


def _controls(buttons, handler, valid_states, limits):
    records = []
    for node in buttons:
        attrs = [c for c in _children(node) if c.type == "jsx_attribute"]
        names = [_text(_children(a)[0]) for a in attrs]
        # Spreads may override both onClick and disabled; do not infer a binding.
        if any(c.type == "jsx_expression" for c in _children(node)) or len(names) != len(set(names)):
            limits.add("ambiguous_jsx_attributes")
            continue
        values = {}
        for name, attr in zip(names, attrs):
            parts = _children(attr)
            expr = _children(parts[1]) if len(parts) == 2 and parts[1].type == "jsx_expression" else []
            values[name] = expr[0] if len(expr) == 1 else None
        event = values.get("onClick")
        linked = _name(event) == handler
        if event and event.type == "arrow_function" and not _children(event.child_by_field_name("parameters")):
            name, _ = _call(event.child_by_field_name("body"))
            linked = name == handler
        if not linked:
            continue
        state, shape = _disabled_state(values.get("disabled"))
        records.append({"line": _line(node), "line_end": node.end_point[0] + 1,
                        "event": "onClick", "disabled": shape if state in valid_states else "not_checked",
                        "state": state if state in valid_states else None})
        if len(records) >= MAX_ITEMS:
            limits.add("items_per_handler_limit")
            break
    return records


def _handler_record(fn, name, component, path, states, controls, limits):
    body = fn.child_by_field_name("body")
    if not body or body.type != "statement_block":
        limits.add("unsupported_async_body")
        return None
    nodes = list(_walk(body, _SKIP))
    awaits = [n for n in nodes if n.type == "await_expression"]
    if not awaits:
        return None
    first = min(n.start_byte for n in awaits)
    stmts = _children(body)
    checks = []
    for stmt in stmts:
        if stmt.type != "if_statement" or stmt.end_byte >= first or stmt.child_by_field_name("alternative"):
            continue
        condition = stmt.child_by_field_name("condition")
        if condition and condition.type == "parenthesized_expression":
            parts = _children(condition)
            condition = parts[0] if len(parts) == 1 else None
        state, shape = _disabled_state(condition)
        consequence = stmt.child_by_field_name("consequence")
        exits = _children(consequence) if consequence and consequence.type == "statement_block" else [consequence]
        if state in states and len(exits) == 1 and exits[0] and exits[0].type == "return_statement":
            checks.append({"kind": "react_async_entry_guard", "result": "observed", "state": state,
                           "condition": shape, "line": _line(stmt),
                           "detail": "Direct state-condition return before await. Earlier effects, state freshness "
                           "and protection across event entry points not verified."})
    for state, setter in states.items():
        before = [s for s in stmts if s.end_byte < first]
        raised = next((s for s in before if _literal_setter(s, setter, "true")), None)
        if raised:
            reset = next((s for s in stmts if s.start_byte > first and _literal_setter(s, setter, "false")), None)
            final_reset = None
            for stmt in stmts:
                if stmt.type != "try_statement" or stmt.start_byte < raised.end_byte:
                    continue
                final = stmt.child_by_field_name("finalizer")
                final_body = final.child_by_field_name("body") if final else None
                parts = _children(final_body)
                if (parts and _literal_setter(parts[0], setter, "false")
                        and all(stmt.start_byte < a.start_byte < final.start_byte for a in awaits)):
                    final_reset = parts[0]
            checks.append({"kind": "react_async_state_reset", "result": "observed", "state": state,
                           "set_true_line": _line(raised),
                           "direct_reset_line": _line(reset) if reset else None,
                           "finally_reset_line": _line(final_reset) if final_reset else None,
                           "detail": ("State is set true before await. " +
                                      ("A direct false reset follows await; a propagating rejection may bypass it. "
                                       if reset and not final_reset else "") +
                                      ("A try/finally encloses the recorded awaits and starts its finally "
                                       "with a false reset. " if final_reset else
                                       "No supported finally reset enclosing all recorded awaits observed. ") +
                                      "Other exits, catches, setter effects and UI consequences not verified.")})
        cleared = next((s for s in before if _call(s)[0] == setter and len(_call(s)[1]) == 1
                        and _call(s)[1][0].type == "string" and _text(_call(s)[1][0]) in {"''", '""'}), None)
        if cleared:
            linked = [c["line"] for c in controls if c["state"] == state
                      and c["disabled"] in {"state_empty", "trimmed_state_empty"}]
            checks.append({"kind": "react_async_input_clear", "result": "observed", "state": state,
                           "clear_line": _line(cleared), "disabled_button_lines": linked,
                           "detail": "Direct empty-string setter before await; listed buttons use the same state's "
                           "empty check and handler spelling. React rendering, other entry points and "
                           "duplicate request prevention are not verified."})
    if not checks and not controls:
        return None
    if len(checks) > MAX_ITEMS or len(awaits) > MAX_ITEMS:
        limits.add("items_per_handler_limit")
    return {"file": path, "line": _line(fn), "line_end": fn.end_point[0] + 1,
            "scope": component + "." + name, "await_lines": [_line(a) for a in awaits[:MAX_ITEMS]],
            "checks": checks[:MAX_ITEMS], "controls": controls}


def _file_records(root, path, nodes, limits):
    hooks, namespaces = _imports(root, _bindings(nodes))
    attempted = 0
    for component, fn in _definitions(root):
        body = fn.child_by_field_name("body")
        if not component or not component[0].isupper() or not body or body.type != "statement_block":
            continue
        bindings = _bindings(list(_walk(fn)))
        states = {}
        for stmt in _children(body):
            if stmt.type != "lexical_declaration":
                continue
            for dec in _children(stmt):
                value, pattern = dec.child_by_field_name("value"), dec.child_by_field_name("name")
                if not value or value.type != "call_expression" or not pattern or pattern.type != "array_pattern":
                    continue
                call = value.child_by_field_name("function")
                imported = _name(call) in hooks
                if call and call.type == "member_expression":
                    imported = (_name(call.child_by_field_name("object")) in namespaces
                                and _text(call.child_by_field_name("property")) == "useState")
                pair = _children(pattern)
                punctuation = [c.type for c in pattern.children if c.type != "comment"]
                if (not imported or len(pair) != 2 or not all(_name(n) for n in pair)
                        or punctuation not in (["[", "identifier", ",", "identifier", "]"],
                                               ["[", "identifier", ",", "identifier", ",", "]"])):
                    continue
                state, setter = map(_name, pair)
                if bindings[state] == bindings[setter] == 1:
                    if len(states) < MAX_STATES:
                        states[state] = setter
                    else:
                        limits.add("state_limit_reached")
                else:
                    limits.add("ambiguous_state_binding")
        buttons = [n for n in _walk(body, _SKIP)
                   if n.type in {"jsx_opening_element", "jsx_self_closing_element"}
                   and _text(n.child_by_field_name("name")) == "button"]
        if len(buttons) > MAX_BUTTONS:
            limits.add("button_limit_reached")
        for name, handler in _definitions(body):
            if not name or not any(c.type == "async" for c in handler.children):
                continue
            if attempted >= MAX_HANDLERS:
                limits.add("handler_limit_reached")
                return
            attempted += 1
            if bindings[name] != 1:
                limits.add("ambiguous_handler_binding")
                continue
            controls = _controls(buttons[:MAX_BUTTONS], name, states, limits)
            record = _handler_record(handler, name, component, path, states, controls, limits)
            if record:
                yield record


def collect_react_async_context(fileobj):
    records, limits = [], set()
    parsed = attempted = used = excluded = 0
    with zipfile.ZipFile(fileobj) as archive:
        infos = archive.infolist()
        counts = Counter(i.filename for i in infos)
        for info in sorted(infos, key=lambda i: i.filename):
            path = info.filename
            if info.is_dir() or not path.endswith((".js", ".jsx", ".ts", ".tsx")):
                continue
            if (is_non_production_path(path) or stat.S_ISLNK(info.external_attr >> 16)
                    or any(p in path.split("/") for p in ("vendor", "node_modules"))):
                excluded += 1
                continue
            if counts[path] != 1:
                limits.add("ambiguous_archive_path")
                continue
            if info.file_size > MAX_FILE_BYTES or len(path) > 512:
                limits.add("file_size_or_path_limit")
                continue
            if attempted >= MAX_FILES or used + info.file_size > MAX_TOTAL_BYTES:
                limits.add("scan_budget_reached")
                break
            attempted += 1
            used += info.file_size
            data = archive.read(info)
            try:
                data.decode("utf-8", errors="strict")
                grammar = (tree_sitter_typescript.language_typescript if path.endswith(".ts")
                           else tree_sitter_typescript.language_tsx)
                parser = Parser(Language(grammar()))
                tree = parser.parse(data)
                if tree.root_node.has_error:
                    limits.add("unparseable_js_ts")
                    continue
                nodes = []
                for node in _walk(tree.root_node):
                    nodes.append(node)
                    if len(nodes) > MAX_NODES:
                        break
                if len(nodes) > MAX_NODES:
                    limits.add("node_limit_reached")
                    continue
                parsed += 1
                for record in _file_records(tree.root_node, path, nodes, limits):
                    if len(records) >= MAX_RECORDS:
                        limits.add("record_limit_reached")
                        break
                    records.append(record)
            except (UnicodeError, ValueError, RecursionError):
                limits.add("unparseable_js_ts")
            if "record_limit_reached" in limits:
                break
    return {"scope": SCOPE, "records": records, "parsed_files": parsed,
            "excluded_files": excluded, "limitations": sorted(limits)}


def react_async_finding_context(finding, facts):
    start, end = finding.get("line_start"), finding.get("line_end")
    if type(start) is not int or type(end) is not int or not 1 <= start <= end:
        return []
    matches = []
    for record in (facts.get("react_async") or {}).get("records", []):
        if record["file"] != finding.get("file"):
            continue
        locations = [record, *record["controls"]]
        if any(loc["line"] <= start <= end <= loc["line_end"] for loc in locations):
            matches.append(record)
    # A line can contain multiple handlers. Do not guess which the model cited.
    if len(matches) != 1:
        return []
    return [{"kind": "react_async_context", "result": "observed", **matches[0], "detail": SCOPE}]

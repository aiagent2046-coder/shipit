"""Bounded React async syntax inventory, independent of model calls/titles.

Only direct, named handlers and useState bindings in top-level components are
linked. This is source evidence, not a control-flow or concurrency proof.
Never execute uploaded code or retain its string literals.
"""
from collections import Counter
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
MAX_ITEMS = 16
MAX_HANDLERS = 128
MAX_BUTTONS = 128
MAX_STATES = 64
SCOPE = (
    "React async syntax, collected without LLM or code execution. Direct named async handlers in "
    "top-level named components; direct imported useState bindings; literal boolean setters, "
    "empty-string setters, simple state/empty-input return guards and native button onClick/disabled syntax only. "
    "Direct catch resets, awaited fetch calls and same-binding Response.ok branches are recorded. "
    "Separate narrow counterexamples link a sole awaited fetch and all handler awaits to a catch "
    "whose sole statement resets the same state, with no later statement or finally. "
    "A narrow unchecked-HTTP check links discarded/unused fetch responses to a following visible saved "
    "state or imported Next router navigation in a straight-line block. Status-aware and opaque flows "
    "are left unresolved; catch alone handles rejection, not HTTP error responses. "
    "Source order and try/catch/finally placement are observations, not full control-flow proofs. "
    "Indirect handlers, custom hooks/components, refs, all event entry points, runtime bindings, "
    "request idempotency and harmful outcomes are not verified. Missing observations do not prove "
    "missing protection. String values redacted; tests/vendor files excluded."
)
_FUNCTIONS = {"function_declaration", "function_expression", "arrow_function", "method_definition",
              "generator_function_declaration", "generator_function"}
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
        if node.type in {"variable_declarator", "function_declaration", "function_expression", "class_declaration",
                         "generator_function_declaration", "generator_function"}:
            names.extend(_bound_names(node.child_by_field_name("name")))
        if node.type in _FUNCTIONS:
            names.extend(_bound_names(node.child_by_field_name("parameters")
                                      or node.child_by_field_name("parameter")))
        if node.type == "catch_clause":
            names.extend(_bound_names(node.child_by_field_name("parameter")))
        if node.type in {"assignment_expression", "augmented_assignment_expression", "update_expression",
                         "for_in_statement"}:
            target = node.child_by_field_name("left") or node.child_by_field_name("argument")
            # Loop targets can declare a shadow or write an existing binding.
            # A namespace member write also makes linking unsafe.
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
    if (node.type != "call_expression" or node.child_by_field_name("optional_chain")
            or any(c.type == "?." for c in node.children)):
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


def _catch_resets(nodes, setter, limits):
    records = []
    for stmt in nodes:
        if stmt.type != "try_statement":
            continue
        caught = stmt.child_by_field_name("handler")
        body = stmt.child_by_field_name("body")
        parts = _children(caught.child_by_field_name("body")) if caught else []
        for index, reset in enumerate(parts):
            if not _literal_setter(reset, setter, "false"):
                continue
            records.append({"try_line": _line(body), "try_line_end": body.end_point[0] + 1,
                            "catch_line": _line(caught), "reset_line": _line(reset),
                            "first_statement": index == 0})
            if len(records) >= MAX_ITEMS:
                limits.add("items_per_handler_limit")
                return records
    return records


def _standard_fetch(root, nodes, bindings):
    """Local evidence must not contradict the standard-global-fetch assumption."""
    if bindings["fetch"] or any(
        n.type == "identifier" and _name(n) == "fetch"
        for stmt in root.named_children if stmt.type == "import_statement" for n in _walk(stmt)
    ):
        return False
    globals_ = {"window", "globalThis", "self"}
    for node in nodes:
        if node.type in {"member_expression", "subscript_expression"}:
            obj = node.child_by_field_name("object")
            prop = node.child_by_field_name("property") or node.child_by_field_name("index")
            if _name(obj) in globals_ and _text(prop).strip("'\"") == "fetch":
                return False
        # Global aliases / reflective writes are unresolved. Do not attempt to
        # follow Object.defineProperty, an alias of window, or dynamic keys.
        if _name(node) in globals_:
            parent = node.parent
            if parent and not (parent.type == "member_expression"
                               and parent.child_by_field_name("object") == node):
                return False
    return True


def _router_hooks(root, bindings):
    imported, candidates = Counter(), set()
    for stmt in root.named_children:
        if stmt.type != "import_statement":
            continue
        source = _text(stmt.child_by_field_name("source")).strip("'\"")
        for node in _walk(stmt):
            if node.type != "import_specifier":
                continue
            local = _name(node.child_by_field_name("alias") or node.child_by_field_name("name"))
            imported[local] += 1
            if (source in {"next/navigation", "next/router"}
                    and _name(node.child_by_field_name("name")) == "useRouter"
                    and not any(c.type == "type" for c in (*stmt.children, *node.children))):
                candidates.add(local)
    return {n for n in candidates if n and imported[n] == 1 and not bindings[n]}


def _unescaped_routers(body, routers):
    """A router passed to another value/helper could have mutable methods."""
    ambiguous = set()
    for node in _walk(body):
        name = _text(node) if node.type in {"identifier", "shorthand_property_identifier"} else ""
        if name not in routers:
            continue
        parent = node.parent
        if parent.type == "variable_declarator" and parent.child_by_field_name("name") == node:
            continue
        if parent.type == "member_expression" and parent.child_by_field_name("object") == node:
            caller = parent.parent
            if caller and caller.type == "call_expression" and caller.child_by_field_name("function") == parent:
                continue
        ambiguous.add(name)
    return routers - ambiguous


def _visible_success_states(body, states):
    """Recognize a tiny visible-success vocabulary; never retain source text."""
    visible = {}
    for node in _walk(body, _SKIP):
        if node.type == "ternary_expression":
            state = _name(node.child_by_field_name("condition"))
            value = node.child_by_field_name("consequence")
        elif node.type == "binary_expression" and _text(node.child_by_field_name("operator")) == "&&":
            state = _name(node.child_by_field_name("left"))
            value = node.child_by_field_name("right")
        else:
            continue
        if state not in states or not value:
            continue
        # Attribute values and deferred callbacks are not rendered child text.
        child, parent, guards = node, node.parent, set()
        while parent and parent.type in {"ternary_expression", "parenthesized_expression"}:
            if parent.type == "ternary_expression" and (
                _name(parent.child_by_field_name("condition")) not in states
                or parent.child_by_field_name("alternative") != child
            ):
                break
            if parent.type == "ternary_expression":
                guards.add(_name(parent.child_by_field_name("condition")))
            child = parent
            parent = parent.parent
        if not (parent and parent.type == "jsx_expression" and parent.parent
                and parent.parent.type in {"jsx_element", "jsx_fragment"}):
            continue
        # A JSX value stored in an unused variable, or under an unsupported
        # conditional return, is not a directly rendered component result.
        rendered = parent.parent
        hidden = False
        if _hidden_jsx_ancestor(rendered):
            hidden = True
        while rendered.parent and rendered.parent.type in {"jsx_element", "jsx_fragment",
                                                          "parenthesized_expression"}:
            rendered = rendered.parent
            if _hidden_jsx_ancestor(rendered):
                hidden = True
        if hidden or not (rendered.parent and rendered.parent.type == "return_statement"
                and rendered.parent.parent == body):
            continue
        if value.type == "string":
            label = _text(value)[1:-1].casefold()
        elif value.type == "jsx_element":
            parts = _children(value)
            if ([c.type for c in parts] != ["jsx_opening_element", "jsx_text", "jsx_closing_element"]
                    or len(_children(parts[0])) != 1
                    or not _text(parts[0].child_by_field_name("name")).islower()):
                continue
            label = _text(parts[1]).casefold()
        else:
            continue
        if re.fullmatch(r"[\W_]*(?:saved|saved successfully|success|successfully saved|submitted|"
                        r"сохранено|успешно сохранено)[\W_]*", label):
            visible.setdefault(state, []).append(guards)
    return visible


def _hidden_jsx_ancestor(node):
    if node.type != "jsx_element":
        return False
    opening = next((c for c in _children(node) if c.type == "jsx_opening_element"), None)
    # The TSX grammar represents <> fragments as a nameless JSX element.
    if opening and not opening.child_by_field_name("name") and not _children(opening):
        return False
    if not opening or not _text(opening.child_by_field_name("name")).islower():
        return True
    for attr in _children(opening):
        # A spread may introduce hidden, and custom components may omit children.
        if attr.type == "jsx_expression":
            return True
        parts = _children(attr)
        if attr.type != "jsx_attribute" or not parts:
            continue
        name = _text(parts[0])
        value = parts[1] if len(parts) == 2 else None
        if name in {"hidden", "aria-hidden"}:
            expr = _children(value) if value and value.type == "jsx_expression" else []
            if not (len(expr) == 1 and expr[0].type == "false"):
                return True
        if name == "style" and value and value.type == "jsx_expression":
            for pair in _walk(value):
                if pair.type != "pair":
                    continue
                key = _text(pair.child_by_field_name("key")).strip("'\"")
                val = _text(pair.child_by_field_name("value")).strip("'\"")
                if (key, val) in {("display", "none"), ("visibility", "hidden"), ("visibility", "collapse")}:
                    return True
    return False


def _display_guards_allow(effect, body, nodes, states, alternatives):
    """Reject known or ambiguous writes hiding the success branch.

    These states had a literal false initializer. Only later literal setters
    on the supported path can restore a false observation after another write.
    This remains local syntax evidence, not a proof across other event handlers.
    """
    for guards in alternatives:
        values = {states[g]: False for g in guards}
        for node in nodes:
            if node.type != "call_expression":
                continue
            # Optional calls are still potential writes; they must not be
            # ignored merely because a strict positive linker rejects them.
            setter = _name(node.child_by_field_name("function"))
            args = _children(node.child_by_field_name("arguments"))
            if setter not in values:
                continue
            if node.start_byte >= effect.start_byte:
                if len(args) != 1 or args[0].type != "false":
                    values[setter] = None
                continue
            stmt = node.parent
            same_path = (stmt.type == "expression_statement" and _straight_block(stmt, body)
                         and stmt.parent.start_byte <= effect.start_byte < stmt.parent.end_byte)
            values[setter] = (args[0].type == "true" if same_path and len(args) == 1
                              and args[0].type in {"true", "false"} else None)
        if all(value is False for value in values.values()):
            return True
    return False


def _straight_block(stmt, body):
    block = stmt.parent
    while block and block.type == "statement_block":
        if any(s.type in {"return_statement", "throw_statement"} and s.start_byte < stmt.start_byte
               for s in _children(block)):
            return False
        if block == body:
            return True
        parent = block.parent
        if not parent or parent.type != "try_statement" or parent.child_by_field_name("body") != block:
            return False
        stmt, block = parent, parent.parent
    return False


def _boolean_setter(stmt, setters):
    name, args = _call(stmt)
    return name in setters and len(args) == 1 and args[0].type in {"true", "false"}


def _caught_side_effect(stmt):
    """An optional synchronous call enclosed by an empty catch can fall through.

    This supports best-effort telemetry between save and navigation. Loops,
    awaited calls, callbacks, returns and finally effects remain unknown.
    """
    if stmt.type != "try_statement" or stmt.child_by_field_name("finalizer"):
        return False
    handler = stmt.child_by_field_name("handler")
    if not handler or _children(handler.child_by_field_name("body")):
        return False
    statements = _children(stmt.child_by_field_name("body"))
    if len(statements) != 1 or statements[0].type != "expression_statement":
        return False
    parts = _children(statements[0])
    if len(parts) != 1 or parts[0].type != "call_expression":
        return False
    return not any(n.type in _SKIP | {"await_expression", "assignment_expression",
                                     "augmented_assignment_expression", "update_expression"}
                   for n in _walk(parts[0]))


def _http_success_check(stmt, response, nodes, body, states, visible, routers):
    if not _straight_block(stmt, body):
        return None
    # Any use of a stored response might implement status/body validation via
    # a helper. Absence of a supported .ok branch is insufficient evidence.
    if response and any(_name(n) == response and n.start_byte >= stmt.end_byte for n in nodes):
        return None
    setters = set(states.values())
    for following in _children(stmt.parent):
        if following.start_byte < stmt.end_byte:
            continue
        state = next((s for s in visible if _literal_setter(following, states[s], "true")), None)
        effect, binding = ("success_state", state) if state else (None, None)
        parts = _children(following)
        call = parts[0] if following.type == "expression_statement" and len(parts) == 1 else None
        fn = call.child_by_field_name("function") if call and call.type == "call_expression" else None
        if (fn and fn.type == "member_expression" and not fn.child_by_field_name("optional_chain")
                and not call.child_by_field_name("optional_chain")
                and not any(c.type == "?." for c in call.children)
                and _name(fn.child_by_field_name("object")) in routers
                and _text(fn.child_by_field_name("property")) in {"push", "replace"}):
            args = _children(call.child_by_field_name("arguments"))
            if len(args) == 1 and args[0].type == "string":
                effect, binding = "navigation", _name(fn.child_by_field_name("object"))
        if effect:
            # React may batch these setters; a synchronously reverted success
            # state does not establish a rendered success indication.
            if effect == "success_state":
                if not _display_guards_allow(following, body, nodes, states, visible[state]):
                    return None
                # Later direct/conditional/finally writes can be batched with
                # true. Functional setters and unknown arguments are writes,
                # too; deferred callback bodies are outside this traversal.
                if any(n.type == "call_expression" and n.start_byte >= following.end_byte
                       and _name(n.child_by_field_name("function")) == states[state] for n in nodes):
                    return None
            return {"kind": "react_async_http_success", "result": "observed",
                    "fetch_line": _line(stmt), "effect_line": _line(following),
                    "effect": effect, "binding": binding,
                    "detail": "A direct UI effect follows a discarded or unused fetch response without "
                    "status/body handling in this supported block. Standard fetch resolves for HTTP error "
                    "responses; catch/finally alone does not make a 4xx/5xx response reject. The handler's "
                    "runtime entry, server outcome and global fetch behavior outside this file are not verified."}
        if not (_boolean_setter(following, setters) or _caught_side_effect(following)):
            return None
    return None


def _http_checks(nodes, bindings, limits, handler_body, states, visible, routers):
    """Link direct awaited fetch results only; no aliases, wrappers or URL text."""
    checks = []
    for node in nodes:
        if node.type != "await_expression":
            continue
        parts = _children(node)
        if (len(parts) != 1 or _call(parts[0])[0] != "fetch"
                or len(_call(parts[0])[1]) not in {1, 2}):
            continue
        parent = node.parent
        response = (_name(parent.child_by_field_name("name"))
                    if parent.type == "variable_declarator" else "")
        if response and bindings[response] != 1:
            limits.add("ambiguous_response_binding")
            continue
        stmt = parent.parent if response else parent
        if (stmt.type not in {"lexical_declaration", "expression_statement"}
                or stmt.parent.type != "statement_block"):
            continue
        if stmt.type == "lexical_declaration" and len(_children(stmt)) != 1:
            continue
        branches = []
        for sibling in _children(stmt.parent):
            if not response or sibling.start_byte < stmt.end_byte or sibling.type != "if_statement":
                continue
            condition = _children(sibling.child_by_field_name("condition"))
            expr = condition[0] if len(condition) == 1 else None
            negated = (expr is not None and expr.type == "unary_expression"
                       and _text(expr.child_by_field_name("operator")) == "!")
            member = expr.child_by_field_name("argument") if negated else expr
            if (member is None or member.type != "member_expression"
                    or member.child_by_field_name("optional_chain")
                    or _name(member.child_by_field_name("object")) != response
                    or _text(member.child_by_field_name("property")) != "ok"):
                continue
            branch = sibling.child_by_field_name("consequence")
            statements = _children(branch) if branch.type == "statement_block" else [branch]
            exits = [s.type.removesuffix("_statement") for s in statements
                     if s.type in {"throw_statement", "return_statement"}]
            branches.append({"line": _line(sibling), "path": "http_error" if negated else "http_success",
                             "direct_exits": exits[:MAX_ITEMS]})
            if len(branches) >= MAX_ITEMS:
                limits.add("items_per_handler_limit")
                break
        caught = None
        ancestor = node.parent
        while ancestor is not None and ancestor.type not in _SKIP:
            if ancestor.type == "try_statement":
                body = ancestor.child_by_field_name("body")
                handler = ancestor.child_by_field_name("handler")
                if handler and body.start_byte < node.start_byte < body.end_byte:
                    caught = handler
                    break
            ancestor = ancestor.parent
        checks.append({"kind": "react_async_http_response", "result": "observed", "line": _line(node),
                       "response": response or None, "branches": branches,
                       "rejection_catch_line": _line(caught) if caught else None,
                       "summary": (f"Awaited fetch at line {_line(node)}. " +
                                   (f"Response stored as {response}. " if response else
                                    "Response is not assigned to a variable here. ") +
                                   (f"Request rejection is inside try/catch at line {_line(caught)}. "
                                    if caught else "No enclosing catch observed for this await. ") +
                                   ("Response.ok branches: " + ", ".join(
                                       f"{b['path']} at line {b['line']}" for b in branches) + ". "
                                    if branches else "No supported same-response HTTP status branch observed. ")),
                       "detail": "For standard fetch, request rejection can enter "
                       "an enclosing catch; an HTTP error response does not itself reject. Response.ok separates "
                       "2xx from other statuses. Missing branches mean not observed in this bounded check, "
                       "not missing protection. Wrappers, global fetch replacement, response-body errors, "
                       "branch reachability and UI success effects are not verified."})
        success = _http_success_check(stmt, response, nodes, handler_body, states, visible, routers)
        if success:
            checks.append(success)
        if len(checks) >= MAX_ITEMS:
            limits.add("items_per_handler_limit")
            break
    return checks


def _enclosing_rejection_catch(node):
    """Nearest catch whose try body contains this syntax node."""
    ancestor = node.parent
    while ancestor is not None and ancestor.type not in _SKIP:
        if ancestor.type == "try_statement":
            body = ancestor.child_by_field_name("body")
            handler = ancestor.child_by_field_name("handler")
            if handler and body.start_byte < node.start_byte < body.end_byte:
                return ancestor, handler
        ancestor = ancestor.parent
    return None, None


def _rejection_counterevidence(body, awaits, states):
    """Small positive counterexamples, separate from the inventory's non-proofs.

    One direct standard fetch is required, including no competing fetch inside
    nested callbacks. A network-reset counterexample additionally requires all
    awaits to share the same catch, whose only statement resets the same React
    state. This deliberately leaves indirect, competing and opaque flows open.
    """
    uses = [n for n in _walk(body) if n.type in {"identifier", "shorthand_property_identifier"}
            and _text(n) == "fetch"]
    if len(uses) != 1:
        return []  # Includes optional calls, aliases and competing nested fetches.
    fetch = uses[0].parent
    if fetch is None or fetch.type != "call_expression" or _call(fetch)[0] != "fetch":
        return []
    awaited = fetch.parent
    if (awaited is None or awaited.type != "await_expression" or awaited not in awaits
            or len(_call(fetch)[1]) not in {1, 2}):
        return []
    checks = [{"kind": "react_async_fetch_await", "result": "observed", "line": _line(awaited),
               "detail": "The only direct fetch call in this handler is the operand of await. "
               "This contradicts an unawaited-fetch premise only; HTTP status handling and "
               "successful navigation are separate questions."}]
    tried, caught = _enclosing_rejection_catch(awaited)
    if not caught or tried.child_by_field_name("finalizer"):
        return checks
    parameter = caught.child_by_field_name("parameter")
    if parameter and parameter.type != "identifier":
        return checks  # A destructuring catch binding can throw before reset.
    parts = _children(caught.child_by_field_name("body"))
    if len(parts) != 1 or any(_enclosing_rejection_catch(a)[1] != caught for a in awaits):
        return checks
    # The supported catch is a top-level handler statement. Following code can
    # restore the busy state or invoke an unknown callback, so remain unknown.
    if tried.parent != body or _children(body)[-1] != tried:
        return checks
    for state, setter in states.items():
        if not _literal_setter(parts[0], setter, "false"):
            continue
        # Link a real busy-state write; an arbitrary reset of an unrelated state
        # must not be offered as evidence for the claimed flag.
        raised = [s for s in _children(body) if s.end_byte < tried.start_byte
                  and _literal_setter(s, setter, "true")]
        if len(raised) != 1:
            continue
        checks.append({"kind": "react_async_network_reset", "result": "observed", "state": state,
                       "fetch_line": _line(awaited), "catch_line": _line(caught),
                       "reset_line": _line(parts[0]), "set_true_line": _line(raised[0]),
                       "detail": "The same React state is set true before the try. The awaited fetch "
                       "and all other recorded awaits enter the same catch, whose sole statement "
                       "directly resets that state to false. No following handler statement or finally "
                       "can overwrite this reset in the supported syntax. This counters the asserted "
                       "missing reset on request rejection; HTTP error responses, runtime bindings, "
                       "concurrent invocations and successful-navigation behavior are not established."})
    return checks


def _handler_record(fn, name, component, path, states, controls, limits, fetch_unbound, visible, routers):
    body = fn.child_by_field_name("body")
    if not body or body.type != "statement_block":
        limits.add("unsupported_async_body")
        return None
    nodes = list(_walk(body, _SKIP))
    awaits = [n for n in nodes if n.type == "await_expression"
              or (n.type == "for_in_statement" and any(c.type == "await" for c in n.children))]
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
        catches = _catch_resets(nodes, setter, limits)
        if raised or catches:
            reset = next((s for s in stmts if s.start_byte > first and _literal_setter(s, setter, "false")), None)
            final_reset = None
            for stmt in stmts:
                if not raised or stmt.type != "try_statement" or stmt.start_byte < raised.end_byte:
                    continue
                final = stmt.child_by_field_name("finalizer")
                final_body = final.child_by_field_name("body") if final else None
                parts = _children(final_body)
                if (parts and _literal_setter(parts[0], setter, "false")
                        and all(stmt.start_byte < a.start_byte < final.start_byte for a in awaits)):
                    final_reset = parts[0]
            checks.append({"kind": "react_async_state_reset", "result": "observed", "state": state,
                           "set_true_line": _line(raised) if raised else None,
                           "direct_reset_line": _line(reset) if reset else None,
                           "finally_reset_line": _line(final_reset) if final_reset else None,
                           "catch_resets": catches,
                           "summary": " ".join(
                               f"Catch at line {r['catch_line']} encloses try lines "
                               f"{r['try_line']}–{r['try_line_end']} and contains a {state}=false setter "
                               f"at line {r['reset_line']} "
                               + ("as its first statement." if r['first_statement'] else
                                  "after earlier statements that may throw.") for r in catches) +
                               (" A missing finally alone does not establish missing error cleanup."
                                if catches else ""),
                           "detail": (("State is set true before await. " if raised else "") +
                                      ("A direct false reset follows await; a propagating rejection may bypass it. "
                                       if reset and not final_reset else "") +
                                      ("A try/finally encloses the recorded awaits and starts its finally "
                                       "with a false reset. " if final_reset else
                                       "No supported finally reset enclosing all recorded awaits observed. ") +
                                      "Catch reset locations describe only direct statements in the listed catch, "
                                      "not all error paths. Earlier catch statements may throw; nested or conditional "
                                      "cleanup, setter effects and UI consequences are not verified.")})
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
    if fetch_unbound:
        http_checks = _http_checks(nodes, _bindings(list(_walk(fn))), limits, body, states, visible, routers)
        checks.extend(http_checks)
        if any(c["kind"] == "react_async_http_response" for c in http_checks):
            checks.extend(_rejection_counterevidence(body, awaits, states))
    if not checks and not controls:
        return None
    if len(checks) > MAX_ITEMS or len(awaits) > MAX_ITEMS:
        limits.add("items_per_handler_limit")
    return {"file": path, "line": _line(fn), "line_end": fn.end_point[0] + 1,
            "scope": component + "." + name, "await_lines": [_line(a) for a in awaits[:MAX_ITEMS]],
            "checks": checks[:MAX_ITEMS], "controls": controls}


def _file_records(root, path, nodes, limits):
    file_bindings = _bindings(nodes)
    hooks, namespaces = _imports(root, file_bindings)
    fetch_unbound = _standard_fetch(root, nodes, file_bindings)
    router_hooks = _router_hooks(root, file_bindings)
    attempted = 0
    for component, fn in _definitions(root):
        body = fn.child_by_field_name("body")
        if not component or not component[0].isupper() or not body or body.type != "statement_block":
            continue
        bindings = _bindings(list(_walk(fn)))
        states, routers, false_states = {}, set(), set()
        for stmt in _children(body):
            if stmt.type != "lexical_declaration":
                continue
            for dec in _children(stmt):
                value, pattern = dec.child_by_field_name("value"), dec.child_by_field_name("name")
                if (_name(pattern) and value and _call(value)[0] in router_hooks
                        and not _call(value)[1] and bindings[_name(pattern)] == 1):
                    routers.add(_name(pattern))
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
                        args = _children(value.child_by_field_name("arguments"))
                        if len(args) == 1 and args[0].type == "false":
                            false_states.add(state)
                    else:
                        limits.add("state_limit_reached")
                else:
                    limits.add("ambiguous_state_binding")
        visible = _visible_success_states(body, false_states)
        routers = _unescaped_routers(body, routers)
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
            record = _handler_record(handler, name, component, path, states, controls, limits,
                                     fetch_unbound, visible, routers)
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


_IDENTIFIER = r"[A-Za-z_$][\w$]*"
_NETWORK_CLAIM = re.compile(
    r"(?P<handler>" + _IDENTIFIER + r")(?:\(\))?(?:\s+handler)?\s+"
    r"(?:leaves|keeps)\s+(?P<state>" + _IDENTIFIER + r")"
    r"(?:\s*=\s*true)?\s+(?:stuck\s+)?(?:on|after)\s+(?:a\s+)?"
    r"network\s+(?:error|failure|rejection)", re.I)
_AWAIT_ABSENCE = re.compile(
    r"\bfetch(?:\s*\([^)]{0,160}\))?[^.\n]{0,120}\b(?:is|was|remains)\s+"
    r"(?:entirely\s+)?(?:not\s+awaited|unawaited)\b|"
    r"\b(?:unawaited|fire\s+and\s+forget)\s+fetch\b|"
    r"\b(?:no|missing)\s+await(?:\s+keyword)?\s+before\s+fetch\b|"
    r"\bfetch\b[^.\n]{0,100}\bwithout\s+(?:being\s+)?awaited\b|"
    r"\b(?:does\s+not|fails\s+to)\s+await\s+(?:the\s+)?fetch\b", re.I)
_REACT_PREMISE_CLAIMS = {
    "react_async_fetch_unawaited": "The fetch request in the cited handler is not awaited.",
    "react_async_network_reset_absent": "The cited handler leaves the named React state true on request rejection.",
}


def _claim_text(value):
    # Markdown and typographic hyphens are presentation, not different claims.
    return re.sub(r"[-‐‑‒–—]", " ", str(value or "")[:16000].replace("`", ""))


def _react_claim_requests(finding):
    title = _claim_text(finding.get("title"))
    network = _NETWORK_CLAIM.search(title)
    requests = []
    if network:
        requests.append({"kind": "react_async_network_reset_absent", "target": network["state"],
                         "handler": network["handler"]})
    narrative = title + "\n" + _claim_text(finding.get("explanation"))
    if _AWAIT_ABSENCE.search(narrative):
        requests.append({"kind": "react_async_fetch_unawaited", "target": "fetch"})
    return requests


def react_async_premise_checks(finding, source_facts):
    """Return partial source counterexamples without trusting model evidence.

    Title/explanation select claims only. Every positive result comes from the
    source-facts collector; claim_evidence and model-supplied premises/results
    are never accepted as evidence. A compound HTTP or success-path concern is
    not dismissed by counterevidence about fetch rejection.
    """
    contexts = react_async_finding_context(finding, source_facts or {})
    context = contexts[0] if len(contexts) == 1 else None
    result = []
    for request in _react_claim_requests(finding):
        check = {"kind": request["kind"], "target": request["target"],
                 "claim": _REACT_PREMISE_CLAIMS[request["kind"]], "result": "not_checked",
                 "detail": "No unambiguous source counterexample within this React handler check's scope."}
        result.append(check)
        if context is None:
            continue
        handler = context["scope"].rsplit(".", 1)[-1]
        if request.get("handler", handler) != handler:
            continue
        observed_kind = ("react_async_fetch_await" if request["kind"] == "react_async_fetch_unawaited"
                         else "react_async_network_reset")
        matches = [c for c in context["checks"] if c.get("kind") == observed_kind
                   and c.get("result") == "observed"
                   and (observed_kind == "react_async_fetch_await" or c.get("state") == request["target"])]
        if len(matches) != 1:
            continue
        observed = matches[0]
        check.update(result="contradicted", line_start=observed.get("fetch_line", observed.get("line")),
                     line_end=observed.get("reset_line", observed.get("line")),
                     anchor_line_start=context["line"], anchor_line_end=context["line_end"],
                     detail=observed["detail"] + " This is a partial premise check, not a verdict on "
                     "other claims in the finding.")
    return result


def _network_syntax_check(finding, facts):
    title = _claim_text(finding.get("title"))
    match = _NETWORK_CLAIM.search(title)
    if not match:
        return None
    unknown = {"kind": "react_async_network_reset_absent", "result": "not_checked",
               "claim": _REACT_PREMISE_CLAIMS["react_async_network_reset_absent"],
               "detail": "Only a complete single network-rejection claim can be dismissed by this check."}
    contexts = react_async_finding_context(finding, facts or {})
    component = contexts[0]["scope"].rsplit(".", 1)[0] if contexts else ""
    if (title[:match.start()].strip() not in {"", "The", "the", component}
            or title[match.end():].strip() not in {"", "."}):
        return unknown
    # Presence of prose can hide another concern without a recognizable marker.
    # Whole disposition therefore requires no narrative beyond a literal repeat
    # of the same atomic title. Other narratives receive partial checks only.
    narrative = [finding.get(k) for k in ("explanation", "observation", "required_conditions")]
    if finding.get("premises") or any(value and _claim_text(value).strip().rstrip(".")
                                     != title.strip().rstrip(".") for value in narrative):
        return unknown
    checks = react_async_premise_checks(finding, facts)
    result = next((c for c in checks if c["kind"] == "react_async_network_reset_absent"), unknown)
    if result["result"] == "contradicted":
        result = {**result, "detail": result["detail"].split(" This is a partial premise check", 1)[0]
                  + " Only the complete network-rejection premise is contradicted."}
    return result


def react_async_syntax_check(finding, facts):
    """Only a complete, atomic absence title can be dismissed by presence.

    Catch presence alone does not refute outcome claims. A stronger source
    counterexample can refute only a complete network-rejection premise; other
    narratives receive partial checks. Model prose never supplies the proof.
    """
    match = re.fullmatch(r"([A-Za-z_$][\w$]*)(?:\(\))? has no catch reset for ([A-Za-z_$][\w$]*)[.]?",
                         str(finding.get("title", "")))
    if not match:
        return _network_syntax_check(finding, facts)
    result = {"kind": "react_async_catch_reset", "result": "not_checked",
              "claim": "The named handler contains no direct catch reset for the named state.",
              "detail": "No unambiguous supported catch reset observed; absence is not established."}
    contexts = react_async_finding_context(finding, facts or {})
    if not contexts or contexts[0]["scope"].rsplit(".", 1)[-1] != match[1]:
        return result
    resets = [r for c in contexts[0]["checks"] if c.get("kind") == "react_async_state_reset"
              and c.get("state") == match[2] for r in c.get("catch_resets", [])]
    if resets:
        reset = resets[0]
        result.update(result="contradicted", line_start=reset["catch_line"], line_end=reset["reset_line"],
                      detail="A direct false setter for that state is present in this handler's catch. "
                      "This contradicts absence only. Earlier catch statements may throw; reaching the reset, "
                      "other error paths and UI recovery are not proven.")
    return result

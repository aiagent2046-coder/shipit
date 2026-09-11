"""Read runtime TLS options with bounded TypeScript/JavaScript syntax and provenance.

Only Node https/tls calls and process.env are resolved. Local import, require,
constructor and options aliases are followed; unknown wrappers, cross-file data
flow and computed option objects remain unresolved. Target code is never run.
"""

from __future__ import annotations

import ast
from collections import Counter
from dataclasses import dataclass

import tree_sitter_typescript
from tree_sitter import Language, Parser

_FUNCTIONS = {
    "function_declaration",
    "function_expression",
    "arrow_function",
    "generator_function",
    "generator_function_declaration",
    "method_definition",
}
_TYPES = {
    "type_alias_declaration",
    "interface_declaration",
    "type_annotation",
    "type_arguments",
    "type_parameters",
    "ambient_declaration",
}
_SINKS = {"https.Agent", "https.request", "https.get", "tls.connect", "tls.TLSSocket"}
_MAX_NODES = 20_000
_MAX_DEPTH = 100


def _text(node):
    return node.text.decode("utf-8", "replace") if node is not None else ""


def _unwrap(node):
    while node is not None and node.type in {
        "parenthesized_expression",
        "as_expression",
        "satisfies_expression",
        "non_null_expression",
        "type_assertion",
    }:
        children = [child for child in node.named_children if child.type != "comment"]
        if not children:
            return None
        node = children[-1] if node.type == "type_assertion" else children[0]
    return node


def _string(node):
    node = _unwrap(node)
    if node is None or node.type != "string":
        return None
    try:
        value = ast.literal_eval(_text(node))
        return value if isinstance(value, str) else None
    except (ValueError, SyntaxError):
        return None


def _property(node):
    if node is None:
        return ""
    if node.type in {"property_identifier", "identifier"}:
        return _text(node)
    return _string(node) or ""


def _pattern_names(node):
    if node is None:
        return set()
    if node.type in {"identifier", "shorthand_property_identifier_pattern"}:
        return {_text(node)}
    if node.type in {"required_parameter", "optional_parameter"}:
        return _pattern_names(node.child_by_field_name("pattern"))
    if node.type in {"pair_pattern", "assignment_pattern", "object_assignment_pattern"}:
        return _pattern_names(node.child_by_field_name("value") or node.child_by_field_name("left"))
    if node.type in {"object_pattern", "array_pattern", "rest_pattern", "formal_parameters"}:
        return set().union(*(_pattern_names(child) for child in node.named_children))
    return set()


@dataclass(frozen=True)
class _Value:
    path: str = ""
    options: object = None


_UNKNOWN = _Value()


def js_evidence(text, tsx=False, *, incomplete_reason: dict[str, str] | None = None):
    # With ASCII bytes and no escapes, every supported setting must contain one
    # of these exact property names. Escaped or Unicode source always reaches
    # the parser, so spelling a key as "reject\\u0055nauthorized" cannot hide it.
    if (
        text.isascii()
        and "\\" not in text
        and not any(marker in text for marker in ("rejectUnauthorized", "NODE_TLS_REJECT_UNAUTHORIZED"))
    ):
        return []
    parser = Parser(
        Language(tree_sitter_typescript.language_tsx() if tsx else tree_sitter_typescript.language_typescript())
    )
    tree = parser.parse(text.encode("utf-8"))
    # A malformed tree cannot certify that a literal is executable code.
    if tree.root_node.has_error:
        if incomplete_reason is not None:
            incomplete_reason["reason"] = "parse_error"
        return []
    pending, count = [(tree.root_node, 0)], 0
    while pending:
        node, depth = pending.pop()
        count += 1
        if count > _MAX_NODES or depth > _MAX_DEPTH:
            if incomplete_reason is not None:
                incomplete_reason["reason"] = "ast_limit"
            return []
        pending.extend((child, depth + 1) for child in node.named_children)
    found = []

    def emit(node, what):
        if len(found) < 32:
            found.append((node.start_point.row + 1, what, "certificate"))
        elif incomplete_reason is not None:
            incomplete_reason["reason"] = "finding_limit"

    def resolve(node, bindings):
        node = _unwrap(node)
        if node is None:
            return _UNKNOWN
        if node.type == "identifier":
            return bindings.get(_text(node), _UNKNOWN)
        if node.type == "object":
            return _Value(options=node)
        if node.type in {"member_expression", "subscript_expression"}:
            base = resolve(node.child_by_field_name("object"), bindings).path
            prop = _property(node.child_by_field_name("property") or node.child_by_field_name("index"))
            return _Value(path=f"{base}.{prop}") if base and prop else _UNKNOWN
        if node.type == "call_expression":
            callee = resolve(node.child_by_field_name("function"), bindings).path
            args = node.child_by_field_name("arguments")
            values = [child for child in args.named_children if child.type != "comment"] if args else []
            if callee == "builtin:require" and len(values) == 1:
                module = (_string(values[0]) or "").removeprefix("node:")
                if module in {"https", "tls", "process"}:
                    return _Value(path=module)
        if node.type == "new_expression":
            callee = resolve(node.child_by_field_name("constructor"), bindings).path
            if callee in {"https.Agent", "tls.TLSSocket"}:
                return _Value(path="instance:" + callee)
        return _UNKNOWN

    def false_option(value, bindings):
        if value.options is None:
            return None
        selected = None
        for child in value.options.named_children:
            if child.type == "comment":
                continue
            if child.type == "pair":
                key = _property(child.child_by_field_name("key"))
                if key == "rejectUnauthorized":
                    val = _unwrap(child.child_by_field_name("value"))
                    selected = child if val is not None and val.type == "false" else None
                elif not key:
                    selected = None  # An unknown computed key can replace the setting.
            elif child.type == "spread_element":
                selected = None  # A later spread can override an earlier explicit literal.
            elif _text(child) == "rejectUnauthorized":
                selected = None
        return selected

    def bound(nodes):
        counts = Counter()
        pending = list(nodes)
        while pending:
            node = pending.pop()
            if node.type in _TYPES:
                continue
            if node.type in _FUNCTIONS or node.type == "class_declaration":
                name = node.child_by_field_name("name")
                if name is not None:
                    counts[_text(name)] += 1
                continue
            if node.type in {"variable_declarator", "assignment_expression", "augmented_assignment_expression"}:
                counts.update(_pattern_names(node.child_by_field_name("name") or node.child_by_field_name("left")))
            elif node.type == "import_statement":
                counts.update(import_bindings(node).keys())
                continue
            pending.extend(node.named_children)
        return counts

    def import_bindings(node):
        if any(child.type == "type" for child in node.children):
            return {}
        module = (_string(node.child_by_field_name("source")) or "").removeprefix("node:")
        clause = next((child for child in node.named_children if child.type == "import_clause"), None)
        result = {}
        if clause is None:
            return result
        for child in clause.named_children:
            if child.type == "identifier":
                result[_text(child)] = _Value(path=module) if module in {"https", "tls", "process"} else _UNKNOWN
            elif child.type == "namespace_import":
                name = next((part for part in child.named_children if part.type == "identifier"), None)
                result[_text(name)] = _Value(path=module) if module in {"https", "tls", "process"} else _UNKNOWN
            elif child.type == "named_imports":
                for part in child.named_children:
                    if any(token.type == "type" for token in part.children):
                        continue
                    name = part.child_by_field_name("name")
                    alias = part.child_by_field_name("alias") or name
                    result[_text(alias)] = (
                        _Value(path=f"{module}.{_text(name)}") if module in {"https", "tls", "process"} else _UNKNOWN
                    )
        return result

    def invalidate(value, bindings):
        for name, known in list(bindings.items()):
            if (value.path and (known.path == value.path or known.path.startswith(value.path + "."))) or (
                value.options is not None and known.options == value.options
            ):
                bindings.pop(name, None)

    def assign(target, value, bindings, emit_setting=True):
        target = _unwrap(target)
        if target is None:
            return
        origin = resolve(value, bindings)
        if target.type == "identifier":
            bindings[_text(target)] = origin
        elif target.type == "object_pattern":
            for child in target.named_children:
                if child.type == "pair_pattern":
                    key = _property(child.child_by_field_name("key"))
                    destination = child.child_by_field_name("value")
                else:
                    key, destination = _text(child), child
                if destination is not None and destination.type in {
                    "identifier",
                    "shorthand_property_identifier_pattern",
                }:
                    bindings[_text(destination)] = _Value(path=f"{origin.path}.{key}") if origin.path else _UNKNOWN
                else:
                    for name in _pattern_names(destination):
                        bindings[name] = _UNKNOWN
        elif target.type in {"member_expression", "subscript_expression"}:
            path = resolve(target, bindings).path
            raw = _unwrap(value)
            if emit_setting and path == "process.env.NODE_TLS_REJECT_UNAUTHORIZED":
                if _string(raw) == "0" or (raw is not None and raw.type == "number" and _text(raw) == "0"):
                    emit(target, "sets process.env.NODE_TLS_REJECT_UNAUTHORIZED to 0")
            elif emit_setting and path in {
                "instance:https.Agent.options.rejectUnauthorized",
                "https.globalAgent.options.rejectUnauthorized",
            }:
                if raw is not None and raw.type == "false":
                    emit(target, "sets HTTPS agent options.rejectUnauthorized=false")
            else:
                invalidate(resolve(target.child_by_field_name("object"), bindings), bindings)
        else:
            for name in _pattern_names(target):
                bindings[name] = _UNKNOWN

    def lexical_names(nodes):
        """Declarations owned by this block; assignments can target an outer scope."""
        names = set()
        for node in nodes:
            if node.type == "lexical_declaration":
                for child in node.named_children:
                    if child.type == "variable_declarator":
                        names.update(_pattern_names(child.child_by_field_name("name")))
            elif node.type in {"function_declaration", "generator_function_declaration", "class_declaration"}:
                name = node.child_by_field_name("name")
                if name is not None:
                    names.add(_text(name))
        return names

    def scope(nodes, inherited, parameters=(), local=False, block_scope=False):
        counts = bound(nodes)
        bindings = inherited.copy()
        if local or block_scope:
            for name in lexical_names(nodes) if block_scope else counts:
                bindings.pop(name, None)
        for name in parameters:
            bindings.pop(name, None)
        deferred = []

        def expression(node, state):
            if node is None or node.type in _TYPES or node.type in {"comment", "string", "regex"}:
                return
            if node.type == "statement_block":
                declarations = lexical_names(node.named_children)
                completed = scope(node.named_children, state, block_scope=True)
                # A lexical block isolates its declarations, not writes to outer
                # names or mutations through aliases of an outer object.
                for name in set(state) | set(completed):
                    if name not in declarations:
                        if name in completed:
                            state[name] = completed[name]
                        else:
                            state.pop(name, None)
                return
            if node.type in _FUNCTIONS:
                name = node.child_by_field_name("name")
                if name is not None:
                    state.pop(_text(name), None)
                deferred.append(node)
                return
            if node.type == "template_string":
                for child in node.named_children:
                    if child.type == "template_substitution":
                        expression(child, state)
                return
            if node.type in {"assignment_expression", "augmented_assignment_expression"}:
                value = node.child_by_field_name("right")
                expression(value, state)
                assign(
                    node.child_by_field_name("left"),
                    value if node.type == "assignment_expression" else None,
                    state,
                    emit_setting=node.type == "assignment_expression",
                )
                return
            if node.type in {"call_expression", "new_expression"}:
                callee = resolve(
                    node.child_by_field_name("function") or node.child_by_field_name("constructor"), state
                ).path
                args = node.child_by_field_name("arguments")
                if callee in _SINKS and args is not None:
                    for arg in args.named_children:
                        option = false_option(resolve(arg, state), state)
                        if option is not None:
                            emit(option, f"passes rejectUnauthorized=false to {callee}")
            if node.type == "variable_declarator":
                value = node.child_by_field_name("value")
                expression(value, state)
                assign(node.child_by_field_name("name"), value, state)
                return
            if node.type == "import_statement":
                state.update(import_bindings(node))
                return
            if node.type in {
                "if_statement",
                "for_statement",
                "for_in_statement",
                "while_statement",
                "do_statement",
                "try_statement",
                "switch_statement",
            }:
                for child in node.named_children:
                    branch = state.copy()
                    # Catch and loop bindings must not impersonate imports/globals.
                    for name in _pattern_names(child.child_by_field_name("parameter")) | _pattern_names(
                        node.child_by_field_name("left")
                    ):
                        branch.pop(name, None)
                    expression(child, branch)
                for name in bound([node]):
                    state.pop(name, None)
                # Conservative after conditional mutations to imported namespaces.
                todo = list(node.named_children)
                while todo:
                    child = todo.pop()
                    if child.type in _FUNCTIONS:
                        continue
                    if child.type in {"assignment_expression", "augmented_assignment_expression"}:
                        target = child.child_by_field_name("left")
                        if target is not None and target.type in {"member_expression", "subscript_expression"}:
                            assign(target, None, state, emit_setting=False)
                    todo.extend(child.named_children)
                return
            for child in node.named_children:
                expression(child, state)

        for node in nodes:
            expression(node, bindings)
        stable = {name: value for name, value in bindings.items() if counts[name] <= 1}
        for function in deferred:
            params = function.child_by_field_name("parameters") or function.child_by_field_name("parameter")
            names = _pattern_names(params)
            body = function.child_by_field_name("body")
            if body is not None:
                scope(body.named_children if body.type == "statement_block" else [body], stable, names, local=True)
        return bindings

    scope(
        tree.root_node.named_children,
        {"process": _Value(path="process"), "require": _Value(path="builtin:require")},
        local=True,
    )
    return found

"""Bounded source-only SQL refinement; never executes JavaScript or claims exploitability."""
from __future__ import annotations

import hashlib

import tree_sitter_typescript
from tree_sitter import Language, Parser

from app.scan.sql_injection_js import _sink_name

MAX_FILE_BYTES = 400_000
MAX_NODES = 80_000
MAX_DEPTH = 160
MAX_EXPRESSION_DEPTH = 24


def _text(node):
    return node.text.decode("utf-8") if node is not None else ""


def _children(node):
    return [n for n in node.named_children if n.type != "comment"]


def _same(a, b):
    return a is not None and b is not None and a.id == b.id


def analyze_source(raw: bytes, path: str, line: int, sink_method: str | None = None) -> dict:
    """Resolve a unique sink to fixed syntax or explicitly retain uncertainty.

    Fixed syntax is not a database safety verdict: the receiver, SQL meaning,
    authorization and runtime behavior are deliberately outside this proof.
    """
    result = {
        "version": 1, "file": path, "source_sha256": hashlib.sha256(raw).hexdigest(),
        "sink_line": line, "sink_column": None, "sink_method": sink_method,
        "verdict": "unavailable", "parameter_argument": "unknown", "fragments": [],
        "reason": "sink_not_found", "runtime_verified": False,
    }

    def unavailable(reason):
        result["reason"] = reason
        return result

    if len(raw) > MAX_FILE_BYTES:
        return unavailable("file_limit")
    if not path.lower().endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts")):
        return unavailable("unsupported_file")
    try:
        raw.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return unavailable("invalid_utf8")
    language = tree_sitter_typescript.language_tsx if path.lower().endswith((".tsx", ".jsx")) else (
        tree_sitter_typescript.language_typescript
    )
    tree = Parser(Language(language())).parse(raw)
    if tree.root_node.has_error:
        return unavailable("parse_error")
    nodes, pending = [], [(tree.root_node, 0)]
    while pending:
        node, depth = pending.pop()
        if depth > MAX_DEPTH:
            return unavailable("depth_limit")
        nodes.append(node)
        if len(nodes) > MAX_NODES:
            return unavailable("node_limit")
        pending.extend((child, depth + 1) for child in node.named_children)
    sinks = [n for n in nodes if n.start_point[0] + 1 == line and _sink_name(n) is not None]
    # Method filtering must not hide a second sink on the same reported line.
    if len(sinks) > 1:
        return unavailable("ambiguous_sink")
    if not sinks or (sink_method is not None and _sink_name(sinks[0]) != sink_method):
        return unavailable("sink_not_found")
    sink = sinks[0]
    result.update(sink_column=sink.start_point[1] + 1, sink_method=_sink_name(sink))
    arguments = _children(sink.child_by_field_name("arguments"))
    result["parameter_argument"] = "present" if len(arguments) > 1 else "absent"
    fragments = []
    identifiers = {}
    for node in nodes:
        if node.type in {"identifier", "shorthand_property_identifier_pattern"}:
            identifiers.setdefault(_text(node), []).append(node)
    # Dynamic lexical environments invalidate static name resolution.
    dynamic_scope = any("\\" in name or name in {"eval", "Function", "globalThis", "window", "global", "self"}
                        for name in identifiers) or any(n.type == "with_statement" or (
        n.type == "call_expression" and _text(n.child_by_field_name("function")) == "eval"
    ) for n in nodes)

    def record(node, kind, reason):
        item = {"line": node.start_point[0] + 1, "kind": kind, "reason": reason}
        if item not in fragments and len(fragments) < 32:
            fragments.append(item)

    def literal(node):
        return node.type in {"string", "number", "true", "false", "null"}

    def fixed(node, params=frozenset(), depth=0, const_allowed=True, helper_allowed=True):
        if node is None or depth > MAX_EXPRESSION_DEPTH:
            return False
        kind = node.type
        if literal(node):
            record(node, "fixed_literal", "literal")
            return True
        if kind == "parenthesized_expression":
            children = _children(node)
            return len(children) == 1 and fixed(children[0], params, depth + 1, const_allowed, helper_allowed)
        if kind == "template_string":
            substitutions = [n for n in _children(node) if n.type == "template_substitution"]
            ok = True
            for sub in substitutions:
                children = _children(sub)
                ok = (len(children) == 1 and fixed(
                    children[0], params, depth + 1, const_allowed, helper_allowed
                )) and ok
            if not substitutions:
                record(node, "fixed_literal", "literal")
            return ok
        if kind == "binary_expression" and _text(node.child_by_field_name("operator")) == "+":
            left = fixed(node.child_by_field_name("left"), params, depth + 1, const_allowed, helper_allowed)
            right = fixed(node.child_by_field_name("right"), params, depth + 1, const_allowed, helper_allowed)
            return left and right
        if kind == "ternary_expression":
            # Helper parameters are mutable: an ignored condition could overwrite them.
            # The supported helper grammar is deliberately side-effect free.
            if not helper_allowed:
                return False
            # Every possible result has fixed syntax; the condition is not executed.
            yes = fixed(node.child_by_field_name("consequence"), params, depth + 1, const_allowed, helper_allowed)
            no = fixed(node.child_by_field_name("alternative"), params, depth + 1, const_allowed, helper_allowed)
            return yes and no
        if kind == "identifier" and _text(node) in params:
            return True
        if kind == "identifier" and const_allowed and not dynamic_scope:
            name = _text(node)
            occurrences = identifiers.get(name, [])
            declarations = [n.parent for n in occurrences if n.parent.type == "variable_declarator"
                            and _same(n.parent.child_by_field_name("name"), n)]
            if len(declarations) != 1:
                return False
            declaration = declarations[0]
            lexical = declaration.parent
            if lexical.type != "lexical_declaration" or not any(n.type == "const" for n in lexical.children):
                return False
            scope = lexical.parent
            if scope.type not in {"program", "statement_block"}:
                return False
            if not (scope.start_byte <= node.start_byte < scope.end_byte and declaration.end_byte < node.start_byte):
                return False
            allowed = {"template_substitution", "binary_expression", "arguments", "return_statement",
                       "parenthesized_expression"}
            for occurrence in occurrences:
                parent = occurrence.parent
                if _same(parent, declaration):
                    continue
                if parent.type == "variable_declarator" and _same(parent.child_by_field_name("value"), occurrence):
                    continue
                if parent.type not in allowed:
                    return False
            ok = fixed(declaration.child_by_field_name("value"), frozenset(), depth + 1, False, helper_allowed)
            if ok:
                record(declaration, "fixed_const", "stable_const")
            return ok
        if kind == "call_expression" and helper_allowed and not dynamic_scope:
            func = node.child_by_field_name("function")
            args_node = node.child_by_field_name("arguments")
            if func is None or func.type != "identifier" or args_node is None:
                return False
            args = _children(args_node)
            if not all(literal(arg) for arg in args):
                return False
            occurrences = identifiers.get(_text(func), [])
            declarations = [n.parent for n in occurrences if n.parent.type == "function_declaration"
                            and _same(n.parent.child_by_field_name("name"), n)]
            if len(declarations) != 1:
                return False
            declaration = declarations[0]
            parent = declaration.parent
            if parent.type == "export_statement":
                parent = parent.parent
            if parent.type != "program" or any(c.type == "async" for c in declaration.children):
                return False
            if not any(n.type in {"import_statement", "export_statement"} for n in parent.named_children):
                return False
            for occurrence in occurrences:
                owner = occurrence.parent
                if _same(owner, declaration):
                    continue
                if owner.type != "call_expression" or not _same(owner.child_by_field_name("function"), occurrence):
                    return False
            parameters = _children(declaration.child_by_field_name("parameters"))
            names = []
            for parameter in parameters:
                if parameter.type == "identifier":
                    names.append(_text(parameter))
                elif parameter.type == "required_parameter":
                    pattern = parameter.child_by_field_name("pattern")
                    if pattern is None or pattern.type != "identifier" or parameter.child_by_field_name("value"):
                        return False
                    names.append(_text(pattern))
                else:
                    return False
            if len(names) != len(args) or len(set(names)) != len(names):
                return False
            body = _children(declaration.child_by_field_name("body"))
            if len(body) != 1 or body[0].type != "return_statement":
                return False
            expressions = _children(body[0])
            ok = len(expressions) == 1 and fixed(expressions[0], frozenset(names), depth + 1, False, False)
            if ok:
                record(declaration, "fixed_helper", "single_return_literal_args")
            return ok
        return False

    proven = bool(arguments) and fixed(arguments[0])
    result.update(verdict="fixed_sql_fragments" if proven else "dynamic_sql_unresolved",
                  reason="proven_fixed" if proven else "unresolved_expression")
    if not proven:
        record(arguments[0] if arguments else sink, "unknown", "unresolved_expression")
    result["fragments"] = fragments
    return result

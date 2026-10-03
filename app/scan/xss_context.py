"""Bounded, descriptive HTML input facts; never a sanitizer or trust verdict.

Only syntax is inspected. Calls remain unverified, including functions named
escapeHtml or sanitize. Literal dictionary bindings describe their initializer,
not the runtime contents of a mutable object or the identity of Object.entries.
"""
from __future__ import annotations

import re

_MAX_VISITS = 256
_MAX_DEPTH = 24
_MAX_NAMES = 16
_FUNCTIONS = {
    "function_declaration", "function_expression", "arrow_function", "method_definition",
    "generator_function", "generator_function_declaration",
}
_NAME = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]{0,63}\Z")


def _name(node):
    if node is None or node.end_byte - node.start_byte > 64:
        return None
    value = node.text.decode("utf-8", errors="replace")
    return value if _NAME.fullmatch(value) else None


def _children(node):
    return [child for child in node.named_children if child.type != "comment"]


def _visible_const(declaration, use, *, cross_function=False):
    if declaration is None or declaration.end_byte > use.start_byte:
        return False
    parent = declaration.parent
    if parent is None or parent.type != "lexical_declaration":
        return False
    if not any(child.type == "const" for child in parent.children):
        return False
    scope = parent.parent
    current = use.parent
    while current is not None:
        if current == scope:
            return True
        if not cross_function and current.type in _FUNCTIONS:
            return False
        current = current.parent
    return False


def describe_html_inputs(value, sink_node, nodes, declarations) -> dict:
    """Return serializable counts and identifier names, without source values.

    ``declarations`` is the conservative unique-name map from xss._declarations.
    A resolved const gets only one hop. Unrecognized constructs stay unresolved.
    ``nodes`` supplies a bounded index of possible loop-binding conflicts.
    """
    facts = {
        "status": "unresolved",
        "parts": {"literal": 0, "calls_unverified": 0, "unresolved": 0,
                  "literal_dictionary_bindings": 0},
        "calls": [], "references": [], "const_bindings_resolved": 0,
        "limits": False,
    }
    visits = 0
    # Loop destructuring is not in the unique-const map. Reject any competing
    # declaration/parameter or mutation of its names before describing a source.
    loop_conflicts = set()
    conflict_visits = 0
    for syntax in nodes[:20_000]:
        target = None
        if syntax.type == "variable_declarator":
            target = syntax.child_by_field_name("name")
        elif syntax.type in {"formal_parameters", "import_clause", "catch_clause"}:
            target = syntax
        elif syntax.type == "arrow_function":
            target = syntax.child_by_field_name("parameter")
        elif syntax.type in {"assignment_expression", "augmented_assignment_expression", "update_expression"}:
            target = syntax.child_by_field_name("left") or syntax.child_by_field_name("argument")
        pending = [target] if target is not None else []
        while pending:
            conflict_visits += 1
            if conflict_visits > 20_000:
                facts["limits"] = True
                break
            part = pending.pop()
            if part.type in {"identifier", "shorthand_property_identifier_pattern"}:
                loop_conflicts.add(_name(part))
            pending.extend(_children(part))
        if facts["limits"]:
            break
    if len(nodes) > 20_000:
        facts["limits"] = True

    def spend(depth):
        nonlocal visits
        visits += 1
        if visits > _MAX_VISITS or depth > _MAX_DEPTH:
            facts["limits"] = True
            return False
        return True

    def add_name(bucket, name):
        if name is None or name in facts[bucket]:
            return
        if len(facts[bucket]) >= _MAX_NAMES:
            facts["limits"] = True
        else:
            facts[bucket].append(name)

    def literal_tree(node, depth=0):
        if node is None or not spend(depth):
            return False
        if node.type in {"string", "number", "true", "false", "null"}:
            return True
        if node.type == "array":
            return all(literal_tree(c, depth + 1) for c in _children(node))
        if node.type == "object":
            for pair in _children(node):
                if pair.type != "pair":
                    return False
                key = pair.child_by_field_name("key")
                if key is None or key.type not in {"property_identifier", "string", "number"}:
                    return False
                if not literal_tree(pair.child_by_field_name("value"), depth + 1):
                    return False
            return True
        return False

    def dictionary_binding(reference):
        if _name(reference) in loop_conflicts or facts["limits"]:
            return False
        current = reference.parent
        while current is not None:
            if not spend(0) or current.type in _FUNCTIONS:
                return False
            if current.type == "for_in_statement":
                left = current.child_by_field_name("left")
                pending = [left] if left is not None else []
                bound = False
                while pending:
                    part = pending.pop()
                    if not spend(0):
                        return False
                    if (part.type in {"identifier", "shorthand_property_identifier_pattern"}
                            and _name(part) == _name(reference)):
                        bound = True
                    pending.extend(_children(part))
                if bound:
                    right = current.child_by_field_name("right")
                    if right is None or right.type != "call_expression":
                        return False
                    callee = right.child_by_field_name("function")
                    if callee is None or callee.type != "member_expression":
                        return False
                    if (_name(callee.child_by_field_name("object")) != "Object"
                            or _name(callee.child_by_field_name("property")) != "entries"):
                        return False
                    arguments = right.child_by_field_name("arguments")
                    args = _children(arguments) if arguments is not None else []
                    if len(args) != 1 or args[0].type != "identifier":
                        return False
                    declaration = declarations.get(_name(args[0]))
                    if not _visible_const(declaration, current, cross_function=True):
                        return False
                    initializer = declaration.child_by_field_name("value")
                    return initializer is not None and initializer.type == "object" and literal_tree(initializer)
            current = current.parent
        return False

    def visit(node, depth=0, resolve=True):
        if not spend(depth):
            return
        if node is None:
            facts["parts"]["unresolved"] += 1
            return
        kind = node.type
        if kind == "string":
            facts["parts"]["literal"] += 1
        elif kind == "template_string":
            substitutions = [c for c in _children(node) if c.type == "template_substitution"]
            if not substitutions or any(c.type in {"string_fragment", "escape_sequence"} for c in _children(node)):
                facts["parts"]["literal"] += 1
            for substitution in substitutions:
                for expression in _children(substitution):
                    visit(expression, depth + 1, resolve)
        elif kind == "parenthesized_expression":
            children = _children(node)
            if len(children) == 1:
                visit(children[0], depth + 1, resolve)
            else:
                facts["parts"]["unresolved"] += 1
        elif kind == "binary_expression" and node.child_by_field_name("operator").type == "+":
            visit(node.child_by_field_name("left"), depth + 1, resolve)
            visit(node.child_by_field_name("right"), depth + 1, resolve)
        elif kind == "ternary_expression":
            # Branch values only; the predicate is not inserted into HTML.
            visit(node.child_by_field_name("consequence"), depth + 1, resolve)
            visit(node.child_by_field_name("alternative"), depth + 1, resolve)
        elif kind in {"call_expression", "new_expression"}:
            facts["parts"]["calls_unverified"] += 1
            callee = node.child_by_field_name("function") or node.child_by_field_name("constructor")
            if callee is not None and callee.type == "member_expression":
                callee = callee.child_by_field_name("property")
            if callee is not None and callee.type in {"identifier", "property_identifier"}:
                add_name("calls", _name(callee))
        elif kind == "identifier":
            name = _name(node)
            declaration = declarations.get(name)
            if resolve and _visible_const(declaration, node):
                facts["const_bindings_resolved"] += 1
                visit(declaration.child_by_field_name("value"), depth + 1, False)
            elif resolve and dictionary_binding(node):
                facts["parts"]["literal_dictionary_bindings"] += 1
                add_name("references", name)
            else:
                facts["parts"]["unresolved"] += 1
                add_name("references", name)
        else:
            facts["parts"]["unresolved"] += 1

    if isinstance(value, list):
        for part in value[:_MAX_VISITS]:
            visit(part)
        if len(value) > _MAX_VISITS:
            facts["limits"] = True
    else:
        visit(value)
    categories = [key for key, count in facts["parts"].items() if count]
    if facts["limits"] and "unresolved" not in categories:
        categories.append("unresolved")
    facts["status"] = ("mixed" if len(categories) > 1 else
                       "literal" if categories == ["literal"] else
                       "calls" if categories == ["calls_unverified"] else "unresolved")
    return facts

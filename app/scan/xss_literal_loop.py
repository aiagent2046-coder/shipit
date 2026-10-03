"""Narrow immutable string bindings from local literal Object.entries loops.

This is syntax proof within one file, under normal native built-in semantics.
Unknown uses, aliases, writes, shadowing, escaping closures and parser errors
abstain. It is not a general JavaScript data-flow or sanitizer analysis.
"""
from __future__ import annotations

from collections import defaultdict
import re

_NAME = re.compile(rb"[A-Za-z_$][A-Za-z0-9_$]{0,63}\Z")
_FUNCTIONS = {"function_declaration", "function_expression", "arrow_function",
              "method_definition", "generator_function", "generator_function_declaration"}
_NAMES = {"identifier", "type_identifier", "shorthand_property_identifier", "shorthand_property_identifier_pattern"}
_MAX_NODES = 20_000
_MAX_LOOPS = 64


def _name(node):
    return node.text.decode("ascii") if node is not None and _NAME.fullmatch(node.text) else None


def _children(node):
    return [c for c in node.named_children if c.type != "comment"]


def _inside(node, container):
    return container.start_byte <= node.start_byte and node.end_byte <= container.end_byte


def _array_items(node):
    """Reject holes/spread/defaults; named children alone lose array holes."""
    result = []
    expect_value = True
    for child in node.children[1:-1]:
        if child.type == "comment":
            continue
        if expect_value:
            if not child.is_named:
                return None
            result.append(child)
        elif child.type != ",":
            return None
        expect_value = not expect_value
    return result


def _literal_tree(node, depth=0):
    if node is None or depth > 16:
        return False
    if node.type == "string":
        return True
    if node.type == "array":
        parts = _array_items(node)
        return parts is not None and all(_literal_tree(c, depth + 1) for c in parts)
    # Only string leaves are needed for this proof; reject other literal kinds.
    return False


def _path_bindings(pattern, prefix=(), depth=0):
    if depth > 16:
        return None
    if pattern.type == "identifier":
        name = _name(pattern)
        return [(name, pattern, prefix)] if name else None
    if pattern.type != "array_pattern":
        return None
    children = _array_items(pattern)
    if children is None:
        return None
    result = []
    for index, child in enumerate(children):
        values = _path_bindings(child, prefix + (index,), depth + 1)
        if values is None:
            return None
        result.extend(values)
    return result


def _string_at(node, path):
    for index in path:
        if node.type != "array":
            return False
        parts = _array_items(node)
        if parts is None or index >= len(parts):
            return False
        node = parts[index]
    return node.type == "string"


def _read_in_body(reference, body):
    if not _inside(reference, body):
        return False
    current = reference
    while current != body:
        parent = current.parent
        if parent is None or parent.type in _FUNCTIONS:
            return False
        if parent.type in {"variable_declarator", "formal_parameters", "catch_clause",
                           "array_pattern", "object_pattern", "rest_pattern",
                           "required_parameter", "optional_parameter", "update_expression",
                           "class_declaration", "class", "import_specifier"}:
            return False
        if parent.type in {"assignment_expression", "augmented_assignment_expression", "for_in_statement"}:
            target = parent.child_by_field_name("left")
            if target is not None and _inside(reference, target):
                return False
        current = parent
    return True


def build_literal_loop_bindings(nodes):
    """Return (name, body_start, body_end) facts, built at most once per file."""
    if len(nodes) > _MAX_NODES:
        return set()
    names = defaultdict(list)
    loops = []
    for node in nodes:
        if node.type in {"ERROR", "with_statement"} or node.is_missing:
            return set()
        if node.type in _NAMES:
            name = _name(node)
            # Escaped spellings could alias a table/binding/Object or eval.
            if name is None:
                return set()
            if name in {"eval", "Function", "globalThis", "window", "self", "global"}:
                return set()
            names[name].append(node)
        if node.type == "for_in_statement":
            loops.append(node)
        # Explicit alternate access to the global Object is not resolved.
        if node.type == "member_expression":
            prop = node.child_by_field_name("property")
            if prop is not None and prop.text == b"Object":
                return set()
    if len(loops) > _MAX_LOOPS:
        return set()
    result = set()
    for loop in loops:
        if not any(c.type == "const" for c in loop.children) or not any(c.type == "of" for c in loop.children):
            continue
        pattern = loop.child_by_field_name("left")
        call = loop.child_by_field_name("right")
        body = loop.child_by_field_name("body")
        if (pattern is None or pattern.type != "array_pattern" or call is None
                or call.type != "call_expression" or body is None):
            continue
        pair_pattern = _array_items(pattern)
        if pair_pattern is None or len(pair_pattern) != 2 or pair_pattern[0].type != "identifier":
            continue
        bindings = _path_bindings(pair_pattern[1])
        if not bindings:
            continue
        callee = call.child_by_field_name("function")
        arguments = call.child_by_field_name("arguments")
        args = _children(arguments) if arguments is not None else []
        if callee is None or callee.type != "member_expression" or len(args) != 1 or args[0].type != "identifier":
            continue
        obj = callee.child_by_field_name("object")
        prop = callee.child_by_field_name("property")
        if _name(obj) != "Object" or _name(prop) != "entries" or len(names["Object"]) != 1:
            continue
        # No optional call/access or special property syntax.
        if any(c.type in {"optional_chain", "?."} for c in (*call.children, *callee.children)):
            continue
        table_name = _name(args[0])
        refs = names[table_name]
        if len(refs) != 2:
            continue
        declaration_ref = next((r for r in refs if r != args[0]), None)
        declaration = declaration_ref.parent if declaration_ref is not None else None
        if (declaration is None or declaration.type != "variable_declarator"
                or declaration.child_by_field_name("name") != declaration_ref):
            continue
        lexical = declaration.parent
        if (lexical.type != "lexical_declaration"
                or not any(c.type == "const" for c in lexical.children)
                or declaration.end_byte >= loop.start_byte):
            continue
        scope = lexical.parent
        ancestor = loop.parent
        while ancestor is not None and ancestor != scope:
            ancestor = ancestor.parent
        if ancestor is None or scope.type not in {"program", "statement_block"}:
            continue
        # Exported mutable dictionaries can be changed by another module.
        if lexical.parent is not None and lexical.parent.type == "export_statement":
            continue
        table = declaration.child_by_field_name("value")
        if table is None or table.type != "object":
            continue
        values = []
        for pair in _children(table):
            if pair.type != "pair":
                break
            key = pair.child_by_field_name("key")
            value = pair.child_by_field_name("value")
            if (key is None or key.type not in {"property_identifier", "string"}
                    or key.text.strip(b"\"'") == b"__proto__" or not _literal_tree(value)):
                break
            values.append(value)
        else:
            if not values:
                continue
            binding_names = [name for name, _, _ in bindings] + [_name(pair_pattern[0])]
            if len(set(binding_names)) != len(binding_names):
                continue
            for name, binding, path in bindings:
                if all(_string_at(value, path) for value in values) and all(
                    ref == binding or _read_in_body(ref, body) for ref in names[name]
                ):
                    result.add((name, body.start_byte, body.end_byte))
    return result


def literal_loop_binding(value, use, bindings):
    """Check one identifier against the precomputed set of lexical facts."""
    if value is None or value.type != "identifier":
        return False
    name = _name(value)
    return any(name == bound and start <= value.start_byte <= value.end_byte <= end
               and start <= use.start_byte <= use.end_byte <= end
               for bound, start, end in bindings)

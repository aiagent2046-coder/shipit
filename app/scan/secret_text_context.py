"""Bounded source evidence for repeated document text in JavaScript tests.

This is contextual classification, never a secret-value allowlist. Callers
retain the candidate and leave provider-format rules untouched.
"""
from __future__ import annotations

import re

from app.scan.check_loading import is_native_import_error

_FUNCTIONS = {"arrow_function", "function_expression", "function_declaration", "method_definition"}
_MAX_BYTES = 256 * 1024
_MAX_NODES = 40000


def _function(node):
    node = node.parent
    while node is not None:
        if node.type in _FUNCTIONS:
            return node
        node = node.parent
    return None


def _text_pair(node) -> bool:
    parent = node.parent
    if parent is None or parent.type != "pair" or parent.child_by_field_name("value") != node:
        return False
    key = parent.child_by_field_name("key")
    return key is not None and key.text in {b"text", b"'text'", b'"text"'}


def _includes_assertion(node) -> bool:
    args = node.parent
    if args is None or args.type != "arguments" or args.named_children != [node]:
        return False
    call = args.parent
    member = call.child_by_field_name("function") if call.type == "call_expression" else None
    if member is None or member.type != "member_expression":
        return False
    prop = member.child_by_field_name("property")
    if prop is None or prop.text != b"includes":
        return False
    # Accept only assert.ok(<receiver>.includes(token)), not an access-control
    # predicate, a returned value, or a call nested in another expression.
    outer_args = call.parent
    if outer_args.type != "arguments" or outer_args.named_children != [call]:
        return False
    outer = outer_args.parent
    fn = outer.child_by_field_name("function") if outer.type == "call_expression" else None
    return (fn is not None and fn.text == b"assert.ok"
            and outer.parent.type == "expression_statement")


def repeated_test_text_spans(
    text: str, *, tsx: bool = False, coverage: dict | None = None,
) -> set[tuple[int, int, int]]:
    """Return (line, value-start-byte-column, value-end-byte-column).

    The caller must establish test-path context and exclude migrations. Only
    a local const named exactly `token` is considered. Unknown syntax, use,
    scope or unavailable parsers leave ordinary secret reporting in place.
    No literal bytes are returned or persisted.
    """
    raw = text.encode("utf-8")
    if len(raw) > _MAX_BYTES or ".repeat" not in text:
        return set()
    try:
        import tree_sitter_typescript
        from tree_sitter import Language, Parser
    except ImportError as exc:
        if not is_native_import_error(exc):
            raise
        if coverage is not None:
            limits = coverage.setdefault("limitations", [])
            if "javascript_text_fixture_context_unavailable" not in limits:
                limits.append("javascript_text_fixture_context_unavailable")
        return set()
    grammar = tree_sitter_typescript.language_tsx if tsx else tree_sitter_typescript.language_typescript
    root = Parser(Language(grammar())).parse(raw).root_node
    if root.has_error:
        return set()
    nodes, pending = [], [root]
    while pending:
        node = pending.pop()
        nodes.append(node)
        if len(nodes) > _MAX_NODES:
            return set()
        pending.extend(node.named_children)
    result = set()
    work = 0
    for node in nodes:
        if node.type != "variable_declarator":
            continue
        target, value = node.child_by_field_name("name"), node.child_by_field_name("value")
        if (target is None or target.type != "identifier" or target.text != b"token"
                or value is None or value.type != "call_expression"
                or node.parent.type != "lexical_declaration"
                or node.parent.children[0].type != "const"):
            continue
        owner = _function(node)
        if owner is None:
            continue
        member, args = value.child_by_field_name("function"), value.child_by_field_name("arguments")
        if member is None or member.type != "member_expression" or args is None:
            continue
        literal, prop = member.child_by_field_name("object"), member.child_by_field_name("property")
        if (literal is None or literal.type != "string" or prop is None or prop.text != b"repeat"
                or not re.fullmatch(rb"(['\"])[A-Za-z -]{8,128}\1", literal.text)
                or len(args.named_children) != 1):
            continue
        count = args.named_children[0]
        if count.type != "number" or not re.fullmatch(rb"[0-9]{1,6}", count.text):
            continue
        if not 2 <= int(count.text) <= 100000:
            continue
        if literal.start_point.row != literal.end_point.row:
            continue
        work += len(nodes)
        if work > 1000000:
            return result
        has_text_use, valid = False, True
        for ref in nodes:
            if not owner.start_byte <= ref.start_byte < owner.end_byte:
                continue
            # Dynamic access can read a local binding without an identifier
            # reference. Abstain instead of treating the traversal as complete.
            if ref.type == "identifier" and ref.text in {b"eval", b"Function"}:
                valid = False
                break
            if ref.text != b"token" or ref.type not in {
                "identifier", "shorthand_property_identifier", "shorthand_property_identifier_pattern",
            }:
                continue
            if ref == target:
                continue
            if _function(ref) != owner:
                valid = False
                break
            if _text_pair(ref):
                has_text_use = True
            elif not _includes_assertion(ref):
                valid = False
                break
        if valid and has_text_use:
            result.add((literal.start_point.row + 1, literal.start_point.column + 1,
                        literal.end_point.column - 1))
    return result

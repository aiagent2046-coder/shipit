"""Statement/token primitives for bounded source claim checks.

Canonical AST token strings, constant collection and native-import
binding checks that both the AuthSourceVerifier in
auth_source_assessment and the injected url_token checks in
url_token_assessment build on. Extracted verbatim during the
import-cycles fix phase (the verifier called the checks while the
checks reached back into the verifier's private helpers).
"""
from __future__ import annotations

from app.scan import guard_context as g
from app.scan import imported_error_context as i


def _ast_tokens(node):
    # named-only walking omits punctuation; include all AST leaves for equality.
    todo, parts = [node] if node else [], []
    while todo:
        n = todo.pop()
        if n.type == "comment":
            continue
        if n.children:
            todo.extend(reversed(n.children))
        else:
            parts.append(g._text(n))
    return "".join(parts)


def _top(node, body):
    while node and node.parent != body:
        node = node.parent
    return node


def _const(node):
    return bool(
        node
        and node.type == "variable_declarator"
        and node.parent.type == "lexical_declaration"
        and any(n.type == "const" for n in node.parent.children)
    )


def _consts(fn):
    return [n for n in g._walk(fn.child_by_field_name("body"), g._SKIP) if _const(n)]


def _native_import(root, local, source, imported):
    specs = [
        n
        for stmt in root.named_children
        if stmt.type == "import_statement"
        and g._literal(stmt.child_by_field_name("source")) == source
        and not any(n.type == "type" for n in stmt.children)
        for n in g._walk(stmt)
        if n.type == "import_specifier"
        and g._name(n.child_by_field_name("name")) == imported
        and g._name(n.child_by_field_name("alias") or n.child_by_field_name("name")) == local
        and not any(child.type == "type" for child in n.children)
    ]
    return len(specs) == 1 and i._unambiguous(root, local)

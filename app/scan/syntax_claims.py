"""Bounded checks of two syntax premises, not verification of harmful outcomes.

English title patterns only select a check. The parsers decide its result.
Files come from the supplied archive, never the model's excerpts or filesystem.
Unsupported claims, ambiguous locations, invalid input and exhausted budgets
remain unknown. Neither parser executes or imports the submitted code.
"""
from __future__ import annotations

import re
import zipfile
from bisect import bisect_right
from typing import BinaryIO

from pglast import ast, parse_sql, scan
from pglast.parser import ParseError
from tree_sitter import Language, Parser
import tree_sitter_typescript

MAX_FILE_BYTES = 256_000
MAX_PARSE_BYTES = 2_000_000
MAX_CHECKS = 40
_FUNCTIONS = {"function_declaration", "function_expression", "arrow_function", "method_definition"}
_SKIP = _FUNCTIONS | {"class_declaration", "class", "comment"}
_HOOK_CLAIM = re.compile(
    r"\b(?:hooks?|useState|useEffect)\b.*\b(?:after|follow|below)\b.*\b(?:return|exit)\b", re.I)
_SQL_CLAIM = re.compile(r"\bupdate\b.*\b(?:without|missing|no)\b.*\bwhere\b", re.I)
_CLAIMS = {
    "react_hook_order": "A React hook call follows an early return in the cited function.",
    "sql_update_where": "The cited PostgreSQL UPDATE has no WHERE clause of its own.",
}


def _result(kind: str, result: str, detail: str, **location) -> dict:
    return {"kind": kind, "result": result, "claim": _CLAIMS.get(kind, "Unsupported syntax claim."),
            "detail": detail, **location}


class SyntaxVerifier:
    """One scan's parsing budget; no cross-customer cache or model calls."""

    def __init__(self, archive: BinaryIO):
        self.archive = archive
        self.remaining = MAX_PARSE_BYTES
        self.checks = 0

    def check(self, finding: dict) -> dict:
        title = str(finding.get("title", ""))
        kind = ("react_hook_order" if _HOOK_CLAIM.search(title) else
                "sql_update_where" if _SQL_CLAIM.search(title) else "unsupported")
        def unknown(detail):
            return _result(kind, "not_checked", detail)
        if (kind == "unsupported" or re.search(r"\b(?:not|never|and|or)\b|[;\n]", title, re.I)
                or (_HOOK_CLAIM.search(title) and _SQL_CLAIM.search(title))):
            return unknown("No supported, unambiguous syntax premise recognized in the title.")
        path = finding.get("file")
        suffixes = (".tsx", ".jsx", ".ts", ".js") if kind == "react_hook_order" else (".sql",)
        if not isinstance(path, str) or not path.endswith(suffixes):
            return unknown("File type outside this check's scope.")
        if self.checks >= MAX_CHECKS:
            return unknown("Per-audit syntax check budget exhausted.")
        self.checks += 1
        try:
            with zipfile.ZipFile(self.archive) as zf:
                matches = [i for i in zf.infolist() if i.filename == path]
                if len(matches) != 1 or matches[0].is_dir():
                    return unknown("Source file missing or ambiguous in archive.")
                info = matches[0]
                if info.file_size > min(MAX_FILE_BYTES, self.remaining):
                    return unknown("File or per-audit parsing byte limit exceeded.")
                self.remaining -= info.file_size
                data = zf.read(info)
            source = data.decode("utf-8", errors="strict")
            start, end = int(finding["line_start"]), int(finding["line_end"])
            if not 1 <= start <= end <= len(source.splitlines()):
                return unknown("Invalid source coordinates.")
            if kind == "react_hook_order":
                return _react(data, start, end, path)
            return _sql(source, start, end)
        except (UnicodeError, ValueError, TypeError, KeyError, OverflowError, RecursionError,
                zipfile.BadZipFile, ParseError):
            return unknown("Source could not be parsed within this check's scope.")


def _walk(node, *, skip=frozenset()):
    todo = [node]
    while todo:
        current = todo.pop()
        yield current
        if current.type not in skip:
            todo.extend(reversed(current.named_children))


def _text(node) -> str:
    return node.text.decode("utf-8") if node is not None else ""


def _react(data: bytes, start: int, end: int, path: str) -> dict:
    kind = "react_hook_order"
    def unknown(detail):
        return _result(kind, "not_checked", detail)
    language = (tree_sitter_typescript.language_typescript() if path.endswith(".ts")
                else tree_sitter_typescript.language_tsx())
    root = Parser(Language(language)).parse(data).root_node
    if root.has_error:
        return unknown("TypeScript/JSX parser reported an error or incomplete syntax.")
    functions = [n for n in _walk(root) if n.type in _FUNCTIONS
                 and n.start_point.row + 1 <= start <= end <= n.end_point.row + 1]
    if not functions:
        return unknown("The cited range does not identify a complete function.")
    fn = min(functions, key=lambda n: n.end_byte - n.start_byte)
    if any(not (n.start_byte <= fn.start_byte and fn.end_byte <= n.end_byte) for n in functions):
        return unknown("The line range also identifies another function on the same line.")
    body = fn.child_by_field_name("body")
    name = fn.child_by_field_name("name")
    if name is None and fn.parent.type == "variable_declarator":
        name = fn.parent.child_by_field_name("name")
    if body is None or body.type != "statement_block" or not re.match(r"(?:[A-Z]|use[A-Z])", _text(name)):
        return unknown("Only named components/hooks with block bodies are supported.")

    hooks, namespaces = set(), set()
    for imp in root.named_children:
        if imp.type != "import_statement" or _text(imp.child_by_field_name("source")) not in ('"react"', "'react'"):
            continue
        if re.match(r"import\s+type\b", _text(imp)):
            return unknown("Type-only React imports do not establish a runtime hook binding.")
        for node in _walk(imp):
            if node.type == "import_specifier":
                if any(c.type == "type" for c in node.children):
                    return unknown("Type-only React imports do not establish a runtime hook binding.")
                imported = _text(node.child_by_field_name("name"))
                if re.fullmatch(r"use[A-Z]\w*", imported):
                    hooks.add(_text(node.child_by_field_name("alias") or node.child_by_field_name("name")))
            elif node.type == "identifier" and node.parent.type in ("import_clause", "namespace_import"):
                namespaces.add(_text(node))

    nodes = list(_walk(body, skip=_SKIP))
    # Imported names shadowed by parameters/declarations or reassigned anywhere
    # are not a resolved React binding. Give up instead of claiming certainty.
    bindings = hooks | namespaces
    scope = fn
    while scope is not None:
        params = scope.child_by_field_name("parameters") if scope.type in _FUNCTIONS else None
        if params and any(_text(n) in bindings for n in _walk(params)
                          if n.type in ("identifier", "shorthand_property_identifier_pattern")):
            return unknown("A parameter in this or an enclosing function may shadow the React import.")
        scope = scope.parent
    for n in _walk(root):
        if n.type in _FUNCTIONS | {"class_declaration"} and _text(n.child_by_field_name("name")) in bindings:
            return unknown("A declaration may shadow the React import.")
        if n.type in ("variable_declarator", "assignment_expression", "augmented_assignment_expression"):
            target = n.child_by_field_name("name") or n.child_by_field_name("left")
            if target and any(_text(b) in bindings for b in _walk(target)):
                return unknown("A React import may be shadowed or reassigned.")

    for n in nodes:
        if n.type != "identifier" or _text(n) not in bindings:
            continue
        parent = n.parent
        if parent.type == "call_expression" and parent.child_by_field_name("function") == n:
            continue
        if (parent.type == "member_expression" and parent.child_by_field_name("object") == n
                and parent.parent.type == "call_expression"
                and parent.parent.child_by_field_name("function") == parent):
            continue
        return unknown("React binding used indirectly; aliases and wrappers are not resolved.")

    calls = []
    for n in nodes:
        if n.type != "call_expression":
            continue
        callee = n.child_by_field_name("function")
        text = _text(callee)
        recognized = text in hooks
        if callee and callee.type == "member_expression":
            obj = _text(callee.child_by_field_name("object"))
            prop = _text(callee.child_by_field_name("property"))
            recognized = obj in namespaces and bool(re.fullmatch(r"use[A-Z]\w*", prop))
        if not recognized:
            if re.search(r"\buse[A-Z]\w*", text):
                return unknown("Unresolved custom or shadowed hook-like call.")
            continue
        statement = n.parent
        if statement.type == "variable_declarator" and statement.child_by_field_name("value") == n:
            statement = statement.parent
        if statement.type not in ("lexical_declaration", "variable_declaration", "expression_statement"):
            return unknown("Hook call outside a direct statement/initializer.")
        if statement.parent != body:
            return unknown("Conditional or nested hook calls are outside this order check.")
        calls.append(n)
    returns = [n for n in nodes if n.type == "return_statement"]
    if not calls or not returns:
        return unknown("No resolved React hook calls and returns to compare.")
    location = {"line_start": fn.start_point.row + 1, "line_end": fn.end_point.row + 1}
    if max(c.end_byte for c in calls) <= min(r.start_byte for r in returns):
        return _result(kind, "contradicted", "All resolved direct React hook calls precede every return "
                       "in this function; nested functions are excluded.", **location)
    for statement in body.named_children:
        if statement.type != "if_statement" or statement.child_by_field_name("alternative") is not None:
            continue
        branch = statement.child_by_field_name("consequence")
        if branch and branch.type == "statement_block":
            children = [c for c in branch.named_children if c.type != "comment"]
            branch = children[0] if len(children) == 1 else None
        if branch and branch.type == "return_statement" and any(c.start_byte > statement.end_byte for c in calls):
            return _result(kind, "observed", "A direct React hook call follows a top-level conditional return. "
                           "Whether renders take different paths was not tested.", **location)
    return unknown("Return/control-flow shape outside this bounded order check.")


def _sql(source: str, start: int, end: int) -> dict:
    kind = "sql_update_where"
    # pglast exposes character offsets. Use the next statement's location:
    # stmt_len is not reliable after multibyte text in pglast 7.7.
    line_starts = [0] + [i + 1 for i, char in enumerate(source) if char == "\n"]
    tokens = [t for t in scan(source) if t.name not in ("SQL_COMMENT", "C_COMMENT")]
    candidates = []
    index = 0
    statements = parse_sql(source)
    for position, statement in enumerate(statements):
        lo = statement.stmt_location
        hi = statements[position + 1].stmt_location if position + 1 < len(statements) else len(source)
        relevant = []
        while index < len(tokens) and tokens[index].start < hi:
            if tokens[index].start >= lo:
                relevant.append(tokens[index])
            index += 1
        if not relevant:
            continue
        first, last = relevant[0], relevant[-1]
        a, b = bisect_right(line_starts, first.start), bisect_right(line_starts, last.end)
        if start <= b and end >= a:
            candidates.append((statement.stmt, a, b))
    if len(candidates) != 1 or not isinstance(candidates[0][0], ast.UpdateStmt):
        return _result(kind, "not_checked", "The cited range does not identify one top-level PostgreSQL UPDATE.")
    update, a, b = candidates[0]
    # An UPDATE inside a CTE or nested statement needs its own location binding.
    todo = [update]
    updates = 0
    while todo:
        n = todo.pop()
        if isinstance(n, ast.UpdateStmt):
            updates += 1
        if isinstance(n, ast.Node):
            todo.extend(getattr(n, field) for field in n)
        elif isinstance(n, (tuple, list)):
            todo.extend(n)
    if updates != 1:
        return _result(kind, "not_checked", "Multiple UPDATE nodes inside the statement; target is ambiguous.")
    present = update.whereClause is not None
    return _result(kind, "contradicted" if present else "observed",
                   "The selected UPDATE has its own WHERE clause. Its selectivity and safety were not tested."
                   if present else "The selected UPDATE has no WHERE clause of its own. Intent and effects "
                   "were not tested; a WHERE inside a subquery/CTE does not restrict the outer UPDATE.",
                   line_start=a, line_end=b)

"""Statements of ONE Python lexical scope, block statements included.

A `try:`, `if:`, `with:` or `for:` does NOT open a scope in Python, so a route
declared inside one still hangs on the router built in the same scope, and a
handler's parameter is still request input. Written as `for node in scope.body`
a discovery pass reads direct statements only and goes silent on every such
route -- measured on four rules of one family, where the same fixture wrapped in
`try:` / `if True:` / `with suppress(...)` produced zero findings while the flat
form produced one. A conditionally registered route is ordinary FastAPI code
(feature flags, debug-only endpoints), and the pairing rules exist to compare
routes that share a router object.

Nested `def`/`class`/`lambda` DO open a scope: they are yielded, never entered.
That is the same rule `_scope_stores` in auth_read.py already follows, so blocks
and callables are treated consistently inside one pass.
"""

from __future__ import annotations

import ast
from typing import Iterator

# `ast.TryStar` exists from 3.11; every block statement Python has that can hold
# a route declaration or a route handler.
BLOCK_STATEMENTS = (
    ast.Try, ast.TryStar, ast.If, ast.With, ast.AsyncWith,
    ast.For, ast.AsyncFor, ast.While, ast.Match,
)

_SCOPE_OPENERS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)


def scope_statements(scope: ast.AST | list[ast.stmt]) -> Iterator[ast.stmt]:
    """Every statement of one scope, in source order, blocks expanded.

    Accepts the scope node or its statement list. Yields nested `def`/`class`
    declarations themselves so the caller can decide what to do with them, but
    never descends into their bodies.
    """
    if isinstance(scope, list):
        body = scope
    elif isinstance(scope, BLOCK_STATEMENTS):
        body = [stmt for arm in block_arms(scope) for stmt in arm]
    else:
        body = list(getattr(scope, "body", []))
    pending: list[ast.AST] = list(reversed(body))
    while pending:
        node = pending.pop()
        if isinstance(node, _SCOPE_OPENERS):
            if isinstance(node, ast.stmt):
                yield node
            continue
        if isinstance(node, ast.stmt):
            yield node
        pending.extend(reversed(list(ast.iter_child_nodes(node))))


def block_arms(stmt: ast.AST) -> Iterator[list[ast.stmt]]:
    """The statement lists of one block statement: bodies, handlers, cases.

    One list per arm, so a caller can scan each arm against its own copy of the
    state instead of merging facts from branches that do not both run.
    """
    for key in ("body", "orelse", "finalbody"):
        value = getattr(stmt, key, None)
        if value:
            yield value
    for handler in getattr(stmt, "handlers", ()):
        yield handler.body
    for case in getattr(stmt, "cases", ()):
        yield case.body


def route_conditions(scope: ast.AST) -> dict[ast.AST, dict[ast.AST, int]]:
    """Keep mutually exclusive declaration arms apart when pairing routes.

    This is lexical evidence, not an evaluation of feature flags. A declaration
    outside a choice remains compatible with each of its arms. Callable bodies
    are owned by another scope and are never entered. A choice inside a loop
    can take different arms across iterations, registering both routes on an
    outer router, so only choices outside the repeated body remain exclusive.
    """
    result = {}
    pending = [(scope.body, {}, False)]
    while pending:
        body, conditions, repeated = pending.pop()
        for stmt in body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                result[stmt] = conditions
            elif isinstance(stmt, ast.If):
                for index, arm in enumerate((stmt.body, stmt.orelse)):
                    pending.append((arm, conditions if repeated else {**conditions, stmt: index}, repeated))
            elif isinstance(stmt, ast.Match):
                for index, case in enumerate(stmt.cases):
                    pending.append((case.body, conditions if repeated else {**conditions, stmt: index}, repeated))
            elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
                pending.append((stmt.body, conditions, True))
                # Loop else runs once, unless an enclosing loop repeats it.
                pending.append((stmt.orelse, conditions, repeated))
            elif isinstance(stmt, ast.Try):
                for arm in (stmt.body, stmt.orelse, stmt.finalbody):
                    pending.append((arm, conditions, repeated))
                # Ordinary except handlers are alternatives; except* handlers
                # may both run and deliberately take the general path below.
                for index, handler in enumerate(stmt.handlers):
                    pending.append((handler.body, conditions if repeated else {**conditions, stmt: index}, repeated))
            elif isinstance(stmt, BLOCK_STATEMENTS):
                for arm in block_arms(stmt):
                    pending.append((arm, conditions, repeated))
    return result


def compatible_routes(left: dict[ast.AST, int], right: dict[ast.AST, int]) -> bool:
    return all(choice not in right or right[choice] == arm for choice, arm in left.items())

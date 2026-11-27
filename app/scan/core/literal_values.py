"""Statically known literal values: literal concatenations and unambiguous
bindings -- the Python twin of the JS readers' one-hop evidence
(cookie_flags_js._local_string_bindings / _leading_string).

READING, NOT GUESSING. A binding whose value is a literal (or a chain of
such bindings, or a concatenation of literals) is knowable from the file
alone, so following it is reading. What stays UNRESOLVED is exactly what
stayed unresolved before this module existed: a parameter, an f-string with
interpolation, a call result -- the callers stay silent on those.

VISIBILITY. A binding counts only where Python would run it: it must live in
the use site's own scope or an enclosing one (a sibling function's binding is
NOT evidence -- the same claim `binding-in-other-scope` pins for archive
receivers), and it must be written BEFORE the use (`call-before-binding`).

STABILITY. Only names written exactly once in the file and never a parameter
are followed -- the same filter the cookie reader already applied to its
module constants, now shared and applied to function-locals too. Chains are
bounded by _MAX_HOPS. Comprehension targets are never followed: a loop
variable's value is not knowable from the file.

f-strings are deliberately NOT resolved: "a name built by an f-string cannot
be shown ... and guessing it is how a scanner starts asserting what it cannot
see" (cookie_flags_python). Bytes and every other type stay unresolved too.
"""

from __future__ import annotations

import ast
from collections import Counter
from dataclasses import dataclass

_MAX_HOPS = 4

UNRESOLVED = object()

_SCOPE_NODES = (
    ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda,
    ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp,
)


@dataclass(frozen=True)
class _Binding:
    value: ast.AST
    scope: int  # id() of the owning scope node
    lineno: int


class LiteralContext:
    """Per-file bindings and parent links; resolve() at any use site."""

    def __init__(self, tree: ast.Module) -> None:
        self._parents: dict[int, ast.AST] = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                self._parents[id(child)] = node
        self._bindings = self._collect(tree)

    # -- collection ---------------------------------------------------------

    def _scope_of(self, node: ast.AST) -> int:
        current: ast.AST | None = node
        while current is not None and not isinstance(current, _SCOPE_NODES):
            current = self._parents.get(id(current))
        return id(current) if current is not None else 0

    def _collect(self, tree: ast.Module) -> dict[str, _Binding]:
        writes = Counter(
            node.id for node in ast.walk(tree)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
        )
        arguments = {
            node.arg for node in ast.walk(tree) if isinstance(node, ast.arg)
        }
        # These writes have no ast.Name(Store), but can replace a constant.
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    arguments.add(alias.asname or alias.name.split(".")[0])
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                arguments.add(node.name)
            elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name:
                arguments.add(node.name)
        # Comprehension targets are loop variables: never evidence.
        for node in ast.walk(tree):
            if isinstance(node, ast.comprehension):
                for name in (n for n in ast.walk(node.target) if isinstance(n, ast.Name)):
                    arguments.add(name.id)
        bindings: dict[str, _Binding] = {}
        for node in ast.walk(tree):
            target: str | None = None
            value: ast.AST | None = None
            if (isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)):
                target, value = node.targets[0].id, node.value
            elif (isinstance(node, ast.AnnAssign)
                    and isinstance(node.target, ast.Name)
                    and node.value is not None):
                target, value = node.target.id, node.value
            if (target is None or value is None or target in bindings
                    or target in arguments
                    or writes[target] != 1):
                continue
            bindings[target] = _Binding(
                value=value,
                scope=self._scope_of(node),
                lineno=getattr(node, "lineno", 0),
            )
        return bindings

    # -- resolution ---------------------------------------------------------

    def _visible(self, binding: _Binding, use: ast.AST) -> bool:
        if binding.lineno >= getattr(use, "lineno", 0):
            return False  # written after the use: `call-before-binding`
        current: ast.AST | None = use
        crossed_scope = False
        while current is not None:
            if id(current) == binding.scope:
                # A class namespace is available while executing its body,
                # but is not a closure for methods or nested classes.
                if isinstance(current, ast.ClassDef) and crossed_scope:
                    return False
                return True
            if isinstance(current, _SCOPE_NODES):
                crossed_scope = True
            current = self._parents.get(id(current))
        return False  # sibling scope: `binding-in-other-scope`

    def resolve(self, node: ast.AST | None) -> object:
        """The statically known value of ``node``, or UNRESOLVED."""
        return self._resolve(node, _MAX_HOPS)

    def _resolve(self, node: ast.AST | None, hops: int) -> object:
        if node is None:
            return UNRESOLVED
        if isinstance(node, ast.Constant):
            if node.value is None or isinstance(node.value, (str, int, float, bool)):
                return node.value
            return UNRESOLVED
        if isinstance(node, ast.Name):
            if hops <= 0:
                return UNRESOLVED
            binding = self._bindings.get(node.id)
            if binding is None or not self._visible(binding, node):
                return UNRESOLVED
            return self._resolve(binding.value, hops - 1)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._resolve(node.left, hops)
            right = self._resolve(node.right, hops)
            if isinstance(left, str) and isinstance(right, str):
                return left + right
            return UNRESOLVED
        return UNRESOLVED


def literal_context(tree: ast.Module) -> LiteralContext:
    """Build the per-file resolution context once, resolve at many sites."""
    return LiteralContext(tree)

"""Bounded source provenance, never a claim about installed modules or runtime.

Only straight-line, same-file synchronous connect()/cursor() chains qualify.
Compound control flow drops incoming and outgoing facts. Unknown calls cannot
return a driver object, and escaped objects cannot establish later provenance.
This pass enriches SQL observations; it never changes which queries are flagged.
"""
from __future__ import annotations

import ast
from collections import Counter
from dataclasses import dataclass
from itertools import islice


@dataclass(frozen=True)
class _Origin:
    kind: str
    import_line: int
    connection_line: int = 0
    cursor_line: int = 0

    def evidence(self) -> dict:
        return {"version": 1, "driver": "psycopg3", "method": "python_ast_straight_line",
                "import_line": self.import_line, "connection_line": self.connection_line,
                "cursor_line": self.cursor_line}


def _root(node):
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _writes(nodes):
    names = []
    for node in nodes:
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            names.append(node.id)
        elif isinstance(node, ast.arg):
            names.append(node.arg)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.append(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            names.extend(alias.asname or alias.name.split('.')[0] for alias in node.names)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names.append(node.name)
    return Counter(names)


class _Trace:
    def __init__(self, writes):
        self.writes = writes
        self.sinks = {}
        self.visited = Counter()

    def invalidate(self, origin, state):
        if origin is None:
            return
        # An escaped module/factory may replace any imported driver member.
        # Connections and cursors share a group so aliases cannot restore facts.
        for name, value in tuple(state.items()):
            if (origin.kind in {"module", "connect"}
                    or (value.import_line, value.connection_line)
                    == (origin.import_line, origin.connection_line)):
                state.pop(name, None)

    def assign(self, target, origin, state):
        if isinstance(target, ast.Name):
            state.pop(target.id, None)
            if origin:
                state[target.id] = origin
        else:
            for child in ast.walk(target):
                if isinstance(child, ast.Name):
                    self.invalidate(state.get(child.id), state)
                    state.pop(child.id, None)
            # Storing into an object/container escapes the assigned object.
            self.invalidate(origin, state)

    def expression(self, node, state):
        if node is None:
            return None
        if isinstance(node, ast.Name):
            return state.get(node.id)
        if isinstance(node, ast.Attribute):
            base = self.expression(node.value, state)
            if base and base.kind == "module" and node.attr == "connect":
                return _Origin("connect", base.import_line)
            return None
        if isinstance(node, ast.NamedExpr):
            origin = self.expression(node.value, state)
            self.assign(node.target, origin, state)
            return origin
        if isinstance(node, (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp,
                             ast.IfExp, ast.BoolOp, ast.Await, ast.Yield, ast.YieldFrom)):
            state.clear()
            return None
        if not isinstance(node, ast.Call):
            for child in ast.iter_child_nodes(node):
                self.invalidate(self.expression(child, state), state)
            return None
        receiver = self.expression(node.func.value, state) if isinstance(node.func, ast.Attribute) else None
        function = (self.expression(node.func, state) if not isinstance(node.func, ast.Attribute)
                    else _Origin("connect", receiver.import_line)
                    if receiver and receiver.kind == "module" and node.func.attr == "connect" else None)
        before = dict(state)
        arguments = [self.expression(arg, state) for arg in node.args]
        arguments += [self.expression(kw.value, state) for kw in node.keywords]
        # Argument evaluation may escape/mutate a receiver before the call.
        if any(before.get(name) != state.get(name) for name in before):
            receiver = function = None
        for argument in arguments:
            self.invalidate(argument, state)
        method = node.func.attr if isinstance(node.func, ast.Attribute) else None
        if method in {"execute", "executemany", "executescript", "raw", "execute_sql"}:
            origin = (receiver if receiver and receiver.kind == "cursor"
                      and method in {"execute", "executemany"} else None)
            key = (node.lineno, method)
            self.visited[key] += 1
            # Legacy findings merge same-line calls. All must agree before the
            # coarser location can carry a driver fact.
            if key not in self.sinks:
                self.sinks[key] = origin
            elif self.sinks[key] != origin:
                self.sinks[key] = None
        if function and function.kind == "connect":
            if (len(node.args) <= 1 and not any(isinstance(arg, ast.Starred) for arg in node.args)
                    and all(kw.arg is not None and kw.arg not in {"cursor_factory", "connection_factory"}
                            for kw in node.keywords) and not any(arguments)):
                return _Origin("connection", function.import_line, node.lineno)
        if receiver and receiver.kind == "connection" and method == "cursor":
            if not node.args and not node.keywords:
                return _Origin("cursor", receiver.import_line, receiver.connection_line, node.lineno)
        # A known cursor's query method preserves its source identity. Other
        # methods/wrappers can mutate the object and are deliberately opaque.
        if not (receiver and receiver.kind == "cursor" and method in {"execute", "executemany"}):
            self.invalidate(receiver, state)
        return None

    def block(self, statements, state, *, functions=True):
        for node in statements:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                if isinstance(node, ast.ImportFrom) and any(a.name == '*' for a in node.names):
                    state.clear()
                for alias in node.names:
                    bound = alias.asname or alias.name.split('.')[0]
                    state.pop(bound, None)
                    if isinstance(node, ast.Import) and alias.name == "psycopg":
                        state[bound] = _Origin("module", node.lineno)
                    elif (isinstance(node, ast.ImportFrom) and node.level == 0
                          and node.module == "psycopg" and alias.name == "connect"):
                        state[bound] = _Origin("connect", node.lineno)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                parameters = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs,
                              node.args.vararg, node.args.kwarg]
                for expr in [*node.decorator_list, *node.args.defaults, *node.args.kw_defaults,
                             node.returns, *(arg.annotation for arg in parameters if arg is not None)]:
                    self.expression(expr, state)
                # Only immutable import bindings cross a deferred scope. Never
                # freeze a connection/cursor from the time a function is defined.
                inherited = {name: value for name, value in state.items()
                             if value.kind in {"module", "connect"} and self.writes[name] == 1}
                for name in _writes(ast.walk(node)):
                    inherited.pop(name, None)
                if functions and not node.decorator_list:
                    self.block(node.body, inherited, functions=False)
                state.pop(node.name, None)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                if node.value is not None:
                    origin = self.expression(node.value, state)
                    for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
                        self.assign(target, origin, state)
            elif isinstance(node, ast.With):
                for item in node.items:
                    origin = self.expression(item.context_expr, state)
                    if not origin or origin.kind not in {"connection", "cursor"}:
                        state.clear()  # An arbitrary __enter__ can mutate objects.
                        origin = None
                    if item.optional_vars:
                        self.assign(item.optional_vars, origin, state)
                self.block(node.body, state, functions=functions)
                state.clear()  # No lifetime/transaction claims after __exit__.
            elif isinstance(node, ast.Expr):
                self.expression(node.value, state)
            elif isinstance(node, (ast.Return, ast.Raise)):
                self.expression(node.value if isinstance(node, ast.Return) else node.exc, state)
                break
            elif isinstance(node, ast.Pass):
                continue
            else:
                # Branches, loops, exception handling, classes, augmented stores
                # and deletion are outside the first provenance contract.
                state.clear()
                # No descent: a call at this location remains unknown.


def cursor_provenance(tree: ast.AST, *, max_nodes: int = 80_000) -> dict:
    nodes = list(islice(ast.walk(tree), max_nodes + 1))
    if len(nodes) > max_nodes:
        return {}
    # Visible monkeypatching/dynamic namespaces make import identity ambiguous,
    # including mutations in deferred scopes. Fail closed for the whole file.
    for node in nodes:
        if (isinstance(node, (ast.Global, ast.Nonlocal))
                or isinstance(node, ast.ImportFrom) and any(a.name == "*" for a in node.names)):
            return {}
        if isinstance(node, ast.Attribute) and (
                node.attr == "__dict__" or isinstance(node.ctx, (ast.Store, ast.Del))):
            return {}
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {
                "setattr", "delattr", "exec", "eval", "globals", "locals", "vars"}:
            return {}
    imported = {alias.asname or alias.name.split('.')[0] for node in nodes
                if isinstance(node, (ast.Import, ast.ImportFrom)) for alias in node.names
                if (isinstance(node, ast.Import) and alias.name == "psycopg")
                or (isinstance(node, ast.ImportFrom) and node.module == "psycopg")}
    # Propagate module/factory spellings solely for detecting escapes, including
    # an escape from a function declared before another function uses the import.
    aliases = set(imported)
    for node in nodes:
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and _root(node.value) in aliases:
            aliases.update(child.id for target in (node.targets if isinstance(node, ast.Assign) else [node.target])
                           for child in ast.walk(target) if isinstance(child, ast.Name))
    if any(isinstance(node, ast.Call) and any(isinstance(child, ast.Name) and child.id in aliases
           for arg in [*node.args, *(kw.value for kw in node.keywords)] for child in ast.walk(arg)) for node in nodes):
        return {}
    if any(isinstance(node, (ast.List, ast.Tuple, ast.Set, ast.Dict, ast.Return))
           and any(isinstance(child, ast.Name) and child.id in aliases for child in ast.walk(node))
           for node in nodes):
        return {}
    trace = _Trace(_writes(nodes))
    try:
        trace.block(tree.body, {})
    except RecursionError:
        return {}
    expected = Counter((node.lineno, node.func.attr) for node in nodes
                       if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute))
    return {key: origin.evidence() for key, origin in trace.sinks.items()
            if origin and trace.visited[key] == expected[key]}

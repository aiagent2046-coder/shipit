"""Bounded source provenance, never a claim about installed modules or runtime.

Only straight-line, same-file synchronous connect()/cursor() chains qualify.
Compound control flow drops incoming and outgoing facts. Unknown calls cannot
return a driver object, and escaped objects cannot establish later provenance.
This pass enriches SQL observations; it never changes which queries are flagged.
"""
from __future__ import annotations

import ast
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from itertools import islice


@dataclass(frozen=True)
class _Origin:
    kind: str
    import_line: int
    connection_line: int = 0
    cursor_line: int = 0
    epoch: int = 0

    def evidence(self) -> dict:
        return {"version": 1, "driver": "psycopg3", "method": "python_ast_straight_line",
                "import_line": self.import_line, "connection_line": self.connection_line,
                "cursor_line": self.cursor_line}


def _root(node, budget):
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        budget.spend()
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


class _WorkLimitReached(Exception):
    pass


class _Budget:
    def __init__(self, maximum):
        self.remaining = maximum

    def spend(self, amount=1):
        self.remaining -= amount
        if self.remaining < 0:
            raise _WorkLimitReached

    def walk(self, node):
        for child in ast.walk(node):
            self.spend()
            yield child


def _writes(nodes, budget):
    names = []
    for node in nodes:
        budget.spend()
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
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            names.append(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            names.append(node.rest)
    return Counter(names)


class _State:
    """Lazy revocation keeps aliases cheap and prevents escaped facts returning."""

    def __init__(self, trace):
        self.trace = trace
        self.facts = {}
        self.revoked = set()
        self.blocked = False
        self.epoch = 0
        self.revision = 0

    def valid(self, origin):
        return (origin is not None and not self.blocked and origin.epoch == self.epoch
                and (origin.import_line, origin.connection_line) not in self.revoked)

    def get(self, name):
        origin = self.facts.get(name)
        return origin if self.valid(origin) else None

    def pop(self, name):
        if name in self.facts:
            del self.facts[name]
            self.revision += 1

    def bind(self, name, origin):
        self.pop(name)
        if self.valid(origin):
            self.facts[name] = origin
            self.revision += 1

    def items(self):
        for name, origin in self.facts.items():
            self.trace.budget.spend()
            if self.valid(origin):
                yield name, origin

    def clear(self):
        self.trace.budget.spend(len(self.facts) + len(self.revoked))
        self.facts.clear()
        self.revoked.clear()
        self.epoch += 1
        self.revision += 1

    def invalidate(self, origin):
        if not self.valid(origin):
            return
        if origin.kind in {"module", "connect"}:
            # Imported modules can be shared by deferred scopes. Discard even
            # previously observed sinks if their import could later be mutated.
            self.trace.driver_escaped = True
            self.blocked = True
        else:
            self.revoked.add((origin.import_line, origin.connection_line))
        self.revision += 1


class _Trace:
    def __init__(self, writes, budget, tree):
        self.writes = writes
        self.budget = budget
        self.tree = tree
        self.sinks = {}
        self.visited = Counter()
        self.driver_escaped = False

    def invalidate(self, origin, state):
        state.invalidate(origin)

    def assign(self, target, origin, state):
        if isinstance(target, ast.Name):
            state.bind(target.id, origin)
        else:
            for child in self.budget.walk(target):
                if isinstance(child, ast.Name):
                    self.invalidate(state.get(child.id), state)
                    state.pop(child.id)
            # Storing into an object/container escapes the assigned object.
            self.invalidate(origin, state)

    def expression(self, node, state):
        self.budget.spend()
        if node is None:
            return None
        if isinstance(node, ast.Name):
            return state.get(node.id)
        if isinstance(node, ast.Attribute):
            base = self.expression(node.value, state)
            if base and base.kind == "module" and node.attr == "connect":
                return _Origin("connect", base.import_line, epoch=state.epoch)
            # A retrieved bound method retains its receiver, even when called
            # much later under another name. Unsupported attributes escape it.
            self.invalidate(base, state)
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
                    else _Origin("connect", receiver.import_line, epoch=state.epoch)
                    if receiver and receiver.kind == "module" and node.func.attr == "connect" else None)
        called_receiver = receiver
        before = state.revision
        arguments = [self.expression(arg, state) for arg in node.args]
        arguments += [self.expression(kw.value, state) for kw in node.keywords]
        # Argument evaluation may escape/mutate a receiver before the call.
        for argument in arguments:
            self.invalidate(argument, state)
        if before != state.revision:
            receiver = function = None
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
                return _Origin("connection", function.import_line, node.lineno, epoch=state.epoch)
        if receiver and receiver.kind == "connection" and method == "cursor":
            if not node.args and not node.keywords:
                return _Origin("cursor", receiver.import_line, receiver.connection_line, node.lineno, state.epoch)
        # A known cursor's query method preserves its source identity. Other
        # methods/wrappers can mutate the object and are deliberately opaque.
        if not (receiver and receiver.kind == "cursor" and method in {"execute", "executemany"}):
            self.invalidate(called_receiver, state)
        return None

    def block(self, statements, state, *, functions=True):
        for node in statements:
            self.budget.spend()
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                if isinstance(node, ast.ImportFrom) and any(a.name == '*' for a in node.names):
                    state.clear()
                for alias in node.names:
                    bound = alias.asname or alias.name.split('.')[0]
                    state.pop(bound)
                    if isinstance(node, ast.Import) and alias.name == "psycopg":
                        state.bind(bound, _Origin("module", node.lineno, epoch=state.epoch))
                    elif (isinstance(node, ast.ImportFrom) and node.level == 0
                          and node.module == "psycopg" and alias.name == "connect"):
                        state.bind(bound, _Origin("connect", node.lineno, epoch=state.epoch))
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                parameters = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs,
                              node.args.vararg, node.args.kwarg]
                for expr in [*node.decorator_list, *node.args.defaults, *node.args.kw_defaults]:
                    # Defaults are retained by the function;
                    # their objects escape even if evaluating them was inert.
                    self.invalidate(self.expression(expr, state), state)
                for expr in [*(arg.annotation for arg in parameters if arg is not None), node.returns]:
                    before = state.revision
                    self.invalidate(self.expression(expr, state), state)
                    # Postponed annotations must not manufacture bindings.
                    if before != state.revision:
                        state.clear()
                # Only immutable import bindings cross a deferred scope. Never
                # freeze a connection/cursor from the time a function is defined.
                supported_route = False
                if functions and isinstance(node, ast.FunctionDef) and node.decorator_list:
                    from app.scan.sql_input_evidence import is_supported_fastapi_route

                    supported_route = is_supported_fastapi_route(self.tree, node, spend=self.budget.spend)
                if functions and (not node.decorator_list or supported_route):
                    inherited = _State(self)
                    locals_ = _writes(self.budget.walk(node), self.budget)
                    for name, value in state.items():
                        if (value.kind in {"module", "connect"} and self.writes[name] == 1
                                and name not in locals_):
                            inherited.bind(name, _Origin(value.kind, value.import_line))
                    self.block(node.body, inherited, functions=False)
                state.pop(node.name)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                if node.value is not None:
                    origin = self.expression(node.value, state)
                    for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
                        self.assign(target, origin, state)
                if isinstance(node, ast.AnnAssign):
                    # At module/class scope CPython evaluates annotations after
                    # the value/store. Deferred annotations cannot create facts:
                    # retain an inert annotation, drop state on any side effect.
                    before = state.revision
                    if node.value is None and not isinstance(node.target, ast.Name):
                        self.invalidate(self.expression(node.target, state), state)
                    self.invalidate(self.expression(node.annotation, state), state)
                    if before != state.revision:
                        state.clear()
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


def _cursor_provenance(tree, max_nodes, budget):
    nodes = list(islice(budget.walk(tree), max_nodes + 1))
    if len(nodes) > max_nodes:
        return {}
    # Visible monkeypatching/dynamic namespaces make import identity ambiguous,
    # including mutations in deferred scopes. Fail closed for the whole file.
    imported = set()
    assignments = defaultdict(set)
    for node in nodes:
        budget.spend()
        if (isinstance(node, (ast.Global, ast.Nonlocal))
                or isinstance(node, ast.ImportFrom) and any(a.name == "*" for a in node.names)):
            return {}
        if isinstance(node, ast.Attribute) and (
                node.attr == "__dict__" or isinstance(node.ctx, (ast.Store, ast.Del))):
            return {}
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {
                "setattr", "delattr", "exec", "eval", "globals", "locals", "vars"}:
            return {}
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if ((isinstance(node, ast.Import) and alias.name == "psycopg")
                        or (isinstance(node, ast.ImportFrom) and node.module == "psycopg")):
                    imported.add(alias.asname or alias.name.split('.')[0])
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            root = _root(node.value, budget)
            if root:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    assignments[root].update(child.id for child in budget.walk(target)
                                             if isinstance(child, ast.Name))
    # Propagate module/factory spellings solely for detecting escapes, including
    # an escape from a function declared before another function uses the import.
    # A graph handles aliases independently of ast.walk's breadth-first order.
    aliases = set(imported)
    pending = deque(imported)
    while pending:
        budget.spend()
        for name in assignments.get(pending.popleft(), ()):
            budget.spend()
            if name not in aliases:
                aliases.add(name)
                pending.append(name)

    def mentions_alias(node):
        return any(isinstance(child, ast.Name) and child.id in aliases for child in budget.walk(node))

    for node in nodes:
        budget.spend()
        if isinstance(node, ast.Call) and any(mentions_alias(arg)
                for arg in [*node.args, *(kw.value for kw in node.keywords)]):
            return {}
        if isinstance(node, (ast.List, ast.Tuple, ast.Set, ast.Dict, ast.Return)) and mentions_alias(node):
            return {}
        # These escapes may occur in an unsupported/deferred block which the
        # straight-line interpreter intentionally does not enter.
        if isinstance(node, ast.Attribute) and _root(node.value, budget) in aliases and node.attr != "connect":
            return {}
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            metadata = [*node.args.defaults, *node.args.kw_defaults]
            if not isinstance(node, ast.Lambda):
                parameters = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs,
                              node.args.vararg, node.args.kwarg]
                metadata += [node.returns, *(arg.annotation for arg in parameters if arg is not None)]
            if any(expr is not None and mentions_alias(expr)
                   for expr in metadata):
                return {}
        if isinstance(node, ast.AnnAssign) and mentions_alias(node.annotation):
            return {}
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and _root(node.value, budget) in aliases:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(not isinstance(target, ast.Name) for target in targets):
                return {}
    trace = _Trace(_writes(nodes, budget), budget, tree)
    trace.block(tree.body, _State(trace))
    if trace.driver_escaped:
        return {}
    expected = Counter()
    for node in nodes:
        budget.spend()
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            expected[node.lineno, node.func.attr] += 1
    return {key: origin.evidence() for key, origin in trace.sinks.items()
            if origin and trace.visited[key] == expected[key]}


def cursor_provenance(tree: ast.AST, *, max_nodes: int = 80_000, max_work: int = 640_000) -> dict:
    """Return complete source facts, or none when either analysis budget is spent."""
    try:
        return _cursor_provenance(tree, max_nodes, _Budget(max_work))
    except (RecursionError, _WorkLimitReached):
        return {}

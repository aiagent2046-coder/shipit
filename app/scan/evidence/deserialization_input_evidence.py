"""Bounded source evidence for a FastAPI Body parameter reaching pickle.loads.

Only resolved imports, an explicit bytes Body parameter and straight-line local
assignments are supported. Facts describe source bindings and locations; they do
not establish authentication, attacker control, reachability or loader behavior.
No project code is imported or executed.
"""

from __future__ import annotations

import ast
import re
from typing import Callable

_METHODS = frozenset({'get', 'post', 'put', 'patch', 'delete', 'head', 'options'})
_ROUTERS = frozenset({'fastapi.FastAPI', 'fastapi.APIRouter'})
_ANNOTATED = frozenset({'typing.Annotated', 'typing_extensions.Annotated'})
_TYPES = frozenset({'bytes', 'str', 'int', 'float', 'bool'})
_PROTECTED = ('fastapi', 'pickle', 'typing', 'typing_extensions', 'builtins', '@router')
_NAMESPACE_CALLS = frozenset({'exec', 'eval', 'globals', 'locals', 'vars', 'setattr', 'delattr'})
_MAX_NODES = 20_000
_MAX_DEPTH = 100
_MAX_WORK = 120_000
_MAX_LOCATIONS = 128


class _Limit(Exception):
    pass


def _empty(reason: str) -> dict:
    return {'status': 'unknown', 'reason': reason, 'facts': []}


def _span(node: ast.AST) -> tuple[int, int, int, int]:
    return (node.lineno, node.col_offset, node.end_lineno, node.end_col_offset)


class _BodyTrace:
    def __init__(self, tree: ast.Module, sink: ast.Call, spend: Callable | None):
        self.tree, self.sink, self.external_spend = tree, sink, spend
        self.work = 0
        self.nodes: list[ast.AST] = []
        self.parents: dict[ast.AST, ast.AST] = {}
        self.bindings: dict[str, str] = {}
        self.module_bound: set[str] = set()
        self.router_prefixes: dict[str, str] = {}
        pending = [(tree, 0)]
        while pending:
            node, depth = pending.pop()
            self.spend()
            if len(self.nodes) >= _MAX_NODES or depth > _MAX_DEPTH:
                raise _Limit
            self.nodes.append(node)
            for child in ast.iter_child_nodes(node):
                self.parents[child] = node
                pending.append((child, depth + 1))

    def spend(self, amount: int = 1):
        if self.external_spend is not None:
            self.external_spend(amount)
        self.work += amount
        if self.work > _MAX_WORK:
            raise _Limit

    def qualified(self, node: ast.AST | None) -> str:
        self.spend()
        if isinstance(node, ast.Name):
            return self.bindings.get(node.id, '')
        if isinstance(node, ast.Attribute):
            base = self.qualified(node.value)
            return f'{base}.{node.attr}' if base else ''
        return ''

    def builtin_type(self, node: ast.AST | None) -> str:
        self.spend()
        if isinstance(node, ast.Name) and node.id in _TYPES and node.id not in self.module_bound:
            return node.id
        qualified = self.qualified(node)
        if qualified.startswith('builtins.') and qualified[9:] in _TYPES:
            return qualified[9:]
        return ''

    def body_marker(self, node: ast.AST | None) -> bool:
        self.spend()
        if not isinstance(node, ast.Call) or self.qualified(node.func) != 'fastapi.Body':
            return False
        if len(node.args) > 1 or node.args and not (isinstance(node.args[0], ast.Constant)
                                                  and node.args[0].value is Ellipsis):
            return False
        seen = set()
        for keyword in node.keywords:
            self.spend()
            if (keyword.arg not in {'default', 'media_type', 'embed', 'description', 'title',
                                    'alias', 'deprecated', 'include_in_schema'}
                    or keyword.arg in seen or not isinstance(keyword.value, ast.Constant)):
                return False
            if keyword.arg == 'default' and (node.args or keyword.value.value is not Ellipsis):
                return False
            seen.add(keyword.arg)
        return True

    def signature(self, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.arg] | None:
        """Accept evaluated metadata only when its meaning is source-resolved."""
        self.spend()
        if fn.args.posonlyargs or fn.args.vararg or fn.args.kwarg or getattr(fn, 'type_params', []):
            return None
        args = [*fn.args.args, *fn.args.kwonlyargs]
        defaults = ([None] * (len(fn.args.args) - len(fn.args.defaults))
                    + list(fn.args.defaults) + list(fn.args.kw_defaults))
        bodies = []
        for arg, default in zip(args, defaults):
            self.spend()
            annotation = arg.annotation
            if self.builtin_type(annotation) == 'bytes' and self.body_marker(default):
                bodies.append(arg)
                continue
            if (isinstance(annotation, ast.Subscript) and self.qualified(annotation.value) in _ANNOTATED
                    and isinstance(annotation.slice, ast.Tuple) and len(annotation.slice.elts) == 2
                    and self.builtin_type(annotation.slice.elts[0]) == 'bytes'
                    and self.body_marker(annotation.slice.elts[1])
                    and (default is None or isinstance(default, ast.Constant) and default.value is Ellipsis)):
                bodies.append(arg)
                continue
            if annotation is not None and not self.builtin_type(annotation):
                return None
            if default is not None and not isinstance(default, ast.Constant):
                return None
        if (fn.returns is not None and not self.builtin_type(fn.returns)
                and not (isinstance(fn.returns, ast.Constant) and fn.returns.value is None)):
            return None
        return bodies

    def route(self, fn: ast.FunctionDef | ast.AsyncFunctionDef, bodies: list[ast.arg]) -> bool:
        self.spend()
        if len(fn.decorator_list) != 1:
            return False
        call = fn.decorator_list[0]
        supported = (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                and call.func.attr in _METHODS and self.qualified(call.func.value) == '@router'
                and len(call.args) == 1 and not call.keywords
                and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str))
        if not supported or not isinstance(call.func.value, ast.Name):
            return False
        path = self.router_prefixes.get(call.func.value.id, '') + call.args[0].value
        path_names = set(re.findall(r'\{([A-Za-z_]\w*)(?::[^{}]+)?\}', path))
        # FastAPI rejects Body metadata on parameters occupying route path slots.
        return not any(arg.arg in path_names for arg in bodies)

    def module(self, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.arg] | None:
        counts: dict[str, int] = {}
        # Names bound anywhere in the module can shadow builtin annotations.
        for stmt in self.tree.body:
            self.spend()
            if isinstance(stmt, (ast.Import, ast.ImportFrom)):
                names = [alias.asname or alias.name.split('.')[0] for alias in stmt.names]
            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                names = [stmt.name]
            elif isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                names = [stmt.targets[0].id]
            elif isinstance(stmt, ast.Pass) or isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
                names = []
            else:
                return None
            for name in names:
                self.spend()
                counts[name] = counts.get(name, 0) + 1
                if counts[name] > 1:
                    return None
        self.module_bound = set(counts)
        at_definition = None
        selected = None
        for stmt in self.tree.body:
            self.spend()
            if isinstance(stmt, (ast.Import, ast.ImportFrom)):
                for alias in stmt.names:
                    self.spend()
                    if alias.name == '*' or isinstance(stmt, ast.ImportFrom) and stmt.level:
                        return None
                    name = alias.asname or alias.name.split('.')[0]
                    self.bindings[name] = ((alias.name if alias.asname else name) if isinstance(stmt, ast.Import)
                                           else f'{stmt.module}.{alias.name}')
            elif isinstance(stmt, ast.Assign):
                value, name = stmt.value, stmt.targets[0].id
                if isinstance(value, ast.Call) and self.qualified(value.func) in _ROUTERS:
                    if value.args or any(kw.arg is None or not isinstance(kw.value, ast.Constant)
                                         for kw in value.keywords):
                        return None
                    prefix = next((kw.value.value for kw in value.keywords if kw.arg == 'prefix'), '')
                    if not isinstance(prefix, str):
                        return None
                    self.router_prefixes[name] = prefix if self.qualified(value.func) == 'fastapi.APIRouter' else ''
                    self.bindings[name] = '@router'
                elif not isinstance(value, ast.Constant):
                    return None
            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                bodies = self.signature(stmt)
                if bodies is None or stmt.decorator_list and not self.route(stmt, bodies):
                    return None
                if stmt is fn:
                    if not self.route(stmt, bodies):
                        return None
                    self.spend(len(self.bindings))
                    at_definition = self.bindings.copy()
                    selected = bodies
        if at_definition is None:
            return None
        self.namespace_bindings = self.bindings.copy()
        self.bindings = at_definition
        return selected

    def stable_namespace(self) -> bool:
        for node in self.nodes:
            self.spend()
            if isinstance(node, (ast.Global, ast.Nonlocal)):
                return False
            if isinstance(node, (ast.Import, ast.ImportFrom)) and self.parents.get(node) is not self.tree:
                return False
            if isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(node.ctx, (ast.Store, ast.Del)):
                return False
            if isinstance(node, ast.Attribute):
                if node.attr == '__dict__':
                    return False
                qualified = self.qualified(node)
                if qualified.startswith(_PROTECTED):
                    allowed = qualified in _ROUTERS | _ANNOTATED | {'fastapi.Body', 'pickle.loads'}
                    allowed |= qualified.startswith('builtins.') and qualified[9:] in _TYPES
                    allowed |= (qualified.removeprefix('@router.') in _METHODS
                                and isinstance(self.parents.get(node), ast.Call)
                                and self.parents[node].func is node)
                    if not allowed:
                        return False
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                if node.id == '__builtins__':
                    return False
                if self.bindings.get(node.id, '').startswith(_PROTECTED):
                    parent = self.parents.get(node)
                    allowed = isinstance(parent, ast.Attribute) and parent.value is node
                    allowed |= isinstance(parent, ast.Call) and parent.func is node
                    allowed |= (isinstance(parent, ast.Subscript) and parent.value is node
                                and self.qualified(node) in _ANNOTATED)
                    allowed |= self.builtin_type(node) != '' and isinstance(parent, (ast.arg, ast.Tuple))
                    if not allowed:
                        return False
            if isinstance(node, ast.Call):
                if (isinstance(node.func, ast.Name)
                        and node.func.id in _NAMESPACE_CALLS):
                    return False
                qualified = self.qualified(node.func)
                if qualified.startswith('builtins.') and qualified[9:] in _NAMESPACE_CALLS:
                    return False
        return True

    def local_bindings(self, fn: ast.AST) -> set[str]:
        names = set()
        pending = [fn]
        while pending:
            node = pending.pop()
            self.spend()
            if node is not fn and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(node.name)
                continue
            if isinstance(node, ast.Lambda):
                continue
            if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                names.add(node.id)
            elif isinstance(node, ast.arg):
                names.add(node.arg)
            elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
                names.add(node.name)
            elif isinstance(node, ast.MatchMapping) and node.rest:
                names.add(node.rest)
            elif isinstance(node, ast.ExceptHandler) and node.name:
                names.add(node.name)
            pending.extend(ast.iter_child_nodes(node))
        return names

    def located(self, locations: tuple, node: ast.AST) -> tuple:
        self.spend(len(locations) + 1)
        if len(locations) >= _MAX_LOCATIONS:
            raise _Limit
        span = _span(node)
        return locations if span in locations else (*locations, span)

    def collect(self) -> dict:
        if self.sink not in self.parents:
            return _empty('sink_not_in_tree')
        fn = self.parents[self.sink]
        while fn in self.parents and not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self.spend()
            fn = self.parents[fn]
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) or self.parents.get(fn) is not self.tree:
            return _empty('unsupported_function_scope')
        bodies = self.module(fn)
        if bodies is None or len(bodies) != 1:
            return _empty('body_binding_not_established')
        at_definition = self.bindings
        self.bindings = self.namespace_bindings
        stable = self.stable_namespace()
        self.bindings = at_definition
        if not stable:
            return _empty('body_binding_not_established')
        for name in self.local_bindings(fn):
            self.spend()
            if name == 'bytes' or self.bindings.get(name, '').startswith(_PROTECTED):
                return _empty('local_binding_shadowed')
        if (self.qualified(self.sink.func) != 'pickle.loads' or len(self.sink.args) != 1
                or self.sink.keywords):
            return _empty('unsupported_deserialization_call')
        source = bodies[0]
        if len(source.arg) > 128:
            return _empty('input_identifier_unsupported')
        values = {source.arg: (_span(source),)}
        for stmt in fn.body:
            self.spend()
            value = stmt.value if isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.Expr, ast.Return)) else None
            if value is self.sink:
                argument = self.sink.args[0]
                if not isinstance(argument, ast.Name) or argument.id not in values:
                    return _empty('input_path_not_established')
                locations = self.located(self.located(values[argument.id], argument), self.sink)
                return {'status': 'established', 'reason': 'fastapi_body_straight_line_input', 'facts': [
                    {'id': 'request_input_source', 'method': 'fastapi_ast_binding',
                     'sources': [{'parameter': source.arg, 'channel': 'body', 'span': list(_span(source))}]},
                    {'id': 'local_input_flow', 'method': 'python_ast_straight_line',
                     'locations': [list(span) for span in locations]},
                ]}
            if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                if isinstance(stmt, ast.AnnAssign) and not self.builtin_type(stmt.annotation):
                    return _empty('unsupported_input_statement')
                targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                if any(not isinstance(target, ast.Name) for target in targets):
                    return _empty('unsupported_input_statement')
                if value is None:
                    continue
                if not isinstance(value, (ast.Name, ast.Constant)):
                    return _empty('unsupported_input_expression')
                locations = values.get(value.id) if isinstance(value, ast.Name) else None
                if locations is not None:
                    locations = self.located(locations, value)
                for target in targets:
                    self.spend()
                    if locations is None:
                        values.pop(target.id, None)
                    else:
                        values[target.id] = self.located(locations, target)
            elif isinstance(stmt, ast.Pass) or isinstance(stmt, ast.Expr) and isinstance(value, ast.Constant):
                pass
            else:
                return _empty('unsupported_input_statement')
        return _empty('input_path_not_established')


def analyze_deserialization_input(tree: ast.Module, sink: ast.Call, *, spend: Callable | None = None) -> dict:
    """Trace one exact AST call, propagating exceptions from the shared budget."""
    if not isinstance(tree, ast.Module) or not isinstance(sink, ast.Call):
        return _empty('invalid_input_ast')
    try:
        return _BodyTrace(tree, sink, spend).collect()
    except _Limit:
        return _empty('input_evidence_limit')

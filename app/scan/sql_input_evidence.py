"""Bounded FastAPI input evidence for a single Python SQL call.

This collector reads source only. Its symbolic SQL parts are internal inputs to
another collector; public facts contain names, types and locations, never query
text or input values. A route binding proves neither reachability nor permission.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, replace
from typing import Callable

_SPAN = tuple[int, int, int, int]
_METHODS = frozenset({'get', 'post', 'put', 'patch', 'delete', 'head', 'options'})
_TYPES = frozenset({'str', 'int', 'float', 'bool'})
_ROUTERS = frozenset({'fastapi.FastAPI', 'fastapi.APIRouter'})
_REQUESTS = frozenset({'fastapi.Request', 'starlette.requests.Request'})
_CONNECTIONS = frozenset({'psycopg.connect', 'psycopg.Connection.connect'})
_FRAMEWORK_PREFIXES = ('fastapi', '@router', 'starlette.requests')
_MAX_PARTS = 128
_MAX_TEXT = 16_000
_MAX_LOCATIONS = 256


def _span(node: ast.AST) -> _SPAN:
    return (node.lineno, node.col_offset, node.end_lineno, node.end_col_offset)


@dataclass(frozen=True)
class _Source:
    parameter: str
    channel: str
    span: _SPAN


@dataclass(frozen=True)
class _Constraint:
    kind: str
    type: str
    span: _SPAN


@dataclass(frozen=True)
class _Slot:
    source: _Source | None
    constraints: tuple[_Constraint, ...]
    locations: tuple[_SPAN, ...]


@dataclass(frozen=True)
class _Value:
    parts: tuple[str | _Slot, ...]
    type: str = ''


class _Unsupported(Exception):
    pass


class _InputLimit(_Unsupported):
    pass


class _InputTrace:
    def __init__(self, tree: ast.Module, sink: ast.Call, spend: Callable):
        self.tree, self.sink, self.spend = tree, sink, spend
        self.parents: dict[ast.AST, ast.AST] = {}
        self.nodes = []
        pending = [tree]
        while pending:
            node = pending.pop()
            spend()
            self.nodes.append(node)
            for child in ast.iter_child_nodes(node):
                self.parents[child] = node
                pending.append(child)
        self.path = set()
        node = sink
        while node in self.parents:
            spend()
            self.path.add(node)
            node = self.parents[node]
        self.bindings: dict[str, str] = {}
        self.values: dict[str, _Value] = {}
        self.requests: dict[str, _Source] = {}
        self.database: dict[str, str] = {}
        self.locals: set[str] = set()
        self.module_bound: set[str] = set()
        self.route = False
        self.tainted = False
        self.result: _Value | None = None
        self.found = False

    def walk(self, root: ast.AST, *, scope=False):
        pending = [root]
        while pending:
            node = pending.pop()
            self.spend()
            yield node
            if scope and node is not root and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                                                ast.ClassDef, ast.Lambda)):
                continue
            pending.extend(ast.iter_child_nodes(node))

    def qualified(self, node: ast.AST | None) -> str:
        self.spend()
        if isinstance(node, ast.Name):
            return self.bindings.get(node.id, '')
        if isinstance(node, ast.Attribute):
            base = self.qualified(node.value)
            return f'{base}.{node.attr}' if base else ''
        return ''

    def constant(self, node: ast.AST | None) -> bool:
        self.spend()
        return node is None or isinstance(node, ast.Constant)

    def module(self, fn: ast.FunctionDef) -> str | None:
        """Resolve imports and one locally constructed route, without executing it."""
        counts: dict[str, int] = {}
        at_definition: dict[str, str] = {}
        safe = True
        for stmt in self.tree.body:
            self.spend()
            names = []
            if isinstance(stmt, (ast.Import, ast.ImportFrom)):
                for alias in stmt.names:
                    self.spend()
                    name = alias.asname or alias.name.split('.')[0]
                    names.append(name)
                    if alias.name == '*' or (isinstance(stmt, ast.ImportFrom) and stmt.level):
                        safe = False
                    elif isinstance(stmt, ast.Import):
                        self.bindings[name] = alias.name if alias.asname else name
                    else:
                        self.bindings[name] = f'{stmt.module}.{alias.name}'
            elif isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                name, value = stmt.targets[0].id, stmt.value
                names.append(name)
                qualified = self.qualified(value)
                if isinstance(value, ast.Call) and self.qualified(value.func) in _ROUTERS:
                    if value.args or any(kw.arg is None or not self.constant(kw.value) for kw in value.keywords):
                        safe = False
                    self.bindings[name] = '@router'
                elif qualified:
                    self.bindings[name] = qualified
                elif not self.constant(value):
                    # A module-level call may mutate the imports or registered route.
                    safe = False
            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                names.append(stmt.name)
                if stmt is fn:
                    self.spend(len(self.bindings))
                    at_definition = self.bindings.copy()
                if stmt is not fn:
                    defaults = [*stmt.args.defaults,
                                *(value for value in stmt.args.kw_defaults if value is not None)]
                    if not all(self.constant(value) for value in defaults):
                        safe = False
                    if stmt.decorator_list and self.route_path(stmt) is None:
                        safe = False
                    annotations = [arg.annotation for arg in
                                   [*stmt.args.posonlyargs, *stmt.args.args, *stmt.args.kwonlyargs]]
                    annotations.append(stmt.returns)
                    for annotation in annotations:
                        self.spend()
                        if annotation is not None and not isinstance(annotation, (ast.Name, ast.Constant)):
                            safe = False
            elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
                pass
            elif not isinstance(stmt, ast.Pass):
                safe = False
            for name in names:
                self.spend()
                counts[name] = counts.get(name, 0) + 1
        self.bindings = at_definition
        self.module_bound = set(counts)
        self.spend(len(counts))
        if any(count > 1 for count in counts.values()):
            safe = False
        # Explicit mutation, namespace access, and stores through objects revoke
        # framework identity, including mutations in a deferred local function.
        for node in self.nodes:
            self.spend()
            if isinstance(node, (ast.Global, ast.Nonlocal)):
                safe = False
            if (isinstance(node, ast.Attribute) and
                    (isinstance(node.ctx, (ast.Store, ast.Del)) or node.attr == '__dict__')):
                safe = False
            if (isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
                    and self.bindings.get(node.id, '').startswith(_FRAMEWORK_PREFIXES)):
                parent = self.parents.get(node)
                permitted_use = isinstance(parent, ast.Attribute) and parent.value is node
                permitted_use |= isinstance(parent, ast.Call) and parent.func is node
                permitted_use |= (isinstance(parent, ast.Assign) and parent.value is node
                                  and self.parents.get(parent) is self.tree)
                permitted_use |= isinstance(parent, ast.arg) and parent.annotation is node
                if not permitted_use:
                    safe = False
            if isinstance(node, ast.Attribute):
                qualified = self.qualified(node)
                if qualified.startswith(('fastapi.', '@router.', 'starlette.requests.')):
                    allowed = qualified in _ROUTERS | _REQUESTS
                    allowed |= (qualified.removeprefix('@router.') in _METHODS
                                and isinstance(self.parents.get(node), ast.Call)
                                and self.parents[node].func is node)
                    if not allowed:
                        safe = False
            if isinstance(node, ast.Call):
                for arg in [*node.args, *(kw.value for kw in node.keywords)]:
                    for child in self.walk(arg):
                        if (isinstance(child, ast.Name)
                                and self.bindings.get(child.id, '').startswith(_FRAMEWORK_PREFIXES)):
                            safe = False
                if self.qualified(node.func) in {'builtins.setattr', 'builtins.delattr'}:
                    safe = False
                if (isinstance(node.func, ast.Name)
                        and node.func.id in {'exec', 'eval', 'globals', 'locals', 'setattr', 'delattr'}):
                    safe = False
        return self.route_path(fn) if safe else None

    def route_path(self, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
        self.spend()
        if len(fn.decorator_list) != 1:
            return None
        decorator = fn.decorator_list[0]
        if (not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute)
                or decorator.func.attr not in _METHODS or self.qualified(decorator.func.value) != '@router'
                or len(decorator.args) != 1 or decorator.keywords
                or not isinstance(decorator.args[0], ast.Constant)
                or not isinstance(decorator.args[0].value, str)):
            return None
        return decorator.args[0].value

    def annotation_type(self, node: ast.AST | None) -> str:
        self.spend()
        if isinstance(node, ast.Name) and node.id in _TYPES and node.id not in self.module_bound:
            return node.id
        qualified = self.qualified(node)
        if qualified.startswith('builtins.') and qualified[9:] in _TYPES:
            return qualified[9:]
        return ''

    def initialize(self, fn: ast.FunctionDef, path: str | None):
        args = [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]
        for node in self.walk(fn, scope=True):
            if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                self.locals.add(node.id)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node is not fn:
                self.locals.add(node.name)
            elif isinstance(node, ast.arg):
                self.locals.add(node.arg)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                self.locals.update(alias.asname or alias.name.split('.')[0] for alias in node.names)
            elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
                self.locals.add(node.name)
            elif isinstance(node, ast.MatchMapping) and node.rest:
                self.locals.add(node.rest)
        defaults = [*fn.args.defaults, *(value for value in fn.args.kw_defaults if value is not None)]
        annotations = [*(arg.annotation for arg in args if arg.annotation is not None)]
        if fn.returns is not None:
            annotations.append(fn.returns)
        metadata_safe = all(self.constant(value) for value in defaults)
        for annotation in annotations:
            self.spend()
            if not isinstance(annotation, (ast.Name, ast.Constant)):
                if (not isinstance(annotation, ast.Attribute)
                        or not (self.qualified(annotation) in _REQUESTS or self.annotation_type(annotation))):
                    metadata_safe = False
        self.route = path is not None and metadata_safe and not (fn.args.vararg or fn.args.kwarg or fn.args.posonlyargs)
        path_names = set(re.findall(r'\{([A-Za-z_]\w*)(?::[^{}]+)?\}', path or ''))
        for arg in args:
            self.spend()
            arg_type = self.annotation_type(arg.annotation)
            source = _Source(arg.arg, 'path' if arg.arg in path_names else 'query', _span(arg))
            if self.route and self.qualified(arg.annotation) in _REQUESTS:
                self.requests[arg.arg] = source
            constraints = (_Constraint('declared_type', arg_type, _span(arg.annotation)),) if arg_type else ()
            self.values[arg.arg] = _Value((_Slot(source if self.route and arg_type else None, constraints,
                                                (_span(arg),)),), arg_type)

    def unknown(self, node: ast.AST) -> _Value:
        return _Value((_Slot(None, (), (_span(node),)),))

    def located(self, value: _Value, node: ast.AST) -> _Value:
        self.spend(len(value.parts))
        span = _span(node)
        parts = []
        for part in value.parts:
            if isinstance(part, _Slot):
                if len(part.locations) >= _MAX_LOCATIONS:
                    raise _Unsupported
                self.spend(len(part.locations))
                part = replace(part, locations=(*part.locations, span))
            parts.append(part)
        return _Value(tuple(parts), value.type)

    def combine(self, values: list[_Value]) -> _Value:
        size = sum(len(value.parts) for value in values)
        self.spend(size)
        if size > _MAX_PARTS:
            raise _Unsupported
        parts = tuple(part for value in values for part in value.parts)
        if sum(len(part) for part in parts if isinstance(part, str)) > _MAX_TEXT:
            raise _Unsupported
        return _Value(parts, 'str')

    def request(self, node: ast.AST) -> _Value | None:
        receiver = None
        if (isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant)
                and isinstance(node.slice.value, str)):
            receiver = node.value
        elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'get'
              and len(node.args) == 1 and not node.keywords and isinstance(node.args[0], ast.Constant)
              and isinstance(node.args[0].value, str)):
            receiver = node.func.value
        if (isinstance(receiver, ast.Attribute) and receiver.attr == 'query_params'
                and isinstance(receiver.value, ast.Name) and receiver.value.id in self.requests):
            self.spend()
            source = self.requests[receiver.value.id]
            # get() can also produce None when the key is absent. It still
            # identifies an input channel, but cannot prove a string constraint.
            constraints = ((_Constraint('request_string', 'str', _span(node)),)
                           if isinstance(node, ast.Subscript) else ())
            return _Value((_Slot(replace(source, channel='query'), constraints, (_span(node),)),),
                          'str' if constraints else '')
        return None

    def expression(self, node: ast.AST) -> _Value:
        self.spend()
        if node is self.sink:
            query = node.args[0] if node.args else next((kw.value for kw in node.keywords if kw.arg == 'query'), None)
            if (query is None or any(kw.arg is None for kw in node.keywords)
                    or node.args and any(kw.arg == 'query' for kw in node.keywords)):
                raise _Unsupported
            if (not isinstance(node.func, ast.Attribute) or not isinstance(node.func.value, ast.Name)):
                self.tainted = True
            # Other arguments are evaluated before the call too. Unsupported
            # effects must not acquire a proof merely by following the query.
            for arg in [*node.args[1:], *(kw.value for kw in node.keywords if kw.value is not query)]:
                self.expression(arg)
            self.result = self.expression(query)
            self.found = True
            return self.unknown(node)
        request = self.request(node)
        if request is not None:
            return request
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if len(node.value) > _MAX_TEXT:
                raise _Unsupported
            return _Value((node.value,), 'str')
        if isinstance(node, ast.Name):
            return self.located(self.values.get(node.id, self.unknown(node)), node)
        if isinstance(node, ast.JoinedStr):
            values = []
            for part in node.values:
                self.spend()
                if isinstance(part, ast.Constant) and isinstance(part.value, str):
                    values.append(self.expression(part))
                elif isinstance(part, ast.FormattedValue) and part.conversion == -1 and part.format_spec is None:
                    value = self.expression(part.value)
                    values.append(self.located(value, part))
                else:
                    raise _Unsupported
            return self.combine(values)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = self.expression(node.left), self.expression(node.right)
            if left.type == right.type == 'str':
                return self.combine([left, right])
            raise _Unsupported
        if isinstance(node, ast.Call):
            builtin_int = ((isinstance(node.func, ast.Name) and node.func.id == 'int'
                            and 'int' not in self.locals and 'int' not in self.module_bound)
                           or self.qualified(node.func) == 'builtins.int' and
                           isinstance(node.func, ast.Name) and node.func.id not in self.locals)
            if builtin_int and len(node.args) == 1 and not node.keywords:
                value = self.expression(node.args[0])
                if len(value.parts) == 1 and isinstance(value.parts[0], _Slot):
                    part = value.parts[0]
                    if len(part.constraints) > 8:
                        raise _Unsupported
                    constraint = _Constraint('int_conversion', 'int', _span(node))
                    converted = replace(part, constraints=(*part.constraints, constraint))
                    return self.located(_Value((converted,), 'int'), node)
            qualified = self.qualified(node.func)
            safe_database = qualified in _CONNECTIONS
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                safe_database |= self.database.get(node.func.value.id) == 'connection' and node.func.attr == 'cursor'
            for arg in [*node.args, *(kw.value for kw in node.keywords)]:
                self.expression(arg)
            if not safe_database:
                self.tainted = True
            return self.unknown(node)
        if isinstance(node, (ast.NamedExpr, ast.Await, ast.Lambda, ast.ListComp, ast.SetComp,
                             ast.DictComp, ast.GeneratorExp, ast.IfExp, ast.BoolOp)):
            self.tainted = True
            raise _Unsupported
        # Unknown attribute access can execute a descriptor. Retain neither its
        # presumed value nor any proof that depends on it.
        if not isinstance(node, ast.Constant):
            self.tainted = True
        return self.unknown(node)

    def assign(self, target: ast.AST, expr: ast.AST, value: _Value):
        self.spend()
        if not isinstance(target, ast.Name):
            self.tainted = True
            return
        name = target.id
        request = self.requests.get(expr.id) if isinstance(expr, ast.Name) else None
        database = self.database.get(expr.id) if isinstance(expr, ast.Name) else None
        if isinstance(expr, ast.Call):
            if self.qualified(expr.func) in _CONNECTIONS:
                database = 'connection'
            elif (isinstance(expr.func, ast.Attribute) and isinstance(expr.func.value, ast.Name)
                  and expr.func.attr == 'cursor' and self.database.get(expr.func.value.id) == 'connection'):
                database = 'cursor'
        self.requests.pop(name, None)
        self.database.pop(name, None)
        self.bindings.pop(name, None)
        self.values[name] = self.located(value, target)
        if request is not None:
            self.requests[name] = request
        if database is not None:
            self.database[name] = database

    def block(self, body: list[ast.stmt]):
        for stmt in body:
            self.spend()
            if self.found:
                break
            if isinstance(stmt, ast.Assign):
                value = self.expression(stmt.value)
                for target in stmt.targets:
                    self.assign(target, stmt.value, value)
            elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
                if not isinstance(stmt.annotation, (ast.Name, ast.Attribute, ast.Constant)):
                    self.tainted = True
                self.assign(stmt.target, stmt.value, self.expression(stmt.value))
            elif isinstance(stmt, (ast.Expr, ast.Return)):
                if stmt.value is not None:
                    self.expression(stmt.value)
                if isinstance(stmt, ast.Return):
                    break
            elif isinstance(stmt, ast.With):
                for item in stmt.items:
                    value = self.expression(item.context_expr)
                    if item.optional_vars is not None:
                        self.assign(item.optional_vars, item.context_expr, value)
                    if (not isinstance(item.context_expr, ast.Call) or
                            not (self.qualified(item.context_expr.func) in _CONNECTIONS
                                 or isinstance(item.context_expr.func, ast.Attribute)
                                 and isinstance(item.context_expr.func.value, ast.Name)
                                 and self.database.get(item.context_expr.func.value.id) == 'connection'
                                 and item.context_expr.func.attr == 'cursor')):
                        self.tainted = True
                self.block(stmt.body)
                if not self.found:
                    self.tainted = True
            elif isinstance(stmt, ast.Pass):
                pass
            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self.tainted = True
                self.values.pop(stmt.name, None)
            elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                # Function-local annotation expressions are not executed.
                pass
            else:
                if stmt in self.path:
                    raise _Unsupported
                self.tainted = True
                self.spend(len(self.values) + len(self.requests) + len(self.database))
                self.values.clear()
                self.requests.clear()
                self.database.clear()

    def collect(self) -> dict:
        if self.sink not in self.parents:
            return _empty('unknown', 'sink_not_in_tree')
        fn = self.parents[self.sink]
        while fn in self.parents and not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self.spend()
            fn = self.parents[fn]
        if not isinstance(fn, ast.FunctionDef):
            return _empty('unsupported', 'unsupported_function_scope')
        path = self.module(fn) if self.parents.get(fn) is self.tree else None
        self.initialize(fn, path)
        # Function-local bindings shadow imports for the whole function, even
        # when the corresponding assignment occurs after the sink.
        for name in self.locals:
            self.spend()
            self.bindings.pop(name, None)
        self.block(fn.body)
        if not self.found or self.result is None or self.result.type != 'str':
            return _empty('unsupported', 'unsupported_query_expression')
        parts = []
        slots = []
        for part in self.result.parts:
            self.spend()
            if isinstance(part, str):
                parts.append(part)
            else:
                parts.append(len(slots))
                slots.append(part)
        if len(slots) > 64:
            raise _InputLimit
        if not slots:
            return {**_empty('unknown', 'no_dynamic_input'), 'parts': parts}
        if not self.route or self.tainted or any(slot.source is None for slot in slots):
            return {**_empty('unknown', 'input_path_not_established'), 'parts': parts}
        sources, locations, constraints = [], [], []
        seen_sources, seen_locations = set(), set()
        for index, slot in enumerate(slots):
            self.spend()
            source = slot.source
            if source not in seen_sources:
                seen_sources.add(source)
                sources.append({'parameter': source.parameter, 'channel': source.channel, 'span': list(source.span)})
            for span in slot.locations:
                self.spend()
                if span not in seen_locations:
                    seen_locations.add(span)
                    locations.append(list(span))
            for constraint in slot.constraints:
                self.spend()
                constraints.append({'slot': index, 'kind': constraint.kind, 'type': constraint.type,
                                    'span': list(constraint.span)})
        if _span(self.sink) not in seen_locations:
            locations.append(list(_span(self.sink)))
        if len(sources) > 64 or len(locations) > 128 or len(constraints) > 128:
            raise _InputLimit
        return {'status': 'established', 'reason': 'fastapi_straight_line_input',
                'facts': [{'id': 'request_input_source', 'method': 'fastapi_ast_binding', 'sources': sources},
                          {'id': 'local_input_flow', 'method': 'python_ast_straight_line', 'locations': locations}],
                'parts': parts, 'constraints': constraints,
                'constraint_status': 'established' if all(slot.constraints for slot in slots) else 'unknown'}


def _empty(status: str, reason: str) -> dict:
    return {'status': status, 'reason': reason, 'facts': [], 'parts': None,
            'constraints': [], 'constraint_status': 'unknown'}


def analyze_query_input(tree: ast.Module, sink: ast.Call, *, spend: Callable) -> dict:
    """Trace a selected call; caller owns the shared work budget and its exception."""
    try:
        return _InputTrace(tree, sink, spend).collect()
    except _InputLimit:
        return _empty('unsupported', 'input_evidence_limit')
    except (_Unsupported, RecursionError):
        return _empty('unsupported', 'unsupported_query_expression')


def is_supported_fastapi_route(tree: ast.Module, fn: ast.FunctionDef, *, spend: Callable) -> bool:
    """Check a supported framework decorator without implying HTTP reachability.

    This lets independent collectors enter a registered, unwrapped local body.
    It establishes no SQL, cursor, input-flow, or runtime facts of its own.
    """
    if not isinstance(fn, ast.FunctionDef):
        return False
    for stmt in tree.body:
        spend()
        if stmt is fn:
            break
    else:
        return False
    try:
        sentinel = ast.Call(func=ast.Name(id='_route_check', ctx=ast.Load()), args=[], keywords=[])
        trace = _InputTrace(tree, sentinel, spend)
        trace.initialize(fn, trace.module(fn))
        return trace.route
    except (_Unsupported, RecursionError):
        return False

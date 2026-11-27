"""Bounded source bindings for a parameter opened before ``pickle.load``.

This is a local syntactic trace, not a control-flow or trust proof. In particular,
an earlier returning branch may contain calls whose runtime effects are unknown.
We record neither its predicate nor an inferred file format. Imports are resolved
from their spelling; project modules, callbacks and path protocols are not run.
Explicit rebinding, namespace mutation and protected-object escape revoke facts.
"""

from __future__ import annotations

import ast
from typing import Callable

_MAX_NODES = 20_000
_MAX_DEPTH = 100
_MAX_WORK = 120_000
_NAMESPACE_NAMES = frozenset({'exec', 'eval', 'globals', 'locals', 'vars', 'setattr', 'delattr', '__import__'})
_NAMESPACE_CALLS = frozenset(f'builtins.{name}' for name in _NAMESPACE_NAMES)
_DYNAMIC_NAMESPACES = frozenset({'sys.modules', 'sys._getframe', 'importlib.import_module'})
_NAMESPACE_ATTRIBUTES = frozenset({'__dict__', '__globals__', '__builtins__', 'f_globals', 'f_builtins', 'f_locals'})
_PICKLE_CALLS = frozenset({'pickle.load', 'pickle.loads', 'pickle.dump', 'pickle.dumps'})
_BUILTIN_TYPES = frozenset({'str', 'bytes', 'int', 'float', 'bool', 'object'})
_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)


class _Limit(Exception):
    pass


def _empty(reason: str) -> dict:
    return {'status': 'unknown', 'reason': reason, 'facts': []}


def _span(node: ast.AST) -> list[int]:
    return [node.lineno, node.col_offset, node.end_lineno, node.end_col_offset]


class _FileTrace:
    def __init__(self, tree: ast.Module, sink: ast.Call, spend: Callable | None):
        self.tree, self.sink, self.external_spend = tree, sink, spend
        self.work = 0
        self.nodes: list[ast.AST] = []
        self.parents: dict[ast.AST, ast.AST] = {}
        self.bindings: dict[str, str] = {}
        self.protected: set[str] = {'open'}
        pending = [(tree, 0)]
        while pending:
            node, depth = pending.pop()
            self.spend()
            if len(self.nodes) >= _MAX_NODES or depth > _MAX_DEPTH:
                raise _Limit
            self.nodes.append(node)
            for child in ast.iter_child_nodes(node):
                self.spend()
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
            return self.bindings.get(node.id, 'builtins.open' if node.id == 'open' else '')
        if isinstance(node, ast.Attribute):
            base = self.qualified(node.value)
            return f'{base}.{node.attr}' if base else ''
        return ''

    def literal(self, node: ast.AST) -> bool:
        self.spend()
        if isinstance(node, ast.Constant):
            return True
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            return all(self.literal(item) for item in node.elts)
        if isinstance(node, ast.Dict):
            return all(key is not None and self.literal(key) and self.literal(value)
                       for key, value in zip(node.keys, node.values))
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
            return isinstance(node.operand, ast.Constant) and type(node.operand.value) in (int, float, complex)
        return False

    def plain_signature(self, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        self.spend()
        if fn.decorator_list or getattr(fn, 'type_params', []):
            return False
        args = [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]
        args += [arg for arg in (fn.args.vararg, fn.args.kwarg) if arg is not None]
        for annotation in [*(arg.annotation for arg in args), fn.returns]:
            self.spend()
            if (annotation is not None and not isinstance(annotation, ast.Constant)
                    and not (isinstance(annotation, ast.Name) and annotation.id in _BUILTIN_TYPES
                             and annotation.id not in self.bindings)):
                return False
        return all(value is None or self.literal(value)
                   for value in [*fn.args.defaults, *fn.args.kw_defaults])

    def module_bindings(self) -> bool:
        """Only inert top-level definitions and explicit imports are supported."""
        counts: dict[str, int] = {}
        for stmt in self.tree.body:
            self.spend()
            bound = []
            if isinstance(stmt, (ast.Import, ast.ImportFrom)):
                if isinstance(stmt, ast.ImportFrom) and stmt.level:
                    return False
                for alias in stmt.names:
                    self.spend()
                    if alias.name == '*':
                        return False
                    name = alias.asname or alias.name.split('.')[0]
                    value = ((alias.name if alias.asname else name) if isinstance(stmt, ast.Import)
                             else f'{stmt.module}.{alias.name}')
                    bound.append(name)
                    self.bindings[name] = value
            elif isinstance(stmt, _FUNCTIONS):
                bound = [stmt.name]
            elif isinstance(stmt, ast.Assign) and self.literal(stmt.value):
                if any(not isinstance(target, ast.Name) for target in stmt.targets):
                    return False
                bound = [target.id for target in stmt.targets]
            elif isinstance(stmt, ast.Pass) or isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
                pass
            else:
                return False
            for name in bound:
                self.spend()
                counts[name] = counts.get(name, 0) + 1
        self.protected.update(name for name, value in self.bindings.items()
                              if value in {'pickle', 'builtins'} or value.startswith(('pickle.', 'builtins.')))
        # Imports must be the sole definitions of the names used to resolve them.
        for name in self.protected:
            self.spend()
            if counts.get(name, 0) != (1 if name in self.bindings else 0):
                return False
        if 'open' in self.bindings and self.bindings['open'] != 'builtins.open':
            return False
        for stmt in self.tree.body:
            self.spend()
            if isinstance(stmt, _FUNCTIONS) and not self.plain_signature(stmt):
                return False
        return True

    def bound_names(self, node: ast.AST) -> tuple[str, ...]:
        self.spend()
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            return (node.id,)
        if isinstance(node, ast.arg):
            return (node.arg,)
        if isinstance(node, (*_FUNCTIONS, ast.ClassDef)):
            return (node.name,)
        if isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name:
            return (node.name,)
        if isinstance(node, ast.MatchMapping) and node.rest:
            return (node.rest,)
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            return tuple(alias.asname or alias.name.split('.')[0] for alias in node.names)
        return ()

    def stable_namespace(self) -> bool:
        """Reject visible namespace mutations; arbitrary call effects stay unknown."""
        for node in self.nodes:
            self.spend()
            parent = self.parents.get(node)
            if isinstance(node, (ast.Global, ast.Nonlocal)):
                return False
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    self.spend()
                    if alias.name == '*':
                        return False
                    module = alias.name if isinstance(node, ast.Import) else node.module or ''
                    if parent is not self.tree and module.split('.')[0] in {'pickle', 'builtins', 'sys', 'importlib'}:
                        return False
            if not (isinstance(node, (ast.Import, ast.ImportFrom)) and parent is self.tree):
                if any(name in self.protected for name in self.bound_names(node)):
                    return False
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                value = self.qualified(node)
                if (node.id == '__builtins__' or node.id in _NAMESPACE_NAMES
                        or value in _NAMESPACE_CALLS | _DYNAMIC_NAMESPACES):
                    return False
                if value in {'sys', 'importlib'} and not (isinstance(parent, ast.Attribute) and parent.value is node):
                    return False
                if node.id in self.protected:
                    allowed = (isinstance(parent, ast.Attribute) and parent.value is node
                               and value in {'pickle', 'builtins'})
                    allowed |= (isinstance(parent, ast.Call) and parent.func is node
                                and value in _PICKLE_CALLS | {'builtins.open'})
                    if not allowed:
                        return False
            if isinstance(node, ast.Attribute):
                value = self.qualified(node)
                if (node.attr in _NAMESPACE_ATTRIBUTES or value in _DYNAMIC_NAMESPACES
                        or value.startswith('sys.modules.')):
                    return False
                if value.startswith(('pickle.', 'builtins.')):
                    if (value not in _PICKLE_CALLS | {'builtins.open'}
                            or not isinstance(node.ctx, ast.Load)
                            or not isinstance(parent, ast.Call) or parent.func is not node):
                        return False
        return True

    def collect(self) -> dict:
        if self.sink not in self.parents:
            return _empty('sink_not_in_tree')
        statement = self.parents[self.sink]
        block = self.parents.get(statement)
        fn = self.parents.get(block)
        if (not isinstance(fn, _FUNCTIONS) or self.parents.get(fn) is not self.tree
                or not isinstance(block, ast.With) or len(block.items) != 1
                or block.body != [statement] or not isinstance(statement, ast.Return)
                or statement.value is not self.sink):
            return _empty('unsupported_file_input_structure')
        if not self.module_bindings() or not self.stable_namespace():
            return _empty('file_binding_not_established')
        if (self.qualified(self.sink.func) != 'pickle.load' or len(self.sink.args) != 1
                or self.sink.keywords or not isinstance(self.sink.args[0], ast.Name)):
            return _empty('unsupported_deserialization_call')
        context = block.items[0]
        call, handle = context.context_expr, context.optional_vars
        if (not isinstance(call, ast.Call) or self.qualified(call.func) != 'builtins.open'
                or not isinstance(handle, ast.Name) or not call.args
                or not isinstance(call.args[0], ast.Name)
                or self.sink.args[0].id != handle.id):
            return _empty('file_binding_not_established')
        if len(call.args) == 2 and not call.keywords:
            mode = call.args[1]
        elif len(call.args) == 1 and len(call.keywords) == 1 and call.keywords[0].arg == 'mode':
            mode = call.keywords[0].value
        else:
            return _empty('unsupported_file_open')
        if not isinstance(mode, ast.Constant) or mode.value != 'rb':
            return _empty('unsupported_file_open')
        parameters = [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]
        source = next((arg for arg in parameters if arg.arg == call.args[0].id), None)
        if source is None or source.arg == handle.id:
            return _empty('file_parameter_not_established')
        if any(len(name) > 128 for name in (fn.name, source.arg, handle.id)):
            return _empty('input_identifier_unsupported')
        # Conservatively reject parameter writes even in an earlier returning arm.
        pending = list(fn.body)
        while pending:
            node = pending.pop()
            self.spend()
            if isinstance(node, (*_FUNCTIONS, ast.ClassDef, ast.Lambda)):
                return _empty('unsupported_file_input_scope')
            if source.arg in self.bound_names(node):
                return _empty('file_parameter_rebound')
            pending.extend(ast.iter_child_nodes(node))
        for prior in fn.body:
            self.spend()
            if prior is block:
                break
            if isinstance(prior, ast.Pass) or isinstance(prior, ast.Expr) and isinstance(prior.value, ast.Constant):
                continue
            # The only supported split is an arm with an explicit final return.
            # Its runtime condition and the behavior of its calls remain unknown.
            if not (isinstance(prior, ast.If) and not prior.orelse and prior.body
                    and isinstance(prior.body[-1], ast.Return)):
                return _empty('unsupported_file_input_prefix')
        locations = [_span(source), _span(call), _span(handle), _span(self.sink)]
        return {'status': 'established', 'reason': 'file_parameter_open_binding', 'facts': [
            {'id': 'file_input_source', 'method': 'python_ast_file_binding', 'sources': [{
                'function': fn.name, 'parameter': source.arg, 'handle': handle.id, 'mode': 'rb',
                'function_span': _span(fn), 'parameter_span': locations[0],
                'open_span': locations[1], 'handle_span': locations[2],
            }]},
            {'id': 'local_input_flow', 'method': 'python_ast_file_flow', 'locations': locations},
        ]}


def analyze_deserialization_file_input(tree: ast.Module, sink: ast.Call, *, spend: Callable | None = None) -> dict:
    """Trace one exact AST call and propagate exceptions from the shared budget."""
    if not isinstance(tree, ast.Module) or not isinstance(sink, ast.Call):
        return _empty('invalid_input_ast')
    try:
        return _FileTrace(tree, sink, spend).collect()
    except _Limit:
        return _empty('input_evidence_limit')

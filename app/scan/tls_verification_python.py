"""Bounded local import/constructor provenance for TLS configuration in Python.

Bindings are followed within a module/function, in statement order. Parameters,
local rebinding, conditional bindings and member replacement cannot borrow an
import's meaning. Helpers, instance attributes and external configuration are not
resolved. No target source is imported or executed.
"""

from __future__ import annotations

import ast
from collections import Counter

_METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "options", "request"})
_CONSTRUCTORS = {
    "requests.Session": "requests.Session",
    "requests.sessions.Session": "requests.Session",
    "httpx.Client": "httpx.Client",
    "httpx.AsyncClient": "httpx.Client",
    "aiohttp.ClientSession": "aiohttp.ClientSession",
    "ssl.SSLContext": "ssl.SSLContext",
    "ssl.create_default_context": "ssl.SSLContext",
    "ssl._create_unverified_context": "ssl.SSLContext",
    "ssl._create_stdlib_context": "ssl.SSLContext",
}
_HELPERS = {"ssl._create_unverified_context", "ssl._create_stdlib_context"}
_ROOTS = {"requests", "httpx", "aiohttp", "ssl", "urllib3", "tornado", "elasticsearch"}
_MAX_NODES = 20_000
_MAX_DEPTH = 100


def _bounded(tree):
    pending, count = [(tree, 0)], 0
    while pending:
        node, depth = pending.pop()
        count += 1
        if count > _MAX_NODES or depth > _MAX_DEPTH:
            return False
        pending.extend((child, depth + 1) for child in ast.iter_child_nodes(node))
    return True


def _names(node):
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, (ast.Tuple, ast.List)):
        return set().union(*(_names(child) for child in node.elts))
    if isinstance(node, ast.Starred):
        return _names(node.value)
    return set()


def _qualified(node, bindings):
    if isinstance(node, ast.Name):
        return bindings.get(node.id, "")
    if isinstance(node, ast.Attribute):
        base = _qualified(node.value, bindings)
        return f"{base}.{node.attr}" if base else ""
    if isinstance(node, ast.Call):
        constructor = _CONSTRUCTORS.get(_qualified(node.func, bindings))
        return f"instance:{constructor}" if constructor else ""
    return ""


def _false(node):
    return isinstance(node, ast.Constant) and node.value is False


def _cert_none(node, bindings):
    return _qualified(node, bindings) == "ssl.CERT_NONE"


def _bound(body):
    """Count lexical assignments; nested callable bodies belong to another scope."""
    counts = Counter()
    pending = list(body)
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            counts[node.name] += 1
            continue
        if isinstance(node, (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            continue
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            counts.update(
                alias.asname or (alias.name.split(".")[0] if isinstance(node, ast.Import) else alias.name)
                for alias in node.names
            )
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            counts[node.id] += 1
        elif isinstance(node, ast.ExceptHandler) and node.name:
            counts[node.name] += 1
        pending.extend(ast.iter_child_nodes(node))
    return counts


def python_evidence(text):
    tree = ast.parse(text)
    if not _bounded(tree):
        return []
    found = []

    def emit(node, what, kind="certificate"):
        if len(found) < 32:
            found.append((node.lineno, what, kind))

    def inspect_call(node, bindings):
        callee = _qualified(node.func, bindings)
        kwargs = {kw.arg: kw.value for kw in node.keywords if kw.arg is not None}
        # A helper's defaults can be explicitly overridden to require a certificate.
        if callee in _HELPERS:
            cert = kwargs.get("cert_reqs", node.args[1] if len(node.args) > 1 else None)
            if not any(kw.arg is None for kw in node.keywords) and (cert is None or _cert_none(cert, bindings)):
                emit(node, f"calls {callee} with certificate verification disabled")
            return
        keys = set()
        if callee in {f"requests.{method}" for method in _METHODS} | {
            f"requests.api.{method}" for method in _METHODS
        } | {f"instance:requests.Session.{method}" for method in _METHODS}:
            keys = {"verify"}
        elif callee in {f"httpx.{method}" for method in _METHODS | {"stream"}} | {"httpx.Client", "httpx.AsyncClient"}:
            keys = {"verify"}
        elif callee == "aiohttp.TCPConnector" or callee in {
            f"instance:aiohttp.ClientSession.{method}" for method in _METHODS
        } | {"aiohttp.request"}:
            keys = {"ssl", "verify_ssl"}
        elif callee in {"tornado.httpclient.HTTPRequest", "tornado.httpclient.AsyncHTTPClient.fetch"}:
            keys = {"validate_cert"}
        elif callee == "elasticsearch.Elasticsearch":
            keys = {"verify_certs"}
        for key in keys:
            if _false(kwargs.get(key)):
                emit(node, f"passes {key}=False to {callee}")
        if callee in {
            "urllib3.PoolManager",
            "urllib3.ProxyManager",
            "urllib3.HTTPSConnectionPool",
            "urllib3.connection.HTTPSConnection",
        } and _cert_none(kwargs.get("cert_reqs"), bindings):
            emit(node, f"passes cert_reqs=ssl.CERT_NONE to {callee}")

    def expression(node, bindings):
        if node is None:
            return
        if isinstance(node, ast.Lambda):
            local = bindings.copy()
            for arg in (
                *node.args.posonlyargs,
                *node.args.args,
                *node.args.kwonlyargs,
                *([node.args.vararg] if node.args.vararg else []),
                *([node.args.kwarg] if node.args.kwarg else []),
            ):
                local.pop(arg.arg, None)
            expression(node.body, local)
            return
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            local = bindings.copy()
            for gen in node.generators:
                expression(gen.iter, local)
                for name in _names(gen.target):
                    local.pop(name, None)
                for condition in gen.ifs:
                    expression(condition, local)
            for child in [node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]:
                expression(child, local)
            return
        if isinstance(node, ast.NamedExpr):
            expression(node.value, bindings)
            assign(node.target, node.value, bindings)
            return
        if isinstance(node, ast.Call):
            inspect_call(node, bindings)
        for child in ast.iter_child_nodes(node):
            expression(child, bindings)

    def assign(target, value, bindings, report=True):
        qualified = _qualified(value, bindings)
        if isinstance(target, ast.Name):
            bindings.pop(target.id, None)
            if qualified:
                bindings[target.id] = qualified
        elif isinstance(target, ast.Attribute):
            receiver = _qualified(target.value, bindings)
            if report and receiver == "instance:ssl.SSLContext":
                if target.attr == "check_hostname" and _false(value):
                    emit(target, "sets SSLContext.check_hostname=False", "hostname")
                elif target.attr == "verify_mode" and _cert_none(value, bindings):
                    emit(target, "sets SSLContext.verify_mode=ssl.CERT_NONE")
            elif report and receiver == "instance:requests.Session" and target.attr == "verify" and _false(value):
                emit(target, "sets requests.Session.verify=False")
            # Configuration attributes preserve the known object, replacing a
            # method/module member invalidates every local alias of that object.
            if not (
                (receiver == "instance:ssl.SSLContext" and target.attr in {"check_hostname", "verify_mode"})
                or (receiver == "instance:requests.Session" and target.attr == "verify")
            ):
                if receiver:
                    for name, origin in list(bindings.items()):
                        if origin == receiver or origin.startswith(receiver + "."):
                            bindings.pop(name, None)
        else:
            for name in _names(target):
                bindings.pop(name, None)

    def scope(body, inherited, parameters=(), local=False, method_globals=None):
        counts = _bound(body)
        bindings = inherited.copy()
        if local:
            for name in counts:
                bindings.pop(name, None)
        for name in parameters:
            bindings.pop(name, None)
        deferred = []

        def block(statements, state):
            for statement in statements:
                if isinstance(statement, ast.Import):
                    for alias in statement.names:
                        name = alias.asname or alias.name.split(".")[0]
                        state.pop(name, None)
                        if alias.name.split(".")[0] in _ROOTS:
                            state[name] = alias.name if alias.asname else alias.name.split(".")[0]
                elif isinstance(statement, ast.ImportFrom):
                    if any(alias.name == "*" for alias in statement.names):
                        # An unknown exported name can replace any imported client.
                        state.clear()
                        continue
                    for alias in statement.names:
                        name = alias.asname or alias.name
                        state.pop(name, None)
                        if (
                            not statement.level
                            and statement.module
                            and statement.module.split(".")[0] in _ROOTS
                            and alias.name != "*"
                        ):
                            state[name] = f"{statement.module}.{alias.name}"
                elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    state.pop(statement.name, None)
                    deferred.append(statement)
                    for decorator in statement.decorator_list:
                        expression(decorator, state)
                    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        for default in (*statement.args.defaults, *statement.args.kw_defaults):
                            expression(default, state)
                elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
                    expression(statement.value, state)
                    targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                    for target in targets:
                        assign(target, statement.value, state)
                elif isinstance(statement, (ast.AugAssign, ast.Delete)):
                    targets = statement.targets if isinstance(statement, ast.Delete) else [statement.target]
                    if isinstance(statement, ast.AugAssign):
                        expression(statement.value, state)
                    for target in targets:
                        assign(target, None, state, report=False)
                elif isinstance(statement, (ast.With, ast.AsyncWith)):
                    for item in statement.items:
                        expression(item.context_expr, state)
                        if item.optional_vars:
                            assign(item.optional_vars, item.context_expr, state)
                    block(statement.body, state)
                elif isinstance(statement, (ast.Global, ast.Nonlocal)):
                    for name in statement.names:
                        state.pop(name, None)
                elif isinstance(statement, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.TryStar, ast.Match)):
                    before = state.copy()
                    for field, value in ast.iter_fields(statement):
                        if field in {"body", "orelse", "finalbody"}:
                            branch = before.copy()
                            if isinstance(statement, (ast.For, ast.AsyncFor)):
                                assign(statement.target, None, branch, report=False)
                            block(value, branch)
                        elif field == "handlers":
                            for handler in value:
                                branch = before.copy()
                                branch.pop(handler.name, None)
                                block(handler.body, branch)
                        elif field == "cases":
                            for case in value:
                                branch = before.copy()
                                # Pattern capture names are never imported clients.
                                for pattern in ast.walk(case.pattern):
                                    for key in ("name", "rest"):
                                        name = getattr(pattern, key, None)
                                        if isinstance(name, str):
                                            branch.pop(name, None)
                                expression(case.guard, branch)
                                block(case.body, branch)
                        elif isinstance(value, ast.AST):
                            expression(value, before)
                    if any(
                        isinstance(child, ast.ImportFrom) and any(alias.name == "*" for alias in child.names)
                        for child in ast.walk(statement)
                    ):
                        state.clear()
                    for name in _bound([statement]):
                        state.pop(name, None)
                    # A conditional member replacement also invalidates provenance.
                    for child in ast.walk(statement):
                        if isinstance(child, ast.Attribute) and isinstance(child.ctx, (ast.Store, ast.Del)):
                            assign(child, None, state, report=False)
                else:
                    expression(statement, state)

        block(body, bindings)
        stable = {name: origin for name, origin in bindings.items() if counts[name] <= 1}
        for statement in deferred:
            if isinstance(statement, ast.ClassDef):
                scope(statement.body, stable, method_globals=stable)
            else:
                args = statement.args
                names = [arg.arg for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs)]
                names += [arg.arg for arg in (args.vararg, args.kwarg) if arg]
                scope(statement.body, method_globals if method_globals is not None else stable, names, local=True)

    scope(tree.body, {})
    return found

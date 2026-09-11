"""Local AST consistency signal for Python/FastAPI object reads.

Compare get(id) with a protected read on the same repository binding in
sibling routes. This neither resolves middleware in other modules nor
proves public reachability. It never runs uploaded code or calls an LLM.
"""
from __future__ import annotations

import ast
from collections import Counter, deque
from dataclasses import dataclass, field
import stat
import zipfile
from typing import BinaryIO

from app.scan.checks import CheckFinding
from app.scan.scope_statements import BLOCK_STATEMENTS, compatible_routes, route_conditions, scope_statements
from app.scan.secrets import is_non_production_path

RULE_ID = "python-route-read-auth-consistency"
_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


def _name(node: ast.AST) -> str:
    return node.id if isinstance(node, ast.Name) else ""


# How a `Depends(...)` argument is read. This started as one pattern --
# `get_*_repo` is storage injection, EVERY other name might authorize the
# request -- and scripts/hunt_detector_escapes.py showed what that costs. Asked
# for ten rewrites of the write rule's positive fixture, a local model produced
# ten that kept the defect and escaped, all ten for this one reason: the
# storage dependency had been renamed `fetch_record_repository`,
# `load_event_service` or `fetch_log_manager`, so the route looked guarded to a
# rule that only recognised `get_*_repo`. The silence was invisible BY
# CONSTRUCTION -- a name nobody anticipated counted as authorization.
#
# Read in three layers instead. An authorization word anywhere wins first,
# because it also protects the other direction: `Depends(get_auth_service)` is
# shaped like storage, and treating it as storage would invent a gap on a route
# that plainly requires authorization. Storage is then a HEAD and a TAIL
# together, not a prefix -- `auth_service` and `security_manager` stay
# unclassified because their heads say nothing about storage. Everything else
# is unknown, and unknown still counts as authorization: this rule reports a
# disagreement it can see, never the absence of a guard it cannot see.
#
# The vocabulary here is measured, not guessed: a second hunt round produced
# get_storage_interface, get_db_connection, get_notes_pool, create_connection and
# retrieve_storage, so the tails gained connection/interface/pool/factory/
# connector and the heads gained provide/obtain/retrieve/connect. The first
# round's ten escapes are in the write rule's corpus.
#
# A person noun makes an ambiguous tail such as session unknown. Explicit
# storage tails such as repository still identify storage; an identity word
# always takes precedence. Unknown suppresses a target finding, but cannot
# establish that a sibling has an identity check.
_IDENTITY_WORDS = frozenset({
    "auth", "authenticated", "authorization", "authorize", "authorized", "claims",
    "current", "identity", "permission", "permissions", "principal", "require",
    "required", "requires", "role", "roles", "scope", "scopes", "token", "verify",
    "verified",
})
_STORAGE_HEADS = frozenset({
    "build", "connect", "create", "db", "fetch", "get", "load", "make", "new",
    "obtain", "open", "provide", "resolve", "retrieve",
})
_STORAGE_TAILS = frozenset({
    "access", "cache", "client", "connector", "connection", "dao", "database",
    "db", "factory", "fetcher", "gateway", "handle", "interface", "limiter",
    "manager", "mgr", "opener", "pool", "registry", "repo", "repository",
    "service", "session", "storage", "store", "svc", "transport",
})
# `handler` is deliberately NOT a storage tail, and it was measured rather than
# argued: the same shape appeared as a guard (`resolve_handler`) and as storage
# (`get_repository_handler`) in two hunt rounds, and adding it caught one body
# while losing two. A tail that both roles wear is not evidence of either.
# Tails that say "storage" beyond doubt. Only the OTHERS (service, manager,
# session, ...) can be talked out of storage by a person noun, because
# `get_account_repo` is a table's repository while `get_user_session` is
# indistinguishable from an identity check. Getting this wrong is not academic:
# treating every person-noun name as ambiguous made `get_account_repo` an
# unknown, which made `POST /v1/audits` look guarded, which made the product's
# own free `/v1/fixpacks` endpoint read as a disagreement.
_UNAMBIGUOUS_STORAGE_TAILS = frozenset({
    "access", "cache", "client", "connector", "connection", "dao", "database",
    "db", "factory", "fetcher", "gateway", "handle", "interface", "limiter",
    "opener", "pool", "registry", "repo", "repository", "storage", "store",
    "transport",
})
_PERSON_NOUNS = frozenset({
    "account", "actor", "admin", "agent", "customer", "member", "operator",
    "owner", "person", "staff", "subscriber", "user", "users",
})


def _dependency_role(dependency: str) -> str:
    tokens = [token for token in dependency.lower().split("_") if token]
    if not tokens:
        return "unknown"
    if _IDENTITY_WORDS & set(tokens):
        return "identity"
    if tokens[0] in _STORAGE_HEADS and tokens[-1] in _PERSON_NOUNS:
        return "identity"  # get_admin, get_acting_user, resolve_actor
    # A plural tail is the same tail: the hunt produced manage_services and
    # fetch_notes_collection(s), and refusing to read the plural lost them.
    tail = tokens[-1][:-1] if tokens[-1].endswith("s") and tokens[-1][:-1] in _STORAGE_TAILS else tokens[-1]
    if tokens[0] not in _STORAGE_HEADS or tail not in _STORAGE_TAILS:
        return "unknown"
    if tail not in _UNAMBIGUOUS_STORAGE_TAILS and _PERSON_NOUNS & set(tokens[1:-1]):
        return "unknown"
    return "storage"


def _handler_nodes(fn: ast.FunctionDef | ast.AsyncFunctionDef, *, signature: bool = False):
    """Walk one handler, excluding code owned by nested functions/classes.

    Dependency declarations belong to the signature; write/read evidence must
    come from the body. No nested callable is assumed to execute here.
    """
    pending = deque([fn.args, *fn.body] if signature else fn.body)
    while pending:
        node = pending.popleft()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        yield node
        pending.extend(ast.iter_child_nodes(node))


@dataclass
class _ScopeBindings:
    dependencies: dict[str, str]
    repositories: dict[str, tuple[int, str]]
    uncertain: frozenset[str] = frozenset()
    non_dependencies: dict[str, int] = field(default_factory=dict)


def _scope_stores(scope: ast.AST) -> Counter:
    """Visible bindings in one lexical scope, without entering child scopes."""
    names: Counter = Counter()
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        names.update(arg.arg for arg in ast.walk(scope.args) if isinstance(arg, ast.arg))
    pending = list(scope.body)
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names[node.name] += 1
            continue
        if isinstance(node, ast.Lambda):
            continue
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names.update(alias.asname or alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            names[node.id] += 1
        elif isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
            owner = _name(node.value)
            if owner:
                names[owner] += 1
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            names.update(node.names)
        elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name:
            names[node.name] += 1
        elif isinstance(node, ast.MatchMapping) and node.rest:
            names[node.rest] += 1
        pending.extend(ast.iter_child_nodes(node))
    return names


def _scope_bindings(scope: ast.AST, inherited: _ScopeBindings | None = None) -> _ScopeBindings:
    """Only stable, direct imports establish FastAPI dependency provenance.

    Rebindings, conditional imports and parameter collisions stay unknown.

    Measured, and this is why the conservatism stays: across twelve pinned public
    FastAPI projects (569 Python files; the measurement ships as
    scripts/measure_route_block_impact.py in the block-declaration change),
    the only provenance-bearing import written inside a block was
    `if TYPE_CHECKING: from fastapi import ...` -- a typing-only import that binds
    nothing at run time -- plus one docs generator's `try: from fastapi import ...`.
    Reading the first as a runtime binding would invent provenance for code that
    never binds the name, and a rule that accuses a caller-filled value on an
    invented binding is worse than one that stays silent. A runtime fallback
    import in `try:` is the shape where widening would be defensible; nothing
    measured yet depends on it.

    Keeping the old alias as unknown matters: it can still guard a target, but
    cannot provide the positive identity witness needed to accuse a sibling.
    """
    dependencies = dict(inherited.dependencies) if inherited else {}
    repositories = dict(inherited.repositories) if inherited else {}
    non_dependencies = dict(inherited.non_dependencies) if inherited else {}
    stores = _scope_stores(scope)
    uncertain = set(inherited.uncertain) if inherited else set()
    uncertain.update(stores)
    for name in stores:
        repositories.pop(name, None)
        non_dependencies.pop(name, None)
        if name in dependencies:
            dependencies[name] = "unknown_module" if "module" in dependencies[name] else "unknown"
    for node in scope.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                name = alias.asname or alias.name.split(".")[0]
                kind = None
                if isinstance(node, ast.Import) and alias.name == "fastapi":
                    kind = "module"
                elif isinstance(node, ast.ImportFrom) and alias.name in {"Depends", "Security"}:
                    kind = alias.name if node.module == "fastapi" and not node.level else "unknown"
                if kind:
                    dependencies[name] = kind if stores[name] == 1 else (
                        "unknown_module" if kind == "module" else "unknown")
                if stores[name] == 1:
                    repositories[name] = (id(scope), name)
                    uncertain.discard(name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if len(targets) == 1 and isinstance(targets[0], ast.Name) and stores[targets[0].id] == 1:
                repositories[targets[0].id] = (id(scope), targets[0].id)
                uncertain.discard(targets[0].id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and stores[node.name] == 1:
            uncertain.discard(node.name)
    # One bounded exception to unknown rebinding: a visible undecorated helper
    # whose entire body returns literal None cannot return a FastAPI marker or
    # run an identity check. Do not infer anything about wrappers with calls,
    # decorators, additional statements or later/conditional rebindings.
    for node in scope.body:
        if (not isinstance(node, ast.FunctionDef) or node.decorator_list or len(node.body) != 1
                or not isinstance(node.body[0], ast.Return)
                or not isinstance(node.body[0].value, ast.Constant) or node.body[0].value.value is not None
                or node.name not in dependencies):
            continue
        prior_imports = sum(
            1 for declaration in scope.body
            if isinstance(declaration, ast.ImportFrom) and declaration.module == "fastapi"
            and not declaration.level and declaration.lineno < node.lineno
            for alias in declaration.names
            if alias.name in {"Depends", "Security"} and (alias.asname or alias.name) == node.name)
        if stores[node.name] == 1 + prior_imports:
            non_dependencies[node.name] = node.lineno
    return _ScopeBindings(dependencies, repositories, frozenset(uncertain), non_dependencies)


def _route_candidates(scope, methods: set[str]) -> bool:
    # Block statements included: a module-level `if:`/`try:` is not a scope, so a
    # route declared inside one belongs to this scope's router. See
    # app/scan/scope_statements.py for the measurement behind this.
    return any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and len(node.decorator_list) == 1
        and isinstance(node.decorator_list[0], ast.Call)
        and isinstance(node.decorator_list[0].func, ast.Attribute)
        and node.decorator_list[0].func.attr in methods
        for node in scope_statements(scope)
    )


def _auth_scopes(tree: ast.Module):
    """Resolve lexical bindings lazily, only for scopes declaring route candidates."""
    parents = {}
    contexts = {}

    def context(scope):
        if scope not in contexts:
            parent = parents.get(scope)
            contexts[scope] = _scope_bindings(scope, context(parent) if parent else None)
        return contexts[scope]

    pending = deque([(tree, None)])
    while pending:
        node, parent = pending.popleft()
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef)):
            parents[node] = parent
            if _route_candidates(node, _METHODS):
                yield node, context(node)
            parent = node
        pending.extend((child, parent) for child in ast.iter_child_nodes(node))


def _dependency_kind(call: ast.Call, bindings: dict[str, str], non_dependencies: dict[str, int] | None = None) -> str:
    if isinstance(call.func, ast.Name):
        definition_line = non_dependencies.get(call.func.id) if non_dependencies else None
        if definition_line is not None and call.lineno > definition_line:
            return ""
        kind = bindings.get(call.func.id, "unknown" if call.func.id in {"Depends", "Security"} else "")
        return kind if kind in {"Depends", "Security", "unknown"} else ""
    if isinstance(call.func, ast.Attribute) and call.func.attr in {"Depends", "Security"}:
        owner = bindings.get(_name(call.func.value), "")
        if owner == "module":
            return call.func.attr
        return "unknown" if owner == "unknown_module" else ""
    return ""


def _dependency_argument(call: ast.Call) -> ast.AST | None:
    return call.args[0] if call.args else next(
        (keyword.value for keyword in call.keywords if keyword.arg == "dependency"), None)


def _nodes_guard_role(nodes, bindings: dict[str, str], *, named_calls: bool,
                      non_dependencies: dict[str, int] | None = None) -> str:
    role = "none"
    for node in nodes:
        if not isinstance(node, ast.Call):
            continue
        name = _name(node.func) or (node.func.attr if isinstance(node.func, ast.Attribute) else "")
        if named_calls and (name == "get_authorized"
                            or name.startswith(("require_", "authorize", "check_auth", "verify_token"))):
            return "identity"
        kind = _dependency_kind(node, bindings, non_dependencies)
        if kind:
            # Constructing a Depends/Security marker inside a running handler
            # does not execute its dependency. Only signature declarations can
            # supply the positive identity witness; unresolved body uses remain
            # conservative target guards, as other unknown dependencies do.
            dependency_role = "unknown" if named_calls or kind == "unknown" else (
                _dependency_role(_name(_dependency_argument(node))))
            if dependency_role == "identity":
                return "identity"
            if dependency_role == "unknown":
                # Includes Depends() with an inferred or unresolved callable.
                # It may authorize, but is not evidence that a sibling does.
                role = "unknown"
    return role


def _guard_role(fn: ast.FunctionDef | ast.AsyncFunctionDef, bindings: _ScopeBindings | None = None) -> str:
    bindings = bindings or _ScopeBindings({}, {})
    signature = _nodes_guard_role(ast.walk(fn.args), bindings.dependencies, named_calls=False,
                                  non_dependencies=bindings.non_dependencies)
    body_bindings = _scope_bindings(fn, bindings)
    body = _nodes_guard_role(_handler_nodes(fn), body_bindings.dependencies, named_calls=True,
                             non_dependencies=body_bindings.non_dependencies)
    return "identity" if "identity" in (signature, body) else "unknown" if "unknown" in (signature, body) else "none"


def _repository_key(fn, name: str, bindings: _ScopeBindings):
    """A stable enclosing object or the same explicit storage dependency."""
    stores = _scope_stores(fn)
    params = [*fn.args.posonlyargs, *fn.args.args]
    defaults = [*zip(params[len(params) - len(fn.args.defaults):], fn.args.defaults),
                *zip(fn.args.kwonlyargs, fn.args.kw_defaults)]
    for parameter, default in defaults:
        if parameter.arg != name or stores[name] != 1 or not isinstance(default, ast.Call):
            continue
        if _dependency_kind(default, bindings.dependencies, bindings.non_dependencies) not in {"Depends", "Security"}:
            continue
        dependency = _name(_dependency_argument(default))
        if dependency and dependency not in bindings.uncertain and _dependency_role(dependency) == "storage":
            return ("dependency", dependency)
    return bindings.repositories.get(name) if not stores[name] else None


def _route_declaration(node, routers: dict[str, tuple[str, int]], methods: set[str]):
    """The route a decorated function declares on a router this scope built.

    One decorator only: an unrecognized second decorator could be the guard, and
    guessing which is how a scanner starts asserting what it cannot see.
    """
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or len(node.decorator_list) != 1:
        return None
    for dec in node.decorator_list:
        if (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)
                and _name(dec.func.value) in routers and dec.func.attr in methods
                and dec.args and isinstance(dec.args[0], ast.Constant)
                and isinstance(dec.args[0].value, str)
                and not any(k.arg == "dependencies" for k in dec.keywords)):
            return (node, dec.args[0].value, dec.func.attr, routers[_name(dec.func.value)])
    return None


def _scope_routes(scope, factories: set[str], methods: set[str]):
    """Route declarations of one scope, blocks included, attached to their router.

    Separate names and successive assignments to the same name are separate
    objects. Unsupported bindings invalidate that name instead of borrowing a
    sibling from a router whose identity is no longer known.

    A route declared inside a module-level `try:`/`if:`/`with:`/`for:` is read,
    because the block opens no scope and the route still hangs on the router
    built here. An ASSIGNMENT inside such a block is not read: a router built
    conditionally has an uncertain identity, so the invalidation pass below keeps
    that name unknown rather than attributing routes to a guessed object.
    """
    if not _route_candidates(scope, methods):
        return []
    routers: dict[str, tuple[str, int]] = {}
    available_factories = set(factories)
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        available_factories.difference_update(arg.arg for arg in ast.walk(scope.args) if isinstance(arg, ast.arg))
    routes = []
    for node in scope.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if len(node.decorator_list) != 1:
                # Another decorator can change the callable or its contract.
                # Ignoring it also avoids rescanning one body per decorator.
                routers.pop(node.name, None)
                available_factories.discard(node.name)
                continue
            found = _route_declaration(node, routers, methods)
            if found:
                routes.append(found)
            routers.pop(node.name, None)
            available_factories.discard(node.name)
            continue
        # Only direct assignments from a known factory establish an object.
        # Any other visible store to an existing router invalidates it.
        for name in _scope_stores(ast.Module(body=[node], type_ignores=[])):
            routers.pop(name, None)
            available_factories.discard(name)
        if isinstance(node, ast.ClassDef):
            routers.pop(node.name, None)
            available_factories.discard(node.name)
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                name = alias.asname or alias.name.split(".")[0]
                routers.pop(name, None)
                if (isinstance(node, ast.ImportFrom) and node.module == "fastapi"
                        and alias.name in {"APIRouter", "FastAPI"}):
                    available_factories.add(name)
                else:
                    available_factories.discard(name)
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, ast.Call) and _name(node.value.func) in available_factories
                and not any(k.arg == "dependencies" for k in node.value.keywords)):
            name = node.targets[0].id
            routers[name] = (name, node.lineno)
        if isinstance(node, BLOCK_STATEMENTS):
            for inner in scope_statements(node):
                found = _route_declaration(inner, routers, methods)
                if found:
                    routes.append(found)
    return routes


def scan_auth_read(fileobj: BinaryIO) -> list[CheckFinding]:
    findings = []
    with zipfile.ZipFile(fileobj) as archive:
        for info in archive.infolist():
            path = info.filename
            if (not path.endswith(".py") or info.file_size > 2_000_000
                    or stat.S_ISLNK(info.external_attr >> 16)
                    or is_non_production_path(path)
                    or any(p in path.split("/") for p in ("vendor", "venv", ".venv", "node_modules"))):
                continue
            try:
                raw = archive.read(info)
                if b"@" not in raw:
                    continue
                tree = ast.parse(raw.decode("utf-8"))
            except (SyntaxError, UnicodeError, ValueError, RecursionError):
                continue
            factories = {
                alias.asname or alias.name for node in tree.body
                if isinstance(node, ast.ImportFrom) and node.module == "fastapi"
                for alias in node.names if alias.name in {"APIRouter", "FastAPI"}
            }
            # ROUTERS AND ROUTES ARE COLLECTED PER SCOPE, not from tree.body.
            #
            # Reading only the module body missed the router factory --
            #
            #     def get_router():
            #         router = APIRouter()
            #         @router.get("/audits/{audit_id}") ...
            #         return router
            #
            # -- which is ordinary FastAPI structure, and the identical pair of
            # routes at module level was reported. Found by
            # scripts/hunt_detector_escapes.py: every one of ten model-written
            # variations wrapped the fixture in a factory, and the detector
            # went silent on all ten while the defect stayed exactly the same.
            #
            # Scopes are kept SEPARATE rather than flattened with ast.walk. The
            # rule's claim is that two routes on the same router disagree about
            # authorisation, and a router built inside one function is not the
            # router built inside another -- flattening would pair routes that
            # never share an object and report a disagreement that does not
            # exist. Each scope is therefore analysed on its own terms.
            #
            # Within one scope, block statements ARE read: `try:`, `if:`,
            # `with:` and `for:` open no scope in Python, so a conditionally
            # registered route still hangs on the router built here. Reading only
            # a scope's direct statements made every such route invisible --
            # measured, the same pair wrapped in `try:` / `if True:` /
            # `with suppress(...)` reported nothing while the flat form reported
            # the disagreement. An assignment inside a block still does not
            # establish a router: see _scope_routes.
            for scope, bindings in _auth_scopes(tree):
                findings.extend(_scope_findings(scope, factories, path, bindings))
    return findings


def _scope_findings(scope, factories: set[str], filename: str,
                    bindings: _ScopeBindings | None = None) -> list[CheckFinding]:
    """Routes declared in one scope, blocks included, and their disagreements."""
    findings: list[CheckFinding] = []
    routes = _scope_routes(scope, factories, _METHODS)
    bindings = bindings or _scope_bindings(scope)
    roles = {fn: _guard_role(fn, bindings) for fn, _, _, _ in routes}
    protected = {}
    conditions = route_conditions(scope)
    for fn, route, method, router in routes:
        identity_dependency = (
            _nodes_guard_role(ast.walk(fn.args), bindings.dependencies, named_calls=False,
                              non_dependencies=bindings.non_dependencies) == "identity")
        for node in _handler_nodes(fn):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            repo = _name(node.func.value)
            key = _repository_key(fn, repo, bindings) if repo else None
            if key is None:
                continue
            if node.func.attr == "get_authorized":
                protected.setdefault((router, key), []).append(
                    (fn, route, node.lineno, f"calls {repo}.get_authorized"))
            elif method == "get" and identity_dependency and node.func.attr in {"get", "list"}:
                protected.setdefault((router, key), []).append((
                    fn, route, node.lineno, f"declares an identity dependency and calls {repo}.{node.func.attr}"))
    for fn, route, _, router in routes:
        if roles[fn] != "none" or len(fn.decorator_list) != 1:
            continue
        for node in _handler_nodes(fn):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "get" and node.args):
                continue
            repo = _name(node.func.value)
            arg = _name(node.args[0])
            key = _repository_key(fn, repo, bindings) if repo else None
            if (router, key) not in protected or not arg or "{" + arg + "}" not in route:
                continue
            witness = next((item for item in protected[router, key]
                            if compatible_routes(conditions[fn], conditions[item[0]])), None)
            if witness is None:
                continue
            _, sibling, line, evidence = witness
            findings.append(_finding(filename, node.lineno, route, sibling, line, repo, arg, evidence))
            # One finding per route. The loop is over every `.get(` in the
            # handler, and a route that reads twice has one disagreement.
            break
    return findings


def _finding(path: str, lineno: int, route: str, sibling: str,
             line: int, repo: str, arg: str, evidence: str) -> CheckFinding:
    return CheckFinding(
        RULE_ID, "Object lookup differs from protected sibling routes",
        "medium", 0.8, "Auth", file=path, line=lineno,
        explanation=(f"{route} calls {repo}.get({arg}); sibling {sibling} "
                     f"{evidence} on the same repository binding at line {line}. "
                     "No local authorization guard was recognized. Global middleware, "
                     "router mounting and public reachability have not been resolved."),
        fix_hint=("Inspect route and middleware authorization. If the sibling's ownership "
                  "contract applies, require its token here and test wrong-owner access "
                  "with synthetic records before changing the route."),
    )

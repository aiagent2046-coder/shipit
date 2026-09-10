"""Local AST consistency signal for Python/FastAPI object reads.

Compare get(id) with get_authorized(id, token) on the same repository name
in sibling routes. This neither resolves middleware in other modules nor
proves public reachability. It never runs uploaded code or calls an LLM.
"""
from __future__ import annotations

import ast
import stat
import zipfile
from typing import BinaryIO

from app.scan.checks import CheckFinding
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
# A PERSON NOUN in the middle turns a storage-shaped name back into an unknown
# one, and that is a deliberate trade in the other direction. `get_user_session`
# and `fetch_user_repository` are indistinguishable by shape, and reading the
# second as storage while the first is a guard would put a wrong claim in a
# report; the cost is silence on a genuinely unguarded route that injects a
# users' repository. Silence is the side this rule errs on.
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
    # A plural tail is the same tail: the hunt produced manage_services and
    # fetch_notes_collection(s), and refusing to read the plural lost them.
    tail = tokens[-1][:-1] if tokens[-1].endswith("s") and tokens[-1][:-1] in _STORAGE_TAILS else tokens[-1]
    if tokens[0] not in _STORAGE_HEADS or tail not in _STORAGE_TAILS:
        return "unknown"
    if tail not in _UNAMBIGUOUS_STORAGE_TAILS and _PERSON_NOUNS & set(tokens[1:-1]):
        return "unknown"
    return "storage"


def _guarded(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        name = _name(node.func) or (node.func.attr if isinstance(node.func, ast.Attribute) else "")
        if name == "get_authorized" or name.startswith(("require_", "authorize", "check_auth", "verify_token")):
            return True
        if name == "Depends" and node.args:
            # Repository injection supplies storage, not caller identity.
            if _dependency_role(_name(node.args[0])) != "storage":
                return True  # identity, or a name this scanner cannot classify
    return False


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
                tree = ast.parse(archive.read(info).decode("utf-8"))
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
            scopes = [tree]
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    scopes.append(node)

            for scope in scopes:
                findings.extend(_scope_findings(scope, factories, path))
    return findings


def _scope_findings(scope, factories: set[str], filename: str) -> list[CheckFinding]:
    """Routes declared directly in one scope's body, and their disagreements."""
    findings: list[CheckFinding] = []
    routers = {
        _name(node.targets[0]) for node in scope.body
        if isinstance(node, ast.Assign) and len(node.targets) == 1
        and isinstance(node.value, ast.Call) and _name(node.value.func) in factories
        and not any(k.arg == "dependencies" for k in node.value.keywords)
    }
    if not routers:
        return findings
    routes = []
    for fn in scope.body:
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in fn.decorator_list:
            if (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)
                    and _name(dec.func.value) in routers and dec.func.attr in _METHODS
                    and dec.args and isinstance(dec.args[0], ast.Constant)
                    and isinstance(dec.args[0].value, str)
                    and not any(k.arg == "dependencies" for k in dec.keywords)):
                routes.append((fn, dec.args[0].value))
    protected = {}
    for fn, route in routes:
        for node in ast.walk(fn):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "get_authorized" and _name(node.func.value)):
                protected.setdefault(_name(node.func.value), (route, node.lineno))
    for fn, route in routes:
        if _guarded(fn) or len(fn.decorator_list) != 1:
            continue
        for node in ast.walk(fn):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "get" and node.args):
                continue
            repo = _name(node.func.value)
            arg = _name(node.args[0])
            if repo not in protected or not arg or "{" + arg + "}" not in route:
                continue
            sibling, line = protected[repo]
            findings.append(_finding(filename, node.lineno, route, sibling, line, repo, arg))
            # One finding per route. The loop is over every `.get(` in the
            # handler, and a route that reads twice has one disagreement.
            break
    return findings


def _finding(path: str, lineno: int, route: str, sibling: str,
             line: int, repo: str, arg: str) -> CheckFinding:
    return CheckFinding(
        RULE_ID, "Object lookup differs from protected sibling routes",
        "medium", 0.8, "Auth", file=path, line=lineno,
        explanation=(f"{route} calls {repo}.get({arg}); sibling {sibling} "
                     f"calls {repo}.get_authorized at line {line}. "
                     "No local authorization guard was recognized. Global middleware, "
                     "router mounting and public reachability have not been resolved."),
        fix_hint=("Inspect route and middleware authorization. If the sibling's ownership "
                  "contract applies, require its token here and test wrong-owner access "
                  "with synthetic records before changing the route."),
    )

"""Local AST consistency signal for Python/FastAPI routes that change data.

A route that writes (POST/PUT/PATCH/DELETE) is compared against a sibling route
on the same router that DOES show an identity check. This neither resolves
middleware in other modules nor proves public reachability: the claim is a
disagreement between two routes that share a router object, and the explanation
says exactly that and no more. It never runs uploaded code and never calls a
model.

The identity-check vocabulary is IMPORTED from app/scan/auth_read.py rather than
copied. Both rules ask the same question -- "is a guard visible in this
handler?" -- and two copies would be free to drift until the same route counted
as guarded in one finding and unguarded in another, in one report, for
unchanged bytes.

Silent, deliberately, in three shapes:

  * a write route with no guarded sibling. The read-side rule pairs two routes
    that disagree; with nothing to disagree with, "no guard visible" is a claim
    about middleware this scanner cannot see, and an unguarded POST is ordinary
    code. Silence here is not a clean bill.
  * conventionally public paths (login, webhook, health, ...), matched as whole
    path SEGMENTS. A login route that demanded an identity first could not let
    anybody log in; flagging it would be a claim about intent, not about code.
    Matching a segment rather than a substring keeps /auth/login-count from
    being excused by /auth/login.
  * a route whose handler carries more than one decorator, matching the read
    rule: an unrecognized decorator could be the guard, and guessing which is
    how a scanner starts asserting what it cannot see.

A route that writes through a method name outside _WRITE_CALLS is not reported
either. Deriving "this changes stored state" from the HTTP verb alone would
catch a POST that only computes a response, so the corpus pins that difference
both ways.
"""

from __future__ import annotations

import ast
import stat
import zipfile
from typing import BinaryIO

from app.scan.auth_read import _guarded, _name
from app.scan.checks import CheckFinding
from app.scan.secrets import is_non_production_path

RULE_ID = "python-route-write-auth-consistency"

# Deleting is a write: the argument a route needs before it may destroy someone
# else's record is the same argument it needs before it may create one.
_MUTATION_METHODS = {"post", "put", "patch", "delete"}

# Method names that change stored state. Kept as a plain list of names so a
# reviewer can read what the rule knows; a name that is missing from it costs a
# missed finding, not a wrong one.
_WRITE_CALLS = frozenset({
    "add", "commit", "create", "delete", "grant", "insert", "mutate", "persist",
    "remove", "replace", "revoke", "save", "store", "update", "upsert", "write",
})

_PUBLIC_SEGMENTS = frozenset({
    "callback", "callbacks", "health", "healthz", "login", "logout", "oauth",
    "ready", "readyz", "refresh", "register", "sign-in", "sign-up", "signin",
    "signup", "token", "webhook", "webhooks",
})


def _write_call(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, int] | None:
    """The first call in the handler that changes stored state, and its line."""
    for node in ast.walk(fn):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr in _WRITE_CALLS):
            return node.func.attr, node.lineno
    return None


def _public_path(route: str) -> bool:
    return any(segment in _PUBLIC_SEGMENTS for segment in route.split("/"))


def scan_auth_write(fileobj: BinaryIO) -> list[CheckFinding]:
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
            # Scopes are kept separate for the same reason the read rule keeps
            # them separate: the claim is that two routes on the SAME router
            # disagree, and a router built inside one function is not the router
            # built inside another. Flattening would pair routes that never
            # share an object and report a disagreement that does not exist.
            scopes: list[ast.AST] = [tree]
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    scopes.append(node)
            for scope in scopes:
                findings.extend(_scope_findings(scope, factories, path))
    return findings


def _scope_findings(scope, factories: set[str], filename: str) -> list[CheckFinding]:
    """Write routes declared in one scope, and their disagreement with siblings."""
    findings: list[CheckFinding] = []
    routers = {
        _name(node.targets[0]) for node in scope.body
        if isinstance(node, ast.Assign) and len(node.targets) == 1
        and isinstance(node.value, ast.Call) and _name(node.value.func) in factories
        and not any(k.arg == "dependencies" for k in node.value.keywords)
    }
    if not routers:
        return findings
    routes: list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, str, str]] = []
    for fn in scope.body:
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in fn.decorator_list:
            if (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)
                    and _name(dec.func.value) in routers and dec.func.attr in _MUTATION_METHODS
                    and dec.args and isinstance(dec.args[0], ast.Constant)
                    and isinstance(dec.args[0].value, str)
                    and not any(k.arg == "dependencies" for k in dec.keywords)):
                routes.append((fn, dec.args[0].value, dec.func.attr))
    # One sibling is enough to make the disagreement observable, and the FIRST
    # one in source order is cited so the same repository always produces the
    # same finding text.
    sibling = next(((fn, route, method) for fn, route, method in routes if _guarded(fn)), None)
    if sibling is None:
        return findings
    sibling_fn, sibling_route, sibling_method = sibling
    for fn, route, method in routes:
        if _guarded(fn) or len(fn.decorator_list) != 1 or _public_path(route):
            continue
        call = _write_call(fn)
        if call is None:
            continue
        findings.append(_finding(filename, route, method, call, sibling_route,
                                 sibling_method, sibling_fn.lineno))
    return findings


def _finding(path: str, route: str, method: str, call: tuple[str, int],
             sibling_route: str, sibling_method: str, sibling_line: int) -> CheckFinding:
    name, line = call
    return CheckFinding(
        RULE_ID, "Write route shows no local identity check",
        "medium", 0.8, "Auth", file=path, line=line,
        explanation=(f"{method.upper()} {route} changes stored state ({name}) and no local identity "
                     f"check was recognized in its handler, while sibling {sibling_method.upper()} "
                     f"{sibling_route} on the same router declares one at line {sibling_line}. "
                     "Router mounting, global middleware and public reachability have not been resolved."),
        fix_hint=("Confirm whether this route is meant to be reachable without an identity -- a webhook "
                  "or an onboarding step would be. If not, require the contract its sibling route uses, "
                  "and test a write with a foreign or absent credential against synthetic records."),
    )

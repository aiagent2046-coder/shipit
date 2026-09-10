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


def _guarded(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        name = _name(node.func) or (node.func.attr if isinstance(node.func, ast.Attribute) else "")
        if name == "get_authorized" or name.startswith(("require_", "authorize", "check_auth", "verify_token")):
            return True
        if name == "Depends" and node.args:
            # Repository injection supplies storage, not caller identity.
            dependency = _name(node.args[0])
            if not dependency.startswith("get_") or not dependency.endswith("_repo"):
                return True  # unknown dependency could authorize the request
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

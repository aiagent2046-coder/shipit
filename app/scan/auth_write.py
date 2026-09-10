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

Silent, deliberately, in these shapes:

  * a write route with no guarded sibling. The read-side rule pairs two routes
    that disagree; with nothing to disagree with, "no guard visible" is a claim
    about middleware this scanner cannot see, and an unguarded POST is ordinary
    code. Silence here is not a clean bill.
  * conventionally public paths (login, webhook, notification, health, ...),
    matched as whole path SEGMENTS. A login route that demanded an identity
    first could not let anybody log in, and a provider's payment notification
    arrives from the provider; flagging either would be a claim about intent,
    not about code. Matching a segment rather than a substring keeps
    /auth/login-count from being excused by /auth/login.
  * a route whose handler carries more than one decorator, matching the read
    rule: an unrecognized decorator could be the guard, and guessing which is
    how a scanner starts asserting what it cannot see.

What counts as a write was measured, not assumed. Round one of
scripts/hunt_detector_escapes.py escaped ten times out of ten against a
`Depends(get_*_repo)` vocabulary; round two, against the fixed one, escaped with
`createRecord`, `modify`, `erase` and handlers that open their own connection and
run `cursor.execute("INSERT ...")`. So the write evidence is now the leading
token of the call name (createRecord and create_record both read as `create`),
or a statement runner whose first argument OPENS with a mutating SQL keyword --
and a SELECT does not count. Deriving it from the HTTP verb alone would catch a
POST that only computes a response, so the corpus pins that difference both ways.

A scheduler is not storage: `add_task`/`create_task` are excluded by full name,
because the product's own YooKassa handler was reported for scheduling a
coroutine.

WHAT REMAINS SILENT, measured rather than argued. Five hunt rounds against this
rule; the counts below are of bodies on disk that a reader can check:

  * round 1, before the fix: 10 of 10 escaped, all by renaming the repository;
  * round 2, after the classifier was widened: 13 of 13 judgeable bodies caught
    (6 more were unreadable -- see the note about the hunt's own dump);
  * round 5, against the shipped code: 2 of 9 judgeable bodies caught. The other
    seven are rewrites that removed the evidence -- both routes protected, or the
    guard moved into the route's own `dependencies=[...]` list, which this rule
    declares it does not read. A rewrite that keeps the defect and renames the
    storage dependency is caught; what is not caught is a storage injection named
    with an unplaceable verb in front of a tail that mentions something else
    (`handle_security`, `manage_assets`). Unknown names count as authorization,
    so those stay silent: reading `handle_security` as storage would let the rule
    assert a gap on a route whose dependency plainly names security.

One tail was measured OUT for the same reason: `handler` appeared as a guard
(`resolve_handler`) and as storage (`get_repository_handler`) in different rounds,
and including it gained one body while losing two. A tail that both roles wear is
not evidence of either.

A note about the hunt's own dump: it masks long identifier runs, so a body such as
`Depends(provide_storage_interface)` is written to disk as
`Depends(prov...[25 chars])` and cannot be parsed or reviewed. Roughly a quarter of
the dumped bodies in every round were unreadable for this reason, which is why the
counts above say "judgeable" instead of "bodies". That is a defect in the tool, not
in the detector, and it is the next thing to fix there.
"""

from __future__ import annotations

import ast
import re
import stat
import zipfile
from typing import BinaryIO

from app.scan.auth_read import _ScopeBindings, _auth_scopes, _guard_role, _handler_nodes, _scope_bindings, _scope_routes
from app.scan.checks import CheckFinding
from app.scan.secrets import is_non_production_path

RULE_ID = "python-route-write-auth-consistency"

# Deleting is a write: the argument a route needs before it may destroy someone
# else's record is the same argument it needs before it may create one.
_MUTATION_METHODS = {"post", "put", "patch", "delete"}

# Method names that change stored state. Matched on the LEADING token, so
# createRecord, create_record and createRecordWithAudit all read as `create`
# (scripts/hunt_detector_escapes.py produced camelCase rewrites that the exact
# match missed -- the corpus only ever wrote snake_case). Kept as a plain list
# so a reviewer can read what the rule knows; a name missing from it costs a
# missed finding, not a wrong one.
_WRITE_VERBS = frozenset({
    "add", "commit", "create", "delete", "drop", "erase", "insert", "modify",
    "mutate", "persist", "remove", "replace", "revoke", "save", "store", "update",
    "upsert", "write",
})

# Raw SQL is write evidence too, and the hunt showed how much of it there is:
# a handler that opens its own connection and calls cursor.execute("INSERT ...")
# names no repository method at all. The statement is a string literal in the
# handler, so this stays a reading of the code rather than a run of it -- and it
# is deliberately narrow: the call must be a known statement runner AND its
# first argument must OPEN with a mutating keyword, so a SELECT does not count.
_SQL_METHODS = frozenset({"execute", "executemany", "execute_sql", "query", "raw", "run", "sql"})
_SQL_MUTATION = re.compile(r"^\s*\(*\s*(insert|update|delete|replace|upsert|merge|truncate)\b", re.IGNORECASE)

_CAMEL_BOUNDARY = re.compile(r"(?<!^)(?=[A-Z])")

_PUBLIC_SEGMENTS = frozenset({
    "callback", "callbacks", "health", "healthz", "hooks", "ipn", "login",
    "logout", "notification", "notifications", "oauth", "ready", "readyz",
    "refresh", "register", "sign-in", "sign-up", "signin", "signup", "token",
    "webhook", "webhooks",
})

# A scheduler is not storage. `background.add_task(...)` and `create_task(...)`
# came out of the hunt as write evidence on the leading verb `add`/`create`, and
# the product's own YooKassa route was reported for it: the handler schedules a
# coroutine, and whether anything is stored depends on code this scanner never
# reads. Excluded by FULL name before the verb is considered.
_NOT_WRITE_CALLS = frozenset({
    "add_background_task", "add_task", "apply_async", "create_task", "delay",
    "enqueue", "schedule", "schedule_task",
})


def _write_call(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, int, str] | None:
    """The first call in the handler that changes stored state, its line, and the
    evidence in the words the report uses. The evidence is attributed rather than
    asserted: `modify` is a name this scanner READS as a write, and saying so is
    the difference between an observation and a claim about the code's intent."""
    for node in _handler_nodes(fn):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        attr = (func.attr if isinstance(func, ast.Attribute)
                else func.id if isinstance(func, ast.Name) else "")
        if not attr:
            continue
        snake = _CAMEL_BOUNDARY.sub("_", attr).lower()
        if snake in _NOT_WRITE_CALLS:
            continue
        if snake.split("_")[0] in _WRITE_VERBS:
            return attr, node.lineno, f"the handler calls {attr}()"
        if (attr in _SQL_METHODS and node.args and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)):
            statement = _SQL_MUTATION.match(node.args[0].value)
            if statement:
                return attr, node.lineno, (f"the handler runs a {statement.group(1).upper()} statement "
                                           f"through {attr}()")
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
            # Scopes are kept separate for the same reason the read rule keeps
            # them separate: the claim is that two routes on the SAME router
            # disagree, and a router built inside one function is not the router
            # built inside another. Flattening would pair routes that never
            # share an object and report a disagreement that does not exist.
            for scope, bindings in _auth_scopes(tree):
                findings.extend(_scope_findings(scope, factories, path, bindings))
    return findings


def _scope_findings(scope, factories: set[str], filename: str,
                    bindings: _ScopeBindings | None = None) -> list[CheckFinding]:
    """Write routes declared in one scope, and their disagreement with siblings."""
    findings: list[CheckFinding] = []
    routes = _scope_routes(scope, factories, _MUTATION_METHODS)
    bindings = bindings or _scope_bindings(scope)
    roles = {fn: _guard_role(fn, bindings) for fn, _, _, _ in routes}
    # Unknown dependencies suppress a target finding, but cannot establish an
    # identity check on a sibling. Each router keeps its own first witness.
    siblings = {}
    for fn, route, method, router in routes:
        if roles[fn] == "identity":
            siblings.setdefault(router, (fn, route, method))
    for fn, route, method, router in routes:
        if roles[fn] != "none" or len(fn.decorator_list) != 1 or _public_path(route):
            continue
        sibling = siblings.get(router)
        if sibling is None:
            continue
        sibling_fn, sibling_route, sibling_method = sibling
        call = _write_call(fn)
        if call is None:
            continue
        findings.append(_finding(filename, route, method, call, sibling_route,
                                 sibling_method, sibling_fn.lineno))
    return findings


def _finding(path: str, route: str, method: str, call: tuple[str, int, str],
             sibling_route: str, sibling_method: str, sibling_line: int) -> CheckFinding:
    name, line, evidence = call
    return CheckFinding(
        RULE_ID, "Write route shows no local identity check",
        "medium", 0.8, "Auth", file=path, line=line,
        explanation=(f"{method.upper()} {route} contains a call recognized as a write ({evidence}) "
                     "and no local identity check was recognized in its handler, while sibling "
                     f"{sibling_method.upper()} {sibling_route} on the same router declares one "
                     f"at line {sibling_line}. "
                     "Names and literal SQL are static evidence; actual writes, router mounting, "
                     "global middleware and public reachability have not been resolved."),
        fix_hint=("Confirm whether this route is meant to be reachable without an identity -- a webhook "
                  "or an onboarding step would be. If not, require the contract its sibling route uses, "
                  "and test a write with a foreign or absent credential against synthetic records."),
    )

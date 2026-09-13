"""A redirect that targets a URL whose authority the caller supplies.

The sinks are the framework redirect constructors -- Starlette/FastAPI
``RedirectResponse`` -- reached inside a locally declared FastAPI route. The
value that reaches the URL's authority (between ``://`` and the first ``/``,
``?`` or ``#``) is the caller's, so a request can steer a visitor's browser to
an attacker-chosen host: the open redirect behind most phishing and OAuth
token-theft flows.

A caller value that only fills the PATH is not an open redirect -- the host is
fixed, so the visitor stays on the same origin -- and stays silent, exactly the
boundary ``_host_inputs`` draws for the outbound-URL rule. A recognised local
check on the address (an allowed-host comparison, a scheme check) suppresses the
signal without certifying that the check is correct.

Flask/Django ``redirect()``, ``HTTPResponse(headers={"Location": ...})`` and the
``<meta http-equiv=refresh>`` pattern, and JS/TS (``res.redirect``,
``window.location``) are outside this rule's claim; it reads only the
Starlette/FastAPI constructor in FastAPI routes. No uploaded code is imported or
executed, and helpers are not analysed across calls -- a helper that assembles
the URL and returns it (``def build_url(h): return RedirectResponse(f"https://{h}")``,
called from the handler) is cross-function taint this rule does not follow, and
that is the dominant residual rather than a hidden gap.
"""

from __future__ import annotations

import ast
import zipfile
from typing import BinaryIO

from app.scan.checks import CheckFinding
from app.scan.outbound_url import (
    _MAX_FILE_BYTES,
    _MAX_FILES,
    _MAX_FINDINGS,
    _FindingLimitReached,
    _State,
    _attr_name,
    _bind,
    _bounded_tree,
    _checked_names,
    _check_call,
    _forget_stores,
    _host_inputs,
    _import,
    _join_states,
    _qualified,
    _request_inputs,
    _skeleton,
    _terminates,
    _test_inspects,
    _walk,
)
from app.scan.rule_coverage import RuleCoverage, track_analysis_limits
from app.scan.scope_statements import block_arms, scope_statements

RULE_ID = "python-open-redirect-unvalidated-url"

# The Starlette/FastAPI redirect constructor. Its first positional (or ``url=``
# keyword) argument is the Location the visitor's browser is sent to.
_REDIRECT_SINKS = frozenset({
    "starlette.responses.RedirectResponse",
    "fastapi.responses.RedirectResponse",
})


def _redirect_argument(call: ast.Call, state: _State) -> ast.AST | None:
    qualified = _qualified(call.func, state.bindings)
    if qualified not in _REDIRECT_SINKS:
        return None
    for keyword in call.keywords:
        if keyword.arg == "url":
            return keyword.value
    return call.args[0] if call.args else None


def _scan_expr(expr: ast.AST, state: _State, path: str, findings: list[CheckFinding]) -> None:
    for call in _walk(expr):
        if len(findings) >= _MAX_FINDINGS:
            raise _FindingLimitReached
        if not isinstance(call, ast.Call):
            continue
        url = _redirect_argument(call, state)
        if url is None:
            continue
        built = _skeleton(url, state)
        reaching = _host_inputs(built) if built is not None else set()
        if reaching and not reaching <= state.checked:
            findings.append(_finding(path, call, reaching))


def _scan_block(body: list[ast.stmt], state: _State, path: str, findings: list[CheckFinding]) -> None:
    for stmt in body:
        if len(findings) >= _MAX_FINDINGS:
            raise _FindingLimitReached
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            _bind(ast.Name(id=stmt.name), None, state)
            continue
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            _import(stmt, state)
            continue
        if isinstance(stmt, ast.If):
            _scan_expr(stmt.test, state, path, findings)
            inspected = (_checked_names(stmt.test, state)
                         if _test_inspects(stmt.test, set(state.values) | state.requests | state.models.keys())
                         else set())
            branch_states = []
            for branch in (stmt.body, stmt.orelse):
                branch_state = state.copy()
                branch_state.checked |= inspected
                _scan_block(branch, branch_state, path, findings)
                if not _terminates(branch):
                    branch_states.append(branch_state)
            if not branch_states:
                return
            if len(branch_states) > 1:
                for branch_state in branch_states:
                    branch_state.checked -= inspected - state.checked
            _join_states(state, branch_states)
            continue
        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                _scan_expr(item.context_expr, state, path, findings)
                if item.optional_vars:
                    _bind(item.optional_vars, item.context_expr, state)
            _scan_block(stmt.body, state, path, findings)
            continue
        if isinstance(stmt, (ast.For, ast.AsyncFor, ast.While, ast.Try, ast.TryStar, ast.Match)):
            for child in ast.iter_child_nodes(stmt):
                if isinstance(child, ast.expr):
                    _scan_expr(child, state, path, findings)
            for branch in block_arms(stmt):
                branch_state = state.copy()
                if isinstance(stmt, (ast.For, ast.AsyncFor)):
                    _bind(stmt.target, None, branch_state)
                for handler in getattr(stmt, "handlers", []):
                    if handler.body is branch and handler.name:
                        _bind(ast.Name(id=handler.name), None, branch_state)
                for case in getattr(stmt, "cases", []):
                    if case.body is branch:
                        for node in _walk(case.pattern):
                            name = getattr(node, "name", None) or getattr(node, "rest", None)
                            if isinstance(name, str):
                                _bind(ast.Name(id=name), None, branch_state)
                _scan_block(branch, branch_state, path, findings)
            for node in _walk(stmt):
                if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)) and isinstance(node.ctx, ast.Store):
                    _bind(node, None, state)
            continue
        _scan_expr(stmt, state, path, findings)
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                _bind(target, stmt.value, state)
        elif isinstance(stmt, ast.AnnAssign):
            _bind(stmt.target, stmt.value, state)
        elif isinstance(stmt, ast.AugAssign):
            _bind(stmt.target, None, state)
        elif isinstance(stmt, ast.Delete):
            for target in stmt.targets:
                _bind(target, None, state)
        elif isinstance(stmt, ast.Expr):
            state.checked |= _check_call(stmt.value, state)
        elif isinstance(stmt, ast.Assert) and _test_inspects(
                stmt.test, set(state.values) | state.requests | state.models.keys()):
            state.checked |= _checked_names(stmt.test, state)
        elif isinstance(stmt, (ast.Return, ast.Raise)):
            return


def _declares_route(fn: ast.FunctionDef | ast.AsyncFunctionDef, state: _State) -> bool:
    return any(isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)
               and dec.func.attr in {"delete", "get", "head", "options", "patch", "post", "put",
                                     "route", "api_route", "websocket"}
               and _qualified(dec.func.value, state.bindings) == "router" for dec in fn.decorator_list)


def _import_context(body: list[ast.stmt], state: _State) -> None:
    for stmt in body:
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            _import(stmt, state)
        elif isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            for target in stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]:
                _bind(target, stmt.value, state)
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            _bind(ast.Name(id=stmt.name), None, state)
        else:
            _forget_stores(stmt, state)


def _scan_scope(body: list[ast.stmt], inherited: _State, path: str, findings: list[CheckFinding]) -> None:
    context = inherited.copy()
    _import_context(body, context)
    for stmt in scope_statements(body):
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            declares_route = _declares_route(stmt, context)
            nested = any(isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                         for child in scope_statements(stmt.body))
            if not declares_route and not nested:
                continue
            local = context.copy()
            args = [*stmt.args.posonlyargs, *stmt.args.args, *stmt.args.kwonlyargs,
                    stmt.args.vararg, stmt.args.kwarg]
            for arg in (arg for arg in args if arg is not None):
                _bind(ast.Name(id=arg.arg), None, local)
            for child in stmt.body:
                _forget_stores(child, local)
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    _bind(ast.Name(id=child.name), None, local)
            if declares_route:
                _request_inputs(stmt, local)
                _scan_block(stmt.body, local, path, findings)
            if nested:
                _scan_scope(stmt.body, local, path, findings)


def scan_open_redirect(fileobj: BinaryIO, *, coverage: dict | None = None) -> list[CheckFinding]:
    findings: list[CheckFinding] = []
    with zipfile.ZipFile(fileobj) as archive:
        accounting = RuleCoverage(archive, extensions=(".py",),
                                  max_file_bytes=_MAX_FILE_BYTES, coverage=coverage)
        for info in accounting.files(findings, max_files=_MAX_FILES, max_findings=_MAX_FINDINGS):
            raw = archive.read(info)
            if b"@" not in raw or b"Redirect" not in raw:
                accounting.analyzed()
                continue
            try:
                source = raw.decode("utf-8")
            except UnicodeError:
                accounting.skip("decode_error")
                continue
            try:
                tree = ast.parse(source)
            except (SyntaxError, ValueError):
                accounting.skip("parse_error")
                continue
            except RecursionError:
                accounting.skip("ast_limit")
                continue
            if not _bounded_tree(tree):
                accounting.skip("ast_limit")
                continue
            try:
                with track_analysis_limits() as limits:
                    _scan_scope(tree.body, _State(), info.filename, findings)
            except _FindingLimitReached:
                accounting.skip("finding_limit")
            except RecursionError:
                accounting.skip("ast_limit")
            else:
                if limits:
                    accounting.skip("analysis_limit")
                else:
                    accounting.analyzed()
        accounting.finish()
    return findings


def _finding(path: str, call: ast.Call, reaching: set[str]) -> CheckFinding:
    names = ", ".join(sorted(reaching))
    return CheckFinding(
        rule_id=RULE_ID,
        title="A redirect targets a URL whose authority comes from the caller",
        severity="high",
        confidence=0.7,
        category="Security",
        file=path,
        line=call.lineno,
        explanation=(
            f"The redirect constructed at {_attr_name(call.func)}() on line {call.lineno} sends the "
            f"visitor's browser to an address whose host is built from request input ({names}). A caller "
            "who controls the target can redirect a signed-in user to an attacker's domain -- the open "
            "redirect that carries OAuth codes, session tokens in the Referer, and phishing flows. No "
            "recognised local check on the address was found on this path. Whether the route is "
            "reachable and whether anything outside this function constrains the target have NOT been "
            "verified, and the value is traced only inside this function."
        ),
        fix_hint=(
            "Validate the target before redirecting: allow only relative paths, or compare the resolved "
            "host against an allowlist of your own origins and reject everything else (including "
            "protocol-relative //host and backslashes that some parsers read as //host). Never redirect "
            "straight to a value the request supplied."
        ),
    )

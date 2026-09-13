"""Bounded, local traces of a shell command built from the caller's input.

Sinks are the calls that run a STRING through a shell. ``os.system``, ``os.popen``
and its deprecated ``popen2``/``popen3``/``popen4`` siblings always do; the
``subprocess`` family does only when ``shell=True`` is passed as a literal. A
caller-controlled value that reaches the command string is reported.

What stays silent, and why, is as much of the claim as what fires:

  * a ``subprocess`` call WITHOUT ``shell=True`` is silent -- its argument list
    is not interpreted by a shell, so the same string there is a program name
    (or one argv entry), not a command line. ``shell=False`` is the library
    default, so a bare ``subprocess.run("ls " + name)`` is a fixed program name,
    not an injection, and the rule treats it as such;
  * ``shell=<variable>`` is NOT read -- only the literal ``shell=True`` is. An
    unknown value counts as safe, exactly like an unknown helper stops the
    trace; this rule never asserts a gap on a value it cannot see;
  * a ``["sh", "-c", value]`` argument list is read when its first element is a
    shell program and the second is the literal ``-c``: that runs the value
    through a shell without ``shell=True``, and the rule reports the command
    part. ``os.exec*``/``os.spawn*`` and the removed Python 2 ``commands``
    module are outside this rule's claim;
  * an argument list assigned to a variable and then passed on
    (``args = ["rm", name]; subprocess.run(args, shell=True)``) is one hop of
    indirection the trace does not follow: the skeleton is built from strings,
    not from a list stored in a name. The list literal in the call itself is
    read; the list behind a variable is not.

Only locally declared FastAPI routes are read; helpers are not analysed across
calls. No uploaded code is imported or executed.
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
    _bind,
    _bounded_tree,
    _forget_stores,
    _import,
    _join_states,
    _qualified,
    _request_inputs,
    _skeleton,
    _terminates,
    _walk,
)
from app.scan.rule_coverage import RuleCoverage, track_analysis_limits
from app.scan.scope_statements import block_arms, scope_statements

RULE_ID = "command-injection-shell-built-command"

# Sinks that always run the argument through a shell.
_SHELL_CALLS = frozenset({"os.system", "os.popen", "os.popen2", "os.popen3", "os.popen4"})
# Sinks that run through a shell only when shell=True is passed as a literal.
_SUBPROCESS_CALLS = frozenset({
    "subprocess.run", "subprocess.call", "subprocess.check_call",
    "subprocess.check_output", "subprocess.Popen",
})
# First element of a ["<prog>", "-c", command] list that makes it a shell command.
_SHELL_PROGRAMS = frozenset({"sh", "bash", "zsh", "dash", "ksh",
                             "/bin/sh", "/bin/bash", "/bin/zsh", "/bin/dash"})


def _shell_true(call: ast.Call) -> bool:
    for keyword in call.keywords:
        if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) \
                and keyword.value.value is True:
            return True
    return False


def _shell_c_arguments(call: ast.Call) -> list[ast.AST]:
    """The command part of a ``["<shell>", "-c", command]`` argument list.

    This is a shell command without ``shell=True``: the first element names a
    shell program and the second is the literal ``-c``, so whatever follows is
    interpreted by that shell. Anything but that exact shape is not a shell
    command and returns nothing.
    """
    if not call.args or not isinstance(call.args[0], (ast.List, ast.Tuple)):
        return []
    elements = call.args[0].elts
    if len(elements) < 3:
        return []
    program, flag = elements[0], elements[1]
    if not (isinstance(program, ast.Constant) and isinstance(program.value, str)
            and program.value in _SHELL_PROGRAMS):
        return []
    if not (isinstance(flag, ast.Constant) and isinstance(flag.value, str)
            and flag.value == "-c"):
        return []
    return list(elements[2:])


def _command_arguments(call: ast.Call, state: _State) -> list[ast.AST]:
    """The command expression(s) a shell will interpret, or none.

    For ``os.system``/``os.popen`` the first positional argument IS the command
    string. For ``subprocess.*`` the ``args`` argument (positional or by keyword)
    is the command, but only when ``shell=True`` is a literal -- otherwise the
    argument list is not shell-interpreted, unless it is a ``["<shell>", "-c",
    command]`` list, which is.
    """
    qualified = _qualified(call.func, state.bindings)
    result: list[ast.AST] = []
    if qualified in _SHELL_CALLS:
        if call.args:
            result.append(call.args[0])
        return result
    if qualified in _SUBPROCESS_CALLS:
        if _shell_true(call):
            for keyword in call.keywords:
                if keyword.arg == "args":
                    result.append(keyword.value)
                    return result
            if call.args:
                result.append(call.args[0])
            return result
        result.extend(_shell_c_arguments(call))
    return result


def _caller_inputs(expr: ast.AST, state: _State) -> set[str]:
    """The request origins a command expression carries, if any.

    A string command is reduced to its skeleton and its caller slots collected.
    An argument LIST under ``shell=True`` is read element by element: any
    element that carries a caller value makes the whole command caller-built.
    """
    if isinstance(expr, (ast.List, ast.Tuple)):
        result: set[str] = set()
        for element in expr.elts:
            built = _skeleton(element, state)
            if built is not None:
                result.update(set().union(*built[1]))
        return result
    built = _skeleton(expr, state)
    if built is None:
        return set()
    return set().union(*built[1])


def _scan_expression(expr: ast.AST, state: _State, path: str, findings: list[CheckFinding]) -> None:
    for call in _walk(expr):
        if len(findings) >= _MAX_FINDINGS:
            raise _FindingLimitReached
        if not isinstance(call, ast.Call):
            continue
        reaching: set[str] = set()
        for argument in _command_arguments(call, state):
            reaching.update(_caller_inputs(argument, state))
        if reaching:
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
            _scan_expression(stmt.test, state, path, findings)
            branch_states = []
            for branch in (stmt.body, stmt.orelse):
                branch_state = state.copy()
                _scan_block(branch, branch_state, path, findings)
                if not _terminates(branch):
                    branch_states.append(branch_state)
            if not branch_states:
                return
            _join_states(state, branch_states)
            continue
        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                _scan_expression(item.context_expr, state, path, findings)
                if item.optional_vars:
                    _bind(item.optional_vars, item.context_expr, state)
            _scan_block(stmt.body, state, path, findings)
            continue
        if isinstance(stmt, (ast.For, ast.AsyncFor, ast.While, ast.Try, ast.TryStar, ast.Match)):
            for child in ast.iter_child_nodes(stmt):
                if isinstance(child, ast.expr):
                    _scan_expression(child, state, path, findings)
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
        _scan_expression(stmt, state, path, findings)
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
    # scope_statements, not `body`: a module-level `if:`/`try:`/`with:`/`for:`
    # opens no scope in Python, so a route declared inside one still hangs on the
    # router built here and its handler still reads request input.
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


def scan_command_injection(fileobj: BinaryIO, *, coverage: dict | None = None) -> list[CheckFinding]:
    findings: list[CheckFinding] = []
    with zipfile.ZipFile(fileobj) as archive:
        accounting = RuleCoverage(archive, extensions=(".py",),
                                  max_file_bytes=_MAX_FILE_BYTES, coverage=coverage)
        for info in accounting.files(findings, max_files=_MAX_FILES, max_findings=_MAX_FINDINGS):
            raw = archive.read(info)
            if b"@" not in raw:
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
        title="A shell command is built from the caller's input",
        severity="high",
        # The assembly is certain -- ast read the string and the value's origin
        # is a parameter the request fills. What is not verified is whether the
        # handler is reachable, whether a check elsewhere constrains the value,
        # or whether the shell actually runs with the attacker's bytes.
        confidence=0.7,
        category="Security",
        file=path,
        line=call.lineno,
        explanation=(
            f"The command handed to {_attr(call)} at line {call.lineno} is assembled from {names}, "
            "which this handler receives from the request, and a shell interprets that string. "
            "A value carrying shell metacharacters (;, &&, $(), backticks) can run a second command "
            "the application never wrote, up to and including arbitrary code as the process user. "
            "Whether the route is reachable, whether anything outside this function constrains the "
            "value, and whether the call executes are NOT verified, and the value is traced only "
            "inside this function."
        ),
        fix_hint=(
            "Do not run a shell on request input. Pass arguments as a list to subprocess without "
            "shell=True (subprocess.run([\"cmd\", arg])) so no shell ever interprets the value, and "
            "avoid os.system/os.popen for anything but a fixed literal command. If a command must be "
            "built, use shlex.quote on each value, or better, whitelist the allowed commands and "
            "reject everything else."
        ),
    )


def _attr(call: ast.Call) -> str:
    if isinstance(call.func, ast.Attribute):
        return call.func.attr + "()"
    if isinstance(call.func, ast.Name):
        return call.func.id + "()"
    return "this call"

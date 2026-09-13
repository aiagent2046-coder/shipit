"""Bounded, local traces of a shell command built from the caller's input.

Sinks are the calls that run a STRING through a shell. ``os.system``, ``os.popen``
and its deprecated ``popen2``/``popen3``/``popen4`` siblings always do; the
``subprocess`` family does only when ``shell=True`` is passed as a literal. A
caller-controlled value that reaches the command string is reported.

The subprocess argument model is POSIX: with ``shell=True`` a sequence's
first element is the command string and the rest are shell positional arguments,
not concatenated command text. For an explicit ``["sh", "-c", command, ...]``
invocation, only ``command`` is shell source; later arguments are data. Re-evaluation
of those arguments by eval or a nested shell is outside this bounded trace.
Windows shell/list conventions are not analysed.

A call without ``shell=True`` or a recognized explicit shell invocation is not
reported by this shell-injection rule. An unknown shell option, helper or list
stored in a variable stops the trace; silence is not proof of safety. ``os.exec*``
and ``os.spawn*`` are outside the supported sinks.

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
    _combine,
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


def _subprocess_args(call: ast.Call) -> ast.AST | None:
    """Normalize the supported positional and keyword forms of subprocess args."""
    named = [kw.value for kw in call.keywords if kw.arg == "args"]
    if call.args:
        # Duplicate args raises at runtime; do not invent a command for it.
        return call.args[0] if not named else None
    return named[0] if len(named) == 1 else None


def _shell_c_arguments(argument: ast.AST) -> list[ast.AST]:
    """Return only command text, not the shell's $0/$1/... argument values."""
    if not isinstance(argument, (ast.List, ast.Tuple)):
        return []
    elements = argument.elts
    if len(elements) < 3:
        return []
    program, flag = elements[0], elements[1]
    if not (isinstance(program, ast.Constant) and isinstance(program.value, str)
            and program.value in _SHELL_PROGRAMS):
        return []
    if not (isinstance(flag, ast.Constant) and flag.value == "-c"):
        return []
    return [elements[2]]


def _command_arguments(call: ast.Call, state: _State) -> list[ast.AST]:
    """Select the expression interpreted as shell source under POSIX semantics."""
    qualified = _qualified(call.func, state.bindings)
    if qualified in _SHELL_CALLS:
        return [call.args[0]] if call.args else []
    if qualified not in _SUBPROCESS_CALLS:
        return []
    argument = _subprocess_args(call)
    if argument is None:
        return []
    if _shell_true(call):
        # POSIX Popen executes ['/bin/sh', '-c', args[0], args[1], ...].
        # The tail is not joined into args[0], even when it contains metacharacters.
        if isinstance(argument, (ast.List, ast.Tuple)):
            return argument.elts[:1]
        return [argument]
    # A non-literal shell option can change which expression is command text.
    # Only the omitted/default or explicit False form has known POSIX argv semantics.
    if any(kw.arg == "shell" and not (isinstance(kw.value, ast.Constant)
                                     and kw.value.value is False) for kw in call.keywords):
        return []
    return _shell_c_arguments(argument)


def _caller_inputs(expr: ast.AST, state: _State) -> set[str]:
    """The request origins in the selected command string, when traceable."""
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
            # `cmd += host` is `cmd = cmd + host`: keep the accumulated string
            # and its caller slots rather than dropping the provenance.
            if isinstance(stmt.target, ast.Name) and isinstance(stmt.op, ast.Add):
                old = _skeleton(stmt.target, state)
                added = _skeleton(stmt.value, state)
                if old is not None and added is not None:
                    combined = _combine([old, added])
                    if combined is not None:
                        state.values[stmt.target.id] = combined
                        continue
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
            "inside this function. Subprocess argument lists use POSIX semantics; Windows shell "
            "conventions and re-evaluation of positional arguments are not analysed."
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

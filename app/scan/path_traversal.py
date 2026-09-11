"""Bounded, local request-to-filesystem traces in declared FastAPI handlers.

Imported filesystem functions and proven pathlib receivers are sinks; constructing
a Path is only propagation. Unknown helpers and objects stop this trace. Imported
secure_filename sanitizes only its own result. basename/commonprefix, validation
names, and a lexical is_relative_to are not containment proofs. A supported guard
checks a resolved Path against a fixed absolute base on the path that reaches the
sink. All uploaded source is parsed, never imported or executed.
"""

from __future__ import annotations

import ast
import zipfile
from dataclasses import dataclass, field
from typing import BinaryIO

from app.scan.checks import CheckFinding
from app.scan.outbound_url import (
    _MAX_FILES,
    _MAX_FILE_BYTES,
    _MAX_FINDINGS,
    _State,
    _bind,
    _bounded_tree,
    _combine,
    _import,
    _qualified,
    _request_inputs,
    _skeleton,
    _walk,
)
from app.scan.scope_statements import scope_statements
from app.scan.secrets import is_non_production_path

RULE_ID = "path-traversal-file-sink"
_PATH_CLASSES = frozenset(f"pathlib.{name}" for name in
                          ("Path", "PosixPath", "WindowsPath", "PurePath", "PurePosixPath", "PureWindowsPath"))
_CONCRETE_PATHS = frozenset({"pathlib.Path", "pathlib.PosixPath", "pathlib.WindowsPath"})
_JOINS = frozenset({"os.path.join", "posixpath.join", "ntpath.join"})
_NORMALIZERS = frozenset({f"{module}.{name}" for module in ("os.path", "posixpath", "ntpath")
                          for name in ("normpath", "abspath", "realpath", "expanduser", "basename")})
_PATH_TRANSFORMS = frozenset({"resolve", "absolute", "expanduser", "joinpath", "with_name", "with_stem",
                            "with_suffix"})
_SANITIZERS = frozenset({"werkzeug.utils.secure_filename"})
_METHOD_SINKS = frozenset({"read_text", "read_bytes", "write_text", "write_bytes", "open", "unlink",
                         "touch", "mkdir", "rmdir", "iterdir", "stat", "lstat", "chmod"})
# Position and keyword are API signatures, not guesses from a method's name.
_FIRST_SINKS = {
    "builtins.open": "file", "os.open": "path",
    **{f"os.{name}": "path" for name in ("listdir", "mkdir", "makedirs", "remove", "rmdir", "scandir",
                                        "stat", "unlink", "utime")},
    "shutil.rmtree": "path", "zipfile.ZipFile": "file", "tarfile.open": "name",
    "flask.send_file": "path_or_file", "flask.helpers.send_file": "path_or_file",
    "werkzeug.utils.send_file": "path_or_file",
    "starlette.responses.FileResponse": "path", "fastapi.responses.FileResponse": "path",
    "pandas.read_csv": "filepath_or_buffer", "pandas.read_table": "filepath_or_buffer",
    "pandas.read_excel": "io", "pandas.read_json": "path_or_buf",
    "numpy.load": "file", "numpy.loadtxt": "fname", "numpy.genfromtxt": "fname",
}
_TWO_PATH_SINKS = frozenset({"os.rename", "os.replace", "shutil.copy", "shutil.copy2", "shutil.copyfile",
                            "shutil.copytree", "shutil.move"})


@dataclass
class _PathState(_State):
    paths: set[str] = field(default_factory=set)
    concrete: set[str] = field(default_factory=set)
    normalized: set[str] = field(default_factory=set)
    checked_paths: set[str] = field(default_factory=set)
    shadowed: set[str] = field(default_factory=set)

    def copy(self) -> _PathState:
        result = _PathState()
        # Keep compatibility with additional provenance fields in outbound_url.
        for name, value in vars(self).items():
            setattr(result, name, value.copy())
        return result


def _call_name(call: ast.Call, state: _PathState) -> str:
    qualified = _qualified(call.func, state.bindings)
    if qualified:
        return qualified
    if isinstance(call.func, ast.Name) and call.func.id in {"open", "str"} \
            and call.func.id not in state.shadowed:
        return "builtins." + call.func.id
    return ""


def _path_type(expr: ast.AST, state: _PathState, *, concrete: bool = False) -> bool:
    if isinstance(expr, ast.Name):
        return expr.id in (state.concrete if concrete else state.paths)
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Div):
        return _path_type(expr.left, state, concrete=concrete)
    if isinstance(expr, ast.Attribute) and expr.attr in {"parent"}:
        return _path_type(expr.value, state, concrete=concrete)
    if isinstance(expr, ast.Call):
        if _call_name(expr, state) in (_CONCRETE_PATHS if concrete else _PATH_CLASSES):
            return True
        if isinstance(expr.func, ast.Attribute) and expr.func.attr in _PATH_TRANSFORMS | {"relative_to"}:
            return _path_type(expr.func.value, state, concrete=concrete)
    return False


def _normalized(expr: ast.AST, state: _PathState) -> bool:
    if isinstance(expr, ast.Name):
        return expr.id in state.normalized
    return (isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute)
            and expr.func.attr == "resolve" and _path_type(expr.func.value, state, concrete=True))


def _path_parts(parts: list[ast.AST], state: _PathState):
    result = ("", [])
    for part in parts:
        piece = _path_skeleton(part, state)
        if piece is None:
            return None
        # _combine checks BOTH budgets before joining text or copying slots.
        result = _combine([result, ("/" if result[0] else "", []), piece])
        if result is None:
            return None
    return result


def _path_skeleton(expr: ast.AST, state: _PathState) -> tuple[str, list[set[str]]] | None:
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Div) and _path_type(expr.left, state):
        return _path_parts([expr.left, expr.right], state)
    if isinstance(expr, ast.Attribute) and expr.attr in {"parent", "name"} and _path_type(expr.value, state):
        return _path_skeleton(expr.value, state)
    if isinstance(expr, ast.Call):
        qualified = _call_name(expr, state)
        if qualified in _JOINS | _PATH_CLASSES:
            return _path_parts(expr.args, state) if not expr.keywords else None
        if qualified in _SANITIZERS and len(expr.args) == 1 and not expr.keywords:
            # Sanitize this expression only; another raw component keeps its origin.
            return "sanitized-name", []
        if qualified in _NORMALIZERS and expr.args:
            return _path_skeleton(expr.args[0], state)
        if qualified == "builtins.str" and len(expr.args) == 1 and _path_type(expr.args[0], state):
            return _path_skeleton(expr.args[0], state)
        if isinstance(expr.func, ast.Attribute) and _path_type(expr.func.value, state):
            if expr.func.attr in {"resolve", "absolute", "expanduser"}:
                return _path_skeleton(expr.func.value, state)
            if expr.func.attr in {"joinpath", "with_name", "with_stem", "with_suffix"}:
                return _path_parts([expr.func.value, *expr.args], state) if not expr.keywords else None
    built = _skeleton(expr, state)
    return _combine([built]) if built is not None else None


def _argument(call: ast.Call, position: int, keyword: str) -> ast.AST | None:
    if any(isinstance(arg, ast.Starred) for arg in call.args) or any(kw.arg is None for kw in call.keywords):
        return None
    for kw in call.keywords:
        if kw.arg == keyword:
            return kw.value
    return call.args[position] if len(call.args) > position else None


def _path_arguments(call: ast.Call, state: _PathState) -> list[ast.AST]:
    qualified = _call_name(call, state)
    arguments = []
    if qualified in _FIRST_SINKS:
        arguments = [_argument(call, 0, _FIRST_SINKS[qualified])]
    elif qualified in _TWO_PATH_SINKS:
        arguments = [_argument(call, 0, "src"), _argument(call, 1, "dst")]
    elif isinstance(call.func, ast.Attribute) and _path_type(call.func.value, state, concrete=True):
        if call.func.attr in _METHOD_SINKS:
            arguments = [call.func.value]
        elif call.func.attr in {"rename", "replace"}:
            arguments = [call.func.value, _argument(call, 0, "target")]
    return [arg for arg in arguments if arg is not None]


def _scan_expression(expr: ast.AST, state: _PathState, path: str, findings: list[CheckFinding]) -> None:
    for call in _walk(expr):
        if len(findings) >= _MAX_FINDINGS:
            return
        if not isinstance(call, ast.Call):
            continue
        reaching = set()
        for argument in _path_arguments(call, state):
            if isinstance(argument, ast.Name) and argument.id in state.checked_paths:
                continue
            built = _path_skeleton(argument, state)
            if built is not None:
                reaching.update(set().union(*built[1]))
        if reaching:
            findings.append(_finding(path, call, reaching))


def _bind_path(target: ast.AST, value: ast.AST | None, state: _PathState) -> None:
    # Capture RHS before rebinding, including x = x.resolve().
    built = _path_skeleton(value, state) if value is not None else None
    path = value is not None and _path_type(value, state)
    concrete = value is not None and _path_type(value, state, concrete=True)
    normalized = value is not None and _normalized(value, state)
    checked = isinstance(value, ast.Name) and value.id in state.checked_paths
    _bind(target, value, state)
    names = {node.id for node in _walk(target) if isinstance(node, ast.Name)}
    for attr in (state.paths, state.concrete, state.normalized, state.checked_paths):
        attr.difference_update(names)
    state.shadowed.update(names)
    if isinstance(target, ast.Name):
        # Do not retain a sibling skeleton when path expansion exceeded its budget.
        state.values.pop(target.id, None)
        if built is not None:
            state.values[target.id] = built
        for enabled, attribute in ((path, state.paths), (concrete, state.concrete),
                                   (normalized, state.normalized), (checked, state.checked_paths)):
            if enabled:
                attribute.add(target.id)


def _containment_call(expr: ast.AST, state: _PathState, method: str) -> str | None:
    if not (isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute)
            and expr.func.attr == method and isinstance(expr.func.value, ast.Name)
            and expr.func.value.id in state.normalized and len(expr.args) == 1 and not expr.keywords):
        return None
    base = _path_skeleton(expr.args[0], state)
    if base is None or base[1] or not base[0].startswith("/") or ".." in base[0].split("/"):
        return None
    return expr.func.value.id


def _guard(test: ast.AST, state: _PathState) -> tuple[str | None, bool]:
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return _containment_call(test.operand, state, "is_relative_to"), False
    return _containment_call(test, state, "is_relative_to"), True


def _join_states(state: _PathState, branches: list[_PathState]) -> None:
    for attr, value in vars(branches[0]).items():
        if attr == "shadowed":
            merged = set.union(*(branch.shadowed for branch in branches))
        elif isinstance(value, dict):
            merged = {key: item for key, item in value.items()
                      if all(getattr(branch, attr).get(key) == item for branch in branches[1:])}
        else:
            merged = set.intersection(*(getattr(branch, attr) for branch in branches))
        setattr(state, attr, merged)


def _forget_stores(stmt: ast.AST, state: _PathState) -> None:
    pending = [stmt]
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            _bind_path(ast.Name(id=node.name), None, state)
            continue
        if isinstance(node, (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            continue
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            _bind_path(node, None, state)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                _bind_path(ast.Name(id=alias.asname or alias.name.split(".")[0]), None, state)
        elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name:
            _bind_path(ast.Name(id=node.name), None, state)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            _bind_path(ast.Name(id=node.rest), None, state)
        pending.extend(ast.iter_child_nodes(node))


def _import_path(stmt: ast.Import | ast.ImportFrom, state: _PathState) -> None:
    for alias in stmt.names:
        _bind_path(ast.Name(id=alias.asname or alias.name.split(".")[0]), None, state)
    _import(stmt, state)


def _scan_block(body: list[ast.stmt], state: _PathState, path: str, findings: list[CheckFinding]) -> bool:
    for stmt in body:
        if len(findings) >= _MAX_FINDINGS:
            return True
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            _bind_path(ast.Name(id=stmt.name), None, state)
            continue
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            _import_path(stmt, state)
            continue
        if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            if stmt.value is not None:
                _scan_expression(stmt.value, state, path, findings)
            for target in stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]:
                _bind_path(target, stmt.value, state)
            continue
        if isinstance(stmt, ast.If):
            _scan_expression(stmt.test, state, path, findings)
            checked, safe_when_true = _guard(stmt.test, state)
            continuing = []
            for truth, branch in ((True, stmt.body), (False, stmt.orelse)):
                local = state.copy()
                if checked and truth == safe_when_true:
                    local.checked_paths.add(checked)
                if _scan_block(branch, local, path, findings):
                    continuing.append(local)
            if not continuing:
                return False
            _join_states(state, continuing)
            continue
        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            local = state.copy()
            for item in stmt.items:
                _scan_expression(item.context_expr, local, path, findings)
                if item.optional_vars is not None:
                    _bind_path(item.optional_vars, None, local)
            _scan_block(stmt.body, local, path, findings)
            # __exit__ can swallow an exception; do not prove termination here.
            _forget_stores(stmt, state)
            continue
        if isinstance(stmt, (ast.Try, ast.TryStar, ast.For, ast.AsyncFor, ast.While, ast.Match)):
            for child in ast.iter_child_nodes(stmt):
                if isinstance(child, ast.expr):
                    _scan_expression(child, state, path, findings)
            arms = [getattr(stmt, key, []) for key in ("body", "orelse", "finalbody")]
            arms += [handler.body for handler in getattr(stmt, "handlers", [])]
            arms += [case.body for case in getattr(stmt, "cases", [])]
            for arm in arms:
                local = state.copy()
                if isinstance(stmt, (ast.For, ast.AsyncFor)):
                    _bind_path(stmt.target, None, local)
                for handler in getattr(stmt, "handlers", []):
                    if handler.body is arm and handler.name:
                        _bind_path(ast.Name(id=handler.name), None, local)
                for case in getattr(stmt, "cases", []):
                    if case.body is arm:
                        for node in _walk(case.pattern):
                            name = getattr(node, "name", None) or getattr(node, "rest", None)
                            if isinstance(name, str):
                                _bind_path(ast.Name(id=name), None, local)
                _scan_block(arm, local, path, findings)
            _forget_stores(stmt, state)
            continue
        _scan_expression(stmt, state, path, findings)
        if isinstance(stmt, ast.Expr):
            checked = _containment_call(stmt.value, state, "relative_to")
            if checked:
                state.checked_paths.add(checked)
        elif isinstance(stmt, ast.AugAssign):
            _bind_path(stmt.target, None, state)
        elif isinstance(stmt, (ast.Return, ast.Raise)):
            return False
    return True


def _declares_route(fn: ast.FunctionDef | ast.AsyncFunctionDef, state: _PathState) -> bool:
    return any(isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)
               and dec.func.attr in {"delete", "get", "head", "options", "patch", "post", "put",
                                     "route", "api_route", "websocket"}
               and _qualified(dec.func.value, state.bindings) == "router" for dec in fn.decorator_list)


def _import_context(body: list[ast.stmt], state: _PathState) -> None:
    for stmt in body:
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            _import_path(stmt, state)
        elif isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            for target in stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]:
                _bind_path(target, stmt.value, state)
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            _bind_path(ast.Name(id=stmt.name), None, state)
        else:
            _forget_stores(stmt, state)


def _scan_scope(body: list[ast.stmt], inherited: _PathState, path: str, findings: list[CheckFinding]) -> None:
    context = inherited.copy()
    _import_context(body, context)
    # scope_statements, not `body`: a module-level `if:`/`try:`/`with:`/`for:`
    # opens no scope in Python, so a route declared inside one still hangs on the
    # router built here and its handler still reads request input. Reading direct
    # statements only made every conditionally registered route invisible --
    # measured on the sibling outbound-URL rule, and this scanner shares the
    # discovery shape.
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
                _bind_path(ast.Name(id=arg.arg), None, local)
            for child in stmt.body:
                _forget_stores(child, local)
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    _bind_path(ast.Name(id=child.name), None, local)
            if declares_route:
                _request_inputs(stmt, local)
                _scan_block(stmt.body, local, path, findings)
            if nested:
                _scan_scope(stmt.body, local, path, findings)


def scan_path_traversal(fileobj: BinaryIO) -> list[CheckFinding]:
    findings: list[CheckFinding] = []
    with zipfile.ZipFile(fileobj) as archive:
        infos = [info for info in archive.infolist()
                 if not info.is_dir() and info.filename.endswith(".py")
                 and info.file_size <= _MAX_FILE_BYTES and not is_non_production_path(info.filename)]
        for info in infos[:_MAX_FILES]:
            if len(findings) >= _MAX_FINDINGS:
                break
            try:
                source = archive.read(info)
                if b"@" not in source:
                    continue
                tree = ast.parse(source.decode("utf-8"))
            except (SyntaxError, UnicodeError, ValueError, RecursionError):
                continue
            if _bounded_tree(tree):
                _scan_scope(tree.body, _PathState(), info.filename, findings)
    return findings


def _finding(path: str, call: ast.Call, reaching: set[str]) -> CheckFinding:
    names = ", ".join(sorted(reaching))
    return CheckFinding(
        rule_id=RULE_ID,
        title="A filesystem path is built from the caller's input",
        severity="high",
        # The assembly is certain -- ast read it, and the value's origin is a
        # parameter the request fills. What is not verified is whether it can
        # actually escape: a containment check in a wrapper, a mount, or a caller
        # that only ever sends safe names are all invisible here.
        confidence=0.8,
        category="Security",
        file=path,
        line=call.lineno,
        explanation=(
            f"The path handed to {_attr(call)} at line {call.lineno} is assembled from {names}, "
            "which this handler receives from the request, and no supported containment guard was "
            "established before this operation. If other controls do not constrain it, a value like "
            "`../../etc/passwd` can cause access to unintended files. Runtime filesystem access, "
            "symlinks and containment patterns outside this bounded trace are unresolved. "
            "Whether anything outside this function constrains the path "
            "has NOT been verified, and the value is traced only inside this function."
        ),
        fix_hint=(
            "Constrain the value to a name rather than a path: pass it through secure_filename (or "
            "keep only a whitelisted character set), then join it to a fixed base directory and "
            "confirm the RESULT is still inside that base -- Path(base, name).resolve() and "
            "is_relative_to(base). Never join the raw value, and never serve a file by a path that "
            "came from the request without that check."
        ),
    )


def _attr(call: ast.Call) -> str:
    if isinstance(call.func, ast.Attribute):
        return call.func.attr + "()"
    if isinstance(call.func, ast.Name):
        return call.func.id + "()"
    return "this call"

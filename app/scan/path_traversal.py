"""Bounded, local request-to-filesystem traces in declared FastAPI handlers.

Imported filesystem functions and proven pathlib receivers are sinks; constructing
a Path is only propagation. Imported secure_filename sanitizes only its own result.
basename/commonprefix, validation names, and a lexical is_relative_to are not
containment proofs. A supported guard checks a resolved Path against a fixed
absolute base on the path that reaches the sink.

A same-file helper is followed through ONE transition when it is a module-level
function declared exactly once, undecorated, never rebound, and called with the
handler's arguments in view: the trace continues inside its body, and a
single-return helper's return expression is read as the call's value. Hunt round 2
measured nineteen model rewrites of this rule's positives escaping through exactly
that mediation -- the natural code shape the old "unknown helpers stop this trace"
boundary could not see. Nested defs, helpers imported from other modules, rebound
names, decorated functions, coroutines, generators and second hops stay unresolved: this is not a call
graph, and the corpus negatives sink-inside-a-local-helper and
helper-builds-the-path pin those boundaries. All uploaded source is parsed, never
imported or executed.
"""

from __future__ import annotations

import ast
import zipfile

from app.scan.rule_coverage import remaining_findings, mark_analysis_limit
from dataclasses import dataclass, field
from typing import BinaryIO

from app.scan.checks import CheckFinding
from app.scan.outbound_url import (
    _MAX_FILES,
    _MAX_FILE_BYTES,
    _MAX_FINDINGS,
    _FindingLimitReached,
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
from app.scan.rule_coverage import RuleCoverage, track_analysis_limits
from app.scan.scope_statements import scope_statements, statically_true

RULE_ID = "path-traversal-file-sink"
# Bound distinct helper calls (including return propagation) and body traversals.
# Re-reading a call for its type/skeleton does not spend another call slot.
_MAX_HELPER_RESOLUTIONS = 32
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
    # Same-file helper resolution. `helpers` maps a name to its module-level
    # declaration and is shared by reference: it is read-only. `resolve_budget`
    # is one mutable counter per file, shared by reference so every branch of
    # the same trace spends from the same budget. `helper_depth` is per-state:
    # one transition, no second hop.
    helpers: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = field(default_factory=dict)
    resolve_budget: dict[str, int] = field(default_factory=lambda: {"count": 0})
    helper_depth: int = 0
    resolved_calls: set[ast.Call] = field(default_factory=set)
    module_context: _PathState | None = None
    helper_defaults: dict[str, dict[str, _PathState]] = field(default_factory=dict)

    def copy(self) -> _PathState:
        result = _PathState()
        for name, value in vars(self).items():
            if name in ("helpers", "resolve_budget", "module_context", "helper_defaults",
                        "resolved_calls", "literals"):
                setattr(result, name, value)
            elif hasattr(value, "copy"):
                setattr(result, name, value.copy())
            else:
                setattr(result, name, value)
        return result


def _call_name(call: ast.Call, state: _PathState) -> str:
    qualified = _qualified(call.func, state.bindings)
    if qualified:
        return qualified
    if isinstance(call.func, ast.Name) and call.func.id in {"open", "str"} \
            and call.func.id not in state.shadowed:
        return "builtins." + call.func.id
    return ""


def _module_helpers(body: list[ast.stmt]) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    """Module-level functions this file declares exactly once, never re-stored.

    A helper is worth resolving only while the name can mean one thing: a second
    declaration, a decorator, an import, an assignment or any other module-level
    store to the name drops it. Nested scopes are not walked -- a method's local
    variable is not a module store.
    """
    candidates: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    invalid: set[str] = set()
    for stmt in body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if (stmt.name in candidates or stmt.decorator_list
                    or isinstance(stmt, ast.AsyncFunctionDef)
                    or any(isinstance(node, (ast.Yield, ast.YieldFrom))
                           for child in stmt.body for node in _walk(child))):
                invalid.add(stmt.name)
            candidates.setdefault(stmt.name, stmt)
            continue
        pending: list[ast.AST] = [stmt]
        while pending:
            node = pending.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                invalid.add(node.name)
                continue
            if isinstance(node, (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                continue
            if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                invalid.add(node.id)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    invalid.add(alias.asname or alias.name.split(".")[0])
            elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name:
                invalid.add(node.name)
            elif isinstance(node, ast.MatchMapping) and node.rest:
                invalid.add(node.rest)
            pending.extend(ast.iter_child_nodes(node))
    # A nested global write can replace a module callable at request time.
    global_writes = set()
    for stmt in body:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Global):
                global_writes.update(node.names)
    invalid.update(global_writes)
    for name, fn in candidates.items():
        if any(isinstance(node, ast.Name) and node.id in global_writes
               for child in fn.body for node in _walk(child)):
            invalid.add(name)
    return {name: node for name, node in candidates.items() if name not in invalid}


def _helper_return(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> ast.expr | None:
    """The single return expression of a straight-line helper, docstring aside.

    Control flow (an if/else with two returns) is NOT resolved to a value: picking
    a branch would be guessing. Such a helper still has its body traced when the
    trace continues inside it -- only its return value stays opaque.
    """
    statements = [stmt for stmt in fn.body
                  if not (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant))]
    if len(statements) == 1 and isinstance(statements[0], ast.Return):
        return statements[0].value
    return None


_HELPER_SHARED = frozenset({"helpers", "resolve_budget", "helper_depth", "module_context",
                            "helper_defaults", "resolved_calls", "literals"})


def _capture_argument(name: str, expr: ast.AST, source: _PathState) -> _PathState:
    """Freeze an argument before any callee parameter is rebound."""
    captured = source.copy()
    # A helper return cannot introduce a second transition through an argument.
    captured.helper_depth = 1
    _bind_path(ast.Name(id=name), expr, captured)
    for attr, value in vars(captured).items():
        if attr in _HELPER_SHARED or attr in {"model_fields", "model_types"}:
            continue
        if isinstance(value, dict):
            setattr(captured, attr, {name: value[name]} if name in value else {})
        elif isinstance(value, set):
            setattr(captured, attr, value & {name})
    return captured


def _helper_state(call: ast.Call, state: _PathState) -> _PathState | None:
    """Bind frozen caller arguments in the helper's module/lexical scope.

    Defaults are captured at the declaration, while free names use module scope.
    Async/generator functions and unresolved unpacking remain opaque.
    """
    if (state.helper_depth or not isinstance(call.func, ast.Name)
            or call.func.id not in state.helpers or state.module_context is None
            or call.func.id in state.shadowed or call.func.id in state.values):
        return None
    helper = state.helpers[call.func.id]
    parameters = [*helper.args.posonlyargs, *helper.args.args]
    if (helper.args.vararg or helper.args.kwarg or helper.args.kwonlyargs
            or any(isinstance(argument, ast.Starred) for argument in call.args)
            or any(keyword.arg is None for keyword in call.keywords)
            or any(isinstance(node, ast.NamedExpr)
                   for argument in [*call.args, *(keyword.value for keyword in call.keywords)]
                   for node in _walk(argument))):
        return None
    if len(call.args) > len(parameters):
        return None
    mapping = {parameter.arg: argument for parameter, argument in zip(parameters, call.args)}
    positional_only = {parameter.arg for parameter in helper.args.posonlyargs}
    names = {parameter.arg for parameter in parameters}
    for keyword in call.keywords:
        if keyword.arg not in names or keyword.arg in positional_only or keyword.arg in mapping:
            return None
        mapping[keyword.arg] = keyword.value
    defaults = state.helper_defaults.get(helper.name, {})
    if any(parameter.arg not in mapping and parameter.arg not in defaults for parameter in parameters):
        return None
    if call not in state.resolved_calls:
        if len(state.resolved_calls) >= _MAX_HELPER_RESOLUTIONS:
            mark_analysis_limit()
            return None
        state.resolved_calls.add(call)
    arguments = {parameter.arg: (_capture_argument(parameter.arg, mapping[parameter.arg], state)
                                if parameter.arg in mapping else defaults[parameter.arg])
                 for parameter in parameters}
    local = state.module_context.copy()
    local.helper_depth = 1
    # Function-local stores shadow globals throughout the entire function.
    for stmt in helper.body:
        _forget_stores(stmt, local)
    for parameter in parameters:
        _bind_path(ast.Name(id=parameter.arg), None, local)
        for attr, value in vars(arguments[parameter.arg]).items():
            if attr not in _HELPER_SHARED:
                getattr(local, attr).update(value)
    return local


def _call_carries_taint(call: ast.Call, state: _PathState) -> bool:
    """Whether any argument hands the helper request-derived path material.

    Literal-only calls still resolve their return value, but their bodies hold
    nothing to report, so scanning them would spend the budget for nothing.
    """
    arguments = [a for a in call.args if not isinstance(a, ast.Starred)]
    arguments += [keyword.value for keyword in call.keywords if keyword.arg is not None]
    for argument in arguments:
        built = _path_skeleton(argument, state)
        if (built is not None and built[1]) or _path_type(argument, state, concrete=True):
            return True
    return False


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
        if isinstance(expr.func, ast.Name):
            local = _helper_state(expr, state)
            if local is not None:
                returned = _helper_return(state.helpers[expr.func.id])
                if returned is not None:
                    return _path_type(returned, local, concrete=concrete)
    return False


def _returned_property(expr: ast.AST, state: _PathState, predicate) -> bool:
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Name):
        local = _helper_state(expr, state)
        if local is not None:
            returned = _helper_return(state.helpers[expr.func.id])
            return returned is not None and predicate(returned, local)
    return False


def _checked_path(expr: ast.AST, state: _PathState) -> bool:
    if isinstance(expr, ast.Name):
        return expr.id in state.checked_paths
    return _returned_property(expr, state, _checked_path)


def _normalized(expr: ast.AST, state: _PathState) -> bool:
    if isinstance(expr, ast.Name):
        return expr.id in state.normalized
    if _returned_property(expr, state, _normalized):
        return True
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
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Name):
        local = _helper_state(expr, state)
        if local is not None:
            returned = _helper_return(state.helpers[expr.func.id])
            if returned is not None:
                return _path_skeleton(returned, local)
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
        if len(findings) >= remaining_findings(_MAX_FINDINGS):
            raise _FindingLimitReached
        if not isinstance(call, ast.Call):
            continue
        # The sink may sit inside a same-file helper: continue the trace into
        # its body once, on the budget, when an argument carries the request's
        # path material into it.
        if (isinstance(call.func, ast.Name) and not state.helper_depth
                and call.func.id in state.helpers):
            local = _helper_state(call, state)
            if local is not None:
                if state.resolve_budget["count"] >= _MAX_HELPER_RESOLUTIONS:
                    mark_analysis_limit()
                elif _call_carries_taint(call, state):
                    state.resolve_budget["count"] += 1
                    _scan_block(state.helpers[call.func.id].body, local, path, findings)
        reaching = set()
        for argument in _path_arguments(call, state):
            if _checked_path(argument, state):
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
    checked = value is not None and _checked_path(value, state)
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
        if attr in _HELPER_SHARED:
            # One registry and one budget per file, shared by reference across
            # every branch; depth is identical in all of them. No join applies.
            continue
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
        if len(findings) >= remaining_findings(_MAX_FINDINGS):
            raise _FindingLimitReached
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
            if stmt.name in state.helpers and stmt is state.helpers[stmt.name]:
                parameters = [*stmt.args.posonlyargs, *stmt.args.args]
                default_parameters = parameters[len(parameters) - len(stmt.args.defaults):]
                state.helper_defaults[stmt.name] = {
                    parameter.arg: _capture_argument(parameter.arg, default, state)
                    for parameter, default in zip(default_parameters, stmt.args.defaults)}
            _bind_path(ast.Name(id=stmt.name), None, state)
            if stmt is state.helpers.get(stmt.name) and stmt.name not in {"open", "str"}:
                # A module-level def binds a callable; it does not shadow itself.
                # Every real rebinding above re-adds the name to `shadowed`, so
                # only the one clean declaration stays resolvable.
                state.shadowed.discard(stmt.name)
        elif isinstance(stmt, ast.If) and statically_true(stmt.test):
            # A literal-true guard is not conditional: its stores are certain
            # (app.scan.scope_statements.statically_true).
            _import_context(stmt.body, state)
        else:
            _forget_stores(stmt, state)


def _scan_scope(body: list[ast.stmt], inherited: _PathState, path: str, findings: list[CheckFinding]) -> None:
    context = inherited.copy()
    _import_context(body, context)
    if context.module_context is None:
        context.module_context = context.copy()
        context.module_context.module_context = context.module_context
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


def scan_path_traversal(fileobj: BinaryIO, *, coverage: dict | None = None) -> list[CheckFinding]:
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
                    _scan_scope(tree.body,
                                _PathState(helpers=_module_helpers(tree.body),
                                           resolve_budget={"count": 0}),
                                info.filename, findings)
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
            "The trace covers this handler and at most one eligible same-file helper. "
            "Constraints outside this bounded trace have NOT been verified."
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

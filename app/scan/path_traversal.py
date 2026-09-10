"""A filesystem path assembled from the caller's input, without a containment check.

WHY THIS EXISTS. The classic path traversal is two tokens long: take a name out of
the request, join it to an upload directory, hand it to open(). `../../../../etc/passwd`
or a `.py` written into a served directory turns a file feature into a read of
anything the process can read, or a write of anything it can write. The static stage
read none of it: measured before writing, no rule in app/scan matched open,
os.path.join, send_file, FileResponse or secure_filename.

WHAT IT REPORTS, AND WHAT IT DOES NOT CLAIM. Inside a function that declares an HTTP
route, a call that hands a filesystem path to a sink -- open, Path, os.open,
send_file, FileResponse, ZipFile, tarfile, shutil, the os removal/rename family,
read_text/write_text -- where the path is assembled from one of that handler's own
request inputs and no containment check on it is visible in the same function. That
is a fact about the source. It is NOT proof of a reachable traversal: a check in a
wrapper, a filesystem that cannot escape a mount, or a caller that only ever sends
safe names are all invisible here, and the finding says so. Silence is not a
certificate either -- a path built in a helper and passed in, or reached through a
variable this rule does not resolve, is not covered.

WHY IT IS NOT A GREP, and what counts as containment:

    open(os.path.join(UPLOAD_DIR, name))                  the defect
    open(os.path.join(UPLOAD_DIR, secure_filename(name))) contained
    open(os.path.join(UPLOAD_DIR, os.path.basename(name))) contained
    target = (BASE / name).resolve(); target.relative_to(BASE)   contained
    open(os.path.join(UPLOAD_DIR, "report.csv"))          a literal

The first and the second differ by one call, and the second and third by which call.
A regex over `open(` reports all four. Containment is therefore a vocabulary read at
the expression AND at the statement level: `secure_filename`, `basename`, `.name`,
`relative_to`, `is_relative_to`, `commonpath`, and the shared validation words
(validate/check/sanitize/allow/...), applied either inside the path expression or in
a test that runs before the sink. `resolve()` alone is NOT containment -- it
normalises a path without restricting it, and treating it as a check would silence
the very case this rule exists for.

THE MACHINERY IS IMPORTED, NOT COPIED. The state, the import binding, the request
input model, the string skeleton and the check vocabulary come from
app/scan/outbound_url.py, the sink rule that shares this family; a second copy of
them would drift and the family would disagree with itself about what a request input
is. What is separate here is the sink judgement (which calls touch the filesystem) and
the containment vocabulary (which calls make a path safe), because those are what a
path rule and a URL rule do NOT share. A follow-up worth doing: the statement-ordered
loop below mirrors the sibling's, and belongs in one place for the whole family.

NEVER EXECUTES THE UPLOADED CODE. ast.parse builds a tree over the bytes in the
archive; nothing is imported, run or opened.
"""

from __future__ import annotations

import ast
import zipfile
from typing import BinaryIO

from app.scan.checks import CheckFinding
from app.scan.outbound_url import (
    _MAX_FILES,
    _MAX_FILE_BYTES,
    _MAX_FINDINGS,
    _State,
    _bind,
    _bounded_tree,
    _check_call,
    _checked_names,
    _import,
    _qualified,
    _request_inputs,
    _skeleton,
    _walk,
)
from app.scan.secrets import is_non_production_path

RULE_ID = "path-traversal-file-sink"

# Calls that take a filesystem path as their dangerous argument. Matched as
# qualified names after import binding (`from os import open as o_open` resolves),
# so the same call is judged however the file spells it.
_PATH_FIRST_SINKS = frozenset({
    "builtins.open",  # open() lives here in the qualified form
    # The bare names cover `from pathlib import Path` read in a snippet whose import
    # this trace did not bind, and the star-import case that binds nothing readable.
    "Path", "PurePath", "PosixPath", "WindowsPath", "FileResponse", "ZipFile",
    "os.open",
    "os.listdir", "os.mkdir", "os.makedirs", "os.remove", "os.rename", "os.replace",
    "os.rmdir", "os.scandir", "os.stat", "os.unlink", "os.utime",
    "pathlib.Path", "pathlib.PosixPath", "pathlib.WindowsPath", "pathlib.PurePath",
    "shutil.copy", "shutil.copy2", "shutil.copyfile", "shutil.copytree", "shutil.move",
    "shutil.rmtree",
    "send_file",
    "zipfile.ZipFile", "tarfile.open",
    "pandas.read_csv", "pandas.read_excel", "pandas.read_json", "pandas.read_table",
    "numpy.load", "numpy.loadtxt", "numpy.genfromtxt",
})

# Classes that are constructed with a path and then written or read through.
_FILE_RESPONSE = frozenset({"starlette.responses.FileResponse", "fastapi.responses.FileResponse"})

# Methods on a path-like object. The receiver is not resolved beyond the parameter
# it was bound to, so these are matched on the method name and judged on the
# argument the same way a bare call is.
_PATH_METHODS = frozenset({
    "read_bytes", "read_text", "write_bytes", "write_text", "open", "unlink", "rename",
    "replace", "touch", "mkdir", "rmdir", "iterdir", "glob", "rglob",
})

# The containment vocabulary. Anything here, applied to the value before it reaches
# the sink, is a check in the sense this rule means: it constrains WHERE the path can
# point. `resolve`/`normpath` are deliberately absent -- they normalise, they do not
# restrict, and `resolve()` immediately before a sink is exactly the case a naive
# vocabulary would silence.
_CONTAINMENT_WORDS = frozenset({
    "basename", "commonpath", "commonprefix", "is_relative_to", "name", "relative_to",
    "secure_filename", "safe_join", "scrub",
})


def _qualified_sink(node: ast.AST, state: _State) -> str:
    """The imported name of a call target, falling back to the dotted source text.

    `_qualified` answers only for names this file BOUND (through an import or an
    assignment), which is right for deciding whether a call is `httpx.get` and wrong
    for `open(...)`: a builtin is never bound, and the first version of this module
    returned an empty name for every builtin call, so the rule was silent on all of
    them. The fallback reads the name as written -- `open`, `shutil.rmtree` -- which
    is also what makes `secure_filename(...)` recognisable as containment.
    """
    qualified = _qualified(node, state.bindings)
    if qualified:
        return "builtins.open" if qualified == "open" else qualified
    return _dotted_text(node)


def _dotted_text(node: ast.AST) -> str:
    """The name as the source spells it, for a call target that resolves to nothing.

    A module used without an import in this file (`shutil.rmtree(...)` in a snippet,
    or one imported inside a function) still says what it is; refusing to read it
    would make the rule's silence depend on import style rather than on the call.
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_text(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _call_name(call: ast.Call, state: _State) -> str:
    if isinstance(call.func, (ast.Name, ast.Attribute)):
        return _qualified_sink(call.func, state)
    return ""


def _contains_containment(call: ast.Call, state: _State) -> bool:
    """Does the path expression itself apply a containment call?

    `secure_filename(name)` inside the argument is the standard fix, and it is the
    shape the corpus pins: the same statement, one call deeper.
    """
    for node in _walk(call):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node, state)
        leaf = name.rsplit(".", 1)[-1].lower()
        if leaf in _CONTAINMENT_WORDS or any(word in leaf for word in _CONTAINMENT_WORDS):
            return True
    return False


# Pure path TRANSFORMS: they change how a path is spelled, not where it points, so the
# caller's influence survives them and the trace follows the receiver. `resolve` and
# `normpath` are here and NOT in the containment vocabulary on purpose -- the shape
# `(BASE / name).resolve().read_text()` is exactly the defect, and a rule that read
# `resolve` as a check would silence it.
_PATH_TRANSFORMS = frozenset({
    "absolute", "expanduser", "joinpath", "normpath", "realpath", "resolve",
    "with_name", "with_stem", "with_suffix", "parent", "os.path.normpath",
    "os.path.abspath", "os.path.realpath", "pathlib.Path.resolve",
})


def _path_skeleton(expr: ast.AST, state: _State) -> tuple[str, list[set[str]]] | None:
    """`_skeleton` plus the two ways this family assembles a path.

    The sibling rule needed `urljoin`; a filesystem path is assembled with
    `os.path.join(BASE, name)` and with `BASE / name`. Both are treated as
    concatenation, because both produce a path whose components are the caller's
    when the caller's value is one of them.
    """
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Div):
        left = _path_skeleton(expr.left, state)
        right = _path_skeleton(expr.right, state)
        if left is not None and right is not None:
            text_left = left[0] + ("/" if left[0] and not left[0].endswith("/") else "")
            return text_left + right[0], [*left[1], *right[1]]
        return None
    if isinstance(expr, ast.Call):
        qualified = _call_name(expr, state)
        if qualified in {"os.path.join", "posixpath.join", "ntpath.join"} or qualified.endswith(".join"):
            text, slots = "", []
            for part in expr.args:
                piece = _path_skeleton(part, state)
                if piece is None:
                    return None
                if text and not text.endswith("/"):
                    text += "/"
                text += piece[0]
                slots.extend(piece[1])
            return text, slots
        leaf = qualified.rsplit(".", 1)[-1]
        if leaf in _PATH_TRANSFORMS or qualified in _PATH_TRANSFORMS:
            # A transform is transparent to the trace: `.resolve()` normalises
            # without restricting, so what it returns still carries the caller's
            # value -- and reading it as a check is the mistake this rule exists to
            # avoid.
            if expr.args:
                return _path_skeleton(expr.args[0], state)
            if isinstance(expr.func, ast.Attribute):
                return _path_skeleton(expr.func.value, state)
            return None
        if (qualified in _FILE_RESPONSE or qualified in _PATH_FIRST_SINKS) and expr.args:
            # `Path(BASE)` / `FileResponse(BASE / name)`: the wrapper's own argument is
            # the path, and the wrapper adds no structure to read.
            return _path_skeleton(expr.args[0], state)
    return _skeleton(expr, state)


def _reaching_inputs(call: ast.Call, argument: ast.AST, state: _State,
                     containment_in_expression: bool) -> set[str]:
    built = _path_skeleton(argument, state)
    if built is None:
        return set()
    reaching = set().union(*built[1]) if built[1] else set()
    if not reaching:
        return set()
    if containment_in_expression:
        return set()
    return {name for name in reaching if name not in state.checked}


_MODULE_PREFIXES = ("os.", "shutil.", "zipfile.", "tarfile.", "pandas.", "numpy.", "pathlib.", "builtins.")


def _path_argument(call: ast.Call, state: _State) -> ast.AST | None:
    """The expression used as a path, for each sink shape.

    A method that is called ON a path takes its path from the receiver
    (`(BASE / name).read_text()`), while a function-style sink takes it as the first
    argument (`open(path)`, `shutil.rmtree(path)`). Confusing the two made the
    inline method form invisible.
    """
    qualified = _call_name(call, state)
    if not qualified:
        return None
    leaf = qualified.rsplit(".", 1)[-1]
    if leaf in _PATH_METHODS and not qualified.startswith(_MODULE_PREFIXES) and not qualified.startswith(
            ("os.", "shutil.", "zipfile.", "tarfile.", "pandas.", "numpy.")):
        if call.args:
            return call.args[0]
        if isinstance(call.func, ast.Attribute):
            return call.func.value
        return None
    if qualified in _PATH_FIRST_SINKS or qualified in _FILE_RESPONSE:
        return call.args[0] if call.args else None
    return None


def _scan_expression(expr: ast.AST, state: _State, path: str, findings: list[CheckFinding]) -> None:
    for call in _walk(expr):
        if len(findings) >= _MAX_FINDINGS:
            return
        if not isinstance(call, ast.Call):
            continue
        argument = _path_argument(call, state)
        if argument is None:
            continue
        reaching = _reaching_inputs(call, argument, state, _contains_containment(call, state))
        if reaching:
            findings.append(_finding(path, call, reaching))


def _bind_path(target: ast.AST, value: ast.AST | None, state: _State) -> None:
    """Bind a local the way the family does, then keep a PATH reading of it too.

    The sibling's binding stores what its own skeleton can read, and that skeleton
    knows `urljoin` but not `.resolve()`. Without this, `candidate = (BASE /
    name).resolve()` loses the caller's value at the assignment -- and `candidate`
    is exactly how the guarded case is written in real code.
    """
    _bind(target, value, state)
    if value is None or not isinstance(target, ast.Name):
        return
    if target.id in state.values:
        return  # the family already read this one; do not overwrite its structure
    built = _path_skeleton(value, state)
    if built is not None:
        state.values[target.id] = built


def _scan_block(body: list[ast.stmt], state: _State, path: str, findings: list[CheckFinding]) -> None:
    """Statements in order, so a check only counts if it runs BEFORE the sink.

    A check after the call is not a check, and a check in a branch that does not
    execute is not one either. The sibling rule's loop is the model; it is repeated
    here in the compact form this rule needs.
    """
    for stmt in body:
        if len(findings) >= _MAX_FINDINGS:
            return
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            _bind(ast.Name(id=stmt.name), None, state)
            continue
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            _import(stmt, state)
            continue
        if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            if stmt.value is not None:
                _scan_expression(stmt.value, state, path, findings)
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            for target in targets:
                _bind_path(target, stmt.value, state)
            continue
        if isinstance(stmt, ast.If):
            _scan_expression(stmt.test, state, path, findings)
            if _test_contains_check(stmt.test, state):
                state.checked |= _checked_from_test(stmt.test, state)
            for branch in (stmt.body, stmt.orelse):
                branch_state = state.copy()
                _scan_block(branch, branch_state, path, findings)
            continue
        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                _scan_expression(item.context_expr, state, path, findings)
                if item.optional_vars is not None:
                    _bind_path(item.optional_vars, item.context_expr, state)
            _scan_block(stmt.body, state, path, findings)
            continue
        if isinstance(stmt, (ast.Try, ast.TryStar)):
            # `ast.iter_child_nodes` YIELDS THE ELEMENTS of list fields, not the lists,
            # so a driver that looks for `isinstance(child, list)` descends into
            # nothing -- and every endpoint that wraps its work in try/except goes
            # unreported. Six of nine hunt candidates sat in exactly that shape.
            for arm in (stmt.body, stmt.orelse, stmt.finalbody):
                _scan_block(arm, state.copy(), path, findings)
            for handler in stmt.handlers:
                _scan_block(handler.body, state.copy(), path, findings)
            continue
        if isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
            for child in ast.iter_child_nodes(stmt):
                if isinstance(child, ast.expr):
                    _scan_expression(child, state, path, findings)
            _scan_block(stmt.body, state.copy(), path, findings)
            if getattr(stmt, "orelse", None):
                _scan_block(stmt.orelse, state.copy(), path, findings)
            continue
        _scan_expression(stmt, state, path, findings)


def _checked_from_test(test: ast.AST, state: _State) -> set[str]:
    """Names a containment test constrains, when the test inspects them."""
    checked = _check_call(test, state)
    if checked:
        return checked
    for node in _walk(test):
        if isinstance(node, ast.Call):
            name = _call_name(node, state)
            leaf = name.rsplit(".", 1)[-1].lower()
            if leaf in _CONTAINMENT_WORDS or any(word in leaf for word in _CONTAINMENT_WORDS):
                target = node.args[1] if len(node.args) > 1 else node
                return _checked_names(target, state)
    return _checked_names(test, state) if _test_looks_like_containment(test, state) else set()


def _test_looks_like_containment(test: ast.AST, state: _State) -> bool:
    for node in _walk(test):
        if isinstance(node, ast.Call):
            leaf = _call_name(node, state).rsplit(".", 1)[-1].lower()
            if leaf in _CONTAINMENT_WORDS or any(word in leaf for word in _CONTAINMENT_WORDS):
                return True
    return False


def _test_contains_check(test: ast.AST, state: _State) -> bool:
    if _test_looks_like_containment(test, state):
        return True
    return bool(_check_call(test, state))


def _scan_file(tree: ast.Module, path: str, findings: list[CheckFinding]) -> None:
    """Route handlers, declared at module level or inside a lexical factory."""
    for stmt in tree.body:
        if isinstance(stmt, (ast.Import, ast.ImportFrom, ast.Assign, ast.AnnAssign)):
            continue
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if _declares_route(stmt):
                local = _State()
                _import_context(tree, local)
                _request_inputs(stmt, local)
                _scan_block(stmt.body, local, path, findings)
            _scan_factory(stmt, path, findings)


def _declares_route(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return any(isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)
               and dec.func.attr in {"delete", "get", "head", "options", "patch", "post",
                                     "put", "route", "api_route", "websocket"}
               for dec in fn.decorator_list)


def _import_context(tree: ast.Module, state: _State) -> None:
    for stmt in tree.body:
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            _import(stmt, state)
        elif isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            for target in targets:
                _bind_path(target, stmt.value, state)


def _scan_factory(fn: ast.FunctionDef | ast.AsyncFunctionDef, path: str,
                  findings: list[CheckFinding]) -> None:
    """A router factory is read lexically; the handler inside it is still a handler."""
    for stmt in fn.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) and _declares_route(stmt):
            local = _State()
            _import_context(ast.Module(body=fn.body, type_ignores=[]), local)
            _request_inputs(stmt, local)
            _scan_block(stmt.body, local, path, findings)
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _scan_factory(stmt, path, findings)


def scan_path_traversal(fileobj: BinaryIO) -> list[CheckFinding]:
    findings: list[CheckFinding] = []
    with zipfile.ZipFile(fileobj) as archive:
        infos = [info for info in archive.infolist()
                 if not info.is_dir() and info.filename.endswith(".py")
                 and info.file_size <= _MAX_FILE_BYTES
                 and not is_non_production_path(info.filename)]
        for info in infos[:_MAX_FILES]:
            if len(findings) >= _MAX_FINDINGS:
                break
            try:
                tree = ast.parse(archive.read(info).decode("utf-8"))
            except (SyntaxError, UnicodeError, ValueError, RecursionError):
                continue
            if not _bounded_tree(tree):
                continue
            _scan_file(tree, info.filename, findings)
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
            "which this handler receives from the request, and no containment check on it was "
            "visible in the same function. A value like `../../etc/passwd` -- or a name that ends "
            "in a served extension -- turns this into reading or writing files the application "
            "never intended to touch. Whether anything outside this function constrains the path "
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

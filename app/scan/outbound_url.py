"""Bounded, source-only signal for caller-controlled outbound Python addresses.

Only locally declared FastAPI routes and HTTP clients with visible import or
constructor provenance are read. A function's statements are visited in order;
plain assignments preserve literal URL structure, while unknown calls stop the
trace. No uploaded code is imported or executed, and helpers are not analysed
across calls -- a local `def` opens its own scope, and its parameter is not this
handler's parameter (corpus: negative/address-inside-a-local-helper). A
recognised local check suppresses this signal without certifying that the check,
redirects, DNS resolution or the network boundary are safe.
"""

from __future__ import annotations

import ast
import re
import string
import zipfile
from dataclasses import dataclass, field
from typing import BinaryIO

from app.scan.checks import CheckFinding
from app.scan.secrets import is_non_production_path

RULE_ID = "python-outbound-request-unvalidated-url"
_METHODS = frozenset({"delete", "get", "head", "options", "patch", "post", "put", "request", "stream"})
_HTTP_MODULES = frozenset({"httpx", "requests", "aiohttp"})
_CONSTRUCTORS = frozenset({
    "httpx.Client", "httpx.AsyncClient", "requests.Session", "requests.sessions.Session",
    "aiohttp.ClientSession", "http.client.HTTPConnection", "http.client.HTTPSConnection",
})
_URL_FUNCTIONS = frozenset({"urllib.request.urlopen", "urllib.request.urlretrieve"})
_ROUTERS = frozenset({"fastapi.FastAPI", "fastapi.APIRouter"})
_REQUEST_TYPES = frozenset({"fastapi.Request", "starlette.requests.Request"})
_MODEL_BASES = frozenset({"pydantic.BaseModel", "pydantic.main.BaseModel", "pydantic.v1.BaseModel"})
_DEPENDENCIES = frozenset({"fastapi.Depends", "fastapi.Security"})
_REQUEST_ATTRS = frozenset({"body", "form", "json", "path_params", "query_params", "headers", "cookies", "url"})
_VALIDATION_WORDS = frozenset({
    "allow", "assert", "canonical", "deny", "ensure", "guard", "is_public",
    "is_safe", "permit", "restrict", "sanitise", "sanitize", "scrub", "validate", "valid", "verify",
})
_URL_INSPECTORS = frozenset({
    "endswith", "fullmatch", "hostname", "ip_address", "is_global", "is_loopback",
    "is_private", "match", "netloc", "resolve", "scheme", "search", "startswith", "urlparse", "urlsplit",
})
_COMPARISON_TARGET_WORDS = frozenset({"allow", "domain", "host", "pattern", "prefix", "safe", "scheme"})
_MAX_FILE_BYTES = 400_000
_MAX_FILES = 400
_MAX_FINDINGS = 32
_MAX_AST_NODES = 20_000
_MAX_AST_DEPTH = 100
# Bound repeated local string expansion as well as the input file itself.
_MAX_TEMPLATE_BYTES = 16_000
_MAX_SLOTS = 256
_MARKER = "\x00"
_PERCENT = re.compile(r"%(?:\((?P<key>[^)]+)\))?[#0 +\-]*\d*(?:\.\d+)?[sradifgGouxXeE%]")


@dataclass
class _State:
    bindings: dict[str, str] = field(default_factory=dict)
    values: dict[str, tuple[str, list[set[str]]]] = field(default_factory=dict)
    requests: set[str] = field(default_factory=set)
    checked: set[str] = field(default_factory=set)
    model_types: dict[str, frozenset[str]] = field(default_factory=dict)
    models: dict[str, str] = field(default_factory=dict)
    model_fields: dict[str, tuple[str, list[set[str]]] | None] = field(default_factory=dict)
    strings: set[str] = field(default_factory=set)

    def copy(self) -> _State:
        return _State(self.bindings.copy(), self.values.copy(), self.requests.copy(), self.checked.copy(),
                      self.model_types.copy(), self.models.copy(), self.model_fields.copy(), self.strings.copy())


def _attr_name(node: ast.AST) -> str:
    if isinstance(node, ast.Attribute):
        return node.attr
    return node.id if isinstance(node, ast.Name) else ""


def _qualified(node: ast.AST | None, bindings: dict[str, str]) -> str:
    if isinstance(node, ast.Name):
        return bindings.get(node.id, "")
    if isinstance(node, ast.Attribute):
        base = _qualified(node.value, bindings)
        return base + "." + node.attr if base else ""
    return ""


def _walk(node: ast.AST):
    """Visit one expression/statement, never an inner callable or class scope."""
    pending = [node]
    while pending:
        item = pending.pop()
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda,
                             ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            continue
        yield item
        pending.extend(reversed(list(ast.iter_child_nodes(item))))


def _referenced_names(expr: ast.AST) -> set[str]:
    return {node.id for node in _walk(expr) if isinstance(node, ast.Name)}


def _bounded_tree(tree: ast.AST) -> bool:
    pending = [(tree, 0)]
    count = 0
    while pending:
        node, depth = pending.pop()
        count += 1
        if count > _MAX_AST_NODES or depth > _MAX_AST_DEPTH:
            return False
        pending.extend((child, depth + 1) for child in ast.iter_child_nodes(node))
    return True


def _field_key(expr: ast.AST | None) -> str | None:
    if isinstance(expr, ast.Constant) and isinstance(expr.value, (str, int)):
        key = repr(expr.value)
        return key if len(key) <= 120 else None
    return None


def _annotation(expr: ast.AST | None, state: _State) -> ast.AST | None:
    if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
        try:
            expr = ast.parse(expr.value, mode="eval").body
        except (SyntaxError, ValueError, RecursionError):
            return None
    if (isinstance(expr, ast.Subscript)
            and _qualified(expr.value, state.bindings) in {"typing.Annotated", "typing_extensions.Annotated"}
            and isinstance(expr.slice, ast.Tuple) and expr.slice.elts):
        return _annotation(expr.slice.elts[0], state)
    return expr


def _string_annotation(expr: ast.AST | None, state: _State) -> bool:
    expr = _annotation(expr, state)
    return ((isinstance(expr, ast.Name) and expr.id == "str" and "str" not in state.bindings)
            or _qualified(expr, state.bindings) == "builtins.str")


def _model_field(expr: ast.AST, state: _State) -> str | None:
    if isinstance(expr, ast.Attribute) and isinstance(expr.value, ast.Name):
        origin = state.models.get(expr.value.id)
        key = f"{origin}.{expr.attr}" if origin is not None else None
        if key in state.model_fields:
            return key
    return None


def _string_value(expr: ast.AST, state: _State) -> bool:
    """Only known strings may use the small, non-validating strip() transfer."""
    if isinstance(expr, ast.Constant):
        return isinstance(expr.value, str)
    if isinstance(expr, ast.Name):
        return expr.id in state.strings
    key = _model_field(expr, state)
    if key is not None:
        return key in state.strings
    receiver = None
    if isinstance(expr, ast.Subscript) and _field_key(expr.slice):
        receiver = expr.value
    elif (isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute)
          and expr.func.attr == "get" and expr.args and _field_key(expr.args[0])):
        # An unknown default may be a custom object with an unrelated strip().
        if (len(expr.args) > 2 or (len(expr.args) > 1 and not _string_value(expr.args[1], state))
                or any(kw.arg != "default" or not _string_value(kw.value, state) for kw in expr.keywords)):
            return False
        receiver = expr.func.value
    if (isinstance(receiver, ast.Attribute) and isinstance(receiver.value, ast.Name)
            and receiver.value.id in state.requests and receiver.attr in {"query_params", "headers", "cookies"}):
        return True
    if isinstance(expr, ast.JoinedStr):
        return True
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        return _string_value(expr.left, state) and _string_value(expr.right, state)
    if (isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute)
            and expr.func.attr == "strip" and not expr.args and not expr.keywords):
        return _string_value(expr.func.value, state)
    return False


def _request_read(expr: ast.AST, state: _State) -> set[str]:
    if isinstance(expr, ast.Await):
        return _request_read(expr.value, state)
    if isinstance(expr, ast.Subscript):
        key = _field_key(expr.slice)
        return {f"{origin}[{key}]" for origin in _request_read(expr.value, state)} if key else set()
    if isinstance(expr, ast.Attribute):
        if isinstance(expr.value, ast.Name) and expr.value.id in state.requests and expr.attr in _REQUEST_ATTRS:
            return {f"{expr.value.id}.{expr.attr}"}
        return {f"{origin}.{expr.attr}" for origin in _request_read(expr.value, state)}
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute):
        if expr.func.attr in {"get", "getlist"} and expr.args:
            key = _field_key(expr.args[0])
            return {f"{origin}[{key}]" for origin in _request_read(expr.func.value, state)} if key else set()
        if expr.func.attr in {"body", "form", "json"}:
            return {origin + "()" for origin in _request_read(expr.func, state)}
    return set()


def _combine(parts: list[tuple[str, list[set[str]]]]):
    if sum(len(text) for text, _ in parts) > _MAX_TEMPLATE_BYTES:
        return None
    if sum(len(slots) for _, slots in parts) > _MAX_SLOTS:
        return None
    return "".join(text for text, _ in parts), [slot for _, slots in parts for slot in slots]


def _skeleton(expr: ast.AST, state: _State) -> tuple[str, list[set[str]]] | None:
    if isinstance(expr, ast.Constant):
        # A literal NUL must not be confused with one of our own placeholders.
        if isinstance(expr.value, str) and _MARKER not in expr.value:
            return expr.value, []
        return None
    if isinstance(expr, ast.Name):
        return state.values.get(expr.id)
    key = _model_field(expr, state)
    if key is not None:
        return state.model_fields[key]
    read = _request_read(expr, state)
    if read:
        return _MARKER, [read]
    if isinstance(expr, ast.Subscript):
        source = _skeleton(expr.value, state)
        # A JSON/query value can be indexed; do not turn a fixed-host URL local
        # into a caller-controlled whole URL merely because it has a subscript.
        key = _field_key(expr.slice)
        if source and source[0] == _MARKER and key:
            return _MARKER, [{f"{origin}[{key}]" for origin in source[1][0]}]
        return None
    if (isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute)
            and expr.func.attr == "strip" and not expr.args and not expr.keywords
            and _string_value(expr.func.value, state)):
        value = _skeleton(expr.func.value, state)
        # Whitespace removal preserves each source slot; it is not validation.
        return (value[0].strip(), value[1]) if value is not None else None
    if isinstance(expr, ast.JoinedStr):
        parts = []
        for value in expr.values:
            if isinstance(value, ast.Constant):
                sub = _skeleton(value, state)
            elif isinstance(value, ast.FormattedValue) and value.format_spec is None:
                sub = _skeleton(value.value, state)
            else:
                return None
            if sub is None:
                return None
            parts.append(sub)
        return _combine(parts)
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        left, right = _skeleton(expr.left, state), _skeleton(expr.right, state)
        return _combine([left, right]) if left is not None and right is not None else None
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Mod):
        if not isinstance(expr.left, ast.Constant) or not isinstance(expr.left.value, str):
            return None
        template = expr.left.value
        args = list(expr.right.elts) if isinstance(expr.right, ast.Tuple) else [expr.right]
        mapping = {}
        if isinstance(expr.right, ast.Dict):
            mapping = {key.value: value for key, value in zip(expr.right.keys, expr.right.values)
                       if isinstance(key, ast.Constant) and isinstance(key.value, str)}
        parts, offset, index = [], 0, 0
        for match in _PERCENT.finditer(template):
            literal = template[offset:match.start()]
            if "%" in literal:
                return None
            parts.append((literal, []))
            if match.group() == "%%":
                parts.append(("%", []))
            else:
                key = match.group("key")
                value = mapping.get(key) if key else args[index] if index < len(args) else None
                if not key:
                    index += 1
                sub = _skeleton(value, state) if value is not None else None
                if sub is None:
                    return None
                parts.append(sub)
            offset = match.end()
        if "%" in template[offset:]:
            return None
        parts.append((template[offset:], []))
        return _combine(parts)
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == "format":
        receiver = expr.func.value
        if not isinstance(receiver, ast.Constant) or not isinstance(receiver.value, str):
            return None
        keywords = {kw.arg: kw.value for kw in expr.keywords if kw.arg is not None}
        parts, auto = [], 0
        try:
            for literal, name, spec, conversion in string.Formatter().parse(receiver.value):
                parts.append((literal, []))
                if name is None:
                    continue
                if spec or conversion:
                    return None
                if not name:
                    name = str(auto)
                    auto += 1
                value = expr.args[int(name)] if name.isdigit() and int(name) < len(expr.args) else keywords.get(name)
                sub = _skeleton(value, state) if value is not None else None
                if sub is None:
                    return None
                parts.append(sub)
        except (ValueError, OverflowError):
            return None
        return _combine(parts)
    if isinstance(expr, ast.Call) and _qualified(expr.func, state.bindings) == "urllib.parse.urljoin":
        args = {kw.arg: kw.value for kw in expr.keywords}
        base_expr = expr.args[0] if expr.args else args.get("base")
        other_expr = expr.args[1] if len(expr.args) > 1 else args.get("url")
        base = _skeleton(base_expr, state) if base_expr is not None else None
        other = _skeleton(other_expr, state) if other_expr is not None else None
        if base is None or other is None:
            return None
        text, slots = other
        # An absolute second URL replaces the base, including its host.
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", text) or text.startswith("//"):
            return other
        prefix = text.split(_MARKER, 1)[0]
        # A value at the beginning can supply a scheme or //host. Even /{value}
        # is unsafe: value=/other-host becomes a network-path reference.
        scheme_prefixes = {"http", "https", "http:", "https:", "http:/", "https:/"}
        if slots and (not prefix or prefix == "/" or prefix in scheme_prefixes):
            origins = set().union(*slots)
            return _MARKER, [origins | _host_inputs(base)]
        return _combine([base, ("/", []), other])
    # Unknown calls may validate/transform a value. Never infer their result.
    return None


def _host_inputs(built: tuple[str, list[set[str]]]) -> set[str]:
    template, slots = built
    scheme = template.find("://")
    start = scheme + 3 if scheme >= 0 else 2 if template.startswith("//") else 0
    end = min((pos for char in "/?#" if (pos := template.find(char, start)) >= 0), default=len(template))
    result, position = set(), -1
    for origins in slots:
        position = template.find(_MARKER, position + 1)
        # A caller-provided prefix before a literal scheme may itself include a
        # complete URL. It must not disappear just because :// occurs later.
        if position < 0:
            break
        if position < end and (position >= start or scheme >= 0):
            result |= origins
    return result


def _client_type(expr: ast.AST, state: _State) -> str:
    if isinstance(expr, ast.Call):
        constructor = _qualified(expr.func, state.bindings)
        return constructor if constructor in _CONSTRUCTORS else ""
    bound = _qualified(expr, state.bindings)
    return bound.removeprefix("client:") if bound.startswith("client:") else ""


def _outbound_argument(call: ast.Call, state: _State) -> tuple[ast.AST, bool] | None:
    qualified = _qualified(call.func, state.bindings)
    constructor = qualified in _CONSTRUCTORS
    if constructor:
        keys = {"host"} if qualified.startswith("http.client.") else {"base_url"}
        positional = 0 if qualified.startswith("http.client.") or qualified == "aiohttp.ClientSession" else None
    elif qualified in _URL_FUNCTIONS:
        keys, positional = {"url", "fullurl"}, 0
    elif isinstance(call.func, ast.Attribute) and call.func.attr in _METHODS:
        module = _qualified(call.func.value, state.bindings)
        client = _client_type(call.func.value, state)
        if module not in _HTTP_MODULES and not client:
            return None
        # HTTPConnection.request receives a path. The host sink is its constructor.
        if client.startswith("http.client."):
            return None
        keys, positional = {"url"}, 1 if call.func.attr in {"request", "stream"} else 0
    elif qualified.rsplit(".", 1)[0] in _HTTP_MODULES and qualified.rsplit(".", 1)[-1] in _METHODS:
        keys, positional = {"url"}, 1 if qualified.rsplit(".", 1)[-1] in {"request", "stream"} else 0
    else:
        return None
    for keyword in call.keywords:
        if keyword.arg in keys:
            return keyword.value, constructor
    if positional is not None and len(call.args) > positional:
        return call.args[positional], constructor
    return None


def _request_inputs(fn: ast.FunctionDef | ast.AsyncFunctionDef, state: _State) -> None:
    positional = [*fn.args.posonlyargs, *fn.args.args]
    defaults = [None] * (len(positional) - len(fn.args.defaults)) + list(fn.args.defaults)
    arguments = list(zip(positional, defaults)) + list(zip(fn.args.kwonlyargs, fn.args.kw_defaults))
    declarations = state.copy()
    for arg, default in arguments:
        _bind(ast.Name(id=arg.arg), None, state)
        annotation = arg.annotation
        if isinstance(annotation, ast.Constant) and isinstance(annotation.value, str):
            try:
                annotation = ast.parse(annotation.value, mode="eval").body
            except (SyntaxError, ValueError, RecursionError):
                annotation = None
        annotations = list(_walk(annotation)) if annotation is not None else []
        if any(isinstance(node, ast.Call) and _qualified(node.func, declarations.bindings) in _DEPENDENCIES
               for node in annotations) or (isinstance(default, ast.Call)
                                            and _qualified(default.func, declarations.bindings) in _DEPENDENCIES):
            continue
        annotation = _annotation(annotation, declarations)
        annotation_type = _qualified(annotation, declarations.bindings)
        if annotation_type in _REQUEST_TYPES:
            state.requests.add(arg.arg)
            continue
        if annotation_type in declarations.model_types:
            fields = declarations.model_types[annotation_type]
            if len(fields) + len(state.model_fields) > _MAX_SLOTS:
                continue
            state.models[arg.arg] = arg.arg
            for name in fields:
                key = f"{arg.arg}.{name}"
                state.model_fields[key] = (_MARKER, [{key}])
                state.strings.add(key)
            continue
        if arg.arg not in {"self", "cls"}:
            # A literal default is still a caller-overridable FastAPI parameter.
            state.values[arg.arg] = (_MARKER, [{arg.arg}])
            if _string_annotation(annotation, declarations):
                state.strings.add(arg.arg)


def _import(stmt: ast.Import | ast.ImportFrom, state: _State) -> None:
    if isinstance(stmt, ast.Import):
        for alias in stmt.names:
            local = alias.asname or alias.name.split(".")[0]
            _bind(ast.Name(id=local), None, state)
            state.bindings[local] = alias.name if alias.asname else local
    else:
        for alias in stmt.names:
            if alias.name != "*":
                local = alias.asname or alias.name
                _bind(ast.Name(id=local), None, state)
                if stmt.level == 0:
                    state.bindings[local] = f"{stmt.module}.{alias.name}"


def _bind(target: ast.AST, value: ast.AST | None, state: _State) -> None:
    key = _model_field(target, state)
    if key is not None:
        built = _skeleton(value, state) if value is not None else None
        string_value = value is not None and _string_value(value, state)
        # Keep an explicit unknown so the original request field cannot reappear
        # after an untraceable assignment. Aliases share this field storage, but
        # saved immutable strings keep their old origins and preceding checks.
        # A replacement field brings its own origins, without the old checks.
        state.model_fields[key] = built
        state.strings.discard(key)
        if string_value:
            state.strings.add(key)
        return
    if not isinstance(target, ast.Name):
        for name in _referenced_names(target):
            _bind(ast.Name(id=name), None, state)
        return
    name = target.id
    built = _skeleton(value, state) if value is not None else None
    client = _client_type(value, state) if value is not None else ""
    qualified = _qualified(value, state.bindings) if value is not None else ""
    router = isinstance(value, ast.Call) and _qualified(value.func, state.bindings) in _ROUTERS
    request = isinstance(value, ast.Name) and value.id in state.requests
    model = state.models.get(value.id) if isinstance(value, ast.Name) else None
    string_value = value is not None and _string_value(value, state)
    # Rebinding an origin invalidates earlier checks of that source.
    old_origins = set().union(*state.values.get(name, ("", []))[1])
    state.checked -= old_origins | {name}
    state.values.pop(name, None)
    state.bindings.pop(name, None)
    state.requests.discard(name)
    state.models.pop(name, None)
    state.strings.discard(name)
    if built is not None:
        state.values[name] = built
    if client:
        state.bindings[name] = "client:" + client
    elif router:
        state.bindings[name] = "router"
    elif qualified:
        state.bindings[name] = qualified
    elif name == "str":
        state.bindings[name] = ""  # A shadowed builtin is not a string annotation.
    if request:
        state.requests.add(name)
    if model is not None:
        state.models[name] = model
    if string_value:
        state.strings.add(name)


def _checked_names(expr: ast.AST, state: _State) -> set[str]:
    value = _skeleton(expr, state)
    if value is not None:
        return set().union(*value[1])
    # Preserve field identity: checking request.email must not check request.url.
    # Unknown attributes/subscripts are not collapsed back to their container.
    if isinstance(expr, (ast.Attribute, ast.Subscript)):
        return set()
    if isinstance(expr, ast.Call):
        children = [*expr.args, *(kw.value for kw in expr.keywords)]
        if isinstance(expr.func, ast.Attribute):
            children.append(expr.func.value)
    else:
        children = list(ast.iter_child_nodes(expr))
    names = set()
    for child in children:
        names |= _checked_names(child, state)
    return names


def _check_call(expr: ast.AST, state: _State) -> set[str]:
    # Only a standalone, preceding check is considered. An unknown builder used
    # as the URL expression stops tracing; it is not evidence of validation.
    if isinstance(expr, ast.Await):
        expr = expr.value
    if isinstance(expr, ast.Call) and any(word in _attr_name(expr.func).lower() for word in _VALIDATION_WORDS):
        return _checked_names(expr, state)
    return set()


def _terminates(body: list[ast.stmt]) -> bool:
    return bool(body) and isinstance(body[-1], (ast.Raise, ast.Return))


def _scan_block(body: list[ast.stmt], state: _State, path: str, findings: list[CheckFinding]) -> None:
    for stmt in body:
        if len(findings) >= _MAX_FINDINGS:
            return
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            _bind(ast.Name(id=stmt.name), None, state)
            continue
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            _import(stmt, state)
            continue
        # Handle control-flow bodies independently. Only checks on the executed
        # path apply; a later/nested/dead check cannot suppress an earlier sink.
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
            # These control-flow joins are outside this deliberately small trace.
            # Scan each lexical arm in isolation, and forget locals assigned by
            # the construct before scanning subsequent statements.
            for child in ast.iter_child_nodes(stmt):
                if isinstance(child, ast.expr):
                    _scan_expr(child, state, path, findings)
            bodies = [getattr(stmt, key, []) for key in ("body", "orelse", "finalbody")]
            bodies += [handler.body for handler in getattr(stmt, "handlers", [])]
            bodies += [case.body for case in getattr(stmt, "cases", [])]
            for branch in bodies:
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


def _join_states(state: _State, branches: list[_State]) -> None:
    # Retain only facts shared by every continuing path; unknown merges stop the
    # trace instead of manufacturing an unproven data-flow relationship.
    first = branches[0]
    state.values = {key: value for key, value in first.values.items()
                    if all(branch.values.get(key) == value for branch in branches[1:])}
    state.bindings = {key: value for key, value in first.bindings.items()
                      if all(branch.bindings.get(key) == value for branch in branches[1:])}
    state.requests = set.intersection(*(branch.requests for branch in branches))
    state.checked = set.intersection(*(branch.checked for branch in branches))
    state.model_types = {key: value for key, value in first.model_types.items()
                         if all(branch.model_types.get(key) == value for branch in branches[1:])}
    state.models = {key: value for key, value in first.models.items()
                    if all(branch.models.get(key) == value for branch in branches[1:])}
    state.model_fields = {key: value for key, value in first.model_fields.items()
                          if all(branch.model_fields.get(key) == value for branch in branches[1:])}
    state.strings = set.intersection(*(branch.strings for branch in branches))


def _scan_expr(expr: ast.AST, state: _State, path: str, findings: list[CheckFinding]) -> None:
    for call in _walk(expr):
        if len(findings) >= _MAX_FINDINGS:
            return
        if not isinstance(call, ast.Call):
            continue
        outbound = _outbound_argument(call, state)
        if outbound is None:
            continue
        url, constructor = outbound
        built = _skeleton(url, state)
        reaching = _host_inputs(built) if built is not None else set()
        if reaching and not reaching <= state.checked:
            findings.append(_finding(path, call, reaching, constructor))


def _forget_stores(stmt: ast.AST, state: _State) -> None:
    """Discard provenance changed by syntax whose value we cannot trace."""
    pending = [stmt]
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            _bind(ast.Name(id=node.name), None, state)
            continue
        if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)) and isinstance(node.ctx, (ast.Store, ast.Del)):
            _bind(node, None, state)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            _bind(ast.Name(id=node.name), None, state)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            _bind(ast.Name(id=node.name), None, state)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            _bind(ast.Name(id=node.rest), None, state)
        pending.extend(ast.iter_child_nodes(node))


def _declare_model(stmt: ast.ClassDef, state: _State) -> None:
    # Only a local, undecorated model with an imported Pydantic base is known.
    # Cross-file models, inheritance chains and custom field types remain out of
    # scope. A matching class/attribute name alone never establishes provenance.
    known = (len(stmt.bases) == 1 and _qualified(stmt.bases[0], state.bindings) in _MODEL_BASES
             and not stmt.decorator_list and not stmt.keywords)
    fields = set()
    if known:
        for member in stmt.body:
            if isinstance(member, ast.AnnAssign) and isinstance(member.target, ast.Name):
                if not member.target.id.startswith("_") and _string_annotation(member.annotation, state):
                    fields.add(member.target.id)
                else:
                    fields.discard(member.target.id)
            elif isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                fields.discard(member.name)
            elif isinstance(member, ast.Assign):
                for target in member.targets:
                    fields -= _referenced_names(target)
    _bind(ast.Name(id=stmt.name), None, state)
    if known:
        key = f"model:{stmt.lineno}:{stmt.name}"
        state.bindings[stmt.name] = key
        state.model_types[key] = frozenset(fields)


def _scan_declarations(body: list[ast.stmt], state: _State, path: str,
                       findings: list[CheckFinding]) -> None:
    """Discover routes inside lexical factories without following any calls.

    Factory arguments have unknown provenance; only the nested handler's own
    request inputs enter its trace. Unsupported scope/assignment forms discard
    imported names instead of pretending the original HTTP binding survived.
    """
    for stmt in body:
        if len(findings) >= _MAX_FINDINGS:
            return
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            _import(stmt, state)
        elif isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            for target in targets:
                _bind(target, stmt.value, state)
        elif isinstance(stmt, ast.ClassDef):
            _declare_model(stmt, state)
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if any(isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)
                   and dec.func.attr in _METHODS | {"route", "api_route", "websocket"}
                   and _qualified(dec.func.value, state.bindings) == "router"
                   for dec in stmt.decorator_list):
                local = state.copy()
                _request_inputs(stmt, local)
                _scan_block(stmt.body, local, path, findings)
            # A factory is inspected lexically, never called. This also sees a
            # factory nested in another factory, within the file's AST budget.
            nested = state.copy()
            args = [*stmt.args.posonlyargs, *stmt.args.args, *stmt.args.kwonlyargs]
            args += [arg for arg in (stmt.args.vararg, stmt.args.kwarg) if arg is not None]
            for arg in args:
                _bind(ast.Name(id=arg.arg), None, nested)
            _scan_declarations(stmt.body, nested, path, findings)
            _bind(ast.Name(id=stmt.name), None, state)
        else:
            _forget_stores(stmt, state)


def _has_route_declaration(body: list[ast.stmt]) -> bool:
    # Match only scopes _scan_declarations can reach. This is a necessary
    # syntactic condition, never a substitute for router import provenance.
    pending = list(body)
    while pending:
        stmt = pending.pop()
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if any(isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)
                   and dec.func.attr in _METHODS | {"route", "api_route", "websocket"}
                   for dec in stmt.decorator_list):
                return True
            pending.extend(stmt.body)
    return False


def scan_outbound_url(fileobj: BinaryIO) -> list[CheckFinding]:
    findings: list[CheckFinding] = []
    with zipfile.ZipFile(fileobj) as archive:
        count = 0
        for info in archive.infolist():
            if (not info.filename.endswith(".py") or info.is_dir() or info.file_size > _MAX_FILE_BYTES
                    or is_non_production_path(info.filename)):
                continue
            count += 1
            if count > _MAX_FILES or len(findings) >= _MAX_FINDINGS:
                break
            try:
                raw = archive.read(info)
                if b"@" not in raw:
                    continue
                tree = ast.parse(raw.decode("utf-8"))
            except (SyntaxError, UnicodeError, ValueError, RecursionError):
                continue
            if not _has_route_declaration(tree.body) or not _bounded_tree(tree):
                continue
            _scan_declarations(tree.body, _State(), info.filename, findings)
    return findings


def _finding(path: str, call: ast.Call, reaching: set[str], constructor: bool) -> CheckFinding:
    names = ", ".join(sorted(reaching))
    action = "client address configured" if constructor else "outbound address passed"
    return CheckFinding(
        rule_id=RULE_ID,
        title="Outbound request built from request input",
        severity="high",
        confidence=0.7,
        category="Security",
        file=path,
        line=call.lineno,
        explanation=(
            f"The {action} at {_attr_name(call.func)}() on line {call.lineno} contains "
            f"request input ({names}) in a position that can influence the URL authority. "
            "No recognised preceding address check was found on this local path. If that "
            "value is not constrained elsewhere, a later request could reach an unintended "
            "service, including internal or cloud metadata endpoints. This is an unverified "
            "source signal, not proof that a request was sent or an SSRF is exploitable. "
            "The value is traced only inside this function; unknown calls, complex control "
            "flow, helpers, redirects, DNS and network policies are outside this trace."
        ),
        fix_hint=(
            "Validate the final URL immediately before use against the expected schemes and "
            "hosts. Reject unexpected resolved addresses, including private and link-local "
            "ranges, and recheck redirect destinations. Build the URL from validated parts."
        ),
    )


def _test_inspects(test: ast.AST, names: set[str]) -> bool:
    """Does this condition examine the value against something, or merely use it?

    `if not host.startswith("api.")` and `if host in ALLOWED_HOSTS` are checks.
    A bare truthiness test (`if host:`) is not, and neither is a condition that
    never mentions the value.
    """
    for node in _walk(test):
        if isinstance(node, ast.Compare) and _referenced_names(node) & names:
            operands = [node.left, *node.comparators]
            if any(_is_a_comparison_target(operand) and not _is_one_of(operand, names)
                   for operand in operands):
                return True
        if isinstance(node, ast.Call):
            callee = _attr_name(node.func).lower().split(".")[-1]
            if (any(word in callee for word in _VALIDATION_WORDS)
                    or callee in _URL_INSPECTORS) and _referenced_names(node) & names:
                return True
    return False


def _is_one_of(node: ast.AST, names: set[str]) -> bool:
    """Is this operand the caller's value itself rather than what it is checked
    against? `if host is None` names `host` on both sides of the question, and the
    value must not be mistaken for the yardstick."""
    return isinstance(node, ast.Name) and node.id in names


def _is_a_comparison_target(node: ast.AST) -> bool:
    """Something an address can be checked AGAINST.

    A literal string or number, a collection, or a constant-style name such as
    ALLOWED_HOSTS. `None` and booleans are excluded on purpose: `if host is None:
    raise` is a presence check, and it says nothing about where the request would
    go -- the finding's claim is that no check on the ADDRESS was visible, so a
    truthiness or presence test must not silence it. Weak-but-real address checks
    (`if host == ""`) do pass, because they are comparisons the caller's value
    takes part in.
    """
    if isinstance(node, ast.Constant):
        return not (node.value is None or isinstance(node.value, bool))
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return True
    if isinstance(node, ast.Name):
        lowered = node.id.lower()
        return node.id.isupper() or any(word in lowered for word in _COMPARISON_TARGET_WORDS)
    return False

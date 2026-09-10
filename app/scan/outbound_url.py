"""An outbound HTTP request whose URL is assembled from the handler's own input.

WHY THIS EXISTS. The static stage reads secrets, migrations, routes and dependency
versions, and none of it notices the one line where a request handler hands a
value that arrived from a stranger to an HTTP client. That is server-side request
forgery, and it is the class a buyer expects a security audit to look for:
`requests.get(f"http://{host}/latest")` inside a route lets the caller choose what
the server talks to -- the cloud metadata endpoint, an internal admin panel, a
service that trusts the caller's network position.

WHAT IT REPORTS, AND WHAT IT DOES NOT CLAIM. One thing only: inside a function
that declares an HTTP route, an outbound call whose URL argument is BUILT from a
name that is one of that handler's own request inputs (a parameter without a
`Depends(...)` injection, or a value read off the `Request` object), where no
validation of that name is visible in the same function. That is a fact about the
source. It is NOT proof of an exploitable SSRF: a host allowlist in a wrapper, a
proxy, or a network policy this scanner cannot read may already contain it. The
inverse is not claimed either -- silence is not a certificate that a repository
cannot be made to fetch something it should not.

THE BOUNDED TRACE, STATED HONESTLY. The value's path is followed WITHIN ONE
FUNCTION: a parameter, a `request.query_params` read assigned to a local, and the
string built from them. A URL assembled in a helper and passed in, a value that
travelled through two modules, or a validation performed by the caller are all
invisible here, and the finding's text says so. Cross-function taint is exactly
what app/scan/sql_injection.py also refuses to attempt, and for the same reason:
guessing there produces findings an owner learns to ignore.

WHY AST, NOT A REGEX. The rule turns on distinctions a text scan cannot make:

    httpx.get(f"https://api.example.com/{path}")     fixed host, variable path
    httpx.get(f"https://{host}/health")              the caller picks the host

Both are f-strings in a call. Only the tree shows which part is interpolated, and
the first one is not the defect being reported.

Python only, deliberately, and FastAPI-shaped routes only: TS/JS fetch calls need
the tree-sitter path and a different sink vocabulary, and shipping half of it
under a rule id that claims both would misdescribe what was checked.

NEVER EXECUTES THE UPLOADED CODE. ast.parse builds a tree; it does not run a
module, import it, or evaluate any expression inside it.
"""

from __future__ import annotations

import ast
import re
import zipfile
from typing import BinaryIO

from app.scan.checks import CheckFinding
from app.scan.secrets import is_non_production_path

RULE_ID = "python-outbound-request-unvalidated-url"

# Method names that make an outbound request, matched on the attribute alone. The
# receiver check below is what keeps `payload.get("url")` out of this set.
_OUTBOUND_METHODS = frozenset({
    "delete", "get", "head", "options", "patch", "post", "put", "request", "send",
    "stream",
})

# Bare function sinks: `urlopen(url)`, `urlretrieve(url, path)`. Matched on the
# attribute too, because the hunt produced `urllib.request.urlopen(...)` -- the
# dotted form is how the stdlib actually gets called, and the earlier version
# only accepted the bare name.
_OUTBOUND_FUNCTIONS = frozenset({"urlopen", "urlretrieve"})

# Constructors that take the ADDRESS. `http.client.HTTPConnection(host)` and
# `httpx.Client(base_url=...)` are the same defect as an interpolated URL with a
# lower-level client: the caller picks where the connection goes. A constructor
# with no address argument (`httpx.Client(timeout=5)`) is not a sink.
_ADDRESS_CONSTRUCTORS = frozenset({
    "AsyncClient", "Client", "ClientSession", "HTTPConnection", "HTTPSConnection", "Session",
})

# Receivers that are HTTP clients by name. A local variable counts if this
# module saw it assigned from a client constructor (`client = httpx.Client(...)`),
# which is one hop -- enough for the ordinary shape, and no more guessing than
# the finding text admits to.
_CLIENT_NAMES = frozenset({
    "aclient", "aioclient", "api", "client", "http", "http_client", "httpclient",
    "httpx", "aiohttp", "http_session", "httpsession", "requests", "s", "sess",
    "session", "urllib",
})

# FastAPI parameter markers that carry a value from the request. `Depends` is
# deliberately absent: an injected dependency is not the caller's value, and
# treating it as one would report every route that injects a configured client.
# `Field` joins them after the escape hunt rewrote a fixture with
# `location: str = Field(...)` -- the model reached for pydantic's marker, and a
# handler parameter declared that way is as caller-filled as `Query(...)`.
_INPUT_MARKERS = frozenset({
    "Body", "Cookie", "Field", "File", "Form", "Header", "Path", "Query", "UploadFile",
})

# Attributes of a `Request` object (or of anything named like one) whose value
# came from the caller.
_REQUEST_ATTRS = frozenset({
    "args", "body", "form", "get_json", "getlist", "json", "path_params",
    "query_params", "values",
})
_REQUEST_CONTAINER_TYPES = frozenset({"Request", "starlette.requests.Request", "fastapi.Request"})

# A name containing one of these is treated as a visible validation of the value.
# "allow" covers allow_list/allowlist/allowed, "restrict" covers host allowlists
# written as restrictions.
_VALIDATION_WORDS = frozenset({
    "allow", "assert", "canonical", "deny", "ensure", "guard", "is_public",
    "is_safe", "permit", "restrict", "sanitise", "sanitize", "scrub", "validate",
    "valid", "verify",
})

# Calls that examine a URL rather than merely mention it. Used only for the
# guarded-branch shape, so a condition that inspects the value counts as a check
# while `if url:` does not.
_URL_INSPECTORS = frozenset({
    "endswith", "fullmatch", "hostname", "ip_address", "is_global", "is_loopback",
    "is_private", "match", "netloc", "resolve", "scheme", "search", "startswith",
    "urlparse", "urlsplit",
})

# Names that hold something a value can be checked against: ALLOWED_HOSTS,
# PUBLIC_HOSTS, SAFE_SCHEMES. Used only for comparisons, so a differently-named
# constant merely loses this particular silence -- it does not create a finding.
_COMPARISON_TARGET_WORDS = frozenset({"allow", "domain", "host", "pattern", "prefix", "safe", "scheme"})

# Mirrors app/scan/sql_injection.py: bounded so a generated or vendored file
# cannot turn one archive into a parse storm.
_MAX_FILE_BYTES = 400_000
_MAX_FILES = 400
_MAX_FINDINGS = 32


def _name(node: ast.AST) -> str:
    return node.id if isinstance(node, ast.Name) else ""


def _attr_name(node: ast.AST) -> str:
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _annotation_name(node: ast.AST | None) -> str:
    if node is None:
        return ""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


def _assigned_name(node: ast.Assign | ast.AnnAssign) -> str:
    """The simple local an assignment binds, or "" when it binds something else."""
    if isinstance(node, ast.AnnAssign):
        return node.target.id if isinstance(node.target, ast.Name) else ""
    if node.targets and isinstance(node.targets[0], ast.Name):
        return node.targets[0].id
    return ""


def _request_inputs(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[dict[str, frozenset[str]], set[str]]:
    """(names carrying caller input -> the request names behind them, Request holders).

    The mapping is what lets a finding name the PARAMETER rather than a local the
    handler happened to copy it into: `url = f"http://{target}/status"` makes
    `url` an input that originates at `target`, and the report says `target`. The
    hop from a value read off the Request object to a local is included, and so
    is a chain of plain assignments -- bounded, intra-procedural, and admitted in
    the finding's text. A call in the middle of the chain is NOT followed: it
    could sanitise the value, and guessing there is how a rule starts reporting
    code that already defends itself.
    """
    origins: dict[str, frozenset[str]] = {}
    containers: set[str] = set()
    args = fn.args
    positional = list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs)
    defaults: list[ast.expr | None] = [None] * (len(positional) - len(args.defaults)) + list(args.defaults)
    for arg, default in zip(positional, defaults):
        if arg.arg in ("self", "cls"):
            continue
        if _annotation_name(arg.annotation) in _REQUEST_CONTAINER_TYPES:
            containers.add(arg.arg)
            continue
        if default is None or (isinstance(default, ast.Constant) and default.value is None):
            # `host: str | None = None` is the ordinary optional parameter, and it
            # is an ast.Constant holding None -- NOT the Python None a missing
            # default gives. Reading only the latter made the hunt's rewrite of
            # the positive fixture silent while the defect sat right there.
            origins[arg.arg] = frozenset({arg.arg})
            continue
        if isinstance(default, ast.Call) and _attr_name(default.func) in _INPUT_MARKERS:
            origins[arg.arg] = frozenset({arg.arg})
    pairs: list[tuple[ast.Assign | ast.AnnAssign, ast.expr]] = []
    for node in ast.walk(fn):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        if value is not None:
            pairs.append((node, value))
    # A value read off the Request object is an origin of its own -- `body` is
    # the name a reader can point at in the handler.
    for node, value in pairs:
        name = _assigned_name(node)
        if not name:
            continue
        for inner in ast.walk(value):
            if (isinstance(inner, ast.Attribute) and inner.attr in _REQUEST_ATTRS
                    and (not _name(inner.value) or _name(inner.value) in containers
                         or _name(inner.value).lower() in {"request", "req"})):
                origins[name] = frozenset({name})
    # Plain assignment chains, to a fixed point. Bounded so a pathological file
    # cannot spin: three rounds cover the shapes seen in real code and in the hunt.
    for _ in range(3):
        changed = False
        for node, value in pairs:
            name = _assigned_name(node)
            if not name:
                continue
            carried: set[str] = set()
            for referenced in _referenced_names(value):
                carried |= origins.get(referenced, frozenset())
            if carried and origins.get(name, frozenset()) != frozenset(carried):
                origins[name] = frozenset(carried)
                changed = True
        if not changed:
            break
    return origins, containers


def _local_clients(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Locals assigned from an HTTP client constructor."""
    clients: set[str] = set()
    for node in ast.walk(fn):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        name = _assigned_name(node)
        if name and isinstance(node.value, ast.Call) and _attr_name(node.value.func) in _ADDRESS_CONSTRUCTORS:
            clients.add(name)
    return clients


def _referenced_names(expr: ast.AST) -> set[str]:
    return {node.id for node in ast.walk(expr) if isinstance(node, ast.Name)}


def _origins_of(names: set[str], inputs: dict[str, frozenset[str]]) -> set[str]:
    """The request names behind these locals, so a finding can name the PARAMETER
    the caller fills rather than the variable the handler copied it into."""
    carried: set[str] = set()
    for name in names:
        carried |= set(inputs.get(name, frozenset()))
    return carried


_MARKER = "\x00"
_FIELD = re.compile(r"\{[0-9]*\}")
_PERCENT = re.compile(r"%\([^)]*\)[sdrf]|%[sdrf]")


def _skeleton(expr: ast.AST, inputs: dict[str, frozenset[str]]) -> tuple[str, list[set[str]]] | None:
    """The address as literal text with a MARKER where a value is interpolated.

    Returns the skeleton and, per marker in order, the REQUEST names behind the
    values that reach it. None means the expression is not string assembly this
    rule can read (a call to a builder, a subscript, anything else) -- silence,
    not a guess.
    """
    if isinstance(expr, ast.Constant):
        return (expr.value, []) if isinstance(expr.value, str) else None
    if isinstance(expr, ast.JoinedStr):
        text, slots = "", []
        for value in expr.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                text += value.value
            elif isinstance(value, ast.FormattedValue):
                text += _MARKER
                slots.append(_origins_of(_referenced_names(value.value), inputs))
        return text, slots
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        left, right = _skeleton(expr.left, inputs), _skeleton(expr.right, inputs)
        if left is None or right is None:
            return None
        return left[0] + right[0], left[1] + right[1]
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Mod):
        left = _skeleton(expr.left, inputs)
        if left is None:
            return None
        args = list(expr.right.elts) if isinstance(expr.right, (ast.Tuple, ast.List)) else [expr.right]
        text, slots = left
        for arg in args:
            sub = _skeleton(arg, inputs)
            if sub is None:
                continue
            text, _ = _replace_first_marker(text, sub[0])
            slots.append(sub[1][0] if sub[1] else set())
        return text, slots
    if isinstance(expr, ast.Call) and _attr_name(expr.func) == "format":
        receiver = _skeleton(expr.func.value, inputs)  # type: ignore[attr-defined]
        if receiver is None:
            return None
        text, slots = receiver
        provided = [*expr.args, *(kw.value for kw in expr.keywords)]
        for arg in provided:
            sub = _skeleton(arg, inputs)
            if sub is None:
                continue
            text, matched = _replace_first_field(text, sub[0])
            if matched:
                slots.append(sub[1][0] if sub[1] else set())
        return text, slots
    if isinstance(expr, ast.Name) and expr.id in inputs:
        return _MARKER, [set(inputs[expr.id])]
    if isinstance(expr, ast.Call) and _attr_name(expr.func) == "urljoin" and expr.args:
        # The base decides the host, so only the base is read; a literal base
        # makes the host fixed however caller-controlled the path is.
        base = _skeleton(expr.args[0], inputs)
        if base is None:
            return None
        return base[0] + "/*", base[1]
    return None


def _replace_first_marker(text: str, replacement: str) -> tuple[str, bool]:
    """Put the value where the template asked for it.

    `%`-formatting spells its slots as `%s`, so the marker goes AT the slot, not
    at the end of the string -- appending would place a caller-controlled host
    outside the authority and turn the defect into silence.
    """
    if _MARKER in text:
        return text.replace(_MARKER, replacement, 1), True
    match = _PERCENT.search(text)
    if match:
        return text[:match.start()] + replacement + text[match.end():], True
    return text + replacement, False


def _replace_first_field(text: str, replacement: str) -> tuple[str, bool]:
    if _FIELD.search(text):
        return _FIELD.sub(replacement, text, count=1), True
    return text, False


def _authority_bounds(template: str) -> tuple[int, int]:
    """Where the host lives: after `://`, up to the next `/`, `?` or `#`."""
    scheme = template.find("://")
    if scheme == -1:
        # No scheme to anchor on: the whole value is caller-chosen as far as this
        # rule can tell, which is the conservative reading of `f"{base}/x"`.
        return 0, len(template)
    start = scheme + 3
    ends = [position for position in (template.find(char, start) for char in "/?#") if position != -1]
    return start, min(ends) if ends else len(template)


def _inputs_reaching_host(expr: ast.AST, inputs: dict[str, frozenset[str]]) -> set[str]:
    """The handler inputs that can change WHICH SERVICE the request goes to.

    This is the whole difference between the two f-strings a text scan cannot
    tell apart: `https://api.example.com/items/{sku}` puts the caller's value in
    the path, and `http://{host}/status` lets the caller pick the host. Only the
    second is reported.
    """
    built = _skeleton(expr, inputs)
    if built is None:
        return set()
    template, slots = built
    start, end = _authority_bounds(template)
    reaching: set[str] = set()
    position = -1
    for names in slots:
        position = template.find(_MARKER, position + 1)
        if position == -1:
            break
        if start <= position < end:
            reaching |= names
    return reaching


def _visible_validation(fn: ast.FunctionDef | ast.AsyncFunctionDef, names: set[str],
                        url_expr: ast.AST) -> bool:
    """Is a check on the value that reaches the host visible in this function?

    Three shapes count, and all of them are readings of the source rather than
    proof of safety: a call whose own name says it validates and which is handed
    one of the names; a guarded branch whose condition inspects one of them
    (`if not host.startswith("api.")`); and a comparison against a literal or a
    named collection (`if host in ALLOWED_HOSTS`). All three are about the value
    that reaches the host, so a check on some other parameter does not silence
    the finding. A check in a helper, a wrapper, a proxy or a network policy is
    invisible here, and the finding says so rather than assuming it away.
    """
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            callee = _attr_name(node.func).lower()
            if any(word in callee for word in _VALIDATION_WORDS):
                passed: set[str] = set()
                for arg in [*node.args, *(kw.value for kw in node.keywords)]:
                    passed |= _referenced_names(arg)
                if passed & names:
                    return True
        if isinstance(node, (ast.If, ast.While, ast.Assert)) and _test_inspects(node.test, names):
            return True
    return False


def _test_inspects(test: ast.AST, names: set[str]) -> bool:
    """Does this condition examine the value against something, or merely use it?

    `if not host.startswith("api.")` and `if host in ALLOWED_HOSTS` are checks.
    A bare truthiness test (`if host:`) is not, and neither is a condition that
    never mentions the value.
    """
    for node in ast.walk(test):
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


def _url_argument(call: ast.Call) -> ast.AST | None:
    """The argument that becomes the target address."""
    for keyword in call.keywords:
        if keyword.arg in ("url", "uri", "target", "endpoint", "base_url"):
            return keyword.value
    if _attr_name(call.func) == "request" and not isinstance(call.func, ast.Attribute):
        # requests.request(method, url, ...)
        return call.args[1] if len(call.args) > 1 else None
    if _attr_name(call.func) in _ADDRESS_CONSTRUCTORS:
        # HTTPConnection(host), ClientSession() -- no positional address means
        # the client is configured later or not at all.
        return call.args[0] if call.args else None
    return call.args[0] if call.args else None


def _is_a_client(expr: ast.AST, clients: set[str]) -> bool:
    """Is this receiver an HTTP client?

    A local assigned from a constructor, a client-shaped name, a module-rooted
    path (`urllib.request`), or a constructor called INLINE
    (`aiohttp.ClientSession().get(...)`) -- the hunt produced that last one, and
    every shape here is a reading of the name, which is what the finding admits
    to.
    """
    if isinstance(expr, ast.Name):
        return expr.id in clients or expr.id in _CLIENT_NAMES
    if isinstance(expr, ast.Call):
        return _attr_name(expr.func) in _ADDRESS_CONSTRUCTORS
    rooted: ast.AST = expr
    while isinstance(rooted, ast.Attribute):
        rooted = rooted.value
    return _name(rooted) in _CLIENT_NAMES


def _outbound_calls(fn: ast.FunctionDef | ast.AsyncFunctionDef, clients: set[str]):
    """(call, address expression) for every outbound request made in this function."""
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        callee = _attr_name(node.func)
        if callee in _OUTBOUND_FUNCTIONS:
            url = _url_argument(node)
            if url is not None:
                yield node, url
            continue
        if callee in _ADDRESS_CONSTRUCTORS:
            url = _url_argument(node)
            if url is not None:
                yield node, url
            continue
        if callee not in _OUTBOUND_METHODS:
            continue
        if not isinstance(node.func, ast.Attribute):
            continue
        if _is_a_client(node.func.value, clients):
            url = _url_argument(node)
            if url is not None:
                yield node, url


def scan_outbound_url(fileobj: BinaryIO) -> list[CheckFinding]:
    findings: list[CheckFinding] = []
    with zipfile.ZipFile(fileobj) as archive:
        infos = [i for i in archive.infolist()
                 if i.filename.endswith(".py") and not i.is_dir()
                 and i.file_size <= _MAX_FILE_BYTES and not is_non_production_path(i.filename)]
        for info in infos[:_MAX_FILES]:
            if len(findings) >= _MAX_FINDINGS:
                break
            try:
                tree = ast.parse(archive.read(info).decode("utf-8"))
            except (SyntaxError, UnicodeError, ValueError, RecursionError):
                # An unparseable file is not a clean file; it is one this rule
                # could not read. Skipping is the honest answer, and the check
                # key's coverage text says parseable files only.
                continue
            for fn in ast.walk(tree):
                if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                findings.extend(_function_findings(fn, info.filename))
                if len(findings) >= _MAX_FINDINGS:
                    break
    return findings


def _function_findings(fn: ast.FunctionDef | ast.AsyncFunctionDef, path: str) -> list[CheckFinding]:
    if not _declares_a_route(fn):
        return []
    inputs, _ = _request_inputs(fn)
    if not inputs:
        return []
    clients = _local_clients(fn)
    findings = []
    for call, url_expr in _outbound_calls(fn, clients):
        reaching = _inputs_reaching_host(url_expr, inputs)
        if not reaching:
            continue
        # A check may name the parameter or the local the handler copied it into,
        # so both are offered to the validation reader.
        carried = set(reaching) | {name for name, origin in inputs.items() if origin & reaching}
        if _visible_validation(fn, carried, url_expr):
            continue
        findings.append(_finding(path, call, reaching, _attr_name(call.func)))
    return findings


def _declares_a_route(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Does this function declare an HTTP route?

    The route decorator is what makes the parameters caller-controlled rather
    than whatever the author passed. A helper called by a handler is out of scope
    on purpose, and the finding's text says the trace stops inside one function.
    """
    for decorator in fn.decorator_list:
        if not isinstance(decorator, ast.Call):
            continue
        if not isinstance(decorator.func, ast.Attribute):
            continue
        if decorator.func.attr in {"delete", "get", "head", "options", "patch", "post", "put",
                                  "route", "websocket"}:
            return True
    return False


def _finding(path: str, call: ast.Call, reaching: set[str], callee: str) -> CheckFinding:
    names = ", ".join(sorted(reaching))
    return CheckFinding(
        rule_id=RULE_ID,
        title="Outbound request built from request input",
        severity="high",
        # Not critical, and not lower. The source fact is certain -- ast saw the
        # interpolation and saw which parameter it came from. What is uncertain
        # is whether anything outside this function already restrains the value,
        # which this rule does not read. 0.7 is that split: a real defect in the
        # code, unproven as a reachable exploit.
        confidence=0.7,
        category="Security",
        file=path,
        line=call.lineno,
        explanation=(
            f"The address handed to {callee}() at line {call.lineno} is assembled from "
            f"{names}, which this handler receives from the request, and no check on that "
            "address was visible in the same function. A caller who controls that value can "
            "choose what the server fetches -- an internal address, a cloud metadata "
            "endpoint, or a service that trusts this host's network position. Whether the "
            "value is constrained elsewhere (a wrapper, a proxy, a network policy) has NOT "
            "been verified; the assembly and the absence of a local check are what was "
            "observed. The value is traced only inside this function."
        ),
        fix_hint=(
            "Check the value immediately before the call: allow only the scheme and hosts you "
            "expect (https, and a fixed host list), refuse private ranges and link-local "
            "addresses, and do the check on the RESOLVED host rather than the string. Build "
            "the URL from the validated parts instead of interpolating the raw value."
        ),
    )

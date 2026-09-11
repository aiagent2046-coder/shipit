"""The TypeScript/JavaScript half: cookie-setting calls in the customers' language.

WHY TREE-SITTER AND NOT A PATTERN. The evidence is a call plus an OPTION OBJECT,
and options are written across lines:

    res.cookie("session", token, {
      httpOnly: false,
      sameSite: "none",
    });

A line-based matcher sees half of that. The repository already parses TS/JS with
tree-sitter for the same reason (`sql_injection_js.py`), so this half does too:
nothing here executes uploaded code.

SHAPES READ, and the API decides the DEFAULT:

  * `res.cookie(name, value, options?)` -- Express's own
    default is `httpOnly: false`, so an ABSENT option is the defect, not a
    silence. Request-shaped receivers are excluded; a custom `.cookie` method
    unrelated to HTTP can still be mistaken for a setter.
  * `cookies().set(name, value, options?)` and `cookieStore.set(...)` (Next.js,
    server cookie store) -- same default, same treatment. Gated on a receiver whose
    text contains `cookie`.
  * `session({ name: "sid", cookie: { ... } })` and `cookieSession({ ... })` --
    express-session and cookie-session, where `httpOnly` defaults to TRUE: an
    ABSENT option here is the safe default, so only an explicit `httpOnly: false`
    or `sameSite: "none"` is reported. Reporting the omission would be an
    accusation whose fix changes nothing.
  * `document.cookie = "session=..."` -- a cookie written by client-side script,
    where HttpOnly is impossible by construction. Read only when the name before
    the first `=` is authentication-shaped.

WHAT IT DOES NOT CLAIM. That a value that arrives as a variable is protecting or
exposing anything: an option whose value is not a literal is left unknown. Nor
does it read `Set-Cookie` header strings, framework config files, or a cookie set
through a wrapper function.

WHAT THE FIRST HUNT ROUND CHANGED HERE, all measured on model rewrites of the
corpus positives: the cookie NAME moved into a local `const` (8 of 8 rewrites of
one case, now resolved one hop), response objects were named
`resParam`/`outgoingRes`/`resData`/`responseBody` rather than `res` (4 of 4 of a
third, so the receiver check now excludes request-shaped names instead of
requiring a response-shaped one), and `document.cookie` was handed a template
held in a variable. A per-request mutation such as
`req.session.cookie.httpOnly = false` is still not read: it is an assignment
through an attribute chain, and only the configuration object is parsed.
"""

from __future__ import annotations

import tree_sitter_typescript
from tree_sitter import Language, Parser

from app.scan.cookie_names import is_auth_cookie, normalise

_PARSERS = {
    False: Parser(Language(tree_sitter_typescript.language_typescript())),
    True: Parser(Language(tree_sitter_typescript.language_tsx())),
}

# A receiver that looks like a REQUEST is excluded: `req.cookie(...)` is not the
# Express setter, and the hunt's rewrites named their response objects
# `resParam`, `outgoingRes`, `resData`, `responseBody` -- every one of which the
# earlier receiver vocabulary missed. Any other `.cookie(...)` is read; a custom
# object with a cookie() method would be a false positive, which the docstring says.
_REQUEST_PREFIXES = ("req", "request")
_SESSION_FUNCTIONS = frozenset({"session", "cookieSession", "cookie_session", "expressSession",
                               "sessionMiddleware"})
# JavaScript option names are case-sensitive. Header spellings such as
# `HttpOnly` / `SameSite` are ignored by these APIs, not aliases for their options.
_HTTPONLY_KEYS = frozenset({"httpOnly"})
_SAMESITE_KEYS = frozenset({"sameSite"})
_UNKNOWN_OPTION = object()
_MAX_NODES = 60_000


def _walk(node, budget: list[int]):
    """Every node, depth-bounded, so a pathological file cannot run away."""
    stack = [node]
    while stack:
        current = stack.pop()
        budget[0] -= 1
        if budget[0] <= 0:
            return
        yield current
        stack.extend(current.named_children)


def _text(node) -> str:
    return node.text.decode("utf-8", "replace")


def _string_value(node) -> str:
    """The literal a string/template node holds, or '' when it is not a plain one."""
    if node is None or node is _UNKNOWN_OPTION:
        return ""
    if node.type == "string":
        text = _text(node)
        if len(text) >= 2 and text[0] in "\"'" and text[-1] == text[0]:
            return text[1:-1]
        return ""
    if node.type == "template_string" and not any(child.type == "template_substitution"
                                                 for child in node.named_children):
        return _text(node)[1:-1]
    return ""


def _bool_value(node):
    """True/False for a literal boolean, None for anything else (unknown or absent).

    `0`/`1` are read too: MEASURED, the hunt wrote `httpOnly: 0` and the rule --
    which only knew the `true`/`false` keywords -- went silent on a flag that is
    plainly off.
    """
    if node is None or node is _UNKNOWN_OPTION:
        return None
    if node.type in {"false", "null"}:
        return False
    if node.type == "true":
        return True
    if node.type == "number":
        number = _text(node).replace("_", "").strip()
        try:
            return bool(int(number, 0)) if number.lower().startswith(("0x", "0o", "0b")) else bool(float(number))
        except ValueError:
            return None
    if node.type == "string":
        return bool(_string_value(node))
    return None


def _options(node) -> dict[str, object]:
    """key -> value node for an object literal, or {} for anything else."""
    if node is None or node.type != "object":
        return {}
    options: dict[str, object] = {}
    for child in node.named_children:
        if child.type == "spread_element":
            # A later spread can replace earlier literals, while literals after
            # the spread are authoritative. Keep that order for each flag.
            options.update({key: _UNKNOWN_OPTION for key in
                            (*options, "httpOnly", "sameSite", "cookie", "name")})
            continue
        if child.type == "shorthand_property_identifier":
            options[_text(child)] = _UNKNOWN_OPTION
            continue
        if child.type == "method_definition":
            name = child.child_by_field_name("name")
            if name is not None:
                options[_text(name)] = _UNKNOWN_OPTION
            continue
        if child.type == "pair":
            key = child.child_by_field_name("key")
            value = child.child_by_field_name("value")
            if key is None:
                continue
            if key.type == "computed_property_name":
                options.update({key: _UNKNOWN_OPTION for key in
                                (*options, "httpOnly", "sameSite", "cookie", "name")})
                continue
            name = _string_value(key) if key.type == "string" else _text(key)
            options[name] = value
    return options


def _first_argument(arguments) -> object:
    named = [node for node in arguments.named_children if node.type != "comment"] if arguments is not None else []
    return named[0] if named else None


def _nth_argument(arguments, index: int):
    named = [node for node in arguments.named_children if node.type != "comment"] if arguments is not None else []
    return named[index] if len(named) > index else None


def _problem_for(options_node, default_http_only: bool) -> tuple[str, str]:
    """(problem text, kind) for one cookie's options, or ('', '') when protected.

    Three cases, and the difference between the first two is the whole point:
    no options node at all means the library default applies; an options node that
    is NOT an object literal (a variable, a spread) cannot be read, so nothing is
    claimed; an object literal is read key by key.
    """
    if options_node is _UNKNOWN_OPTION:
        return "", ""
    if options_node is None:
        options: dict[str, object] = {}
    elif options_node.type == "object":
        options = _options(options_node)
    else:
        return "", ""
    problems: list[str] = []
    http_only_problem = ""
    http_only_key = next((key for key in options if key in _HTTPONLY_KEYS), None)
    if http_only_key is None:
        if not default_http_only:
            http_only_problem = "no HttpOnly"
    elif _bool_value(options[http_only_key]) is False:
        http_only_problem = "HttpOnly switched off"
    same_site_problem = ""
    same_site_key = next((key for key in options if key in _SAMESITE_KEYS), None)
    if same_site_key is not None and _string_value(options[same_site_key]).lower() == "none":
        same_site_problem = "SameSite=None"
    problems = [problem for problem in (http_only_problem, same_site_problem) if problem]
    if not problems:
        return "", ""
    return " and ".join(problems), "httponly" if http_only_problem else "samesite"


def _cookie_store_names(root, budget: list[int]) -> set[str]:
    """Local names bound to `cookies()` in this file, one hop.

    `const store = await cookies(); store.set("session", token)` is how Next.js
    code is often written, and the receiver text alone (`store`) says nothing --
    but a generic `store.set(...)` rule would fire on a Redis or Map store. The
    binding is the evidence: the file itself shows what that name holds.

    The function itself is resolved through the file's imports, because the hunt
    produced `import { cookies as getCookies } from "next/headers"` five times in
    one round: the alias is in the file, so it is evidence too.
    """
    function_names = {"cookies"}
    for node in _walk(root, budget):
        if node.type != "import_statement":
            continue
        source = node.child_by_field_name("source")
        if source is None or _string_value(source) != "next/headers":
            continue
        for inner in _walk(node, [200]):
            if inner.type == "import_specifier":
                name = inner.child_by_field_name("name")
                if name is not None and _text(name) == "cookies":
                    alias = inner.child_by_field_name("alias") or name
                    function_names.add(_text(alias))

    names: set[str] = set()
    for node in _walk(root, budget):
        if node.type != "variable_declarator":
            continue
        name = node.child_by_field_name("name")
        value = node.child_by_field_name("value")
        if name is None or value is None or name.type != "identifier":
            continue
        for inner in _walk(value, [500]):
            if inner.type != "call_expression":
                continue
            called = inner.child_by_field_name("function")
            if called is None:
                continue
            called_text = _text(called)
            if "cookies" in called_text or called_text.split(".")[-1] in function_names:
                names.add(_text(name))
                break
    return names


def _local_string_bindings(root, budget: list[int]) -> dict[str, str]:
    """`const sessionId = "session_id"` -> {"sessionId": "session_id"}, one hop.

    MEASURED: eight of eight rewrites of the Express case moved the cookie NAME
    into a local const, and the rule went silent on all eight -- the same defect,
    spelled the way people actually write it. The same map resolves the value
    handed to `document.cookie`.
    """
    bindings: dict[str, str] = {}
    for node in _walk(root, budget):
        if node.type != "variable_declarator":
            continue
        name = node.child_by_field_name("name")
        value = node.child_by_field_name("value")
        if name is None or value is None or name.type != "identifier":
            continue
        literal = _string_value(value) or (_leading_string(value) if value.type != "string" else "")
        if literal:
            bindings[_text(name)] = literal
    return bindings


def _local_object_bindings(root, budget: list[int]) -> dict[str, object]:
    """`const cookieOptions = { httpOnly: 0 }` -> {"cookieOptions": <object node>}.

    MEASURED: six of eight rewrites of one Express case pulled the options object
    into a local variable, which the rule treated as an unreadable value and stayed
    silent on. The object literal is in the same file, one hop away.
    """
    bindings: dict[str, object] = {}
    for node in _walk(root, budget):
        if node.type != "variable_declarator":
            continue
        name = node.child_by_field_name("name")
        value = node.child_by_field_name("value")
        if name is None or value is None or name.type != "identifier" or value.type != "object":
            continue
        bindings[_text(name)] = value
    return bindings


def _stable_declarations(root) -> dict[str, object]:
    """Keep one-hop names only when their binding is unambiguous in this file.

    This is deliberately conservative: duplicate declarations, parameters and
    mutations invalidate a name instead of borrowing a value from another scope.
    Object mutation also invalidates a const binding: const does not freeze it.
    """
    declarations: dict[str, object] = {}
    invalid: set[str] = set()
    for node in _walk(root, [_MAX_NODES]):
        if node.type == "variable_declarator":
            name = node.child_by_field_name("name")
            if name is None or name.type != "identifier":
                if name is not None:
                    invalid.update(_text(part) for part in _walk(name, [500])
                                   if part.type in {"identifier", "shorthand_property_identifier_pattern"})
                continue
            text = _text(name)
            if text in declarations:
                invalid.add(text)
            declarations[text] = node
        elif node.type == "formal_parameters":
            invalid.update(_text(part) for part in _walk(node, [500]) if part.type == "identifier")
        elif node.type == "arrow_function":
            parameter = node.child_by_field_name("parameter")
            if parameter is not None:
                invalid.add(_text(parameter))
        elif node.type == "catch_clause":
            parameter = node.child_by_field_name("parameter")
            if parameter is not None:
                invalid.update(_text(part) for part in _walk(parameter, [500]) if part.type == "identifier")
        elif node.type in {"assignment_expression", "augmented_assignment_expression", "update_expression"}:
            target = node.child_by_field_name("left") or node.child_by_field_name("argument")
            while target is not None and target.type in {"member_expression", "subscript_expression"}:
                target = target.child_by_field_name("object")
            if target is not None and target.type == "identifier":
                invalid.add(_text(target))
    return {name: node for name, node in declarations.items() if name not in invalid}


def _visible_binding(name: str, use, declarations: dict[str, object]) -> bool:
    declaration = declarations.get(name)
    if declaration is None or declaration.end_byte > use.start_byte:
        return False
    scope = declaration.parent
    while scope is not None and scope.type not in {"statement_block", "program"}:
        scope = scope.parent
    parent = use.parent
    while parent is not None:
        if parent == scope:
            return True
        parent = parent.parent
    return False


def _session_config_names(root, budget: list[int]) -> dict[str, str]:
    """Names bound to express-session / cookie-session by this file's own imports.

    MEASURED: seven of eight rewrites of the session-config case imported the
    library under an alias (`expressSession`, `sess`, `Session`, `sessionConfig`)
    and the rule went silent on all of them. The alias is in the file, so the
    binding is evidence -- the same resolution the TLS rule does for client
    names.
    """
    names = {name: "cookie-session" if name in {"cookieSession", "cookie_session"}
             else "express-session" for name in _SESSION_FUNCTIONS}
    for node in _walk(root, budget):
        if node.type != "import_statement":
            continue
        source = node.child_by_field_name("source")
        module = _string_value(source) if source is not None else ""
        if module not in ("express-session", "cookie-session"):
            continue
        for child in node.named_children:
            if child.type != "import_clause":
                continue
            for inner in _walk(child, [200]):
                if inner.type == "import_specifier":
                    alias = inner.child_by_field_name("alias") or inner.child_by_field_name("name")
                    if alias is not None:
                        names[_text(alias)] = module
                elif inner.type == "identifier":
                    names[_text(inner)] = module
    return names


def _call_evidence(node, store_names: set[str], literals: dict[str, str],
                   session_names: dict[str, str], object_bindings: dict[str, object],
                   declarations: dict[str, object]) -> list[tuple[int, str, str]]:
    function = node.child_by_field_name("function")
    arguments = node.child_by_field_name("arguments")
    if function is None:
        return []
    line = node.start_point[0] + 1

    if function.type == "member_expression":
        receiver = function.child_by_field_name("object")
        property_node = function.child_by_field_name("property")
        method = _text(property_node) if property_node is not None else ""
        receiver_text = _text(receiver) if receiver is not None else ""
        last = normalise(receiver_text).split("_")[-1]
        looks_like_request = last.startswith(_REQUEST_PREFIXES)
        is_cookie_store = (receiver_text in store_names
                           and _visible_binding(receiver_text, node, declarations)) or "cookie" in receiver_text.lower()
        if looks_like_request:
            return []
        sets_a_cookie = method == "cookie" or (method == "set" and is_cookie_store)
        if not sets_a_cookie:
            return []
        first = _first_argument(arguments)
        name = _string_value(first)
        if not name and first is not None and _visible_binding(_text(first), node, declarations):
            name = literals.get(_text(first), "")
        if not is_auth_cookie(name):
            return []
        options_node = _nth_argument(arguments, 2)
        if options_node is not None and options_node.type == "identifier":
            if not _visible_binding(_text(options_node), node, declarations):
                return []
            resolved = object_bindings.get(_text(options_node))
            if resolved is None:
                return []   # options exist but cannot be read: do not guess
            options_node = resolved
        problem, kind = _problem_for(options_node, default_http_only=False)
        if not problem:
            return []
        return [(line, f"sets the authentication cookie {name!r} with {problem}", kind)]

    if function.type == "identifier" or function.type == "call_expression":
        # `sess({...})` and the CommonJS inline form reach the same function.
        callee = _text(function)
        module = session_names.get(callee, "")
        if function.type == "call_expression":
            called = function.child_by_field_name("function")
            if called is None or _text(called) != "require":
                return []
            module = _string_value(_first_argument(function.child_by_field_name("arguments")))
        if module not in {"express-session", "cookie-session"}:
            return []
        config_node = _first_argument(arguments)
        config = _options(config_node)
        # cookie-session passes top-level options to cookies.set; express-session
        # keeps them in its nested `cookie` object. Their HttpOnly default is true.
        cookie_options = config_node if module == "cookie-session" else config.get("cookie")
        if cookie_options is None:
            return []
        declared = _string_value(config.get("name"))
        if "name" in config and not declared:
            return []  # An explicit but unknown name is not the library default.
        # express-session names its cookie `connect.sid` and cookie-session uses
        # `session`; both are authentication-shaped, so an absent name is assumed
        # to be the library default rather than treated as unresolvable.
        name = declared or "connect.sid"
        if not is_auth_cookie(name):
            return []
        problem, kind = _problem_for(cookie_options, default_http_only=True)
        if not problem:
            return []
        return [(line, f"configures the session cookie {name!r} with {problem}", kind)]

    return []


def _leading_string(node) -> str:
    """The string a value starts with: a literal, `"token=" + value`, or a template."""
    if node is None:
        return ""
    if node.type == "string":
        return _string_value(node)
    if node.type == "template_string":
        # `session=${token}` -- the leading name is still readable before the
        # interpolation, and that name is all this shape needs.
        return _text(node)[1:-1].split("${", 1)[0]
    if node.type == "binary_expression":
        return _leading_string(node.child_by_field_name("left"))
    return ""


def _document_cookie_evidence(node, literals: dict[str, str],
                              declarations: dict[str, object]) -> list[tuple[int, str, str]]:
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left is None or left.type != "member_expression" or right is None:
        return []
    if _text(left) != "document.cookie":
        return []
    literal = _leading_string(right)
    if not literal and _visible_binding(_text(right), node, declarations):
        literal = literals.get(_text(right), "")
    # The leading text is the name itself in `"auth_token" + "=" + value`, and
    # `name=value` in `document.cookie = "auth_token=..."`. Requiring an `=` was
    # wrong: MEASURED, the concatenated form escaped for that reason alone.
    name = literal.split("=", 1)[0].strip()
    if not is_auth_cookie(name):
        return []
    return [(
        node.start_point[0] + 1,
        f"writes the authentication cookie {name!r} from client-side script, where HttpOnly cannot be set",
        "httponly",
    )]


def js_evidence(text: str, tsx: bool = False) -> list[tuple[int, str, str]]:
    """(line, what, kind) for every unprotected authentication cookie in one file."""
    root = _PARSERS[bool(tsx)].parse(text.encode("utf-8")).root_node
    if root.has_error:
        return []
    store_names = _cookie_store_names(root, [_MAX_NODES])
    literals = _local_string_bindings(root, [_MAX_NODES])
    session_names = _session_config_names(root, [_MAX_NODES])
    object_bindings = _local_object_bindings(root, [_MAX_NODES])
    declarations = _stable_declarations(root)
    evidence: list[tuple[int, str, str]] = []
    for node in _walk(root, [_MAX_NODES]):
        if node.type == "call_expression":
            evidence += _call_evidence(node, store_names, literals, session_names, object_bindings, declarations)
        elif node.type == "assignment_expression":
            evidence += _document_cookie_evidence(node, literals, declarations)
    return sorted(evidence)

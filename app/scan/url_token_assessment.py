"""Source-only React URL-token state -> request header -> route guard binding.

An API header is not counterevidence to a token originating in the page URL.
Only a narrow direct hook/state path is recorded. No tokens or env values are
returned, and this cannot dismiss a finding or infer token strength/rotation.
"""

from __future__ import annotations

import re

from app.scan import consequence_evidence as c
from app.scan import guard_context as g
from app.scan import imported_error_context as i
from app.scan.auth_source_assessment import _ast_tokens, _consts, _native_import, _top

KIND = "url_token_header_transport"
MAX_PAGES = 32


def _pair(obj, key):
    if not obj or obj.type != "object":
        return None
    fields = g._children(obj)
    if any(n.type != "pair" for n in fields):
        return None
    keys = [g._literal(n.child_by_field_name("key")) or g._text(n.child_by_field_name("key")) for n in fields]
    if len(keys) != len(set(keys)):
        return None
    return next((n.child_by_field_name("value") for n, k in zip(fields, keys) if k == key), None)


def _guard(root, start, end):
    # A finding may cite a nested filter callback later in the API handler;
    # locate its enclosing exported route rather than treating the callback as
    # the full authentication scope.
    routes = [
        fn
        for fn in i._exports(root).values()
        if g._name(fn.child_by_field_name("name")) == "GET" and g._line(fn) <= start <= end <= fn.end_point[0] + 1
    ]
    if len(routes) != 1:
        return None
    fn = routes[0]
    params = g._children(fn.child_by_field_name("parameters"))
    if len(params) != 1:
        return None
    req = g._name(params[0].child_by_field_name("pattern")) or g._name(params[0])
    body = fn.child_by_field_name("body")
    # req.headers is an object: reject aliases, replacement and method escapes
    # rather than assuming every later .get still denotes the original headers.
    for node in g._walk(fn):
        if g._name(node) != req:
            continue
        if node.parent == params[0] or node == params[0]:
            continue
        headers = g._member(node.parent, "headers")
        method = g._member(headers.parent, "get") if headers else None
        if not (
            headers
            and headers.child_by_field_name("object") == node
            and method
            and method.child_by_field_name("object") == headers
            and method.parent.type == "call_expression"
            and method.parent.child_by_field_name("function") == method
        ):
            return None
    for dec in _consts(fn):
        if dec.parent.parent != body:
            continue
        value = dec.child_by_field_name("value")
        receiver, args = g._method(value, "get")
        headers = g._member(receiver, "headers")
        key = g._literal(args[0]) if len(args) == 1 else None
        name = g._name(dec.child_by_field_name("name"))
        if not req or not headers or g._name(headers.child_by_field_name("object")) != req or not name or not key:
            continue
        if not re.fullmatch(r"[A-Za-z0-9-]{1,64}", key):
            continue
        counts = g._bindings(list(g._walk(fn)))
        if counts[name] != 1 or counts[req] != 1:
            continue
        for guard in g._children(body):
            if guard.start_byte <= dec.end_byte or not g._exit(guard):
                continue
            token = _ast_tokens(g._unwrap(guard.child_by_field_name("condition")))
            pattern = r"!process\.env\.([A-Z_][A-Z0-9_]*)\|\|" + re.escape(name) + r"!==process\.env\.\1"
            if re.fullmatch(pattern, token):
                facts = i._file_facts(root)
                if not facts[1]["process"] and not facts[2]["process"] and "process" not in facts[3]:
                    return {"handler": fn, "read": dec, "guard": guard, "header": key}
    return None


def _page_chain(root, url, header):
    facts = i._file_facts(root)
    native = {"fetch", "window", "URLSearchParams"}
    if facts[4] or any(facts[1][n] or facts[2][n] or n in facts[3] for n in native):
        return None
    for fn in g._walk(root):
        if fn.type != "function_declaration":
            continue
        body = fn.child_by_field_name("body")
        if body is None:
            continue
        decs = _consts(fn)
        counts = g._bindings(list(g._walk(fn)))
        for dec in decs:
            if dec.parent.parent != body:
                continue
            pattern, value = dec.child_by_field_name("name"), dec.child_by_field_name("value")
            names = g._bound(pattern)
            if (
                not pattern
                or pattern.type != "array_pattern"
                or len(names) != 2
                or not value
                or value.type != "call_expression"
            ):
                continue
            state, setter = names
            if _ast_tokens(pattern) != "[" + state + "," + setter + "]":
                continue
            hook = g._name(value.child_by_field_name("function"))
            args = g._children(value.child_by_field_name("arguments"))
            if (
                not hook
                or not _native_import(root, hook, "react", "useState")
                or len(args) != 1
                or args[0].type != "null"
                or counts[state] != 1
                or counts[setter] != 1
            ):
                continue
            setters = [
                n for n in g._walk(fn) if n.type == "identifier" and g._name(n) == setter and not (n.parent == pattern)
            ]
            if len(setters) != 1 or setters[0].parent.type != "call_expression":
                continue
            set_call = setters[0].parent
            if set_call.child_by_field_name("function") != setters[0]:
                continue
            effect_fn = i._owner(set_call)
            if not effect_fn or effect_fn.type != "arrow_function" or effect_fn.parent.type != "arguments":
                continue
            effect_call = effect_fn.parent.parent
            effect_name = g._name(effect_call.child_by_field_name("function"))
            effect_args = g._children(effect_fn.parent)
            if (
                not _native_import(root, effect_name, "react", "useEffect")
                or len(effect_args) != 2
                or _ast_tokens(effect_args[1]) != "[]"
                or _top(effect_call, body) != effect_call.parent
            ):
                continue
            effect_stmts = g._children(effect_fn.child_by_field_name("body"))
            effect_decs = _consts(effect_fn)
            if len(effect_stmts) != 2 or len(effect_decs) != 1 or effect_stmts[1] != set_call.parent:
                continue
            read = effect_decs[0]
            local = g._name(read.child_by_field_name("name"))
            set_args = g._children(set_call.child_by_field_name("arguments"))
            query_value = read.child_by_field_name("value")
            receiver, query_args = g._method(query_value, "get")
            query_key = g._literal(query_args[0]) if len(query_args) == 1 else None
            if (
                not local
                or len(set_args) != 1
                or g._name(set_args[0]) != local
                or counts[local] != 1
                or not query_key
                or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", query_key)
                or not receiver
                or receiver.type != "new_expression"
                or _ast_tokens(receiver) != "newURLSearchParams(window.location.search)"
            ):
                continue
            # Only this direct fetch in an imported useCallback that captures
            # the checked React state. Other closures/aliases are not followed.
            fetches = []
            for node in g._walk(fn):
                if node.type != "call_expression" or g._name(node.child_by_field_name("function")) != "fetch":
                    continue
                fa = g._children(node.child_by_field_name("arguments"))
                if len(fa) != 2 or g._literal(fa[0]) != url:
                    continue
                if fa[1].type != "object" or any(n.type != "pair" for n in g._children(fa[1])):
                    continue
                method = _pair(fa[1], "method")
                # This resolver binds the exported GET route, not a similarly
                # named URL receiving POST/DELETE or an overriding option spread.
                if method and g._literal(method) != "GET":
                    continue
                headers = _pair(fa[1], "headers")
                token_value = _pair(headers, header)
                if g._name(token_value) != state:
                    continue
                callback = i._owner(node)
                if not callback or callback.type != "arrow_function" or callback.parent.type != "arguments":
                    continue
                cb_call = callback.parent.parent
                cb_name = g._name(cb_call.child_by_field_name("function"))
                cb_args = g._children(callback.parent)
                if (
                    _native_import(root, cb_name, "react", "useCallback")
                    and len(cb_args) == 2
                    and _ast_tokens(cb_args[1]) == "[" + state + "]"
                    and i._owner(cb_call) == fn
                ):
                    fetches.append(node)
            if len(fetches) == 1:
                return {
                    "url_read": read,
                    "state_binding": dec,
                    "state_setter": set_call,
                    "fetch": fetches[0],
                    "query_key": query_key,
                }
    return None


def url_token_checks(verifier, path, root, start, end):
    separator = "/app/api/"
    if separator in path:
        prefix, route = path.split(separator, 1)
        prefix += "/"
    elif path.startswith("app/api/"):
        prefix, route = "", path[len("app/api/") :]
    else:
        return []
    if not route.endswith("/route.ts"):
        return []
    guard = _guard(root, start, end)
    if not guard:
        return []
    url = "/api/" + route[: -len("/route.ts")]
    pages = sorted(
        p
        for p in verifier.loader._entries()
        if p.startswith(prefix + "app/") and p.endswith("/page.tsx") and i._source_path(p)
    )
    if len(pages) > MAX_PAGES:
        return []
    found = []
    for page in pages:
        try:
            _, page_root = verifier.loader._read(page)
            proof = _page_chain(page_root, url, guard["header"])
        except (ValueError, UnicodeError):
            continue
        if proof:
            found.append((page, proof))
    if len(found) != 1:
        return []
    page, proof = found[0]
    return [
        verifier._record(
            KIND,
            path,
            guard["guard"],
            "A related page reads a query parameter from window.location.search into React state and sends "
            "that same state in the recorded literal API request header. The API reads that header and has a "
            "missing-secret/mismatched-token return. Header validation does not contradict the URL-token origin. "
            "Browser history/referrers, token entropy, rotation, rate limiting and exploitation were not tested.",
            api_header_read=c._loc(guard["read"]),
            api_return=c._loc(guard["guard"]),
            page_url_read=verifier.loader._binding(page, proof["url_read"]),
            page_state_binding=verifier.loader._binding(page, proof["state_binding"]),
            page_state_setter=verifier.loader._binding(page, proof["state_setter"]),
            page_request=verifier.loader._binding(page, proof["fetch"]),
            route_resolution="literal_next_app_route_candidate",
            request_header=guard["header"],
            query_parameter=proof["query_key"],
        )
    ]

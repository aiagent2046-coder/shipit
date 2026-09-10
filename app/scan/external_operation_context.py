"""Bounded request roles, configured limits and client-to-route source links.

These observations do not measure charges, prove successful limiting, or run
uploaded code. Imports use the existing finite, archive-only resolver. Unknown
bindings, additional methods/spreads and ambiguous operations abstain.
"""
from __future__ import annotations

import posixpath
import re

from app.scan import consequence_evidence as c
from app.scan import external_call_assessment as e
from app.scan import guard_context as g
from app.scan import imported_error_context as i

MAX_CALLERS = 24


def _native_fetch(root):
    _, imports, bindings, conflicts, dynamic = i._file_facts(root)
    return not (imports["fetch"] or bindings["fetch"] or "fetch" in conflicts or dynamic)


def _method(init):
    if init is None:
        return "GET"
    if init.type != "object":
        return None
    if any(n.type not in {"pair", "shorthand_property_identifier"} for n in g._children(init)):
        return None
    if any((n.type == "pair" and n.child_by_field_name("key").type != "property_identifier")
           or (n.type == "shorthand_property_identifier" and g._text(n) == "method")
           for n in g._children(init)):
        return None
    methods = [n for n in g._children(init) if g._text(n.child_by_field_name("key")) == "method"]
    if len(methods) > 1:
        return None
    return g._literal(methods[0].child_by_field_name("value")) if methods else "GET"


def _forwarded_fetch(root, call):
    """Check URL and method forwarding, rather than trust a helper's name."""
    if len(e._args(call)) != 2:
        return False
    helper = e._fetch_return_helper(root, call)
    if helper is None or helper == call or not _native_fetch(root):
        return False
    params = g._children(helper.child_by_field_name("parameters"))
    if len(params) != 2 or any(p.child_by_field_name("value") is not None for p in params):
        return False
    url, init = [g._name(p.child_by_field_name("pattern")) for p in params]
    if not url or not init or not e._stable(helper, {url, init}):
        return False
    counts = g._bindings(list(g._walk(helper)))
    if counts[url] != 1 or counts[init] != 1:
        return False
    fetches = [n for n in e._own(helper) if n.type == "call_expression"
               and g._name(n.child_by_field_name("function")) == "fetch"]
    if len(fetches) != 1 or len(e._args(fetches[0])) != 2:
        return False
    forwarded_url, forwarded_init = e._args(fetches[0])
    if g._name(forwarded_url) != url:
        return False
    forwarded_init = g._unwrap(forwarded_init)
    while forwarded_init and forwarded_init.type in {"as_expression", "satisfies_expression"}:
        forwarded_init = g._children(forwarded_init)[0]
    for node in g._walk(helper):
        if node.type != "identifier" or g._name(node) != init:
            continue
        parent = node.parent
        if parent in params or node == forwarded_init:
            continue
        if (parent.type == "member_expression" and parent.child_by_field_name("object") == node
                and g._text(parent.child_by_field_name("property")) == "timeout"):
            continue
        if parent.type == "spread_element" and parent.parent == forwarded_init:
            continue
        # Passing/aliasing the mutable options object can change its method.
        return False
    if g._name(forwarded_init) == init:
        return True
    if not forwarded_init or forwarded_init.type != "object":
        return False
    parts = g._children(forwarded_init)
    if not parts or parts[0].type != "spread_element" or e._tokens(parts[0]) != "..." + init:
        return False
    # Extra method/body/URL options or spreads can replace the recorded request role.
    return all((n.type == "pair" and g._text(n.child_by_field_name("key")) in {"signal", "dispatcher"})
               or (n.type == "shorthand_property_identifier" and g._text(n) == "dispatcher")
               for n in parts[1:])


def _role(root, call):
    name = g._name(call.child_by_field_name("function"))
    if not ((name == "fetch" and _native_fetch(root)) or _forwarded_fetch(root, call)):
        return None
    args = e._args(call)
    if not 1 <= len(args) <= 2:
        return None
    method = _method(args[1] if len(args) == 2 else None)
    url = args[0]
    literal = g._literal(url)
    children = g._children(url)
    leading = (g._text(children[0]) if url.type == "template_string" and children
               and children[0].type == "string_fragment" else "")
    prefix = literal if literal is not None else leading
    # Only public endpoint shape is returned; interpolations and literal identifiers are redacted.
    if method == "POST" and literal == "https://api.replicate.com/v1/predictions":
        return "prediction_creation_post"
    if method == "GET" and prefix.startswith("https://api.replicate.com/v1/predictions/"):
        return "prediction_status_get"
    if method == "GET" and prefix.startswith("https://api.replicate.com/v1/models/"):
        return "model_metadata_get"
    return None


def request_role_checks(verifier, path, root, callback, call, text, common):
    if not e._asserted(text, r"\b(?:\d+\s+paid\s+\w*\s*calls|billed per invocation|"
                       r"\d+.{0,8}[×*].{0,40}(?:calls|cost))"):
        return []
    operations = []
    for node in e._own(callback.child_by_field_name("body")):
        if node.type != "call_expression":
            continue
        role = _role(root, node)
        if role:
            operations.append({"role": role, "call": verifier.loader._binding(path, node)})
        else:
            helper = e._local_function(root, g._name(node.child_by_field_name("function")))
            if helper is None or e._args(node):
                continue
            for request in e._own(helper):
                if request.type == "call_expression" and (role := _role(root, request)):
                    operations.append({"role": role, "call": verifier.loader._binding(path, request),
                                       "helper_call": verifier.loader._binding(path, node)})
    roles = {operation["role"] for operation in operations}
    if not {"prediction_creation_post", "prediction_status_get"} <= roles or len(operations) > 8:
        return []
    record = verifier._record(
        "request_role_billing_boundary", path, call,
        "The selected callback contains separately bound prediction-creation POST and status GET operations; "
        "a same-file zero-argument metadata helper is included only when its direct request is bound. "
        "These roles distinguish HTTP requests from submitted inference operations. GET syntax does not prove "
        "free requests, and POST syntax does not prove execution or charges. "
        "Pricing and runtime counts were not checked.",
        **common, operations=operations, billing_verified=False)
    return [e._review(record, "request_count_as_paid_operations", "The numerical request multiplier is not "
                      "a verified count of billable inference runs. Creation, status polling and metadata "
                      "requests have different source roles; provider pricing, executed attempts and charges "
                      "remain unverified. Preserve the separate risk of recreating work after an unknown outcome.")]


def client_dispatch_checks(verifier, path, root, start, end, text):
    fn = c._function(root, start, end)
    post = c._literal_post(fn) if fn else None
    parts = path.split("/")
    if not post or "app" not in parts or not _native_fetch(root):
        return []
    prefix = "/".join(parts[:parts.index("app")])
    route = posixpath.join(prefix, "app", post[0].lstrip("/"), "route.ts")
    _, route_root = verifier.loader._read(route)
    handler = i._exports(route_root).get("POST")
    if handler is None:
        return []
    # Source convention, not proof about proxies, rewrites or a deployed route.
    checks = verifier._duplicate(route, route_root, g._line(handler), g._line(handler), text, select_unique=True)
    for record in checks:
        record["source_binding"]["client_fetch"] = verifier.loader._binding(path, post[1])
        record["source_binding"]["route_mapping"] = "Next app directory literal POST; rewrites not verified"
        # A server operation identity must never merge a client UI mechanism into it.
        record.pop("operation_identity", None)
        if record.get("narrative_review"):
            record["narrative_review"]["reason"] += (
                " The server link is by literal Next route convention; deployed routing is not verified.")
    return checks


def _claimed_limit(text):
    normalized = re.sub(r"[-`]+", " ", text)
    pattern = r"\b(\d+)\s+requests?\s+(?:per|in|every)\s+(?:(\d+)\s*(seconds?|s|minutes?|m)|minute)\b"
    values = set()
    for sentence in re.split(r"(?<=[.!?])\s+|\n", normalized):
        if not re.search(r"rate\s*limit", sentence, re.I):
            continue
        if not e._asserted(sentence, pattern):
            continue
        for match in re.finditer(pattern, sentence, re.I):
            count, units, unit = match.groups()
            seconds = int(units or 1) * (60 if not unit or unit.lower().startswith("m") else 1)
            values.add((int(count), seconds))
    return next(iter(values)) if len(values) == 1 else None


def _configured_limit(verifier, path, root, call):
    name = g._name(call.child_by_field_name("function"))
    imports, _ = i._imports(root)
    bindings = [entry for entry in imports if entry["name"] == name]
    if name != "checkLimit" or len(bindings) != 1 or not i._unambiguous(root, name) or not e._stable(root, {name}):
        return None
    target, resolution = verifier.loader._resolve(path, bindings[0]["specifier"])
    _, helper_root = verifier.loader._read(target)
    helper = i._exports(helper_root).get(name)
    if helper is None:
        return None
    params = g._children(helper.child_by_field_name("parameters"))
    args = e._args(call)
    if len(params) != 3 or not 1 <= len(args) <= 3:
        return None
    key, maximum, window = [g._name(p.child_by_field_name("pattern")) for p in params]
    if not all((key, maximum, window)) or not e._stable(helper, {key, maximum, window}):
        return None
    counts = g._bindings(list(g._walk(helper)))
    if any(counts[name] != 1 for name in (key, maximum, window)):
        return None
    maximum_node = args[1] if len(args) >= 2 else params[1].child_by_field_name("value")
    window_node = args[2] if len(args) >= 3 else params[2].child_by_field_name("value")
    maximum_value, window_value = g._number(maximum_node), g._literal(window_node)
    duration = re.fullmatch(r"([1-9]\d{0,5}) (s|m)", window_value or "")
    if maximum_value is None or not maximum_value.is_integer() or not 1 <= maximum_value <= 100000 or not duration:
        return None
    ratelimit_imports, _ = i._imports(helper_root)
    if (not any(entry["name"] == "Ratelimit" and entry["specifier"] == "@upstash/ratelimit"
                for entry in ratelimit_imports) or not i._unambiguous(helper_root, "Ratelimit")
            or not e._stable(helper_root, {"Ratelimit"})):
        return None
    windows = [n for n in e._own(helper) if n.type == "call_expression"
               and e._tokens(n) == f"Ratelimit.slidingWindow({maximum},{window})"]
    if len(windows) != 1:
        return None
    configured = windows[0]
    pair = configured.parent
    if pair.type != "pair" or g._text(pair.child_by_field_name("key")) != "limiter":
        return None
    constructor = e._ancestor(pair, "new_expression")
    if not constructor or g._name(constructor.child_by_field_name("constructor")) != "Ratelimit":
        return None
    options = pair.parent
    if options.type != "object" or any(n.type not in {"pair", "shorthand_property_identifier"}
                                       for n in g._children(options)):
        return None
    if e._pair(options, "limiter") != configured:
        return None
    # The configuration must be consumed by this instance, with its success
    # returned by the helper. An unused or unreachable constructor is no counterexample.
    top = g._children(helper.child_by_field_name("body"))
    if len(top) != 1 or top[0].type != "try_statement" or top[0].child_by_field_name("finalizer"):
        return None
    statements = g._children(top[0].child_by_field_name("body"))
    if len(statements) != 3 or statements[2].type != "return_statement":
        return None
    dec = constructor.parent
    if not e._declaration(dec) or dec.parent != statements[0]:
        return None
    instance = g._name(dec.child_by_field_name("name"))
    success_decs = [n for n in g._children(statements[1]) if n.type == "variable_declarator"]
    if not instance or len(success_decs) != 1 or not e._declaration(success_decs[0]):
        return None
    success_dec = success_decs[0]
    success = e._pattern_name(success_dec.child_by_field_name("name"), "success")
    awaited = success_dec.child_by_field_name("value")
    values = g._children(awaited)
    limit_call = values[0] if awaited and awaited.type == "await_expression" and len(values) == 1 else None
    if (not success or not limit_call or e._tokens(limit_call) != f"{instance}.limit({key})"
            or e._tokens(statements[2]) != f"return{success};"
            or not e._stable(helper, {instance, success})
            or any(counts[name] != 1 for name in (instance, success))):
        return None
    return {"maximum_requests": int(maximum_value),
            "window_seconds": int(duration[1]) * (60 if duration[2] == "m" else 1),
            "maximum_mode": "literal_call_override" if len(args) >= 2 else "parameter_default",
            "window_mode": "literal_call_override" if len(args) >= 3 else "parameter_default",
            "helper": verifier.loader._binding(target, helper),
            "configuration_call": verifier.loader._binding(target, configured),
            "consumed_limit_call": verifier.loader._binding(target, limit_call),
            "returned_success": verifier.loader._binding(target, statements[2]),
            "import": verifier.loader._binding(path, bindings[0]["node"]), "resolution": resolution}


def _limiter_before(verifier, path, root, operation):
    owner = i._owner(operation)
    body = owner.child_by_field_name("body") if owner else None
    if body is None:
        return []
    results = []
    statements = g._children(body)
    for index, statement in enumerate(statements[:-1]):
        if statement.end_byte >= operation.start_byte or statement.type != "lexical_declaration":
            continue
        decs = [n for n in g._children(statement) if n.type == "variable_declarator"]
        if len(decs) != 1 or not e._declaration(decs[0]):
            continue
        dec = decs[0]
        value = dec.child_by_field_name("value")
        name = g._name(dec.child_by_field_name("name"))
        children = g._children(value)
        call = children[0] if value and value.type == "await_expression" and len(children) == 1 else None
        if not call or call.type != "call_expression" or not name or not e._stable(owner, {name}):
            continue
        if g._bindings(list(g._walk(owner)))[name] != 1:
            continue
        guard = statements[index + 1]
        if (guard.type != "if_statement" or e._tokens(guard.child_by_field_name("condition")) != f"(!{name})"
                or not g._exit(guard) or guard.end_byte >= operation.start_byte):
            continue
        configured = _configured_limit(verifier, path, root, call)
        if configured:
            results.append({"limiter_call": verifier.loader._binding(path, call),
                            "limiter_guard": verifier.loader._binding(path, guard), **configured})
    return results if len(results) == 1 else []


def rate_limit_checks(verifier, path, root, start, end, text):
    claimed = _claimed_limit(text)
    if claimed is None:
        return []
    selected = c._function(root, start, end)
    if selected is None:
        return []
    candidates = []
    # Local route findings must contain a direct named operation, not an arbitrary nearby limit.
    local_imports, _ = i._imports(root)
    for operation in e._own(selected.child_by_field_name("body")):
        name = g._name(operation.child_by_field_name("function"))
        if (operation.type == "call_expression" and g._line(operation) <= end
                and start <= operation.end_point[0] + 1 and name
                and re.search(r"\b" + re.escape(name) + r"\b", text)
                and any(entry["name"] == name for entry in local_imports)
                and i._unambiguous(root, name) and e._stable(root, {name})):
            imported = [entry for entry in local_imports if entry["name"] == name]
            if len(imported) != 1:
                continue
            target, resolution = verifier.loader._resolve(path, imported[0]["specifier"])
            _, target_root = verifier.loader._read(target)
            exported_operation = i._exports(target_root).get(name)
            if exported_operation is None:
                continue
            for proof in _limiter_before(verifier, path, root, operation):
                proof.update(operation_import=verifier.loader._binding(path, imported[0]["node"]),
                             operation_resolution=resolution,
                             selected_export=verifier.loader._binding(target, exported_operation))
                candidates.append((path, operation, proof))
    exports = i._exports(root)
    exported = next(((name, fn) for name, fn in exports.items() if i._contains(fn, selected)), None)
    if exported:
        name, fn = exported
        paths = sorted((p for p in verifier.loader._entries() if p != path and i._source_path(p)
                        and "/api/" in "/" + p and p.endswith("/route.ts")))[:MAX_CALLERS]
        for caller in paths:
            try:
                _, caller_root = verifier.loader._read(caller)
                imports, _ = i._imports(caller_root)
                imported = [entry for entry in imports if entry["name"] == name]
                if len(imported) != 1 or not i._unambiguous(caller_root, name) or not e._stable(caller_root, {name}):
                    continue
                resolved, resolution = verifier.loader._resolve(caller, imported[0]["specifier"])
                if resolved != path:
                    continue
                for call in g._walk(caller_root):
                    if call.type != "call_expression" or g._name(call.child_by_field_name("function")) != name:
                        continue
                    for proof in _limiter_before(verifier, caller, caller_root, call):
                        proof.update(operation_import=verifier.loader._binding(caller, imported[0]["node"]),
                                     operation_resolution=resolution,
                                     selected_export=verifier.loader._binding(path, fn))
                        candidates.append((caller, call, proof))
            except (ValueError, TypeError, AttributeError, KeyError):
                continue
    records = []
    for caller, operation, proof in candidates[:4]:
        if (proof["maximum_requests"], proof["window_seconds"]) == claimed:
            continue
        record = verifier._record(
            "imported_rate_limit_configuration", path, selected,
            "The recorded named-import operation is preceded by an awaited checkLimit call and its falsy return. "
            "The checkLimit import resolves to the recorded source export; literal arguments or omitted-argument "
            "defaults flow unchanged into Ratelimit.slidingWindow. The numerical configuration differs from the "
            "asserted rate-limit value. Comments do not set this configuration. Runtime limiting, fail-open "
            "behavior, provider caps and actual spend are separate questions.",
            result="contradicted", operation=verifier.loader._binding(caller, operation),
            claimed_maximum_requests=claimed[0], claimed_window_seconds=claimed[1], **proof)
        records.append(e._review(record, "configured_rate_limit_number", "The bound source configuration is "
                                f"{proof['maximum_requests']} requests per {proof['window_seconds']} seconds, "
                                "not the number asserted in this cost calculation. This does not establish a "
                                "runtime request ceiling or any price, token consumption or billing multiplier."))
    return records

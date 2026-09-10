"""Bounded React error-path assessments; uploaded source is parsed, never run.

Only the named state, owning handler and recorded branch are assessed. A reset
on an HTTP-response path is not recovery from a rejected request/JSON promise;
a return through finally is not cleanup of a deferred callback. Navigation
syntax is an observation, never proof of permanent failure or successful routing.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import re
import zipfile

from app.scan import guard_context as g
from app.scan import imported_error_context as imported
from app.scan import react_async_context as react
from app.scan.consequence_evidence import ConsequenceVerifier, _function, _loc, _narrative

HTTP_KIND = "http_error_prevents_state_reset"
RETURN_KIND = "retry_return_skips_finally_reset"
NAVIGATION_KIND = "navigation_pending_outcome_unverified"
MAX_CHECKS = 40
CLAIMS = {
    HTTP_KIND: "An HTTP error status alone prevents the recorded same-state reset on the cited response path.",
    RETURN_KIND: "The recorded retry return skips the same handler's finally state reset.",
    NAVIGATION_KIND: "The recorded state and navigation syntax establishes a permanent disabled-state outcome.",
}
BOUNDARY = (
    "Only this source path is assessed; the whole finding and its other concerns remain open. "
    "Runtime bindings, React rendering, request/body rejection, navigation completion and deferred "
    "callback effects remain unverified."
)


def _selection(finding):
    text = _narrative(finding)
    # A factual observation about HTTP followed by a different network or
    # navigation claim must not invent an HTTP-reset allegation of its own.
    assertion = "\n".join(str(finding.get(k, ""))[:8000] for k in ("title", "explanation"))
    segments = re.split(r"[\n,;]|\b(?:but|however|whereas)\b", assertion, flags=re.I)
    risk = r"\b(?:stuck|disabled|never called|not (?:cleared|called|reset)|without clearing)\b"
    segments = [s for s in segments if re.search(risk, s, re.I) and not re.search(
        r"\b(?:not|never|isn't|doesn't)\s+(?:\w+\s+){0,3}(?:stuck|disabled)\b|"
        r"\b(?:no evidence|not true|not the case)\b", s, re.I)]
    kinds = []
    if any(re.search(r"\bHTTP\b|\bnon[ -]ok\b|\bnon[ -]2xx\b", s, re.I) for s in segments):
        kinds.append(HTTP_KIND)
    # The deferred callback can fail independently even when this invocation
    # resets correctly. Only an explicit reset-absence/return claim is selected.
    if re.search(r"\bretry\b|\bsetTimeout\b", assertion, re.I) and any(
        re.search(r"\breturns?\b", s, re.I)
        and re.search(r"\b(?:not|never)\s+(?:called|reset|cleared)\b|"
                      r"\b(?:skips?|bypasses?)\b.{0,60}\b(?:finally|reset)\b|"
                      r"\bwithout\s+(?:resetting|clearing)\b", s, re.I)
        and not re.search(r"\b(?:callback|deferred)\b|\bafter unmount\b", s, re.I)
        for s in re.split(r"[\n,;]|\b(?:but|however|whereas)\b", assertion, flags=re.I)
    ):
        kinds.append(RETURN_KIND)
    if any(re.search(r"\b(?:navigation|router\.push)\b", s, re.I) for s in segments):
        kinds.append(NAVIGATION_KIND)
    return kinds, text


def _result(kind, detail, binding=None, **extra):
    record = {"kind": kind, "claim": CLAIMS[kind], "result": "not_checked", "whole_finding": False,
              "method": "source_ast", "detail": detail + " " + BOUNDARY, **extra}
    if binding:
        record.update({k: binding[k] for k in ("file", "source_sha256", "line_start", "line_end")})
        record["source_binding"] = binding
    return record


def _node_at(nodes, span):
    return next((n for n in nodes if [n.start_byte, n.end_byte] == span), None)


def _enclosing_finally(node, fn):
    parent = node.parent
    while parent and parent != fn:
        if parent.type in g._FUNCTIONS:
            return True
        if parent.type == "try_statement" and parent.child_by_field_name("finalizer"):
            return True
        parent = parent.parent
    return False


def _calls_setter(node, setter):
    return any(n.type == "call_expression" and g._name(n.child_by_field_name("function")) == setter
               for n in g._walk(node, g._SKIP))


def _pending_path(statement, fn, raised_end, setter, *, terminal_guards=False):
    """Closed block/try path with no earlier exit or different state write.

    A terminal conditional error branch cannot reach the later continuation.
    Other branching and catch/finally effects remain outside this small grammar.
    """
    prefixes, node = [], statement
    while node.parent != fn:
        parent = node.parent
        if parent is None:
            return False
        if parent.type == "statement_block":
            prefixes.extend(s for s in g._children(parent) if s.end_byte <= node.start_byte
                            and s.start_byte >= raised_end)
        elif parent.type == "try_statement":
            if node != parent.child_by_field_name("body") or parent.child_by_field_name("finalizer"):
                return False
        else:
            return False
        node = parent
    for stmt in prefixes:
        if stmt.type in {"expression_statement", "lexical_declaration"} and not _calls_setter(stmt, setter):
            continue
        if terminal_guards and stmt.type == "if_statement" and not stmt.child_by_field_name("alternative"):
            cond = g._unwrap(stmt.child_by_field_name("condition"))
            body = stmt.child_by_field_name("consequence")
            parts = g._children(body) if body and body.type == "statement_block" else [body]
            if (cond and cond.type not in {"true", "false", "number", "string"}
                    and parts and parts[-1] and parts[-1].type in {"return_statement", "throw_statement"}
                    and all(s.type in {"expression_statement", "lexical_declaration"} for s in parts[:-1])):
                continue
        if stmt.type == "try_statement":
            handler = stmt.child_by_field_name("handler")
            parts = g._children(stmt.child_by_field_name("body"))
            if (handler and not g._children(handler.child_by_field_name("body"))
                    and not stmt.child_by_field_name("finalizer")
                    and all(s.type in {"expression_statement", "lexical_declaration"} for s in parts)
                    and not _calls_setter(stmt, setter)):
                continue
        return False
    return True


def _http_reset(fn, record, state_check, setter, nodes):
    responses = [c for c in record["checks"] if c["kind"] == "react_async_http_response"]
    if len(responses) != 1:
        return None
    response = responses[0]
    calls = [n for n in nodes if n.type == "await_expression" and g._line(n) == response["line"]
             and len(g._children(n)) == 1 and react._call(g._children(n)[0])[0] == "fetch"]
    if len(calls) != 1:
        return None
    call = calls[0]
    name = response.get("response")
    statement = call.parent.parent if name else call.parent
    if name:
        dec = call.parent
        if (dec.type != "variable_declarator" or g._name(dec.child_by_field_name("name")) != name
                or not any(c.type == "const" for c in statement.children)):
            return None
    if statement.parent.type != "statement_block" or _enclosing_finally(statement, fn):
        return None
    if not _pending_path(statement, fn, state_check['_raised_end_byte'], setter):
        return None
    siblings = g._children(statement.parent)
    for branch in response["branches"]:
        if branch["path"] != "http_error":
            continue
        guard = next((s for s in siblings if s.type == "if_statement" and g._line(s) == branch["line"]), None)
        if guard is None or siblings.index(guard) != siblings.index(statement) + 1:
            continue
        body = guard.child_by_field_name("consequence") if guard else None
        parts = g._children(body) if body and body.type == "statement_block" else []
        # Body parsing and error-message evaluation can still throw. This only
        # contradicts status-alone/absent-call claims on the recorded return path.
        if (len(parts) >= 2 and parts[-1].type == "return_statement" and not g._children(parts[-1])
                and react._literal_setter(parts[-2], setter, "false")
                and all(s.type in {"expression_statement", "lexical_declaration"} for s in parts[:-2])):
            return {"fetch": _loc(call), "http_error_branch": _loc(guard), "reset": _loc(parts[-2]),
                    "return": _loc(parts[-1]), "path": "http_error_branch_normal_completion",
                    "earlier_branch_effects": "not_checked"}
    index = siblings.index(statement)
    if (index + 1 < len(siblings) and react._literal_setter(siblings[index + 1], setter, "false")
            and not any(n.start_byte > siblings[index + 1].end_byte and n.type == "call_expression"
                        and g._name(n.child_by_field_name("function")) == setter for n in nodes)):
        return {"fetch": _loc(call), "reset": _loc(siblings[index + 1]),
                "path": "fulfilled_fetch_continuation", "standard_fetch_status_semantics": True}
    return None


def _retry_return(fn, state_check, setter, nodes, file_nodes):
    reset_line = state_check.get("finally_reset_line")
    if not reset_line or react._bindings(file_nodes)["setTimeout"]:
        return None
    if any(n.type == "import_statement" and any(g._name(c) == "setTimeout" for c in g._walk(n))
           for n in file_nodes):
        return None
    body = fn.child_by_field_name("body")
    handler = imported._function_name(fn)
    for attempt in g._children(body):
        if attempt.type != "try_statement":
            continue
        final = attempt.child_by_field_name("finalizer")
        final_body = final.child_by_field_name("body") if final else None
        parts = g._children(final_body)
        if not (len(parts) == 1 and g._line(parts[0]) == reset_line
                and react._literal_setter(parts[0], setter, "false")):
            continue
        for ret in nodes:
            if (ret.type != "return_statement" or g._children(ret)
                    or not imported._contains(attempt.child_by_field_name("body"), ret)
                    or ret.parent.type != "statement_block"):
                continue
            parent = ret.parent
            while parent != attempt and parent is not None:
                if parent.type == "try_statement" and parent.child_by_field_name("finalizer"):
                    break
                parent = parent.parent
            if parent != attempt:
                continue
            statements = g._children(ret.parent)
            index = statements.index(ret)
            timer = statements[index - 1] if index else None
            if not timer or react._call(timer)[0] != "setTimeout":
                continue
            args = react._call(timer)[1]
            callback = args[0] if len(args) == 2 else None
            if (callback is None or callback.type != "arrow_function"
                    or g._children(callback.child_by_field_name("parameters"))
                    or callback.child_by_field_name("parameter")
                    or react._call(callback.child_by_field_name("body"))[0] != handler):
                continue
            return {"try": _loc(attempt), "retry_timer": _loc(timer), "return": _loc(ret),
                    "finally": _loc(final), "reset": _loc(parts[0]), "deferred_callback_cleanup": "not_checked"}
    return None


def _navigation(root, component, fn, nodes, file_nodes, state_check, setter):
    hooks = react._router_hooks(root, react._bindings(file_nodes))
    component_body = component.child_by_field_name("body")
    bindings = react._bindings(list(g._walk(component)))
    routers = {}
    for statement in g._children(component_body):
        if statement.type != "lexical_declaration" or not any(c.type == "const" for c in statement.children):
            continue
        for dec in g._children(statement):
            name, value = g._name(dec.child_by_field_name("name")), dec.child_by_field_name("value")
            if (name and value and react._call(value)[0] in hooks and not react._call(value)[1]
                    and bindings[name] == 1):
                routers[name] = dec
    valid = react._unescaped_routers(component_body, set(routers))
    candidates = []
    for node in nodes:
        receiver, args = g._method(node, "push")
        name = g._name(receiver)
        if name not in valid or len(args) != 1 or args[0].type != "string":
            continue
        stmt = node.parent
        if (stmt.type != "expression_statement" or stmt.parent.type != "statement_block"
                or g._children(stmt.parent)[-1] != stmt):
            continue
        if not _pending_path(stmt, fn, state_check['_raised_end_byte'], setter, terminal_guards=True):
            continue
        # Pending navigation is a bounded observation, not a verified failure.
        candidates.append({"router_binding": _loc(routers[name]), "navigation": _loc(node),
                           "navigation_completion": "not_checked", "component_remains_mounted": "not_checked"})
    return candidates[0] if len(candidates) == 1 else None


class ScopedUIClaimVerifier:
    def __init__(self, archive):
        self.loader = ConsequenceVerifier(archive)
        self.checks = 0
        self._files = {}
        self._results = {}

    def checks_for(self, finding):
        kinds, text = _selection(finding)
        if not kinds:
            return []
        path, start, end = finding.get("file"), finding.get("line_start"), finding.get("line_end")
        if not imported._source_path(path) or type(start) is not int or type(end) is not int or not 1 <= start <= end:
            return [_result(k, "Unsupported source path or coordinates.") for k in kinds]
        key = (path, start, end, tuple(kinds), text)
        if key in self._results:
            return deepcopy(self._results[key])
        if self.checks >= MAX_CHECKS:
            return [_result(k, "Per-audit scoped UI claim budget exhausted.") for k in kinds]
        self.checks += 1
        binding, records = None, []
        try:
            if path not in self._files:
                data, root = self.loader._read(path)
                file_nodes = list(g._walk(root))
                inventory = list(react._file_records(root, path, file_nodes, set()))
                self._files[path] = data, root, file_nodes, inventory
            data, root, file_nodes, inventory = self._files[path]
            candidates = [r for r in inventory if r["line"] <= start <= end <= r["line_end"]]
            if len(candidates) != 1:
                raise ValueError("Coordinates do not identify one supported named React handler")
            record = candidates[0]
            fn = _node_at(file_nodes, record["function_span"])
            component = _node_at(file_nodes, record["component_span"])
            if _function(root, start, end) != fn:
                raise ValueError("Anchor belongs to a nested function, not this handler")
            if any(n.type in {"class", "class_declaration"} and g._line(n) <= start <= end <= n.end_point[0] + 1
                   for n in file_nodes):
                raise ValueError("Anchor belongs to a nested class")
            handler_names = {r['scope'].rsplit('.', 1)[1] for r in inventory
                             if re.search(r'\b' + re.escape(r['scope'].rsplit('.', 1)[1]) + r'\b',
                                          str(finding.get('title', '')), re.I)}
            if handler_names and handler_names != {record['scope'].rsplit('.', 1)[1]}:
                raise ValueError("Named narrative handler differs from the source anchor")
            states = [c for c in record["checks"] if c["kind"] == "react_async_state_reset"
                      and c.get("set_true_line") and re.search(r"\b" + re.escape(c["state"]) + r"\b", text, re.I)]
            if len(states) != 1:
                raise ValueError("Narrative does not identify one source-bound raised state")
            state_check = dict(states[0])
            state = state_check["state"]
            declarations = [n for n in file_nodes if n.type == "variable_declarator"
                            and n.child_by_field_name("name") and n.child_by_field_name("name").type == "array_pattern"
                            and g._name(g._children(n.child_by_field_name("name"))[0]) == state
                            and imported._contains(component, n)]
            if len(declarations) != 1:
                raise ValueError("State binding is ambiguous")
            declaration = declarations[0]
            setter = g._name(g._children(declaration.child_by_field_name("name"))[1])
            raised = [s for s in g._children(fn.child_by_field_name('body'))
                      if g._line(s) == state_check['set_true_line'] and react._literal_setter(s, setter, 'true')]
            if len(raised) != 1:
                raise ValueError('Raised state assignment is ambiguous')
            state_check['_raised_end_byte'] = raised[0].end_byte
            for node in g._walk(component):
                if g._name(node) != setter or imported._contains(declaration, node):
                    continue
                if not (node.parent.type == "call_expression" and node.parent.child_by_field_name("function") == node):
                    raise ValueError("Setter binding escapes the supported direct-call syntax")
            nodes = list(g._walk(fn.child_by_field_name("body"), g._SKIP))
            binding = {"file": path, "source_sha256": sha256(data).hexdigest(), **_loc(fn),
                       "handler": _loc(fn), "state": state, "state_binding": _loc(declaration),
                       "state_raised_line": state_check["set_true_line"]}
            for kind in kinds:
                proof = (_http_reset(fn, record, state_check, setter, nodes) if kind == HTTP_KIND else
                         _retry_return(fn, state_check, setter, nodes, file_nodes) if kind == RETURN_KIND else
                         _navigation(root, component, fn, nodes, file_nodes, state_check, setter))
                if not proof:
                    records.append(_result(kind, "No linked counterevidence in the supported source path.", binding))
                    continue
                bound = {**binding, **proof}
                if kind == NAVIGATION_KIND:
                    reason = ("The handler calls an imported Next router with the recorded state raised. "
                              "Pending navigation alone does not establish permanently disabled UI; "
                              "failed/cancelled navigation and mounting behavior need separate evidence.")
                    records.append(_result(kind, reason, bound, result="observed", narrative_review={
                        "status": "required", "premise": kind, "reason": reason}))
                else:
                    detail = ("The same state has a direct false setter on the recorded HTTP-response path. "
                              "An HTTP status alone is different from network rejection or failed body/message "
                              "evaluation, which may still bypass this reset. HTTP false-success remains separate."
                              if kind == HTTP_KIND else
                              "The recorded retry return leaves a try whose sole finally statement resets the "
                              "same state. Return executes this finally; the later timer invocation and unmount "
                              "cleanup are separate concerns.")
                    records.append(_result(kind, detail, bound, result="contradicted"))
        except (ValueError, TypeError, AttributeError, KeyError, IndexError, UnicodeError, RecursionError,
                RuntimeError, OSError, zipfile.BadZipFile):
            records = [_result(k, "Source binding could not be checked within the supported scope.", binding)
                       for k in kinds]
        self._results[key] = deepcopy(records)
        return records

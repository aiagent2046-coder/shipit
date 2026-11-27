"""Shared primitives for bounded source assessment of external calls.

Call-site evidence helpers (tokens, arguments, fetch helpers, stability)
that both the ExternalCallVerifier class in external_call_assessment and
the injected context checks in external_operation_context build on. The
bottom layer of the external-call assessment trio: this module knows
nothing about either caller.

Moved verbatim from external_call_assessment during the import-cycles fix
phase (the tangle: context used the verifier module's private helpers
while the verifier called the context checks back).
"""
from __future__ import annotations

import re

from app.scan.context import guard_context as g
from app.scan.context import imported_error_context as i


def _tokens(node):
    """Canonical AST leaves for deliberately narrow, local expression grammars."""
    parts, todo = [], [node] if node else []
    while todo:
        current = todo.pop()
        if current.type == "comment":
            continue
        if current.children:
            todo.extend(reversed(current.children))
        else:
            parts.append(g._text(current))
    return "".join(parts)


def _own(node):
    return list(g._walk(node, g._SKIP))


def _args(call):
    return g._children(call.child_by_field_name("arguments"))


def _selected(node, start, end):
    return g._line(node) <= start <= end <= node.end_point[0] + 1


def _introduced(node, start, end):
    """An adjacent comment may introduce one statement, never another operation."""
    if _selected(node, start, end):
        return True
    previous = node.prev_named_sibling
    return bool(previous and previous.type == "comment" and _selected(previous, start, start)
                and end <= node.end_point[0] + 1
                and node.start_point[0] <= previous.end_point[0] + 1)


def _asserted(text, pattern):
    """Select an affirmative consequence, never advice or an explicit disclaimer."""
    for sentence in re.split(r"(?<=[.!?;])\s+|\n", text):
        if (re.search(pattern, sentence, re.I)
                and not re.search(r"\b(?:not|never|cannot|neither|prevents?|"
                                  r"verify|add|consider|recommend\w*|propos\w*|should|must|"
                                  r"not (?:prove|establish|demonstrat|automatically|necessarily)|"
                                  r"unverified|not (?:verified|established|supported|a proof|proof)|"
                                  r"does not|do not|cannot conclude|"
                                  r"whether|verify whether|no evidence|not a (?:deadline|billing))\b", sentence, re.I)):
            return True
    return False


def _review(record, premise, reason):
    record["narrative_review"] = {"status": "required", "premise": premise, "reason": reason}
    return record


def _callback_reentry_claim(text):
    error = r"(?:any (?:thrown )?error|400|422|pars(?:e|ing)|JSON)"
    for sentence in re.split(r"(?<=[.!?;])\s+|\n", text):
        if re.search(r"\b(?:outside|afterwards|separate|after (?:the |its )?(?:callback|retry))\b", sentence, re.I):
            continue
        if _asserted(sentence, r"\bretr\w*.{0,100}" + error + "|" + error + r".{0,100}\bretr\w*"):
            return True
    return False


def _ancestor(node, typ):
    while node and node.type != typ:
        node = node.parent
    return node


def _top_statement(node, body):
    while node and node.parent != body:
        node = node.parent
    return node


def _declaration(node):
    if node is None or node.type != "variable_declarator":
        return False
    stmt = node.parent
    return bool(stmt and stmt.type == "lexical_declaration" and any(n.type == "const" for n in stmt.children))


def _pair(obj, key):
    if not obj or obj.type not in {"object", "object_pattern"}:
        return None
    # Quoted/computed keys and spreads can override an earlier plain key.
    # Abstain instead of treating an ignored property as absent.
    if any(n.type in {"spread_element", "rest_pattern"}
           or (n.type in {"pair", "pair_pattern"}
               and n.child_by_field_name("key").type != "property_identifier")
           for n in g._children(obj)):
        return None
    matches = [
        n
        for n in g._children(obj)
        if n.type in {"pair", "pair_pattern"} and g._text(n.child_by_field_name("key")) == key
    ]
    return matches[0].child_by_field_name("value") if len(matches) == 1 else None


def _pattern_name(obj, key):
    value = _pair(obj, key)
    names = (
        [g._name(value)]
        if value
        else [
            g._text(n)
            for n in g._children(obj)
            if n.type == "shorthand_property_identifier_pattern" and g._text(n) == key
        ]
    )
    return names[0] if len(names) == 1 else ""


def _local_function(root, name):
    funcs = [
        n for n in g._walk(root) if n.type == "function_declaration" and g._name(n.child_by_field_name("name")) == name
    ]
    return funcs[0] if len(funcs) == 1 and i._unambiguous(root, name, declaration=True) else None


def _stable(fn, names, allowed_updates=()):
    """Reject visible writes/aliases to bindings whose identity the grammar uses."""
    nodes = list(g._walk(fn))
    for node in nodes:
        if node.type in {"assignment_expression", "augmented_assignment_expression", "update_expression"}:
            target = node.child_by_field_name("left") or node.child_by_field_name("argument")
            while target and target.type in {"member_expression", "subscript_expression"}:
                target = target.child_by_field_name("object")
            if g._name(target) in names and node not in allowed_updates:
                return False
    return True


def _retry_shape(root, wrapper, call):
    """One for-loop, direct awaited callback return, and terminal catch branch."""
    params = g._children(wrapper.child_by_field_name("parameters"))
    if not 1 <= len(params) <= 2:
        return None
    callback = g._name(params[0].child_by_field_name("pattern"))
    body = wrapper.child_by_field_name("body")
    stmts = g._children(body)
    if not callback or len(stmts) != 2 or stmts[0].type != "for_statement" or stmts[1].type != "throw_statement":
        return None
    loop = stmts[0]
    init = loop.child_by_field_name("initializer")
    decs = [n for n in g._children(init) if n.type == "variable_declarator"]
    if len(decs) != 1 or g._number(decs[0].child_by_field_name("value")) != 1:
        return None
    attempt = g._name(decs[0].child_by_field_name("name"))
    cond, increment = loop.child_by_field_name("condition"), loop.child_by_field_name("increment")
    if not attempt or _tokens(increment) != attempt + "++":
        return None
    if (
        cond.type != "binary_expression"
        or _tokens(cond.child_by_field_name("left")) != attempt
        or g._text(cond.child_by_field_name("operator")) != "<="
    ):
        return None
    bound = cond.child_by_field_name("right")
    bound_name = g._name(bound)
    actual = g._number(bound)
    mode = "literal_loop_bound"
    args = _args(call)
    if bound_name:
        if len(params) != 2 or g._name(params[1].child_by_field_name("pattern")) != bound_name:
            return None
        default = params[1].child_by_field_name("value")
        actual = g._number(args[1] if len(args) == 2 else default)
        mode = "literal_call_override" if len(args) == 2 else "parameter_default"
    elif len(args) != 1:
        return None
    if not actual or not actual.is_integer() or not 1 <= actual <= 100:
        return None
    parts = g._children(loop.child_by_field_name("body"))
    if len(parts) != 1 or parts[0].type != "try_statement" or parts[0].child_by_field_name("finalizer"):
        return None
    attempt_try = parts[0]
    if _tokens(attempt_try.child_by_field_name("body")) != "{returnawait" + callback + "();}":
        return None
    handler = attempt_try.child_by_field_name("handler")
    if handler is None:
        return None
    err = g._name(handler.child_by_field_name("parameter"))
    if not err or not _stable(wrapper, {callback, attempt, bound_name, err}, [increment]):
        return None
    if any(g._name(n) == callback for n in g._walk(handler)):
        return None
    if any(n.type in {"return_statement", "continue_statement", "break_statement"} for n in _own(handler)):
        return None
    counts = g._bindings(list(g._walk(wrapper)))
    if counts[callback] != 1 or counts[attempt] != 2 or bound_name and counts[bound_name] != 1:
        return None
    return (
        {"maximum_attempts": int(actual), "maximum_additional_attempts": int(actual) - 1, "attempt_bound_mode": mode},
        handler,
        err,
    )


def _terminal_classifier(handler, err):
    """Recognize only the explicit abort / typed HTTP classifier used here.

    The ordinary Error message is dynamic: an 'aborted' substring may still
    select the abort branch. Therefore this never proves every poll error terminal.
    """
    stmts = g._children(handler.child_by_field_name("body"))
    consts = g._consts(handler.child_by_field_name("body"))
    required = {"isLast", "isAbort", "status", "isRateLimit", "isUpstream5xx", "retryable"}
    if not required <= consts.keys() or len(stmts) < 7:
        return None
    expected = {
        "isAbort": f"{err}?.name==='AbortError'||{err}?.message?.includes('aborted')",
        "status": f"({err}instanceofAIServiceError)?{err}.status:0",
        "isRateLimit": "status===429",
        "isUpstream5xx": "status>=500&&status<600",
        "retryable": "isAbort||isRateLimit||isUpstream5xx",
    }
    loop = _ancestor(handler, "for_statement")
    condition = loop.child_by_field_name("condition") if loop else None
    if condition is None:
        return None
    expected["isLast"] = (_tokens(condition.child_by_field_name("left")) + "==="
                          + _tokens(condition.child_by_field_name("right")))
    if any(
        _tokens(consts[name].child_by_field_name("value")).replace('"', "'") != value
        for name, value in expected.items()
    ):
        return None
    guard = stmts[6]
    if guard.type != "if_statement" or _tokens(guard.child_by_field_name("condition")) != "(isLast||!retryable)":
        return None
    body = g._children(guard.child_by_field_name("consequence"))
    if not body or body[-1].type != "throw_statement" or any(n.type in g._FUNCTIONS for n in _own(guard)):
        return None
    if not _stable(handler, required | {err}):
        return None
    return guard


def _fetch_return_helper(root, call):
    name = g._name(call.child_by_field_name("function"))
    if name == "fetch":
        facts = i._file_facts(root)
        return call if not facts[1][name] and not facts[2][name] and not facts[4] else None
    helper = _local_function(root, name)
    if not helper:
        return None
    nodes = _own(helper.child_by_field_name("body"))
    fetches = [
        n for n in nodes if n.type == "call_expression" and g._name(n.child_by_field_name("function")) == "fetch"
    ]
    returns = [n for n in nodes if n.type == "return_statement"]
    if len(fetches) != 1 or len(returns) != 1:
        return None
    awaited = i._await(fetches[0])
    dec = awaited.parent if awaited else None
    if not _declaration(dec):
        return None
    result = g._name(dec.child_by_field_name("name"))
    if _tokens(returns[0]) != "return" + result + ";" or not _stable(helper, {result}):
        return None
    if any(
        n.type == "member_expression"
        and g._text(n.child_by_field_name("property")) in {"ok", "json", "text", "status"}
        and g._name(n.child_by_field_name("object")) == result
        for n in nodes
    ):
        return None
    return helper

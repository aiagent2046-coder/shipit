"""Bounded source assessments of a selected retry/call/count premise.

No uploaded code runs. Results concern the recorded source path only, never
provider billing, SDK row-return semantics, transaction isolation or a whole
finding. Unsupported control flow and ambiguous bindings abstain.
"""

from __future__ import annotations

from copy import deepcopy
import re
import zipfile

from app.scan import consequence_evidence as c
from app.scan import guard_context as g
from app.scan import imported_error_context as i

MAX_CHECKS = 48
MAX_RECORDS = 5
KINDS = (
    "retry_callback_scope",
    "retry_classifier_terminal_error",
    "poll_wait_not_deadline",
    "duplicate_key_before_external_call",
    "insert_before_count_schedule",
)
LIMITS = (
    "Only the recorded source premise is assessed; the whole finding, other call sites, runtime bindings, "
    "provider behavior, cancellation, billing and overall concurrency safety are not verified."
)
COUNT_ASSUMPTIONS = [
    "Each successful awaited insert commits one distinct row matching the recorded count filter.",
    "Both counts read the same committed-row view, including their own completed insert and earlier commits.",
    "No matching rows are deleted or excluded by a changing filter between the two inserts and counts.",
]


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


class ExternalCallVerifier:
    def __init__(self, archive):
        self.loader = i.ImportedErrorVerifier(archive)
        self.checks = 0
        self._cache = {}

    def _record(self, kind, path, selected, detail, *, result="observed", **binding):
        source = self.loader._binding(path, selected)
        return {
            "kind": kind,
            "result": result,
            "whole_finding": False,
            "method": "source_ast",
            "scope": "bounded_source_premise",
            "detail": detail + " " + LIMITS,
            **source,
            "source_binding": {**source, **binding},
        }

    def _retry(self, path, root, start, end, text):
        selected_fn = c._function(root, start, end)
        if selected_fn is None:
            return []
        calls = [
            n
            for n in g._walk(root)
            if n.type == "call_expression" and g._name(n.child_by_field_name("function")) == "withRetry"
        ]
        wrapper = _local_function(root, "withRetry")
        if wrapper is None:
            return []
        matched = [n for n in calls if _selected(n, start, end)]
        if selected_fn == wrapper and _selected(wrapper, start, end):
            matched = calls
        if len(matched) != 1:
            return []
        call = matched[0]
        args = _args(call)
        if not 1 <= len(args) <= 2 or args[0].type not in {"arrow_function", "function_expression"}:
            return []
        shape = _retry_shape(root, wrapper, call)
        if shape is None:
            return []
        facts, handler, err = shape
        callback = args[0]
        common = {
            "retry_call": c._loc(call),
            "callback": c._loc(callback),
            "wrapper": self.loader._binding(path, wrapper),
            **facts,
        }
        records = []
        cbbody = g._unwrap(callback.child_by_field_name("body"))
        invoked = cbbody if cbbody.type == "call_expression" else None
        awaited = i._await(call)
        dec = awaited.parent if awaited else None
        if invoked and _declaration(dec) and _fetch_return_helper(root, invoked):
            response = g._name(dec.child_by_field_name("name"))
            block = dec.parent.parent
            owner = i._owner(call)
            if block.type == "statement_block" and owner and _stable(owner, {response}):
                nodes = _own(block)
                checks = [
                    n
                    for n in nodes
                    if n.type == "member_expression"
                    and g._name(n.child_by_field_name("object")) == response
                    and g._text(n.child_by_field_name("property")) == "ok"
                    and n.start_byte > call.end_byte
                ]
                parses = [
                    n
                    for n in nodes
                    if n.type == "call_expression"
                    and g._name(g._method(n, "json")[0]) == response
                    and n.start_byte > call.end_byte
                ]
                if checks and parses and g._bindings(list(g._walk(owner)))[response] == 1:
                    records.append(
                        self._record(
                            KINDS[0],
                            path,
                            call,
                            "The selected callback returns the recorded fetch/helper call. The same response's HTTP "
                            "status check and JSON parse occur after the awaited retry invocation, "
                            "outside its callback; "
                            "errors from those caller statements do not re-enter this invocation. "
                            "The loop bound counts "
                            "total attempts, not additional retries. Helper/runtime failures and charges are separate.",
                            result=(
                                "contradicted"
                                if re.search(r"\b(?:any (?:thrown )?error|400|422|pars(?:e|ing)|JSON)\b", text, re.I)
                                else "observed"
                            ),
                            **common,
                            response_status_checks=[c._loc(n) for n in checks[:4]],
                            response_json_calls=[c._loc(n) for n in parses[:4]],
                        )
                    )
        classifier = _terminal_classifier(handler, err)
        cbnodes = _own(cbbody)
        loops = []
        for node in cbnodes:
            if node.type != "while_statement":
                continue
            preceding = [n for n in g._children(node.parent) if n.end_byte < node.start_byte]
            previous = preceding[-1] if preceding else None
            counters = (
                [
                    n
                    for n in g._children(previous)
                    if n.type == "variable_declarator" and g._number(n.child_by_field_name("value")) == 0
                ]
                if previous
                else []
            )
            counter_selected = (len(counters) == 1 and _selected(counters[0], start, start)
                                and end <= node.end_point[0] + 1)
            counter_name = g._name(counters[0].child_by_field_name("name")) if counter_selected else ""
            condition_names = {g._name(n) for n in g._walk(node.child_by_field_name("condition"))}
            if _selected(node, start, end) or counter_name and counter_name in condition_names:
                loops.append(node)
        if classifier and len(loops) == 1:
            loop = loops[0]
            later = [n for n in g._children(cbbody) if n.start_byte > loop.end_byte]
            terminal = later[0] if later else None
            throws = [n for n in _own(terminal) if n.type == "throw_statement"] if terminal else []
            if terminal and terminal.type == "if_statement" and len(throws) == 1:
                values = g._children(throws[0])
                error = values[0] if len(values) == 1 else None
                if (
                    error
                    and error.type == "new_expression"
                    and g._name(error.child_by_field_name("constructor")) == "Error"
                ):
                    records.append(
                        self._record(
                            KINDS[1],
                            path,
                            loop,
                            "The selected post-poll branch throws an ordinary Error. The retry classifier uses abort "
                            "name/message signals or AIServiceError status 429/5xx; an ordinary Error "
                            "is not automatically "
                            "retryable. Its dynamic message can still match the abort substring. "
                            "Poll exhaustion therefore "
                            "does not by itself establish another prediction or a fixed retry multiplier.",
                            **common,
                            poll_loop=c._loc(loop),
                            terminal_throw=c._loc(throws[0]),
                            classifier=self.loader._binding(path, classifier),
                            terminal_error_message="dynamic_not_evaluated",
                        )
                    )
            sleeps = [
                n
                for n in g._walk(loop)
                if n.type == "call_expression"
                and g._name(n.child_by_field_name("function")) == "setTimeout"
                and len(_args(n)) == 2
                and g._number(_args(n)[1]) is not None
            ]
            fetches = [
                n
                for n in _own(loop)
                if n.type == "call_expression" and g._name(n.child_by_field_name("function")) == "fetch" and i._await(n)
            ]
            if sleeps and fetches:
                records.append(
                    self._record(
                        KINDS[2],
                        path,
                        loop,
                        "The recorded poll loop contains a timer wait and an awaited request. Iteration count times "
                        "sleep duration accounts only for waits, not request durations or other work; it does not "
                        "establish a wall-clock deadline, successful cancellation or a billable-operation count.",
                        **common,
                        poll_loop=c._loc(loop),
                        timer_waits=[c._loc(n) for n in sleeps[:4]],
                        awaited_requests=[c._loc(n) for n in fetches[:4]],
                    )
                )
        return records

    def _duplicate(self, path, root, start, end):
        fn = c._function(root, start, end)
        proof = c._duplicate_branch(root, fn) if fn else None
        if not proof:
            return []
        nodes = _own(fn.child_by_field_name("body"))
        upserts = [n for n in nodes if n.type == "call_expression" and c._table_call(n, "upsert")]
        guards = [n for n in nodes if n.type == "if_statement" and c._loc(n) == proof["guard"]]
        if len(guards) != 1:
            return []
        matches = []
        for query in upserts:
            if guards[0].end_byte >= query.start_byte:
                continue
            dec = _ancestor(query, "variable_declarator")
            if not _declaration(dec):
                continue
            result = _pattern_name(dec.child_by_field_name("name"), "data")
            if (
                not result
                or not _stable(fn, {result, proof["error_binding"]})
                or g._bindings(list(g._walk(fn)))[result] != 1
            ):
                continue
            later = [
                n
                for n in nodes
                if n.type == "call_expression"
                and n.start_byte > query.end_byte
                and g._name(n.child_by_field_name("function"))
            ]
            for call in later:
                helper = _local_function(root, g._name(call.child_by_field_name("function")))
                gate = _ancestor(call, "if_statement")
                if helper is None or gate is None:
                    continue
                condition = g._unwrap(gate.child_by_field_name("condition"))
                if (
                    not condition
                    or condition.type != "member_expression"
                    or g._name(condition.child_by_field_name("object")) != result
                    or g._text(condition.child_by_field_name("property")) != "id"
                ):
                    continue
                if not any(_tokens(arg) == result + ".id" for arg in _args(call)):
                    continue
                if not (_selected(query, start, end) or _selected(call, start, end) or start == g._line(gate)):
                    continue
                if any(
                    n.type == "call_expression" and g._name(n.child_by_field_name("function")) == "fetch"
                    for n in _own(helper)
                ):
                    matches.append((query, call, helper))
        if len(matches) != 1:
            return []
        query, call, helper = matches[0]
        return [
            self._record(
                KINDS[3],
                path,
                call,
                "The recorded earlier insert's 23505 error branch returns before this selected upsert and the later "
                "helper invocation containing fetch syntax. That duplicate-error path does not reach those statements. "
                "Whether repeated requests produce that error, active database constraints, and upsert returned-row "
                "semantics are not established; no overall deduplication guarantee follows.",
                result="observed",
                duplicate_insert=proof["insert"],
                duplicate_guard=proof["guard"],
                selected_upsert=c._loc(query),
                later_call=c._loc(call),
                helper=self.loader._binding(path, helper),
            )
        ]

    def _count(self, path, root, start, end, text):
        fn = c._function(root, start, end)
        if fn is None:
            return []
        # The cited statement must be the callback registration/count, never a nearby insert or fetch.
        callback = fn if fn.type == "arrow_function" else None
        if callback is None:
            return []
        registration = callback.parent.parent if callback.parent and callback.parent.type == "arguments" else None
        if (
            not registration
            or registration.type != "call_expression"
            or g._name(registration.child_by_field_name("function")) != "after"
        ):
            return []
        handler = i._owner(registration)
        body = handler.child_by_field_name("body") if handler else None
        if (
            body is None
            or _top_statement(registration, body) != registration.parent
            or registration.parent.type != "expression_statement"
        ):
            return []
        if any(n.type == "call_expression" and g._method(n, "delete")[0] is not None for n in g._walk(handler)):
            return []
        count_decs = [
            n
            for n in _own(callback.child_by_field_name("body"))
            if n.type == "variable_declarator" and _pattern_name(n.child_by_field_name("name"), "count")
        ]
        if len(count_decs) != 1:
            return []
        dec = count_decs[0]
        if not (_selected(dec, start, end) or start == g._line(registration)) or not _declaration(dec):
            return []
        count_name = _pattern_name(dec.child_by_field_name("name"), "count")
        value = dec.child_by_field_name("value")
        children = g._children(value)
        query = children[0] if value and value.type == "await_expression" and len(children) == 1 else None
        select, eqargs = g._method(query, "eq")
        table = c._table_call(select, "select")
        if not table or len(eqargs) != 2 or not g._literal(eqargs[0]) or not g._name(eqargs[1]):
            return []
        selectargs = table[1]
        if (
            len(selectargs) != 2
            or g._literal(selectargs[0]) != "*"
            or g._literal(_pair(selectargs[1], "count")) != "exact"
        ):
            return []
        filter_key, filter_value = g._literal(eqargs[0]), g._name(eqargs[1])
        guard = [
            n
            for n in _own(callback.child_by_field_name("body"))
            if n.type == "if_statement"
            and _tokens(n.child_by_field_name("condition")) == f"({count_name}!==null&&{count_name}<=1)"
            and n.start_byte > dec.end_byte
        ]
        if len(guard) != 1 or guard[0].parent != dec.parent.parent or not _stable(callback, {count_name}):
            return []
        fetches = [
            n
            for n in _own(guard[0].child_by_field_name("consequence"))
            if n.type == "call_expression" and g._name(n.child_by_field_name("function")) == "fetch" and i._await(n)
        ]
        if len(fetches) != 1:
            return []
        inserts = []
        for stmt in g._children(body):
            if stmt.end_byte >= registration.start_byte or stmt.type != "lexical_declaration":
                continue
            for prior in g._children(stmt):
                awaited = prior.child_by_field_name("value")
                if not _declaration(prior) or not awaited or awaited.type != "await_expression":
                    continue
                calls = [
                    n
                    for n in _own(awaited)
                    if n.type == "call_expression" and (t := c._table_call(n, "insert")) and t[0] == table[0]
                ]
                if len(calls) != 1:
                    continue
                insert = calls[0]
                payload = c._table_call(insert, "insert")[1]
                if (
                    len(payload) != 1
                    or g._name(_pair(payload[0], filter_key)) != filter_value
                    or any(n.type not in {"pair", "shorthand_property_identifier"} for n in g._children(payload[0]))
                ):
                    continue
                error_name = _pattern_name(prior.child_by_field_name("name"), "error")
                following = [n for n in g._children(body) if stmt.end_byte < n.start_byte < registration.start_byte]
                if (
                    not error_name
                    or not following
                    or following[0].type != "if_statement"
                    or _tokens(following[0].child_by_field_name("condition")) != "(" + error_name + ")"
                    or not g._exit(following[0])
                ):
                    continue
                inserts.append(insert)
        if len(inserts) != 1 or not _stable(handler, {filter_value, count_name}):
            return []
        return [
            self._record(
                KINDS[4],
                path,
                query,
                "The matching-row insert is awaited before registering this callback; this callback then awaits the "
                "same-table exact count filtered by the same key and gates the recorded fetch on count <= 1. Under "
                "the explicitly listed, unverified committed-row/no-delete assumptions, two distinct inserts cannot "
                "both be followed by counts of one: the count after the second commit sees at least two matching rows. "
                "This challenges only that proposed schedule; isolation, visibility, filters, other paths and total "
                "race safety remain unverified.",
                # The schedule argument depends on unverified database assumptions.
                # Preserve it as context; it cannot give the card a contradiction badge.
                result="observed",
                insert=c._loc(inserts[0]),
                registration=c._loc(registration),
                count_query=c._loc(query),
                count_guard=c._loc(guard[0]),
                external_call=c._loc(fetches[0]),
                assumptions=list(COUNT_ASSUMPTIONS),
                assumptions_verified=False,
            )
        ]

    def checks_for(self, finding):
        text = c._narrative(finding)
        retry = bool(re.search(r"\b(?:retr\w*|poll\w*|maxAttempts)\b", text, re.I))
        concurrent = bool(re.search(r"\b(?:duplicat\w*|concurren\w*|racy|race|twice|dedup\w*)\b", text, re.I))
        if not (retry or concurrent):
            return []
        path = finding.get("file")
        start, end = finding.get("line_start"), finding.get("line_end")
        if not i._source_path(path) or type(start) is not int or type(end) is not int or not 1 <= start <= end:
            return []
        premises = (
            bool(re.search(r"\b(?:any (?:thrown )?error|400|422|pars(?:e|ing)|JSON)\b", text, re.I)),
            bool(
                re.search(r"\b(?:both|two|second)\b", text, re.I)
                and re.search(r"\b(?:count|first.message)\b", text, re.I)
            ),
        )
        key = (path, start, end, retry, concurrent, premises)
        if key in self._cache:
            return deepcopy(self._cache[key])
        if self.checks >= MAX_CHECKS:
            return []
        self.checks += 1
        results = []
        try:
            _, root = self.loader._read(path)
            facts = i._file_facts(root)
            if facts[4]:
                return []
            if retry and not facts[1]["Error"] and not facts[2]["Error"] and "Error" not in facts[3]:
                results += self._retry(path, root, start, end, text)
            if concurrent:
                results += self._duplicate(path, root, start, end)
                results += self._count(path, root, start, end, text)
        except (
            AttributeError,
            KeyError,
            TypeError,
            ValueError,
            UnicodeError,
            RecursionError,
            RuntimeError,
            OSError,
            zipfile.BadZipFile,
        ):
            return []
        self._cache[key] = deepcopy(results[:MAX_RECORDS])
        return results[:MAX_RECORDS]

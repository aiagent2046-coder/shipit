"""Source-bound counterevidence for individual premises, never whole findings.

This deliberately small grammar links the cited operation to the relevant guard
or consumer. Nearby observations alone cannot contradict a composite claim.
Only source syntax is inspected; no uploaded module, provider or schema runs.
"""

from __future__ import annotations

from copy import deepcopy
import re
import zipfile

from app.scan import guard_context as g
from app.scan import imported_error_context as imported
from app.scan import source_limit_context as limits
from app.scan.consequence_evidence import _function, _loc, _narrative

FACT_KIND = "fact_input_count_unbounded"
INTL_KIND = "local_intl_error_handling_absent"
EMPTY_KIND = "empty_string_schema_guard_absent"
MAX_CHECKS = 40
MAX_RECORDS = 8
CLAIMS = {
    FACT_KIND: "The cited query result reaches the recorded fact-block consumer without a collection-count cap.",
    INTL_KIND: "The cited local timezone-helper call has no source handler for its Intl constructor exception.",
    EMPTY_KIND: "The cited parsed string field reaches its validator without a preceding nonempty schema guard.",
}
BOUNDARY = (
    "Only this recorded source premise is assessed; the whole finding is not dismissed. "
    "Runtime bindings, other operations and paths, data volume, token/byte totals, billing, "
    "authorization policy and harmful outcomes remain unverified."
)


def _selected(finding):
    text = _narrative(finding)
    kinds = []
    if (
        re.search(r"\b(?:facts?|agent_context)\b", text, re.I)
        and re.search(r"\b(?:unbounded|entire|all facts|no (?:row )?limit|not limit|without.*cap)\b", text, re.I)
        and re.search(r"\b(?:prompt|Claude|model|injected|prepended|sanitizeFacts|fact.block)\b", text, re.I)
    ):
        kinds.append(FACT_KIND)
    if re.search(r"\b(?:Intl|time[ _-]?zone|DateTimeFormat)\b", text, re.I) and re.search(
        r"\b(?:exception|error.handling|unhandled|try|catch)\b", text, re.I
    ):
        kinds.append(INTL_KIND)
    if re.search(r"\bempty.string\b|\bnonempty\b", text, re.I):
        kinds.append(EMPTY_KIND)
    return kinds


def _result(kind, detail, binding=None, **extra):
    record = {
        "kind": kind,
        "claim": CLAIMS[kind],
        "result": "not_checked",
        "whole_finding": False,
        "method": "source_ast",
        "detail": detail + " " + BOUNDARY,
        **extra,
    }
    if binding:
        record.update({k: binding[k] for k in ("file", "line_start", "line_end", "source_sha256")})
        record["source_binding"] = binding
    return record


def _overlap(node, start, end):
    return bool(node and g._line(node) <= end and start <= node.end_point[0] + 1)


def _at_span(nodes, location):
    span = location.get("span") if isinstance(location, dict) else None
    return next((n for n in nodes if [n.start_byte, n.end_byte] == span), None)


def _value_references(nodes, name):
    return [
        n
        for n in limits._references(nodes, name)
        if not (n.parent.type == "variable_declarator" and n.parent.child_by_field_name("name") == n)
        and not (n.parent.type == "pair_pattern" and n.parent.child_by_field_name("value") == n)
        and not (
            n.parent.type in {"required_parameter", "optional_parameter"}
            and n.parent.child_by_field_name("pattern") == n
        )
        and not (n.parent.type in g._FUNCTIONS and n.parent.child_by_field_name("name") == n)
    ]


def _input_identifier(node):
    node = g._unwrap(node)
    if node and node.type == "binary_expression" and g._text(node.child_by_field_name("operator")) == "??":
        right = g._unwrap(node.child_by_field_name("right"))
        if not right or right.type != "array" or g._children(right):
            return None
        node = g._unwrap(node.child_by_field_name("left"))
    return node if g._name(node) else None


def _direct_consumer(call, body):
    """A direct call can contribute to a same-block concatenated string value."""
    node = call
    while node and node.parent != body:
        node = node.parent
        if node is None or node.type not in {
            "parenthesized_expression",
            "binary_expression",
            "variable_declarator",
            "lexical_declaration",
        }:
            return False
        if node.type == "binary_expression" and g._text(node.child_by_field_name("operator")) != "+":
            return False
    return bool(node and node.type == "lexical_declaration" and any(n.type == "const" for n in node.children))


def _query_result(body, name):
    """Direct const {data: x} = await client.from(...).select(...).eq/order(...)."""
    for statement in g._children(body):
        if statement.type != "lexical_declaration" or not any(c.type == "const" for c in statement.children):
            continue
        for dec in g._children(statement):
            pattern = dec.child_by_field_name("name")
            if not pattern or pattern.type != "object_pattern":
                continue
            parts = g._children(pattern)
            if len(parts) != 1 or parts[0].type != "pair_pattern":
                continue
            pair = parts[0]
            if g._text(pair.child_by_field_name("key")) != "data" or g._name(pair.child_by_field_name("value")) != name:
                continue
            value = dec.child_by_field_name("value")
            if not value or value.type != "await_expression" or len(g._children(value)) != 1:
                continue
            current, methods = g._unwrap(g._children(value)[0]), []
            for _ in range(12):
                if not current or current.type != "call_expression" or limits._optional(current):
                    break
                member = g._member(current.child_by_field_name("function"))
                if not member:
                    break
                method = g._text(member.child_by_field_name("property"))
                args = g._children(current.child_by_field_name("arguments"))
                if method == "from":
                    if (
                        g._name(member.child_by_field_name("object"))
                        and len(args) == 1
                        and g._literal(args[0]) is not None
                        and methods.count("select") == 1
                    ):
                        return dec
                    break
                if method not in {"select", "eq", "order", "limit", "range"}:
                    break
                methods.append(method)
                current = g._unwrap(member.child_by_field_name("object"))
    return None


def _single_parameter(fn):
    params = g._children(fn.child_by_field_name("parameters"))
    if len(params) != 1 or params[0].child_by_field_name("value"):
        return ""
    return limits._parameter_name(params[0])


def _primitive_string(node):
    return bool(
        node
        and node.type == "string"
        and all(n.type in {"string_fragment", "escape_sequence"} for n in node.named_children)
    )


def _string_expression(node, substitution):
    """String literals, concatenation and templates with checked interpolations."""
    node = g._unwrap(node)
    if not node:
        return False
    if _primitive_string(node):
        return True
    if node.type == "binary_expression" and g._text(node.child_by_field_name("operator")) == "+":
        return _string_expression(node.child_by_field_name("left"), substitution) and _string_expression(
            node.child_by_field_name("right"), substitution
        )
    if node.type != "template_string":
        return False
    for child in g._children(node):
        if child.type in {"string_fragment", "escape_sequence"}:
            continue
        if child.type != "template_substitution" or len(g._children(child)) != 1:
            return False
        if not substitution(g._unwrap(g._children(child)[0])):
            return False
    return True


def _render_helper(fn):
    """One optional empty return and a direct template/map/join renderer."""
    if limits._optional(fn):
        return None
    name = _single_parameter(fn)
    if not name or any(n.type in {"async", "*"} for n in fn.children):
        return None
    statements = g._children(fn.child_by_field_name("body"))
    if len(statements) not in {1, 2} or statements[-1].type != "return_statement":
        return None
    allowed = set()
    if len(statements) == 2:
        guard = statements[0]
        condition = g._unwrap(guard.child_by_field_name("condition"))
        if not g._exit(guard) or not condition or condition.type != "unary_expression":
            return None
        member = g._member(condition.child_by_field_name("argument"), "length")
        if (
            g._text(condition.child_by_field_name("operator")) != "!"
            or not member
            or g._name(member.child_by_field_name("object")) != name
        ):
            return None
        returned = guard.child_by_field_name("consequence")
        if returned.type == "statement_block":
            returned = g._children(returned)[0]
        if len(g._children(returned)) != 1 or g._literal(g._children(returned)[0]) != "":
            return None
        allowed.add(member.child_by_field_name("object"))
    maps = []

    def substitution(node):
        mapped, join_args = g._method(node, "join")
        receiver, map_args = g._method(mapped, "map")
        if (
            g._name(receiver) != name
            or len(join_args) != 1
            or not _primitive_string(join_args[0])
            or len(map_args) != 1
            or map_args[0].type != "arrow_function"
        ):
            return False
        callback = map_args[0]
        param = g._name(callback.child_by_field_name("parameter")) or _single_parameter(callback)
        if not param or any(n.type == "async" for n in callback.children):
            return False
        if not _string_expression(callback.child_by_field_name("body"), lambda n: g._name(n) == param):
            return False
        allowed.add(receiver)
        maps.append(mapped)
        return True

    returned = g._children(statements[-1])
    if len(returned) != 1 or not _string_expression(returned[0], substitution) or len(maps) != 1:
        return None
    refs = _value_references(list(g._walk(fn)), name)
    if any(n not in allowed for n in refs):
        return None
    return {"return": _loc(statements[-1]), "mapped_input": _loc(maps[0])}


class SourceClaimVerifier(limits.SourceLimitVerifier):
    def _fact_input(self, path, root, facts, fn, nodes, start, end):
        body = fn.child_by_field_name("body")
        records = []
        for observation in self._collection(path, root, facts, fn, nodes):
            if observation.get("result") != "observed":
                continue
            bound = observation["source_binding"]
            dec = _at_span(nodes, bound["caller_result"])
            call = _at_span(nodes, bound["call"])
            input_arg = _at_span(nodes, bound["input_argument"])
            input_id = _input_identifier(input_arg)
            input_name = g._name(input_id)
            name = g._name(dec.child_by_field_name("name")) if dec else ""
            if not name or not input_name or facts[2][input_name] != 1:
                continue
            query = _query_result(body, input_name)
            if (
                not query
                or query.end_byte >= dec.start_byte
                or not (_overlap(query, start, end) or _overlap(call, start, end))
            ):
                continue
            refs = _value_references(nodes, name)
            if len(refs) != 1:
                continue
            ref = refs[0]
            args_node = ref.parent
            consumer = args_node.parent if args_node and args_node.type == "arguments" else None
            if (
                not consumer
                or consumer.type != "call_expression"
                or consumer.start_byte <= dec.end_byte
                or g._children(args_node) != [ref]
                or not _direct_consumer(consumer, body)
                or limits._optional(consumer)
            ):
                continue
            if [r for r in _value_references(nodes, input_name) if r.start_byte < consumer.start_byte] != [input_id]:
                continue
            consumer_name = g._name(consumer.child_by_field_name("function"))
            matches = [i for i in facts[0] if i["name"] == consumer_name]
            if len(matches) != 1 or not imported._unambiguous(root, consumer_name, facts=facts):
                continue
            target, resolution = self.loader._resolve(path, matches[0]["specifier"])
            _, target_root, target_facts = self._file(target)
            helper = imported._exports(target_root).get(consumer_name)
            if (
                not helper
                or target_facts[4]
                or not self._native(target, target_root, target_facts, {"Array", "Object"})
            ):
                continue
            self._nodes(helper)
            renderer = _render_helper(helper)
            if not renderer:
                continue
            records.append(
                _result(
                    FACT_KIND,
                    "The cited query-result binding enters the capped helper and its unchanged returned collection "
                    "is the sole array argument of the recorded direct fact-block renderer. This contradicts an "
                    "uncapped fact count on that source path. The preceding database read is not capped by this "
                    "downstream slice; no total prompt-size or billing conclusion follows.",
                    {
                        **bound,
                        "query_result": _loc(query),
                        "consumer_call": _loc(consumer),
                        "consumer_import": _loc(matches[0]["node"]),
                        "consumer_resolution": resolution,
                        "consumer": {**self.loader._binding(target, helper), **renderer},
                        "database_read_bound": "not_checked",
                        "total_prompt_bound": "not_checked",
                    },
                    result="contradicted",
                )
            )
        return records

    def _local_calls(self, root, facts, fn, nodes, start, end):
        for call in nodes:
            if call.type != "call_expression" or not _overlap(call, start, end) or limits._optional(call):
                continue
            if imported._owner(call) != fn:
                continue
            name = g._name(call.child_by_field_name("function"))
            if not name or not imported._unambiguous(root, name, declaration=True, facts=facts):
                continue
            helpers = [
                n
                for n in g._children(root)
                if n.type == "function_declaration" and g._name(n.child_by_field_name("name")) == name
            ]
            if len(helpers) != 1 or helpers[0].end_byte >= fn.start_byte:
                continue
            self._call()
            yield call, helpers[0]

    def _intl(self, path, root, facts, call, helper):
        if facts[1]["Intl"] or facts[2]["Intl"] or "Intl" in facts[3]:
            return None
        file_nodes = self._nodes(root, imported.MAX_NODES)
        if any(limits._references(file_nodes, name) for name in ("globalThis", "window", "self", "global")):
            return None
        for ref in limits._references(file_nodes, "Intl"):
            member = g._member(ref.parent, "DateTimeFormat")
            if not member or member.child_by_field_name("object") != ref or member.parent.type != "new_expression":
                return None
        parameter = _single_parameter(helper)
        if not parameter or any(n.type in {"async", "*"} for n in helper.children):
            return None
        statements = g._children(helper.child_by_field_name("body"))
        if len(statements) != 1 or statements[0].type != "try_statement":
            return None
        guarded = statements[0]
        if guarded.child_by_field_name("finalizer"):
            return None
        block = g._children(guarded.child_by_field_name("body"))
        handler = guarded.child_by_field_name("handler")
        caught = g._children(handler.child_by_field_name("body")) if handler else []
        if (
            handler
            and handler.child_by_field_name("parameter") is not None
            and not g._name(handler.child_by_field_name("parameter"))
        ):
            return None
        if (
            len(block) != 2
            or block[0].type != "expression_statement"
            or len(g._children(block[0])) != 1
            or block[1].type != "return_statement"
            or [n.type for n in g._children(block[1])] != ["true"]
            or len(caught) != 1
            or caught[0].type != "return_statement"
            or [n.type for n in g._children(caught[0])] != ["false"]
        ):
            return None
        constructor = g._children(block[0])[0]
        if constructor.type != "new_expression" or limits._optional(constructor):
            return None
        member = g._member(constructor.child_by_field_name("constructor"), "DateTimeFormat")
        if not member or g._name(member.child_by_field_name("object")) != "Intl":
            return None
        args = g._children(constructor.child_by_field_name("arguments"))
        pairs = limits._object_pairs(args[1]) if len(args) == 2 else None
        if (
            len(args) != 2
            or not _primitive_string(args[0])
            or pairs is None
            or set(pairs) != {"timeZone"}
            or g._name(pairs["timeZone"].child_by_field_name("value")) != parameter
            or len(g._children(call.child_by_field_name("arguments"))) != 1
        ):
            return None
        return _result(
            INTL_KIND,
            "The cited direct local helper executes its Intl.DateTimeFormat constructor inside a try whose "
            "sole catch statement returns false. There is no rethrow or finally in this helper. Only absence "
            "of this source error boundary is contradicted; accepted timezone values and caller enforcement "
            "are not established.",
            {
                **self.loader._binding(path, call),
                "callee": self.loader._binding(path, helper),
                "constructor": _loc(constructor),
                "catch": _loc(handler),
                "caught_return": _loc(caught[0]),
            },
            result="contradicted",
        )

    def _nonempty(self, path, root, facts, fn, nodes, call):
        args = g._children(call.child_by_field_name("arguments"))
        field = g._member(args[0]) if len(args) == 1 else None
        data = g._member(field.child_by_field_name("object"), "data") if field else None
        parsed = g._name(data.child_by_field_name("object")) if data else ""
        key = limits._key(field.child_by_field_name("property")) if field else None
        if not parsed or not key or facts[2][parsed] != 1:
            return None
        body = fn.child_by_field_name("body")
        constants = g._consts(body)
        dec = constants.get(parsed)
        if dec is None or limits._optional(dec.child_by_field_name("value")):
            return None
        schema, arguments = g._method(dec.child_by_field_name("value"), "safeParse") if dec else (None, [])
        schema_name = g._name(schema)
        if (
            len(arguments) != 1
            or not schema_name
            or not imported._unambiguous(root, schema_name, declaration=True, facts=facts)
        ):
            return None
        schema_dec = g._consts(root).get(schema_name)
        if not schema_dec or schema_dec.end_byte >= fn.start_byte:
            return None
        schema_refs = _value_references(self._nodes(root, imported.MAX_NODES), schema_name)
        if schema_refs != [schema]:
            return None
        refs = _value_references(nodes, parsed)
        if any(n.parent.type != "member_expression" or n.parent.child_by_field_name("object") != n for n in refs):
            return None
        guard = next(
            (
                n
                for n in g._children(body)
                if n.start_byte > dec.end_byte
                and n.end_byte < call.start_byte
                and g._exit(n)
                and self._failed_parse_guard(n, parsed)
            ),
            None,
        )
        if guard is None:
            return None
        # Mutating/escaping parsed.data through another property must abstain.
        for ref in refs:
            member = ref.parent
            if g._text(member.child_by_field_name("property")) != "data":
                continue
            if member.start_byte <= guard.end_byte:
                return None
            parent = member.parent
            if not g._member(parent) or parent.child_by_field_name("object") != member:
                return None
            if (
                parent.parent
                and parent.parent.type
                in {
                    "assignment_expression",
                    "augmented_assignment_expression",
                    "update_expression",
                }
                and parent.parent.child_by_field_name("left") == parent
            ):
                return None
        shape = self._object_shape(schema_dec.child_by_field_name("value"), root, facts)
        if shape is None:
            return None
        pairs = limits._object_pairs(shape)
        pair = pairs.get(key) if pairs is not None else None
        minimum = self._minimum_string(pair.child_by_field_name("value"), root, facts) if pair else None
        if minimum is None:
            return None
        return _result(
            EMPTY_KIND,
            "The exact parsed field passed to the cited validator belongs to a literal Zod string schema "
            "with a positive minimum length, and a same-block failed-safeParse return precedes this use. "
            "A field-level optional wrapper allows omission, not an empty string. This contradicts only "
            "absence of the recorded empty-string guard, not whitespace policy or general input validity.",
            {
                **self.loader._binding(path, call),
                "parse": _loc(dec),
                "failed_parse_return": _loc(guard),
                "schema": _loc(schema_dec),
                "field_schema": _loc(pair),
                "minimum_length": minimum,
                "runtime_schema_identity": "not_checked",
            },
            result="contradicted",
        )

    @staticmethod
    def _failed_parse_guard(guard, name):
        condition = g._unwrap(guard.child_by_field_name("condition"))
        if (
            not condition
            or condition.type != "unary_expression"
            or g._text(condition.child_by_field_name("operator")) != "!"
        ):
            return False
        member = g._member(condition.child_by_field_name("argument"), "success")
        return bool(member and g._name(member.child_by_field_name("object")) == name)

    def _zod_name(self, node, root, facts):
        name = g._name(node)
        if not (
            name
            and imported._unambiguous(root, name, facts=facts)
            and any(i["name"] == name and i["specifier"] == "zod" for i in facts[0])
        ):
            return False
        for ref in limits._references(self._nodes(root, imported.MAX_NODES), name):
            if ref.parent.type == "import_specifier":
                continue
            member = g._member(ref.parent)
            if (
                not member
                or member.child_by_field_name("object") != ref
                or member.parent.type != "call_expression"
                or member.parent.child_by_field_name("function") != member
            ):
                return False
        return True

    def _object_shape(self, node, root, facts):
        if limits._optional(node):
            return None
        for _ in range(8):
            receiver, args = g._method(node, "object")
            if self._zod_name(receiver, root, facts) and len(args) == 1 and args[0].type == "object":
                return args[0]
            member = (
                g._member(node.child_by_field_name("function")) if node and node.type == "call_expression" else None
            )
            method = g._text(member.child_by_field_name("property")) if member else ""
            args = g._children(node.child_by_field_name("arguments")) if member else []
            if method in {"strict", "strip"} and not args:
                node = member.child_by_field_name("object")
                continue
            if method != "refine" or len(args) not in {1, 2} or args[0].type != "arrow_function":
                return None
            callback = args[0]
            expression = callback.child_by_field_name("body")
            if not expression or any(
                n.type
                not in {
                    "parenthesized_expression",
                    "binary_expression",
                    "identifier",
                    "member_expression",
                    "property_identifier",
                    "undefined",
                    "null",
                    "true",
                    "false",
                    "number",
                    "string",
                    "string_fragment",
                }
                for n in g._walk(expression)
            ):
                return None
            if len(args) == 2:
                options = limits._object_pairs(args[1])
                if options is None or any(
                    not _primitive_string(p.child_by_field_name("value")) for p in options.values()
                ):
                    return None
            node = member.child_by_field_name("object")
        return None

    def _minimum_string(self, node, root, facts):
        if limits._optional(node):
            return None
        minimum = None
        optional = False
        for _ in range(8):
            receiver, args = g._method(node, "string")
            if self._zod_name(receiver, root, facts) and not args:
                return minimum
            member = (
                g._member(node.child_by_field_name("function")) if node and node.type == "call_expression" else None
            )
            method = g._text(member.child_by_field_name("property")) if member else ""
            args = g._children(node.child_by_field_name("arguments")) if member else []
            if method == "optional" and not args and not optional:
                optional = True
            elif method in {"min", "max"} and len(args) == 1 and limits._integer(args[0]) is not None:
                if method == "min":
                    value = limits._integer(args[0])
                    minimum = max(minimum or 0, value) or None
            else:
                return None
            node = member.child_by_field_name("object")
        return None

    def checks_for(self, finding):
        kinds = _selected(finding)
        if not kinds:
            return []
        path, start, end = finding.get("file"), finding.get("line_start"), finding.get("line_end")
        if not imported._source_path(path) or type(start) is not int or type(end) is not int or not 1 <= start <= end:
            return [_result(k, "Unsupported source path or coordinates.") for k in kinds]
        key = (path, start, end, tuple(kinds))
        if key in self._results:
            return deepcopy(self._results[key])
        if self.checks >= MAX_CHECKS:
            return [_result(k, "Per-audit source-claim assessment budget exhausted.") for k in kinds]
        self.checks += 1
        records = []
        binding = None
        try:
            data, root, facts = self._file(path)
            if end > len(data.splitlines()):
                raise ValueError("Source coordinates exceed the checked file")
            fn = _function(root, start, end)
            if fn is None or facts[4]:
                raise ValueError("No unambiguous supported function at the source anchor")
            binding = self.loader._binding(path, fn)
            nodes = self._nodes(fn)
            if FACT_KIND in kinds:
                records += self._fact_input(path, root, facts, fn, nodes, start, end)
            if INTL_KIND in kinds or EMPTY_KIND in kinds:
                for call, helper in self._local_calls(root, facts, fn, nodes, start, end):
                    if INTL_KIND in kinds:
                        record = self._intl(path, root, facts, call, helper)
                        if record:
                            records.append(record)
                    if EMPTY_KIND in kinds:
                        record = self._nonempty(path, root, facts, fn, nodes, call)
                        if record:
                            records.append(record)
                    if len(records) >= MAX_RECORDS:
                        break
            records = records[:MAX_RECORDS]
            records.extend(
                _result(k, "No source-bound counterevidence within the supported direct path.", binding)
                for k in kinds
                if not any(r["kind"] == k for r in records)
            )
        except (
            ValueError,
            TypeError,
            AttributeError,
            KeyError,
            UnicodeError,
            RecursionError,
            RuntimeError,
            OSError,
            zipfile.BadZipFile,
        ) as exc:
            detail = str(exc) if type(exc) is ValueError else "Source binding could not be checked"
            records.extend(_result(k, detail, binding) for k in kinds if not any(r["kind"] == k for r in records))
        self._results[key] = deepcopy(records)
        return records

"""Bounded numeric and one-hop collection limit observations, never dispositions.

Only source syntax is inspected. Findings, consequences and scores are unchanged.
The private loader instance owns separate ZIP/read/parse budgets for this check.
"""

from __future__ import annotations

from copy import deepcopy
import re
import zipfile

from app.scan import guard_context as g
from app.scan import imported_error_context as imported
from app.scan.consequence_evidence import _function, _loc, _narrative

MAX_CHECKS = 40
MAX_CALLS = 128
MAX_TOTAL_CALLS = 512
MAX_RECORDS = 8
MAX_LOCALS = 128
MAX_FUNCTION_NODES = 16_000
MAX_WORK_NODES = 400_000
MAX_BOUND = 1_000_000
NUMERIC_KIND = "finite_clamp_rpc_argument"
COLLECTION_KIND = "imported_collection_return_cap"
_NATIVE_READ_CALLS = {
    "Number": {"isFinite", "isNaN", "isInteger", "isSafeInteger", "parseInt", "parseFloat"},
    "Math": {
        "abs",
        "acos",
        "acosh",
        "asin",
        "asinh",
        "atan",
        "atanh",
        "atan2",
        "cbrt",
        "ceil",
        "clz32",
        "cos",
        "cosh",
        "exp",
        "expm1",
        "floor",
        "fround",
        "hypot",
        "imul",
        "log",
        "log1p",
        "log2",
        "log10",
        "max",
        "min",
        "pow",
        "random",
        "round",
        "sign",
        "sin",
        "sinh",
        "sqrt",
        "tan",
        "tanh",
        "trunc",
    },
    "Array": {"isArray", "from", "of"},
    "Object": {
        "keys",
        "values",
        "entries",
        "fromEntries",
        "hasOwn",
        "getOwnPropertyNames",
        "getOwnPropertySymbols",
        "getOwnPropertyDescriptor",
        "getOwnPropertyDescriptors",
        "is",
    },
}
_PROTOTYPE_NAMES = {
    "__proto__",
    "constructor",
    "__defineGetter__",
    "__defineSetter__",
    "hasOwnProperty",
    "__lookupGetter__",
    "__lookupSetter__",
    "isPrototypeOf",
    "propertyIsEnumerable",
    "toString",
    "toLocaleString",
    "valueOf",
}
CLAIMS = {
    NUMERIC_KIND: "An immutable finite clamp result is the recorded direct RPC-syntax argument.",
    COLLECTION_KIND: "The recorded direct imported helper call has a return-chain slice and a bound cap argument.",
}
LIMITS = (
    "Source context only; the finding, compound premises and harmful outcomes remain unverified. "
    "Only recorded bindings and direct source paths were checked; aliases, runtime builtin or module "
    "replacement, other callers, other operations and deferred effects are not resolved. A downstream "
    "collection slice does not bound the preceding database query, prove token/byte limits, or establish "
    "which data reaches a model. Missing observations do not establish missing guards."
)


def _selected(finding):
    text = _narrative(finding)
    kinds = []
    if re.search(r"\b(?:limits?|negative|zero|finite|clamp\w*|range)\b", text, re.I):
        kinds.append(NUMERIC_KIND)
    if re.search(
        r"\b(?:facts?|records?|rows?|collection\w*|arrays?|context|prompt\w*|size|count|unbounded|sanitize\w*)\b",
        text,
        re.I,
    ):
        kinds.append(COLLECTION_KIND)
    return kinds


def _result(kind, detail, **extra):
    return {
        "kind": kind,
        "claim": CLAIMS[kind],
        "result": "not_checked",
        "scope": "bounded_source_context",
        "detail": detail + " " + LIMITS,
        **extra,
    }


def _statement(node, body):
    """Only direct statement evaluation, excluding conditions/callbacks/nested blocks."""
    allowed = {
        "parenthesized_expression",
        "await_expression",
        "variable_declarator",
        "lexical_declaration",
        "expression_statement",
        "return_statement",
    }
    current = node
    while current and current.parent != body:
        current = current.parent
        if current is None or current.type not in allowed:
            return None
    return current


def _references(nodes, name):
    return [n for n in nodes if g._name(n) == name or n.type == "shorthand_property_identifier" and g._text(n) == name]


def _native_free(root, facts, names):
    _, imports, bindings, conflicting, dynamic = facts
    if dynamic:
        return False
    # Global-object aliases/computed accesses can visibly replace a builtin
    # without mentioning its identifier. This grammar does not resolve them.
    if any(_references(g._walk(root), name) for name in ("globalThis", "window", "self", "global")):
        return False
    for name in names:
        if imports[name] or bindings[name] or name in conflicting:
            return False
        # Reject passing a builtin object by alias, including Object.assign and
        # defineProperty targets. Direct property reads/calls remain syntax only.
        for node in _references(g._walk(root), name):
            parent = node.parent
            if not (
                parent
                and parent.type == "member_expression"
                and parent.child_by_field_name("object") == node
                and parent.parent
                and parent.parent.type == "call_expression"
                and parent.parent.child_by_field_name("function") == parent
                and g._text(parent.child_by_field_name("property")) in _NATIVE_READ_CALLS[name]
            ):
                return False
    return True


def _key(node):
    if node and node.type in {"property_identifier", "identifier"}:
        value = g._text(node)
        return value if len(value) <= 128 else None
    return None


def _object_pairs(node):
    if not node or node.type != "object":
        return None
    result = {}
    for part in g._children(node):
        if part.type != "pair":
            return None
        key = _key(part.child_by_field_name("key"))
        if not key or key in result:
            return None
        result[key] = part
    return result


def _integer(node):
    value = g._number(node)
    return int(value) if value is not None and 0 <= value <= MAX_BOUND and value.is_integer() else None


def _optional(node):
    return any(n.type in {"optional_chain", "?."} for current in g._walk(node) for n in current.children)


def _parameter_name(node):
    return g._name(node.child_by_field_name("pattern")) if node else ""


def _empty_object(node):
    return node is not None and node.type == "object" and not g._children(node)


class SourceLimitVerifier:
    def __init__(self, archive):
        self.archive = archive
        self.loader = imported.ImportedErrorVerifier(archive)
        self.checks = self.calls = 0
        self.remaining_work = MAX_WORK_NODES
        self._facts = {}
        self._native_cache = {}
        self._results = {}

    def _nodes(self, node, maximum=None):
        maximum = MAX_FUNCTION_NODES if maximum is None else maximum
        result = []
        for item in g._walk(node):
            self.remaining_work -= 1
            if self.remaining_work < 0 or len(result) >= maximum:
                raise ValueError("Source limit syntax work budget exhausted")
            result.append(item)
        return result

    def _file(self, path):
        data, root = self.loader._read(path)
        if path not in self._facts:
            self._nodes(root, imported.MAX_NODES)
            self._facts[path] = imported._file_facts(root)
        return data, root, self._facts[path]

    def _native(self, path, root, facts, names):
        key = (path, tuple(sorted(names)))
        if key not in self._native_cache:
            self._native_cache[key] = _native_free(root, facts, names)
        return self._native_cache[key]

    def _numeric(self, path, root, facts, fn, nodes):
        body = fn.child_by_field_name("body")
        if not body or body.type != "statement_block" or not self._native(path, root, facts, {"Number", "Math"}):
            return []
        constants = g._consts(body)
        if len(constants) > MAX_LOCALS:
            raise ValueError("Per-function source limit local-binding budget exhausted")
        file_bindings = facts[2]
        records, local_calls = [], 0
        for dec in constants.values():
            check = g._clamp(dec, file_bindings, constants, {"Number", "Math"})
            if not check or not check["fallback_within_bounds"] or _optional(dec):
                continue
            self.remaining_work -= len(nodes)
            if self.remaining_work < 0:
                raise ValueError("Source limit syntax work budget exhausted")
            result_name = g._name(dec.child_by_field_name("name"))
            value = g._unwrap(dec.child_by_field_name("value"))
            finite = g._native(value.child_by_field_name("condition"), "Number", "isFinite")
            raw_name = g._name(finite[0])
            outer = g._native(value.child_by_field_name("consequence"), "Math", "min")
            inner = g._native(outer[1], "Math", "max")
            bounds = [g._number(inner[0]), g._number(outer[0]), g._number(value.child_by_field_name("alternative"))]
            if any(abs(n) > MAX_BOUND for n in bounds):
                continue
            for call in nodes:
                if call.type != "call_expression":
                    continue
                receiver, args = g._method(call, "rpc")
                if (
                    receiver is None
                    or not g._name(receiver)
                    or len(args) != 2
                    or not _statement(call, body)
                    or call.start_byte <= dec.end_byte
                ):
                    continue
                local_calls += 1
                if local_calls > MAX_CALLS:
                    raise ValueError("Per-anchor source limit call budget exhausted")
                self._call()
                if any(n.type in {"optional_chain", "?."} for n in call.children):
                    continue
                pairs = _object_pairs(args[1])
                if pairs is None:
                    continue
                for key, pair in pairs.items():
                    if g._name(pair.child_by_field_name("value")) != result_name:
                        continue
                    records.append(
                        _result(
                            NUMERIC_KIND,
                            "The finite branch, literal fallback and same-block RPC argument "
                            "share the recorded immutable binding.",
                            result="observed",
                            source_binding={
                                **self.loader._binding(path, fn),
                                "raw_declaration": _loc(constants[raw_name]),
                                "clamp_declaration": _loc(dec),
                                "rpc_call": _loc(call),
                                "argument": {**_loc(pair), "property": key},
                                "binding": result_name,
                                "lower": bounds[0],
                                "upper": bounds[1],
                                "fallback": bounds[2],
                                "runtime_api_identity": "not_checked",
                            },
                        )
                    )
                    if len(records) >= MAX_RECORDS:
                        return records
        return records

    def _call(self):
        if self.calls >= MAX_TOTAL_CALLS:
            raise ValueError("Per-audit source limit call budget exhausted")
        self.calls += 1

    def _cap(self, target, root, facts, fn, args):
        body = fn.child_by_field_name("body")
        if (
            not body
            or body.type != "statement_block"
            or any(n.type in {"async", "*"} for n in fn.children)
            or not self._native(target, root, facts, {"Array", "Object"})
        ):
            return None
        nodes = self._nodes(fn)
        local_bindings = g._bindings(nodes)
        params = g._children(fn.child_by_field_name("parameters"))
        if len(params) != 2 or len(args) not in {1, 2}:
            return None
        first, options = map(_parameter_name, params)
        if (
            not first
            or not options
            or local_bindings[first] != 1
            or local_bindings[options] != 1
            or not _empty_object(params[1].child_by_field_name("value"))
        ):
            return None
        statements = g._children(body)
        if (
            not statements
            or statements[-1].type != "return_statement"
            or any(
                s.type != "lexical_declaration" or not any(c.type == "const" for c in s.children)
                for s in statements[:-1]
            )
        ):
            return None
        returns = g._children(statements[-1])
        if len(returns) != 1:
            return None
        # Only a direct map/filter chain around one slice; no concat, flatMap,
        # conditional return, alias return or callback-return path is inferred.
        chain, current = [], g._unwrap(returns[0])
        for _ in range(12):
            if not current or current.type != "call_expression":
                break
            if any(n.type in {"optional_chain", "?."} for n in current.children):
                return None
            member = g._member(current.child_by_field_name("function"))
            if not member:
                return None
            method = g._text(member.child_by_field_name("property"))
            call_args = g._children(current.child_by_field_name("arguments"))
            if method not in {"map", "filter", "slice"} or (method != "slice" and len(call_args) != 1):
                return None
            chain.append((current, method, call_args))
            current = g._unwrap(member.child_by_field_name("object"))
        else:
            return None
        if current and current.type == "binary_expression" and g._text(current.child_by_field_name("operator")) == "??":
            right = current.child_by_field_name("right")
            if right.type != "array" or g._children(right):
                return None
            current = g._unwrap(current.child_by_field_name("left"))
        if g._name(current) != first:
            return None
        slices = [(call, call_args) for call, method, call_args in chain if method == "slice"]
        if len(slices) != 1:
            return None
        cut, cut_args = slices[0]
        if len(cut_args) != 2 or g._number(cut_args[0]) != 0:
            return None
        cap_name = g._name(cut_args[1])
        constants = g._consts(body)
        dec = constants.get(cap_name)
        if not dec or local_bindings[cap_name] != 1 or dec.end_byte >= statements[-1].start_byte:
            return None
        cap_expr = g._unwrap(dec.child_by_field_name("value"))
        if (
            not cap_expr
            or cap_expr.type != "binary_expression"
            or g._text(cap_expr.child_by_field_name("operator")) != "??"
        ):
            return None
        option = g._member(cap_expr.child_by_field_name("left"))
        option_name = _key(option.child_by_field_name("property")) if option else None
        if (
            not option
            or g._name(option.child_by_field_name("object")) != options
            or not option_name
            or option_name in _PROTOTYPE_NAMES
        ):
            return None
        # The options object is a fresh omitted default or a plain call literal.
        # Passing options elsewhere or aliasing either tracked binding abstains.
        for name, allowed in ((first, {current}), (cap_name, {cut_args[1]})):
            refs = [
                n
                for n in _references(nodes, name)
                if not (
                    n.parent.type in {"required_parameter", "optional_parameter"}
                    and n.parent.child_by_field_name("pattern") == n
                )
                and not (n.parent.type == "variable_declarator" and n.parent.child_by_field_name("name") == n)
            ]
            if any(n not in allowed for n in refs):
                return None
        for node in _references(nodes, options):
            if node.parent.type in {"required_parameter", "optional_parameter"}:
                continue
            member = node.parent
            coalesce = member.parent
            declaration = coalesce.parent if coalesce else None
            if not (
                member.type == "member_expression"
                and member.child_by_field_name("object") == node
                and not member.child_by_field_name("optional_chain")
                and _key(member.child_by_field_name("property")) not in _PROTOTYPE_NAMES
                and coalesce
                and coalesce.type == "binary_expression"
                and g._text(coalesce.child_by_field_name("operator")) == "??"
                and coalesce.child_by_field_name("left") == member
                and declaration
                and declaration.type == "variable_declarator"
                and declaration.child_by_field_name("value") == coalesce
                and declaration in constants.values()
            ):
                return None
        default_expr = cap_expr.child_by_field_name("right")
        default_decl = None
        default = _integer(default_expr)
        if default is None and g._name(default_expr):
            default_name = g._name(default_expr)
            default_decl = g._consts(root).get(default_name)
            if (
                not default_decl
                or facts[2][default_name] != 1
                or facts[1][default_name]
                or default_name in facts[3]
                or default_decl.end_byte >= fn.start_byte
            ):
                return None
            default = _integer(default_decl.child_by_field_name("value"))
        if default is None:
            return None
        value, provenance, override = default, "omitted_options_default", None
        if len(args) == 2:
            pairs = _object_pairs(args[1])
            if pairs is None or any(_integer(p.child_by_field_name("value")) is None for p in pairs.values()):
                return None
            override = pairs.get(option_name)
            value = _integer(override.child_by_field_name("value")) if override else default
            provenance = "explicit_literal_override" if override else "literal_options_default"
        return {
            "callee": self.loader._binding(target, fn),
            "return": _loc(statements[-1]),
            "slice": _loc(cut),
            "cap_declaration": _loc(dec),
            "default_declaration": _loc(default_decl) if default_decl else _loc(default_expr),
            "parameter": option_name,
            "upper": value,
            "argument_mode": provenance,
            "override": _loc(override) if override else None,
            "runtime_array_identity": "not_checked",
        }

    def _collection(self, path, root, facts, fn, nodes):
        body = fn.child_by_field_name("body")
        if not body or body.type != "statement_block" or not self._native(path, root, facts, {"Array", "Object"}):
            return []
        records, examined = [], 0
        constants = g._consts(body)
        if len(constants) > MAX_LOCALS:
            raise ValueError("Per-function source limit local-binding budget exhausted")
        imports = facts[0]
        for dec in constants.values():
            call = g._unwrap(dec.child_by_field_name("value"))
            name = g._name(call.child_by_field_name("function")) if call and call.type == "call_expression" else ""
            matches = [i for i in imports if i["name"] == name]
            if len(matches) != 1 or not imported._unambiguous(root, name, facts=facts):
                continue
            if any(n.type in {"optional_chain", "?."} for n in call.children):
                continue
            examined += 1
            if examined > MAX_CALLS:
                raise ValueError("Per-anchor source limit call budget exhausted")
            self._call()
            result_name = g._name(dec.child_by_field_name("name"))
            if not result_name or facts[2][result_name] != 1:
                continue
            imported_call = matches[0]
            try:
                target, resolution = self.loader._resolve(path, imported_call["specifier"])
                _, target_root, target_facts = self._file(target)
                helper = imported._exports(target_root).get(name)
                if helper is None or target_facts[4]:
                    continue
                args = g._children(call.child_by_field_name("arguments"))
                cap = self._cap(target, target_root, target_facts, helper, args)
                if cap is None:
                    continue
                records.append(
                    _result(
                        COLLECTION_KIND,
                        "The bound call uses a direct return-chain slice cap; preceding query size "
                        "and later consumers are not checked.",
                        result="observed",
                        source_binding={
                            **self.loader._binding(path, fn),
                            "call": _loc(call),
                            "caller_result": _loc(dec),
                            "input_argument": _loc(args[0]),
                            "import": {**_loc(imported_call["node"]), "name": name},
                            "resolution": resolution,
                            **cap,
                        },
                    )
                )
            except ValueError as exc:
                records.append(_result(COLLECTION_KIND, str(exc)))
            if len(records) >= MAX_RECORDS:
                break
        return records

    def checks_for(self, finding):
        kinds = _selected(finding)
        if not kinds:
            return []
        path, start, end = finding.get("file"), finding.get("line_start"), finding.get("line_end")
        if not imported._source_path(path) or type(start) is not int or type(end) is not int or not 1 <= start <= end:
            return [_result(kind, "Unsupported source path or coordinates.") for kind in kinds]
        key = (path, start, end, tuple(kinds))
        if key in self._results:
            return deepcopy(self._results[key])
        if self.checks >= MAX_CHECKS:
            return [_result(kind, "Per-audit source limit check budget exhausted.") for kind in kinds]
        self.checks += 1
        results = []
        try:
            data, root, facts = self._file(path)
            if end > len(data.splitlines()):
                raise ValueError("Source coordinates exceed the checked file")
            fn = _function(root, start, end)
            if fn is None or facts[4]:
                raise ValueError("No unambiguous supported function at the source anchor")
            nodes = self._nodes(fn)
            for kind in kinds:
                records = (
                    self._numeric(path, root, facts, fn, nodes)
                    if kind == NUMERIC_KIND
                    else self._collection(path, root, facts, fn, nodes)
                )
                results.extend(records[:MAX_RECORDS])
                if len(records) >= MAX_RECORDS:
                    results.append(_result(kind, "Source limit output budget reached; remaining paths not checked."))
                if not records:
                    results.append(_result(kind, "No bound limit observation in the supported direct source path."))
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
            reason = str(exc) if type(exc) is ValueError else "Source binding could not be checked"
            results.extend(_result(kind, reason) for kind in kinds if not any(r["kind"] == kind for r in results))
        self._results[key] = deepcopy(results)
        return results

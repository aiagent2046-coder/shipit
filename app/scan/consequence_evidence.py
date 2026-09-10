"""Bounded source context for four frequently overstated consequences.

Free prose selects source observations only. A true local source fact does not
refute a nearby narrative about another target, condition or outcome. This
module therefore never returns ``contradicted`` and never dismisses a finding,
changes its penalty or marks runtime verification as complete. Hashes and
locations are retained instead of source excerpts. No source or model executes.
"""
from __future__ import annotations

import hashlib
from pathlib import PurePosixPath
import re
import stat
import zipfile

from pglast import ast, parse_sql
from pglast.enums import ConstrType
from pglast.parser import ParseError
from tree_sitter import Language, Parser
import tree_sitter_typescript

from app.scan import guard_context as g
from app.scan import react_async_context as react

MAX_FILE_BYTES = 256_000
MAX_TOTAL_BYTES = 2_000_000
MAX_FILES = 64
MAX_CHECKS = 40
MAX_NODES = 40_000


def _narrative(finding):
    values = [finding.get(k) for k in ("title", "explanation", "observation")]
    conditions = finding.get("required_conditions")
    if isinstance(conditions, list):
        values += conditions[:12]
    return "\n".join(v[:8000] for v in values if isinstance(v, str))[:28000]


SOURCE_CLAIMS = {
    "token_write_return_guard": "The recorded local binding has a falsy early return before its later write calls.",
    "react_empty_input_entry_binding": (
        "The same React state has an empty-input return, a clear before await and a native button disabled binding."),
    "discarded_fetch_response": (
        "This handler discards its sole awaited fetch response and has no direct JSON parse call."),
    "duplicate_key_return_branch": "The recorded 23505 error branch returns before later same-table query sites.",
}


def _selected(finding):
    # These broad topic selectors add true source context even when prose is
    # negative, advisory or refers to a different target. They never refute it.
    text = _narrative(finding)
    kinds = []
    if (re.search(r"\b(?:oauth|access[ _-]?token)\b", text, re.I)
            and re.search(r"\b(?:stor\w*|writ\w*|persist\w*|upsert\w*)\b", text, re.I)):
        kinds.append("token_write_return_guard")
    if (re.search(r"\b(?:click|tap|press)\w*\b", text, re.I)
            and re.search(r"\b(?:twice|double[ -]?(?:send|click|submit)|second click|duplicate)\b", text, re.I)
            and re.search(r"\b(?:input|text|message)\b", text, re.I)):
        kinds.append("react_empty_input_entry_binding")
    if re.search(r"\b[A-Za-z_$][\w$]*\s*\.\s*json\s*\(\s*\)", text):
        kinds.append("discarded_fetch_response")
    if (re.search(r"\bduplicate[ -]?(?:key|record|row)|\b23505\b", text, re.I)
            and re.search(r"\b(?:twice|second|repeat\w*|mutual|follow[ -]?up|quer(?:y|ies))\b", text, re.I)):
        kinds.append("duplicate_key_return_branch")
    return list(dict.fromkeys(kinds))


def _result(kind, detail=None, **extra):
    return {"kind": kind, "claim": SOURCE_CLAIMS[kind], "result": "not_checked", "scope": "bounded_source_context",
            "detail": detail or "No unambiguous source observation within this bounded check.", **extra}


def _loc(node):
    return {"line_start": g._line(node), "line_end": node.end_point[0] + 1,
            "span": [node.start_byte, node.end_byte]}


def _own(node):
    return list(g._walk(node, g._SKIP))


def _function(root, start, end):
    candidates = [n for n in g._walk(root) if n.type in g._FUNCTIONS
                  and g._line(n) <= start <= end <= n.end_point[0] + 1]
    if not candidates:
        return None
    fn = min(candidates, key=lambda n: n.end_byte - n.start_byte)
    if any(not (n.start_byte <= fn.start_byte and fn.end_byte <= n.end_byte) for n in candidates):
        return None
    return fn


def _body(fn):
    node = fn.child_by_field_name("body") if fn else None
    return node if node and node.type == "statement_block" else None


def _identifier_negation(node):
    node = g._unwrap(node)
    return (g._name(g._unwrap(node.child_by_field_name("argument")))
            if node and node.type == "unary_expression"
            and g._text(node.child_by_field_name("operator")) == "!" else "")


def _has_assignment(nodes, name, after=0):
    return any(n.start_byte >= after and n.type in {
        "assignment_expression", "augmented_assignment_expression", "update_expression", "for_in_statement"
    } and name in g._bound(n.child_by_field_name("left") or n.child_by_field_name("argument")) for n in nodes)


def _method_calls(nodes, method):
    return [(n, receiver, args) for n in nodes if n.type == "call_expression"
            for receiver, args in [g._method(n, method)] if receiver is not None]


def _plain_return(stmt):
    if not g._exit(stmt):
        return False
    consequence = stmt.child_by_field_name("consequence")
    # A nested function/assignment in the return expression can introduce an
    # alternate effect before the return. Ordinary response helper calls are
    # allowed, but their internal effects are expressly outside the conclusion.
    return not any(n.type in g._FUNCTIONS | {"assignment_expression", "await_expression", "yield_expression"}
                   for n in g._walk(consequence))


def _token_guard(root, fn, start, end):
    body = _body(fn)
    if body is None:
        return None
    own, all_nodes = _own(body), list(g._walk(fn))
    if any(n.type == "finally_clause" or (n.type == "call_expression"
            and g._name(n.child_by_field_name("function")) == "eval") for n in own):
        return None
    declarations = [n for n in all_nodes if n.type == "variable_declarator"]
    candidates = []
    for guard in g._children(body):
        name = _identifier_negation(guard.child_by_field_name("condition")) if guard.type == "if_statement" else ""
        if not name or not _plain_return(guard):
            continue
        # One local binding, no parameter shadow, no reassignment after the
        # return guard, and no closure that captures it.
        bindings = [d for d in declarations if name in g._bound(d.child_by_field_name("name"))]
        shadows = [n for n in all_nodes if (
            n.type == "catch_clause" and name in g._bound(n.child_by_field_name("parameter"))) or (
            n.type in g._FUNCTIONS and name in g._bound(n.child_by_field_name("parameters"))) or (
            n.type in {"class_declaration", "class", "enum_declaration", "internal_module", "import_alias"}
            and g._text(n.child_by_field_name("name")) == name)]
        if len(bindings) != 1 or shadows:
            continue
        if _has_assignment(all_nodes, name, guard.end_byte):
            continue
        if any(n.type in g._FUNCTIONS and n != fn and any(g._name(c) == name for c in g._walk(n))
               for n in all_nodes):
            continue
        # The cited response extraction must write this local from a .json()
        # result before the top-level guard, not an unrelated token variable.
        extracts = []
        for assignment in own:
            if (assignment.type != "assignment_expression"
                    or g._name(assignment.child_by_field_name("left")) != name
                    or assignment.end_byte >= guard.start_byte):
                continue
            value = g._unwrap(assignment.child_by_field_name("right"))
            if (value is None or value.type != "binary_expression"
                    or g._text(value.child_by_field_name("operator")) != "??"
                    or value.child_by_field_name("right").type != "null"):
                continue
            member = g._member(value.child_by_field_name("left"))
            parsed_name = g._name(member.child_by_field_name("object")) if member else ""
            parsed = [d for d in declarations if g._name(d.child_by_field_name("name")) == parsed_name]
            if len(parsed) != 1:
                continue
            parsed_value = parsed[0].child_by_field_name("value")
            if parsed_value is None or parsed_value.type != "await_expression":
                continue
            pieces = g._children(parsed_value)
            receiver, args = g._method(pieces[0] if len(pieces) == 1 else None, "json")
            if not g._name(receiver) or args:
                continue
            # The anchor may span the enclosing token-exchange try block.
            anchored = g._line(parsed[0]) <= start <= end <= parsed[0].end_point[0] + 1
            parent = parsed[0]
            while parent and parent != body:
                if parent.type == "try_statement" and parent.end_byte < guard.start_byte:
                    anchored |= g._line(parent) <= start <= end <= parent.end_point[0] + 1
                parent = parent.parent
            if anchored:
                extracts.append(assignment)
        if len(extracts) != 1:
            continue
        writes = []
        for method in ("insert", "upsert", "update"):
            for call, _, args in _method_calls(own, method):
                if call.start_byte > guard.end_byte and args and any(
                        g._name(n) == name for n in g._walk(args[0])):
                    writes.append({"method": method, **_loc(call)})
        if writes:
            candidates.append({"binding": name, "guard": _loc(guard), "extraction": _loc(extracts[0]),
                               "writes": writes[:8]})
    return candidates[0] if len(candidates) == 1 else None



def _discarded_json(root, fn):
    body = _body(fn)
    if body is None:
        return None
    nodes = _own(body)
    if not react._standard_fetch(root, list(g._walk(root)), react._bindings(list(g._walk(root)))):
        return None
    # Match a response that is never assigned/passed anywhere. Computed method
    # calls, direct json calls and JSON.parse make this narrow absence unknown.
    for n in nodes:
        if n.type != "call_expression":
            continue
        callee = n.child_by_field_name("function")
        if callee and (callee.type == "subscript_expression"
                       or (callee.type == "member_expression"
                           and g._text(callee.child_by_field_name("property")) == "json")
                       or (callee.type == "member_expression"
                           and g._name(callee.child_by_field_name("object")) == "JSON"
                           and g._text(callee.child_by_field_name("property")) == "parse")
                       or g._name(callee) in {"json", "eval"}):
            return None
    fetches = [n for n in nodes if n.type == "call_expression"
               and g._name(n.child_by_field_name("function")) == "fetch"]
    if len(fetches) != 1:
        return None
    call = fetches[0]
    if (call.parent.type != "await_expression" or call.parent.parent.type != "expression_statement"
            or len(g._children(call.parent)) != 1):
        return None
    name = g._name(fn.child_by_field_name("name"))
    if not name and fn.parent and fn.parent.type == "variable_declarator":
        name = g._name(fn.parent.child_by_field_name("name"))
    return {"fetch": _loc(call), "handler": _loc(fn), "handler_name": name, "response_binding": "discarded"}


def _separate_click(root, fn, finding):
    # Reuse the collector's strict imports, no-shadow state and native-control
    # binding rules, then strengthen the observed clear with ordering checks.
    records = list(react._file_records(root, finding["file"], list(g._walk(root)), set()))
    contexts = react.react_async_finding_context(finding, {"react_async": {"records": records}})
    if len(contexts) != 1:
        return None
    context = contexts[0]
    handlers = [n for n in g._walk(root) if n.type in g._FUNCTIONS
                and [n.start_byte, n.end_byte] == context["function_span"]]
    if len(handlers) != 1:
        return None
    fn = handlers[0]
    body = _body(fn)
    all_nodes = list(g._walk(fn))
    statements = g._children(body)
    checks = context["checks"]
    candidates = []
    for clear in checks:
        if clear["kind"] != "react_async_input_clear" or not clear["disabled_button_lines"]:
            continue
        guards = [c for c in checks if c["kind"] == "react_async_entry_guard"
                  and c["state"] == clear["state"] and c["condition"] in {"state_empty", "trimmed_state_empty"}
                  and c["line"] < clear["clear_line"]]
        if len(guards) != 1:
            continue
        clear_stmts = [s for s in statements if g._line(s) == clear["clear_line"]]
        if len(clear_stmts) != 1:
            continue
        clear_stmt = clear_stmts[0]
        setter, _ = react._call(clear_stmt)
        # Reject subsequent restores, updater closures, aliases and reassignment
        # inside this handler. Other event handlers/new typing remain out of scope.
        setter_refs = [n for n in all_nodes if n.type == "identifier" and g._name(n) == setter]
        if len(setter_refs) != 1:
            continue
        prefixes = [s for s in statements if s.end_byte <= clear_stmt.start_byte]
        if not prefixes or g._line(prefixes[0]) != guards[0]["line"]:
            continue
        # Before clearing: only the empty guard and local const declarations.
        # No earlier callbacks, branches, requests or nested function invocations.
        if any(s.type != "lexical_declaration" for s in prefixes[1:]):
            continue
        if any(n.type in g._FUNCTIONS | {"await_expression", "assignment_expression"}
               for s in prefixes[1:] for n in g._walk(s)):
            continue
        if any(n.type == "call_expression" and not (
                g._method(n, "trim")[0] is not None
                and g._name(g._method(n, "trim")[0]) == clear["state"] and not g._method(n, "trim")[1])
               for s in prefixes[1:] for n in g._walk(s)):
            continue
        # Unlike the broader context inventory, this consequence proof accepts
        # only a bare handler reference on a well-formed native button.
        handler_name = context["scope"].rsplit(".", 1)[-1]
        buttons = [n for n in g._walk(root) if n.type == "jsx_opening_element"
                   and g._line(n) in clear["disabled_button_lines"]
                   and g._text(n.child_by_field_name("name")) == "button"]
        valid_lines = []
        for button in buttons:
            closing = button.parent.child_by_field_name("close_tag")
            if not closing or g._text(closing.child_by_field_name("name")) != "button":
                continue
            events = [g._children(attr)[1] for attr in g._children(button)
                      if attr.type == "jsx_attribute" and len(g._children(attr)) == 2
                      and g._text(g._children(attr)[0]) == "onClick"]
            if (len(events) == 1 and events[0].type == "jsx_expression"
                    and len(g._children(events[0])) == 1
                    and g._name(g._children(events[0])[0]) == handler_name):
                valid_lines.append(g._line(button))
        if not valid_lines:
            continue
        clear = {**clear, "disabled_button_lines": valid_lines}
        candidates.append({"handler": _loc(fn), "state": clear["state"], "setter": setter,
                           "guard_line": guards[0]["line"], "clear_line": clear["clear_line"],
                           "disabled_button_lines": clear["disabled_button_lines"],
                           "first_await_line": min(context["await_lines"])})
    return candidates[0] if len(candidates) == 1 else None


def _literal_post(fn):
    nodes = _own(_body(fn)) if _body(fn) else []
    calls = [n for n in nodes if n.type == "call_expression"
             and g._name(n.child_by_field_name("function")) == "fetch"]
    if len(calls) != 1:
        return None
    args = g._children(calls[0].child_by_field_name("arguments"))
    if len(args) != 2 or args[1].type != "object":
        return None
    url = g._literal(args[0])
    if not url or not re.fullmatch(r"/api/(?:[a-zA-Z0-9_-]+/)*[a-zA-Z0-9_-]+", url):
        return None
    pairs = g._children(args[1])
    if any(n.type != "pair" for n in pairs):
        return None
    methods = [g._literal(n.child_by_field_name("value")) for n in pairs
               if g._text(n.child_by_field_name("key")) == "method"]
    return (url, calls[0]) if methods == ["POST"] else None


def _table_call(node, method):
    receiver, args = g._method(node, method)
    client, from_args = g._method(receiver, "from")
    if not g._name(client) or len(from_args) != 1:
        return None
    table = g._literal(from_args[0])
    if not table or not re.fullmatch(r"[a-z_][a-z0-9_]*", table):
        return None
    return table, args


def _eq_duplicate(node, name):
    node = g._unwrap(node)
    if node is None or node.type != "binary_expression":
        return False
    op = g._text(node.child_by_field_name("operator"))
    if op == "||":
        # Under code == 23505 the LHS must be true; RHS effects are then skipped.
        return _eq_duplicate(node.child_by_field_name("left"), name)
    if op != "===":
        return False
    member = g._member(node.child_by_field_name("left"), "code")
    return bool(member and g._name(member.child_by_field_name("object")) == name
                and g._literal(node.child_by_field_name("right")) == "23505")


def _duplicate_branch(root, fn):
    body = _body(fn)
    if body is None:
        return None
    nodes = _own(body)
    if any(n.type == "finally_clause" for n in nodes):
        return None
    matches = []
    for stmt in g._children(body):
        if stmt.type != "lexical_declaration" or not any(c.type == "const" for c in stmt.children):
            continue
        for dec in g._children(stmt):
            pattern, value = dec.child_by_field_name("name"), dec.child_by_field_name("value")
            if not pattern or pattern.type != "object_pattern" or not value or value.type != "await_expression":
                continue
            parts = g._children(value)
            call = parts[0] if len(parts) == 1 else None
            table = _table_call(call, "insert")
            if not table:
                continue
            errors = [g._name(n.child_by_field_name("value")) for n in g._children(pattern)
                      if n.type == "pair_pattern" and g._text(n.child_by_field_name("key")) == "error"]
            errors += [g._text(n) for n in g._children(pattern)
                       if n.type == "shorthand_property_identifier_pattern" and g._text(n) == "error"]
            if len(errors) != 1 or not errors[0] or g._bindings(list(g._walk(fn)))[errors[0]] != 1:
                continue
            name = errors[0]
            later = [s for s in g._children(body) if s.start_byte > stmt.end_byte]
            if not later or later[0].type != "if_statement" or later[0].child_by_field_name("alternative"):
                continue
            guard = later[0]
            if g._name(g._unwrap(guard.child_by_field_name("condition"))) != name:
                continue
            branch = guard.child_by_field_name("consequence")
            children = g._children(branch) if branch and branch.type == "statement_block" else [branch]
            if not children or children[0] is None or children[0].type != "if_statement":
                continue
            duplicate = children[0]
            if not _eq_duplicate(duplicate.child_by_field_name("condition"), name) or not _plain_return(duplicate):
                continue
            # A return helper could perform its own query. The conclusion is
            # specifically non-reachability of these later, direct query sites.
            queries = [n for n in nodes if n.start_byte > guard.end_byte
                       and (q := _table_call(n, "select")) and q[0] == table[0]]
            if not queries:
                continue
            payload = table[1][0] if table[1] else None
            columns = []
            if payload and payload.type == "object":
                for item in g._children(payload):
                    if item.type == "pair":
                        columns.append(g._text(item.child_by_field_name("key")))
                    elif item.type == "shorthand_property_identifier":
                        columns.append(g._text(item))
            matches.append({"table": table[0], "insert": _loc(call), "error_binding": name,
                            "guard": _loc(duplicate), "later_queries": [_loc(n) for n in queries[:8]],
                            "insert_columns": columns})
    return matches[0] if len(matches) == 1 else None


class ConsequenceVerifier:
    """Per-audit bounded parsing/cache. Context evidence is never score relief."""

    def __init__(self, archive):
        self.archive = archive
        self.remaining = MAX_TOTAL_BYTES
        self.checks = 0
        self._cache = {}

    def _read(self, path, *, tree=True):
        if path in self._cache:
            return self._cache[path]
        if len(self._cache) >= MAX_FILES:
            raise ValueError("Source file budget exhausted")
        with zipfile.ZipFile(self.archive) as archive:
            matches = [i for i in archive.infolist() if i.filename == path]
            if len(matches) != 1 or matches[0].is_dir() or stat.S_ISLNK(matches[0].external_attr >> 16):
                raise ValueError("Source path absent or ambiguous")
            info = matches[0]
            if not 0 < info.file_size <= min(MAX_FILE_BYTES, self.remaining):
                raise ValueError("Source byte budget exhausted")
            self.remaining -= info.file_size
            data = archive.read(info)
        data.decode("utf-8", errors="strict")
        root = None
        if tree:
            language = (tree_sitter_typescript.language_typescript() if path.endswith(".ts")
                        else tree_sitter_typescript.language_tsx())
            root = Parser(Language(language)).parse(data).root_node
            if root.has_error:
                raise ValueError("Source contains parse errors")
            for count, _ in enumerate(g._walk(root), 1):
                if count > MAX_NODES:
                    raise ValueError("Source node budget exhausted")
        self._cache[path] = data, root
        return data, root

    def _route(self, path, fn, root):
        post = _literal_post(fn)
        if not post or not react._standard_fetch(root, list(g._walk(root)), react._bindings(list(g._walk(root)))):
            return None
        parts = PurePosixPath(path).parts
        app_positions = [i for i, part in enumerate(parts) if part == "app"]
        if not app_positions:
            return None
        # Select the first app root (app/app/dashboard is a legal route); no
        # route groups, rewrites, alternate source roots or dynamic segments.
        prefix = PurePosixPath(*parts[:app_positions[0]])
        route_path = str(prefix / "app" / post[0].lstrip("/") / "route.ts")
        data, route_root = self._read(route_path)
        functions = [n for n in route_root.named_children if n.type == "export_statement"
                     for n in [n.child_by_field_name("declaration")]
                     if n is not None and n.type == "function_declaration"
                     and g._name(n.child_by_field_name("name")) == "POST"]
        if len(functions) != 1:
            return None
        proof = _duplicate_branch(route_root, functions[0])
        if not proof:
            return None
        proof.update(route_file=route_path, route_sha256=hashlib.sha256(data).hexdigest(),
                     client_fetch=_loc(post[1]), route_mapping="Next app directory literal POST; rewrites not verified")
        proof["declared_unique_constraints"] = self._unique_declarations(prefix, proof)
        return proof

    def _unique_declarations(self, prefix, proof):
        # These are declarations, not an assertion about applied migration
        # history. IF NOT EXISTS, ALTER/DROP, custom schemas and production drift
        # mean even a matching declaration cannot establish active uniqueness.
        base = str(prefix / "supabase" / "migrations") + "/"
        with zipfile.ZipFile(self.archive) as archive:
            paths = [i.filename for i in archive.infolist()
                     if i.filename.startswith(base) and i.filename.endswith(".sql")]
        found = []
        for path in sorted(paths)[:MAX_FILES]:
            try:
                data, _ = self._read(path, tree=False)
                for raw in parse_sql(data.decode("utf-8")):
                    stmt = raw.stmt
                    if (not isinstance(stmt, ast.CreateStmt) or stmt.relation.relname != proof["table"]
                            or stmt.relation.schemaname not in (None, "public")):
                        continue
                    for constraint in stmt.tableElts or ():
                        if not isinstance(constraint, ast.Constraint) or constraint.contype != ConstrType.CONSTR_UNIQUE:
                            continue
                        columns = [item.sval for item in constraint.keys or ()]
                        if (0 < len(columns) <= 16 and all(re.fullmatch(r"[a-z_][a-z0-9_]{0,127}", c)
                                                          for c in columns)
                                and set(columns) <= set(proof["insert_columns"])):
                            found.append({"file": path, "source_sha256": hashlib.sha256(data).hexdigest(),
                                          "columns": columns, "status": "declared_only"})
            except (ValueError, UnicodeError, ParseError, OSError, zipfile.BadZipFile):
                continue
        return found[:8]

    def checks_for(self, finding):
        kinds = _selected(finding)
        if not kinds:
            return []
        results = [_result(kind) for kind in kinds]
        if self.checks >= MAX_CHECKS:
            return [_result(kind, "Per-audit consequence check budget exhausted.") for kind in kinds]
        self.checks += 1
        path, start, end = finding.get("file"), finding.get("line_start"), finding.get("line_end")
        if (not isinstance(path, str) or not path.endswith((".ts", ".tsx", ".js", ".jsx"))
                or type(start) is not int or type(end) is not int or not 1 <= start <= end):
            return results
        try:
            data, root = self._read(path)
            if end > len(data.splitlines()):
                return results
            fn = _function(root, start, end)
            if fn is None:
                return results
            for result in results:
                kind = result["kind"]
                if kind == "token_write_return_guard":
                    proof = _token_guard(root, fn, start, end)
                    detail = ("The recorded local token binding is checked by an unconditional top-level "
                              "falsy return before the recorded write calls, with no later reassignment. "
                              "An absent/falsy token cannot reach those call arguments on this path. "
                              "Nonempty invalid tokens, HTTP status handling, helper side effects, other paths "
                              "and database behavior are not settled.")
                elif kind == "discarded_fetch_response":
                    proof = _discarded_json(root, fn)
                    detail = ("The sole direct fetch result is discarded by an awaited expression statement; "
                              "this complete handler has no direct json() or JSON.parse call. A direct "
                              "response-JSON parsing branch is absent from the checked source. This does not "
                              "establish HTTP success validation or safe navigation and does not dismiss "
                              "the finding's HTTP/UI issue.")
                elif kind == "react_empty_input_entry_binding":
                    proof = _separate_click(root, fn, finding)
                    detail = ("The direct React state binding has an empty-input entry return, an immediate "
                              "empty-string setter before the first await, and the same native button is "
                              "disabled by that empty state. No restoration of that state occurs in this handler. "
                              "This is source context for ordinary distinct-click scenarios, not a runtime "
                              "duplicate-prevention proof. New typing, effects elsewhere, "
                              "programmatic same-tick calls, cached closures, other entry points and general "
                              "request idempotency remain unverified.")
                else:
                    proof = self._route(path, fn, root)
                    detail = ("A literal client POST maps by Next app-directory convention to the recorded route. "
                              "When its insert error has code 23505, the first error branch returns before the "
                              "recorded later query sites on that table. Those query sites cannot be reached "
                              "by that duplicate-error path. Matching UNIQUE declarations are source context "
                              "only; applied migrations, actual duplicate responses, proxies/rewrites, callee "
                              "effects and overall idempotency were not verified. Repeated client requests and "
                              "UI state increments are not prevented by this evidence.")
                if proof:
                    result.update(result="observed", detail=(
                        "Source context only: this observation does not settle the finding's narrative. " + detail),
                        source_binding={"file": path, "source_sha256": hashlib.sha256(data).hexdigest(), **proof})
        except (AttributeError, KeyError, TypeError, ValueError, UnicodeError, RecursionError,
                RuntimeError, OSError, zipfile.BadZipFile):
            # A partial parser failure never turns unknown into a safety claim.
            return results
        return results

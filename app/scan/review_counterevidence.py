"""Source observations that correct two overstatements without declaring safety.

Literal SQL loop inputs and a CORS rejection predicate are bounded source
facts. Hypothetical edits, caller policy and runtime outcomes remain unknown.
"""
from __future__ import annotations

import ast
from hashlib import sha256
import re
import zipfile

from app.scan import guard_context as g
from app.scan.consequence_evidence import _loc
from app.scan.imported_error_context import ImportedErrorVerifier, _source_path
from app.scan.python_sql_identity import PythonSQLResolver, sql_table_claim, _table_slot

SQL_KIND = "sql_table_literal_source"
CORS_KIND = "cors_nonempty_origin_guard"
MAX_CHECKS = 40
MAX_WORK = 400_000
_CORS = re.compile(r"CORS origin check allows all origins when (?P<env>[A-Z_][A-Z_0-9]*) is not configured")
_CLAIMS = {
    SQL_KIND: "The cited table-name slot is fed by a literal-only loop iterable on the checked source path.",
    CORS_KIND: "The cited callback contains a nonempty-Origin mismatch rejection before its next call.",
}
_PREMISES = {SQL_KIND: "sql_table_external_control", CORS_KIND: "cors_all_origins_allowed"}


def _record(kind, binding):
    detail = (_CLAIMS[kind] + " Only the recorded source path is checked. Runtime replacement, other paths, "
              "future code changes, authorization policy and harmful outcomes remain unverified.")
    return {"kind": kind, "claim": _CLAIMS[kind], "result": "observed", "whole_finding": False,
            "method": "source_ast", "detail": detail, "source_binding": binding,
            **{key: binding[key] for key in ("file", "source_sha256", "line_start", "line_end")},
            "narrative_review": {"status": "required", "premise": _PREMISES[kind], "reason": detail}}


def _method(node, receiver, method):
    if not node or node.type != "call_expression":
        return None
    fn = node.child_by_field_name("function")
    if (not fn or fn.type != "member_expression" or g._name(fn.child_by_field_name("object")) != receiver
            or g._text(fn.child_by_field_name("property")) != method
            or any(n.type == "optional_chain" for n in g._walk(node))):
        return None
    return g._children(node.child_by_field_name("arguments"))


def _origin(node, receiver):
    args = _method(g._unwrap(node), receiver, "get")
    return args is not None and len(args) == 1 and g._literal(args[0]) == "origin"


def _binary(node, op):
    node = g._unwrap(node)
    return node if node and node.type == "binary_expression" and g._text(
        node.child_by_field_name("operator")) == op else None


def _reject(node, response):
    """A direct return of res.status(403).json({literal fields})."""
    if node and node.type == "statement_block" and len(g._children(node)) == 1:
        node = g._children(node)[0]
    if not node or node.type != "return_statement" or len(g._children(node)) != 1:
        return False
    call = g._unwrap(g._children(node)[0])
    if not call or call.type != "call_expression":
        return False
    if any(n.type == "optional_chain" for n in g._walk(call)):
        return False
    member = call.child_by_field_name("function")
    args = g._children(call.child_by_field_name("arguments"))
    if (not member or member.type != "member_expression"
            or g._text(member.child_by_field_name("property")) != "json" or len(args) != 1
            or args[0].type != "object"):
        return False
    status = _method(member.child_by_field_name("object"), response, "status")
    return (status is not None and len(status) == 1 and g._text(status[0]) == "403"
            and all(n.type in {"object", "pair", "property_identifier", "string", "string_fragment"}
                    for n in g._walk(args[0])))


def _host_condition(node, request):
    node = g._unwrap(node)
    if not node or node.type != "unary_expression" or g._text(node.child_by_field_name("operator")) != "!":
        return False
    call = g._unwrap(node.child_by_field_name("argument"))
    if not call or call.type != "call_expression":
        return False
    member = call.child_by_field_name("function")
    args = g._children(call.child_by_field_name("arguments"))
    if (not member or member.type != "member_expression"
            or member.child_by_field_name("object").type != "regex"
            or g._text(member.child_by_field_name("property")) != "test" or len(args) != 1):
        return False
    value = _binary(args[0], "||")
    headers = _method(value.child_by_field_name("left"), request, "get") if value else None
    return (headers is not None and len(headers) == 1 and g._literal(headers[0]) == "host"
            and g._literal(value.child_by_field_name("right")) == "")


class ReviewCounterevidence:
    def __init__(self, archive):
        self.sql = PythonSQLResolver(archive)
        self.js = ImportedErrorVerifier(archive)
        self.checks = 0
        self.work = MAX_WORK

    def checks_for(self, finding):
        path, start, end = finding.get("file"), finding.get("line_start"), finding.get("line_end")
        if (not isinstance(path, str) or type(start) is not int or type(end) is not int
                or not 1 <= start <= end or self.checks >= MAX_CHECKS):
            return []
        sql = path.endswith(".py") and sql_table_claim(finding)
        cors = _CORS.fullmatch(str(finding.get("title", ""))[:2000]) if _source_path(path) else None
        if not sql and not cors:
            return []
        self.checks += 1
        try:
            binding = self._sql(finding) if sql else self._cors(path, start, end, cors["env"])
            return [_record(SQL_KIND if sql else CORS_KIND, binding)] if binding else []
        except (UnicodeError, ValueError, TypeError, SyntaxError, RecursionError, RuntimeError,
                OSError, zipfile.BadZipFile):
            return []

    def _sql(self, finding):
        identity = self.sql.identity(finding)
        if identity is None:
            return None
        nodes, offsets, digest = self.sql._document(finding["file"])
        self.work -= len(nodes)
        if self.work < 0:
            return None

        def loc(node):
            return {"line_start": node.lineno, "line_end": node.end_lineno,
                    "span": [offsets[node.lineno - 1] + node.col_offset,
                             offsets[node.end_lineno - 1] + node.end_col_offset]}

        call = next(n for n in nodes if isinstance(n, ast.Call) and loc(n)["span"] == identity["operation_span"])
        slot = _table_slot(call)
        parents = {child: parent for parent in nodes for child in ast.iter_child_nodes(parent)}
        # The call must be the first action of this iteration, optionally in
        # a try body. Do not infer a value through preceding calls or branches.
        stmt = parents[call]
        if isinstance(stmt, ast.Await):
            stmt = parents[stmt]
        if not isinstance(stmt, (ast.Assign, ast.Expr)) or stmt.value not in (call, parents[call]):
            return None
        if isinstance(stmt, ast.Assign) and (len(stmt.targets) != 1 or not isinstance(stmt.targets[0], ast.Name)):
            return None
        container = parents[stmt]
        while isinstance(container, ast.Try) and container.body[0] is stmt:
            stmt, container = container, parents[container]
        if (not isinstance(container, ast.For) or container.body[0] is not stmt
                or not isinstance(container.target, ast.Name) or container.target.id != slot.id):
            return None
        loop = container
        scope = parents[loop]
        while not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
            scope = parents[scope]
        scoped = list(ast.walk(scope))
        if any(isinstance(n, (ast.Global, ast.Nonlocal)) for n in scoped):
            return None
        if any(isinstance(n, ast.Name) and n.id == slot.id and isinstance(n.ctx, (ast.Store, ast.Del))
               and n is not loop.target for n in ast.walk(loop)):
            return None
        iterable, assignment = loop.iter, None
        if isinstance(iterable, ast.Name):
            owner = parents[loop]
            block = next((value for _, value in ast.iter_fields(owner)
                          if isinstance(value, list) and loop in value), [])
            index = block.index(loop)
            assignment = block[index - 1] if index else None
            if (not isinstance(assignment, ast.Assign) or len(assignment.targets) != 1
                    or not isinstance(assignment.targets[0], ast.Name)
                    or assignment.targets[0].id != iterable.id):
                return None
            # No aliases, mutation, escape or rebinding of the iterable in
            # this scope. Unresolved frame inspection is outside this check.
            uses = [n for n in scoped if isinstance(n, ast.Name) and n.id == iterable.id]
            if set(uses) != {iterable, assignment.targets[0]}:
                return None
            iterable = assignment.value
        if (not isinstance(iterable, (ast.List, ast.Tuple)) or not 0 < len(iterable.elts) <= 64
                or any(not isinstance(n, ast.Constant) or not isinstance(n.value, str)
                       or not re.fullmatch(r"[a-zA-Z_][a-zA-Z_0-9]*", n.value) for n in iterable.elts)):
            return None
        return {"file": finding["file"], "source_sha256": digest,
                "line_start": 1, "line_end": len(offsets) - 1, "span": [0, offsets[-1]], "loop": loc(loop),
                "operation": loc(call), "slot": loc(slot), "loop_target": loc(loop.target),
                "iterable": loc(iterable), "assignment": loc(assignment) if assignment else None,
                "literal_count": len(iterable.elts), "binding_mode": "literal_loop_first_action",
                "runtime_control": "not_checked", "future_changes": "not_checked"}

    def _cors(self, path, start, end, environment):
        data, root = self.js._read(path)
        nodes = list(g._walk(root))
        self.work -= len(nodes)
        if self.work < 0 or end > len(data.splitlines()):
            return None
        candidates = []
        for callback in nodes:
            args = callback.parent
            registration = args.parent if args and args.type == "arguments" else None
            fn = registration.child_by_field_name("function") if registration else None
            if (callback.type in g._FUNCTIONS and registration and registration.type == "call_expression"
                    and fn and fn.type == "member_expression"
                    and g._text(fn.child_by_field_name("property")) == "use"
                    and registration.start_point[0] + 1 <= end and start <= registration.end_point[0] + 1):
                candidates.append(callback)
        # Do not redirect a broad quote from an unsupported/unsafe callback to
        # a supported neighboring guard. All directly cited callbacks count.
        if len(candidates) != 1:
            return None
        matches = []
        for callback in candidates:
            if callback.type != "arrow_function" or callback.child_by_field_name("body").type != "statement_block":
                continue
            params = g._children(callback.child_by_field_name("parameters"))
            names = [g._name(p.child_by_field_name("pattern")) for p in params]
            if len(names) != 3 or not all(names) or len(set(names)) != 3:
                continue
            req, res, next_name = names
            args = callback.parent
            registration = args.parent if args and args.type == "arguments" else None
            if (not registration or g._children(args) != [callback]
                    or not registration.start_point[0] + 1 <= end or not start <= registration.end_point[0] + 1):
                continue
            fn = registration.child_by_field_name("function")
            if not fn or fn.type != "member_expression" or g._text(fn.child_by_field_name("property")) != "use":
                continue
            statement = registration.parent
            body = statement.parent if statement and statement.type == "expression_statement" else None
            owner = body.parent if body and body.type == "statement_block" else None
            if not owner or owner.type not in g._FUNCTIONS:
                continue
            own = list(g._walk(owner))
            callback_nodes = list(g._walk(callback))
            self.work -= len(own) + len(callback_nodes)
            if self.work < 0:
                return None
            bindings, callback_bindings = g._bindings(own), g._bindings(callback_nodes)
            owner_params = owner.child_by_field_name("parameters")
            if owner_params is None or any(callback_bindings[name] != 1 for name in names):
                continue
            parameter_nodes, consts = list(g._walk(owner_params)), g._consts(body)
            statements = g._children(callback.child_by_field_name("body"))
            for index, guard in enumerate(statements):
                self.work -= len(statements) + len(parameter_nodes)
                if self.work < 0:
                    return None
                condition = (_binary(guard.child_by_field_name("condition"), "&&")
                             if guard.type == "if_statement" else None)
                comparison = _binary(condition.child_by_field_name("right"), "!==") if condition else None
                if (not comparison or not _origin(condition.child_by_field_name("left"), req)
                        or not _origin(comparison.child_by_field_name("left"), req)
                        or not _reject(guard.child_by_field_name("consequence"), res)
                        or guard.child_by_field_name("alternative")):
                    continue
                origin_name = g._name(comparison.child_by_field_name("right"))
                declaration = consts.get(origin_name)
                value = declaration.child_by_field_name("value") if declaration else None
                if (not value or value.type != "ternary_expression" or declaration.end_byte > statement.start_byte
                        or bindings[origin_name] != 1
                        or value.child_by_field_name("alternative").type != "null"):
                    continue
                config = g._name(value.child_by_field_name("condition"))
                if not config:
                    continue
                defaults = [n for n in parameter_nodes
                            if n.type == "object_assignment_pattern"
                            and g._text(n.child_by_field_name("left")) == config]
                if len(defaults) != 1 or bindings[config] != 1:
                    continue
                default = _binary(defaults[0].child_by_field_name("right"), "||")
                if (not default or g._text(default.child_by_field_name("left")) != "process.env." + environment
                        or g._literal(default.child_by_field_name("right")) != ""):
                    continue
                # Earlier callback statements can only reject; no next(),
                # mutation or arbitrary work can precede this guard.
                if any(n.type != "if_statement" or n.child_by_field_name("alternative")
                       or not _host_condition(n.child_by_field_name("condition"), req)
                       or not _reject(n.child_by_field_name("consequence"), res) for n in statements[:index]):
                    continue
                following = [n for n in statements[index + 1:] if n.type == "expression_statement"
                             and len(g._children(n)) == 1 and g._children(n)[0].type == "call_expression"
                             and g._name(g._children(n)[0].child_by_field_name("function")) == next_name
                             and not g._children(g._children(n)[0].child_by_field_name("arguments"))]
                if len(following) != 1:
                    continue
                matches.append({"file": path, "source_sha256": sha256(data).hexdigest(), **_loc(owner),
                                "registration": _loc(registration), "callback": _loc(callback),
                                "guard": _loc(guard), "configuration": _loc(declaration),
                                "environment_default": _loc(defaults[0]), "next_call": _loc(following[0]),
                                "absent_configuration_value": "null",
                                "nonempty_origin_predicate": True, "missing_origin_predicate": False,
                                "response_status": 403, "runtime_policy": "not_checked"})
        return matches[0] if len(matches) == 1 else None

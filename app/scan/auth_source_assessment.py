"""Bounded authentication/data-source observations, never authorization approval.

Only archive ASTs supply bindings. A verified-user query filter is different
from a database policy or a demonstrated owner bypass. Unknown/mutated flows
abstain; no finding is exempted from scoring and no submitted code executes.
"""

from __future__ import annotations

from copy import deepcopy
import re
import zipfile

from app.scan import consequence_evidence as c
from app.scan import guard_context as g
from app.scan import imported_error_context as i
from app.scan import ownership_claims as o

MAX_CHECKS = 48
MAX_OPERATIONS = 16
KINDS = ("verified_user_operation_scope", "ownership_guard_before_callback", "matched_peer_operation_scope")
LIMITS = (
    "Only the recorded source path is observed, not every operation or caller. SDK/runtime bindings, "
    "JWT validity, deployed SQL policies and grants, successful requests, later membership changes and "
    "overall authorization remain unverified. A privileged client and a missing database second barrier "
    "do not by themselves demonstrate access to another user's records."
)


def _ast_tokens(node):
    # named-only walking omits punctuation; include all AST leaves for equality.
    todo, parts = [node] if node else [], []
    while todo:
        n = todo.pop()
        if n.type == "comment":
            continue
        if n.children:
            todo.extend(reversed(n.children))
        else:
            parts.append(g._text(n))
    return "".join(parts)


def _top(node, body):
    while node and node.parent != body:
        node = node.parent
    return node


def _const(node):
    return bool(
        node
        and node.type == "variable_declarator"
        and node.parent.type == "lexical_declaration"
        and any(n.type == "const" for n in node.parent.children)
    )


def _consts(fn):
    return [n for n in g._walk(fn.child_by_field_name("body"), g._SKIP) if _const(n)]


def _single_const(decs, name):
    values = [n for n in decs if name in g._bound(n.child_by_field_name("name"))]
    return values[0] if len(values) == 1 else None


def _member(node, name, prop):
    return o._member(node, name, prop)


def _native_import(root, local, source, imported):
    specs = [
        n
        for stmt in root.named_children
        if stmt.type == "import_statement"
        and g._literal(stmt.child_by_field_name("source")) == source
        and not any(n.type == "type" for n in stmt.children)
        for n in g._walk(stmt)
        if n.type == "import_specifier"
        and g._name(n.child_by_field_name("name")) == imported
        and g._name(n.child_by_field_name("alias") or n.child_by_field_name("name")) == local
        and not any(child.type == "type" for child in n.children)
    ]
    return len(specs) == 1 and i._unambiguous(root, local)


def _service_key(dec, root):
    call = g._unwrap(dec.child_by_field_name("value"))
    args = g._children(call.child_by_field_name("arguments")) if call else []
    if len(args) != 2:
        return False
    key = args[1]
    if key.type == "non_null_expression" and len(g._children(key)) == 1:
        key = g._children(key)[0]
    env = g._member(key, "SUPABASE_SERVICE_ROLE_KEY")
    process = g._member(env.child_by_field_name("object"), "env") if env else None
    facts = i._file_facts(root)
    return bool(
        process
        and g._name(process.child_by_field_name("object")) == "process"
        and not facts[1]["process"]
        and not facts[2]["process"]
        and "process" not in facts[3]
    )


def _terminal_client_escape(node, fn):
    if i._owner(node) != fn:
        return False
    ret = node.parent
    while ret and ret != fn and ret.type != "return_statement":
        ret = ret.parent
    if not ret or ret.type != "return_statement":
        return False
    ancestor = ret.parent
    while ancestor and ancestor != fn:
        if ancestor.type == "try_statement":
            return False  # a thrown helper or finally can reach a later query
        ancestor = ancestor.parent
    values = g._children(ret)
    value = g._unwrap(values[0]) if len(values) == 1 else None
    if value and value.type == "await_expression" and len(g._children(value)) == 1:
        value = g._unwrap(g._children(value)[0])
    if not value or value.type != "call_expression" or not g._name(value.child_by_field_name("function")):
        return False
    # Only a single returned helper invocation. No comma expression, nested
    # query evaluation or effectful argument can run after the client escape.
    return not any(
        n.type
        in g._FUNCTIONS
        | {"assignment_expression", "augmented_assignment_expression", "update_expression", "sequence_expression"}
        or n.type == "call_expression"
        and n != value
        for n in g._walk(value)
    )


def _safe_objects(fn, names, *, allowed=(), terminal_client="", allow_terminal_escapes=False):
    """No local aliases, writes, shadowing or unknown object escapes, including callbacks."""
    nodes = list(g._walk(fn))
    if any(g._bindings(nodes)[name] != 1 for name in names):
        return False
    for node in nodes:
        if g._name(node) not in names:
            continue
        if node in allowed:
            continue
        parent = node.parent
        if parent.type in {"pair_pattern", "object_pattern"}:
            continue
        if parent.type == "variable_declarator" and parent.child_by_field_name("name") == node:
            continue
        if o._not_name(parent, g._name(node)):
            continue
        member = g._member(parent)
        if member and member.child_by_field_name("object") == node:
            if g._name(node) == terminal_client:
                prop = g._text(member.child_by_field_name("property"))
                if prop == "auth":
                    method = g._member(member.parent, "getUser")
                    if not (
                        method
                        and method.child_by_field_name("object") == member
                        and method.parent.type == "call_expression"
                        and method.parent.child_by_field_name("function") == method
                    ):
                        return False
                elif not (
                    prop == "from"
                    and member.parent.type == "call_expression"
                    and member.parent.child_by_field_name("function") == member
                ):
                    return False
            # Methods on user/profile/row values can mutate the observed object.
            if member.parent.type == "call_expression" and member.parent.child_by_field_name("function") == member:
                if g._name(node) != terminal_client or g._text(member.child_by_field_name("property")) != "from":
                    return False
            continue
        if allow_terminal_escapes and g._name(node) == terminal_client and _terminal_client_escape(node, fn):
            continue
        return False
    # Shorthand aliases are not identifier nodes in the TS grammar.
    for node in nodes:
        if node.type == "shorthand_property_identifier" and g._text(node) in names:
            if node in allowed:
                continue
            if not (allow_terminal_escapes and g._text(node) == terminal_client and _terminal_client_escape(node, fn)):
                return False
    return True


def _auth(root, fn, client_dec):
    client = g._name(client_dec.child_by_field_name("name"))
    body = fn.child_by_field_name("body")
    declarations = o._const_declarations(body)
    counts = g._bindings(list(g._walk(fn)))
    if not client or counts[client] != 1 or not o._trusted_client(root, client_dec, counts):
        return None
    for dec in declarations:
        user, error = o._data_binding(dec, user=True)
        call = o._awaited(dec)
        receiver, args = g._method(call, "getUser")
        if (
            not user
            or not _member(receiver, client, "auth")
            or len(args) != 1
            or not g._name(args[0])
            or dec.start_byte <= client_dec.end_byte
            or any(n.type == "?." for n in call.children)
        ):
            continue
        guards = [n for n in g._children(body) if dec.end_byte < n.start_byte and o._missing_return(n, user, error)]
        if not guards or not _safe_objects(fn, {user, client}, terminal_client=client, allow_terminal_escapes=True):
            continue
        return {"client": client, "user": user, "auth": dec, "guard": guards[0], "client_dec": client_dec}
    return None


def _top_level_function(root, name: str):
    if not name or g._bindings(list(g._walk(root, g._SKIP)))[name] != 1:
        return None
    matches = []
    for stmt in g._children(root):
        target = stmt.child_by_field_name("declaration") if stmt.type == "export_statement" else stmt
        if target and target.type == "function_declaration" and g._name(target.child_by_field_name("name")) == name:
            matches.append(target)
        elif target and target.type == "lexical_declaration" and any(c.type == "const" for c in target.children):
            for dec in g._children(target):
                val = g._unwrap(dec.child_by_field_name("value"))
                if (
                    dec.type == "variable_declarator"
                    and g._name(dec.child_by_field_name("name")) == name
                    and val
                    and val.type in {"arrow_function", "function_expression"}
                ):
                    matches.append(val)
    return matches[0] if len(matches) == 1 else None


def _helper_object_return_fields(helper_fn, inner_client: str, inner_user: str) -> tuple[bool, tuple[object, ...]]:
    body = helper_fn.child_by_field_name("body")
    if not body or body.type != "statement_block":
        return False, ()
    returns = [n for n in g._children(body) if n.type == "return_statement" and len(g._children(n)) == 1]
    if not returns:
        return False, ()
    last_ret = returns[-1]
    obj = g._unwrap(g._children(last_ret)[0])
    if not obj or obj.type != "object":
        return False, ()
    mapped = {}
    allowed_nodes = []
    for prop in g._children(obj):
        if prop.type == "shorthand_property_identifier":
            mapped[g._text(prop)] = g._text(prop)
            allowed_nodes.append(prop)
        elif prop.type == "pair":
            k = prop.child_by_field_name("key")
            v = g._unwrap(prop.child_by_field_name("value"))
            if k and k.type == "property_identifier" and v and v.type == "identifier":
                mapped[g._text(k)] = g._text(v)
                allowed_nodes.append(v)
        else:
            return False, ()
    ok = mapped.get(inner_client) == inner_client and mapped.get(inner_user) == inner_user
    return ok, tuple(allowed_nodes) if ok else ()


def _helper_auth(root, fn):
    """Resolve one-hop same-file auth helper returning { supabase, user }."""
    body = fn.child_by_field_name("body")
    if not body:
        return None
    declarations = o._const_declarations(body)
    fn_counts = g._bindings(list(g._walk(fn)))
    for call_dec in declarations:
        call = o._awaited(call_dec)
        if not call or call.type != "call_expression" or any(n.type == "?." for n in call.children):
            continue
        helper_name = g._name(call.child_by_field_name("function"))
        if not helper_name or fn_counts[helper_name]:
            continue
        helper_fn = _top_level_function(root, helper_name)
        if not helper_fn or helper_fn == fn:
            continue
        helper_body = helper_fn.child_by_field_name("body")
        if not helper_body or helper_body.type != "statement_block":
            continue
        helper_candidates = [n for n in o._const_declarations(helper_body) if _service_key(n, root)]
        if len(helper_candidates) != 1:
            continue
        inner_client_dec = helper_candidates[0]
        inner_client = g._name(inner_client_dec.child_by_field_name("name"))
        helper_counts = g._bindings(list(g._walk(helper_fn)))
        if (
            not inner_client
            or helper_counts[inner_client] != 1
            or not o._trusted_client(root, inner_client_dec, helper_counts)
        ):
            continue
        inner_auth_dec = None
        inner_user = ""
        inner_guard = None
        for dec in o._const_declarations(helper_body):
            u, err = o._data_binding(dec, user=True)
            c_call = o._awaited(dec)
            receiver, args = g._method(c_call, "getUser")
            if (
                not u
                or not _member(receiver, inner_client, "auth")
                or len(args) != 1
                or not g._name(args[0])
                or dec.start_byte <= inner_client_dec.end_byte
                or any(n.type == "?." for n in c_call.children)
            ):
                continue
            guards = [
                n for n in g._children(helper_body) if dec.end_byte < n.start_byte and o._missing_return(n, u, err)
            ]
            ok_ret, ret_nodes = _helper_object_return_fields(helper_fn, inner_client, u)
            if (
                guards
                and ok_ret
                and _safe_objects(
                    helper_fn,
                    {u, inner_client},
                    allowed=ret_nodes,
                    terminal_client=inner_client,
                    allow_terminal_escapes=False,
                )
            ):
                inner_auth_dec, inner_user, inner_guard = dec, u, guards[0]
                break
        if not inner_auth_dec or not inner_guard:
            continue
        # Caller side: either `const a = await authed(req); if (a.error) return ...; const { supabase, user } = a;`
        # or `const { supabase, user, error } = await authed(req); if (error || !user) return ...;`
        lhs = call_dec.child_by_field_name("name")
        if lhs and lhs.type == "identifier":
            holder = g._name(lhs)
            if not holder or fn_counts[holder] != 1:
                continue
            err_guards = [
                n
                for n in g._children(body)
                if call_dec.end_byte < n.start_byte
                and g._exit(n)
                and (
                    _member(g._unwrap(n.child_by_field_name("condition")), holder, "error")
                    or o._not_name(g._unwrap(n.child_by_field_name("condition")), holder)
                )
            ]
            if not err_guards:
                continue
            unpack_decs = [
                d
                for d in declarations
                if d.start_byte > err_guards[0].end_byte
                and g._name(g._unwrap(d.child_by_field_name("value"))) == holder
            ]
            if len(unpack_decs) != 1:
                continue
            fields = o._pattern_fields(unpack_decs[0].child_by_field_name("name"))
            if not fields or inner_client not in fields or inner_user not in fields:
                continue
            caller_client = o._binding(fields[inner_client])
            caller_user = o._binding(fields[inner_user])
            if (
                not caller_client
                or not caller_user
                or fn_counts[caller_client] != 1
                or fn_counts[caller_user] != 1
                or not _safe_objects(
                    fn, {caller_user, caller_client}, terminal_client=caller_client, allow_terminal_escapes=True
                )
            ):
                continue
            return {
                "client": caller_client,
                "user": caller_user,
                "auth": inner_auth_dec,
                "guard": unpack_decs[0],
                "client_dec": inner_client_dec,
                "selected": call_dec,
            }
    return None


def _id_value(node, name, prop, fn, before):
    if _member(node, name, prop):
        return True
    alias = g._name(node)
    dec = _single_const(_consts(fn), alias) if alias else None
    return bool(
        dec
        and dec.parent.parent == fn.child_by_field_name("body")
        and dec.end_byte < before
        and g._bindings(list(g._walk(fn)))[alias] == 1
        and _member(g._unwrap(dec.child_by_field_name("value")), name, prop)
    )


def _query(node):
    receiver, chain = o._chain(node)
    if not receiver or len(chain) < 2 or chain[0][0] != "from" or len(chain[0][1]) != 1:
        return None
    table = g._literal(chain[0][1][0])
    if not table or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", table):
        return None
    if chain[1][0] not in {"select", "delete", "update", "insert"}:
        return None
    return receiver, table, chain


def _direct_queries(fn):
    out = []
    for n in g._walk(fn.child_by_field_name("body"), g._SKIP):
        if n.type != "await_expression" or len(g._children(n)) != 1:
            continue
        call = g._children(n)[0]
        shape = _query(call)
        if shape:
            out.append((call, shape))
    return out


def _direct_user_operations(fn, auth):
    good, unresolved = [], 0
    queries = _direct_queries(fn)
    if len(queries) > MAX_OPERATIONS:
        return [], len(queries)
    for call, (client, table, chain) in queries:
        if client != auth["client"]:
            continue
        if call.start_byte < auth["guard"].end_byte:
            unresolved += 1
            continue
        methods = [part[0] for part in chain]
        op, args, _ = chain[1]
        proof = None
        if op in {"select", "delete", "update"} and set(methods[2:]) <= {
            "eq",
            "order",
            "limit",
            "single",
            "maybeSingle",
            *(["select"] if op in {"update", "delete"} else []),
        }:
            eqs = [
                args
                for method, args, _ in chain[2:]
                if method == "eq" and len(args) == 2 and g._literal(args[0]) == "user_id"
            ]
            if len(eqs) == 1 and _id_value(eqs[0][1], auth["user"], "id", fn, call.start_byte):
                proof = "user_id_equals_verified_user_id"
        if op == "insert" and len(args) == 1 and args[0].type == "object" and len(chain) == 2:
            pairs = g._children(args[0])
            keys = [g._text(n.child_by_field_name("key")) for n in pairs if n.type == "pair"]
            if len(keys) == len(pairs) == len(set(keys)):
                field = next(
                    (
                        n.child_by_field_name("value")
                        for n in pairs
                        if g._text(n.child_by_field_name("key")) == "user_id"
                    ),
                    None,
                )
                if field and _id_value(field, auth["user"], "id", fn, call.start_byte):
                    proof = "insert_user_id_from_verified_user_id"
        if proof:
            projection = next((g._literal(a[0]) for m, a, _ in chain if m == "select" and len(a) == 1), None)
            columns = projection.split(",") if projection is not None else []
            record = {"table": table, "operation": op.upper(), "binding": proof, **c._loc(call)}
            if columns and all(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", s.strip()) for s in columns):
                record["selected_columns"] = [s.strip() for s in columns]
            good.append(record)
        else:
            unresolved += 1
    return good[:MAX_OPERATIONS], unresolved + max(0, len(good) - MAX_OPERATIONS)


def _future_bypass(text):
    # Select an asserted hypothetical consequence, not a denial, an instruction
    # to check it, or unrelated words in another sentence/condition.
    for sentence in re.split(r"(?<=[.!?])\s+|\n", text):
        if re.search(
            r"\b(?:no (?:claim|evidence|risk)|not (?:a |an )?(?:claim|bypass)|cannot|"
            r"does not establish|do not allege|check whether|verify whether)\b",
            sentence,
            re.I,
        ):
            continue
        if (
            re.search(r"\b(?:future|ever|accidentally)\b", sentence, re.I)
            and re.search(r"\b(?:filter|query|queries|user_?id|identity)\b", sentence, re.I)
            and re.search(r"\b(?:remov\w*|omit\w*|wrong|manipulat\w*|bypass\w*|change\w*)\b", sentence, re.I)
            and re.search(r"\b(?:if|would|could|any)\b", sentence, re.I)
            and re.search(
                r"\b(?:expos\w*|return\w*|delet\w*|safety net|silently|ownership enforcement)\b", sentence, re.I
            )
        ):
            return True
    return False


def _absent_ownership_claim(text):
    return bool(
        re.search(r"\b(?:missing|lacks?|without|no|id-only)\b", text, re.I)
        and re.search(r"\b(?:ownership|user_id|cross[- ]?user)\b", text, re.I)
        and not re.search(
            r"\b(?:no (?:claim|evidence|risk)|not (?:a |an )?(?:claim|bypass)|"
            r"correctly checked|relies on rls|explicit user_id filter)\b",
            text,
            re.I,
        )
    )


class AuthSourceVerifier:
    def __init__(self, archive):
        self.loader = i.ImportedErrorVerifier(archive)
        self.checks = 0
        self._cache = {}

    def _record(self, kind, path, selected, detail, *, result="observed", review=False, **binding):
        source = self.loader._binding(path, selected)
        result_record = {
            "kind": kind,
            "result": result,
            "whole_finding": False,
            "method": "source_ast",
            "scope": "bounded_source_premise",
            "detail": detail + " " + LIMITS,
            **source,
            "source_binding": {**source, **binding},
        }
        if review:
            result_record["narrative_review"] = {
                "status": "required",
                "premise": kind,
                "reason": "The active narrative extends the recorded local operation to an unverified "
                "future identity/filter change or a different authorization outcome.",
            }
        return result_record

    def _service(self, path, root, fn, start, end, text):
        body = fn.child_by_field_name("body")
        candidates = [n for n in o._const_declarations(body) if _service_key(n, root)]
        intersect = [n for n in candidates if g._line(n) <= end and start <= n.end_point[0] + 1]
        candidates = intersect or candidates
        if len(candidates) == 1:
            auth = _auth(root, fn, candidates[0])
            selected_node = candidates[0]
        elif not candidates:
            auth = _helper_auth(root, fn)
            selected_node = auth["selected"] if auth else None
        else:
            return []
        if not auth or selected_node is None:
            return []
        operations, unresolved = _direct_user_operations(fn, auth)
        records = []
        if operations:
            title_absent = _absent_ownership_claim(str(text).splitlines()[0] if text else "")
            records.append(
                self._record(
                    KINDS[0],
                    path,
                    selected_node,
                    "The recorded SDK getUser call and missing-user return precede these specific operations. "
                    "Their explicit user_id filter/insert value refers to that returned user's id. These local "
                    "checks are counterevidence to treating privileged-client presence alone as a current "
                    "cross-user access path; other operations and hypothetical future filter changes are separate.",
                    review=_future_bypass(text) or title_absent,
                    auth_call=c._loc(auth["auth"]),
                    auth_return=c._loc(auth["guard"]),
                    client=auth["client"],
                    user=auth["user"],
                    operations=operations,
                    unassessed_direct_operations=unresolved,
                    deferred_operations_assessed=False,
                    sql_policy_status="not_checked",
                )
            )
        records += self._matched_peers(path, root, fn, auth, text)
        return records

    def _matched_peers(self, path, root, fn, auth, text):
        # A deliberately narrow declared loop: own profile -> participating
        # matches -> opposite participant IDs -> a projected peer SELECT.
        decs = _consts(fn)
        body = fn.child_by_field_name("body")
        profiles = []
        for dec in o._const_declarations(body):
            name, _ = o._data_binding(dec)
            if (
                name
                and dec.start_byte > auth["guard"].end_byte
                and o._query(
                    dec,
                    auth["client"],
                    "founder_profiles",
                    {"id"},
                    "user_id",
                    lambda n: _id_value(n, auth["user"], "id", fn, dec.start_byte),
                )
            ):
                guards = [
                    n for n in g._children(body) if dec.end_byte < n.start_byte and o._missing_return(n, name, "")
                ]
                if guards:
                    profiles.append((dec, name, guards[0]))
        if len(profiles) != 1:
            return []
        profile_dec, profile, profile_guard = profiles[0]
        aliases = [
            d
            for d in o._const_declarations(body)
            if d.start_byte > profile_guard.end_byte and _member(d.child_by_field_name("value"), profile, "id")
        ]
        if len(aliases) != 1:
            return []
        founder = g._name(aliases[0].child_by_field_name("name"))
        if not founder:
            return []
        matches = []
        for dec in o._const_declarations(body):
            name, _ = o._data_binding(dec)
            shape = _query(o._awaited(dec))
            if not name or not shape or shape[0] != auth["client"] or shape[1] != "matches":
                continue
            chain = shape[2]
            if [m for m, _, _ in chain] != ["from", "select", "or", "order"]:
                continue
            ors = chain[2][1]
            expected = "`founder1_id.eq.${" + founder + "},founder2_id.eq.${" + founder + "}`"
            if len(ors) == 1 and _ast_tokens(ors[0]) == expected and dec.start_byte > aliases[0].end_byte:
                matches.append((dec, name))
        if len(matches) != 1:
            return []
        match_dec, match_name = matches[0]
        loops = [
            n
            for n in g._children(body)
            if n.type == "for_in_statement"
            and g._name(n.child_by_field_name("right")) == match_name
            and n.start_byte > match_dec.end_byte
        ]
        if len(loops) != 1:
            return []
        loop = loops[0]
        row = g._name(loop.child_by_field_name("left"))
        statements = g._children(loop.child_by_field_name("body"))
        if not row or len(statements) != 3:
            return []
        peer_decs = [n for n in g._children(statements[1]) if _const(n)]
        if len(peer_decs) != 1:
            return []
        peer_dec = peer_decs[0]
        peer = g._name(peer_dec.child_by_field_name("name"))
        expected = f"{row}.founder1_id==={founder}?{row}.founder2_id:{row}.founder1_id"
        if not peer or _ast_tokens(peer_dec.child_by_field_name("value")) != expected:
            return []
        expressions = [g._children(s)[0] if len(g._children(s)) == 1 else None for s in (statements[0], statements[2])]
        pushes = [g._method(e, "push") for e in expressions]
        match_ids, peer_ids = (g._name(p[0]) for p in pushes)
        if (
            not match_ids
            or not peer_ids
            or match_ids == peer_ids
            or len(pushes[0][1]) != 1
            or not _member(pushes[0][1][0], row, "id")
            or len(pushes[1][1]) != 1
            or g._name(pushes[1][1][0]) != peer
        ):
            return []
        arrays = [_single_const(decs, name) for name in (match_ids, peer_ids)]
        if any(
            not d
            or d.parent.parent != body
            or _ast_tokens(d.child_by_field_name("value")) != "[]"
            or d.end_byte >= loop.start_byte
            for d in arrays
        ):
            return []
        queries = []
        for dec in o._const_declarations(body):
            shape = _query(o._awaited(dec))
            if (
                not shape
                or shape[0] != auth["client"]
                or shape[1] != "founder_profiles"
                or dec.start_byte <= loop.end_byte
            ):
                continue
            chain = shape[2]
            if [m for m, _, _ in chain] != ["from", "select", "in"]:
                continue
            args = chain[2][1]
            cols = g._literal(chain[1][1][0]) if len(chain[1][1]) == 1 else None
            if (
                len(args) == 2
                and g._literal(args[0]) == "id"
                and g._name(args[1]) == peer_ids
                and cols
                and all(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", s.strip()) for s in cols.split(","))
            ):
                queries.append((dec, cols))
        if len(queries) != 1:
            return []
        peer_query, columns = queries[0]
        for node in g._walk(fn):
            if node.start_byte >= peer_query.start_byte or g._name(node) != match_name:
                continue
            if node.parent.type in {"pair_pattern", "object_pattern"}:
                continue
            if node == loop.child_by_field_name("right") or o._not_name(node.parent, match_name):
                continue
            member = g._member(node.parent, "length")
            if member and member.child_by_field_name("object") == node:
                continue
            return []
        # Reject additional array writes/aliases, row/profile mutation and
        # shadowed primitive IDs. Array arguments are allowed only in this SELECT.
        counts = g._bindings(list(g._walk(fn)))
        if any(counts[n] != 1 for n in {profile, founder, match_name, peer_ids, match_ids}):
            return []
        for node in g._walk(fn):
            if g._name(node) != peer_ids:
                continue
            if node.parent.type == "variable_declarator" and node.parent.child_by_field_name("name") == node:
                continue
            if node == pushes[1][0] or i._contains(peer_query, node):
                continue
            return []
        if not _safe_objects(fn, {profile}):
            return []
        return [
            self._record(
                KINDS[2],
                path,
                peer_query,
                "The recorded user-scoped profile supplies both sides of the matches filter. A single direct loop "
                "selects each matched row's opposite participant ID, and the recorded peer SELECT uses that exact "
                "array and an explicit column projection. This source chain does not establish an arbitrary-profile "
                "read or approve the disclosure policy; the DTO and deployed SQL permissions are separate checks.",
                review=_future_bypass(text),
                auth_call=c._loc(auth["auth"]),
                auth_return=c._loc(auth["guard"]),
                profile_query=c._loc(profile_dec),
                profile_return=c._loc(profile_guard),
                matches_query=c._loc(match_dec),
                peer_loop=c._loc(loop),
                peer_query=c._loc(peer_query),
                selected_columns=[s.strip() for s in columns.split(",")],
                sql_policy_status="not_checked",
                dto_assessed=False,
            )
        ]

    def _callback(self, path, root, start, end, title):
        selected = c._function(root, start, end)
        if not selected or selected.type not in {"arrow_function", "function_expression"}:
            return []
        args = selected.parent
        call = args.parent if args and args.type == "arguments" else None
        if not call or call.type != "call_expression" or g._children(args) != [selected]:
            return []
        name = g._name(call.child_by_field_name("function"))
        if not name or not _native_import(root, name, "next/server", "after"):
            return []
        fn = i._owner(call)
        if not fn or _top(call, fn.child_by_field_name("body")) != call.parent:
            return []
        decs = o._const_declarations(fn.child_by_field_name("body"))
        inserts = [(d, o._insert(d)) for d in decs if d.end_byte < call.start_byte]
        inserts = [(d, shape) for d, shape in inserts if shape]
        if len(inserts) != 1:
            return []
        insert_dec, shape = inserts[0]
        proof = o._proof(
            root, fn, list(g._walk(fn.child_by_field_name("body"), g._SKIP)), g._bindings(list(g._walk(fn))), ""
        )
        if not proof:
            return []
        _, error = o._data_binding(insert_dec)
        intervening = [
            s
            for s in g._children(fn.child_by_field_name("body"))
            if insert_dec.end_byte < s.start_byte < call.start_byte
        ]
        if (
            len(intervening) != 1
            or not error
            or not g._exit(intervening[0])
            or g._name(g._unwrap(intervening[0].child_by_field_name("condition"))) != error
        ):
            return []
        entities = proof["source_entities"]
        match, profile, subject = (entities[k] for k in ("match", "profile", "subject"))
        if not _safe_objects(fn, {match, profile, entities["user"]}) or not _safe_objects(
            fn, {entities["client"]}, terminal_client=entities["client"]
        ):
            return []
        # Check the deferred target, rather than borrowing a guard for a different
        # recipient or match. Capture only direct const ternary and literal-table query.
        recipients = [
            d
            for d in _consts(selected)
            if _ast_tokens(d.child_by_field_name("value"))
            == f"{match}.founder1_id==={profile}.id?{match}.founder2_id:{match}.founder1_id"
        ]
        if len(recipients) != 1:
            return []
        recipient = g._name(recipients[0].child_by_field_name("name"))
        if not recipient or g._bindings(list(g._walk(fn)))[recipient] != 1:
            return []
        own = list(g._walk(selected.child_by_field_name("body"), g._SKIP))
        query_candidates, inserts_after, callback_clients = [], [], set()
        for n in own:
            if n.type != "await_expression" or len(g._children(n)) != 1:
                continue
            query = _query(g._children(n)[0])
            if not query:
                continue
            client, table, chain = query
            if table == "founder_profiles" and [m for m, _, _ in chain] == ["from", "select", "eq", "single"]:
                vals = chain[2][1]
                if len(vals) == 2 and g._literal(vals[0]) == "id" and g._name(vals[1]) == recipient:
                    query_candidates.append(n)
                    callback_clients.add(client)
            if table == "messages" and [m for m, _, _ in chain] == ["from", "insert"]:
                vals = chain[1][1]
                if len(vals) != 1 or vals[0].type != "object":
                    return []
                pairs = g._children(vals[0])
                keys = [g._text(p.child_by_field_name("key")) for p in pairs if p.type == "pair"]
                if len(keys) != len(pairs) or len(keys) != len(set(keys)):
                    return []
                fields = {g._text(p.child_by_field_name("key")): p.child_by_field_name("value") for p in pairs}
                if g._name(fields.get("match_id")) != subject or g._name(fields.get("sender_id")) != recipient:
                    return []
                inserts_after.append(n)
                callback_clients.add(client)
        if len(query_candidates) != 1 or len(inserts_after) != 1 or len(callback_clients) != 1:
            return []
        admin = next(iter(callback_clients))
        admin_decs = [d for d in decs if g._name(d.child_by_field_name("name")) == admin]
        if (
            len(admin_decs) != 1
            or admin_decs[0].end_byte >= call.start_byte
            or not o._trusted_client(root, admin_decs[0], g._bindings(list(g._walk(fn))))
            or not _safe_objects(fn, {admin}, terminal_client=admin)
        ):
            return []
        recipient_dec = recipients[0]
        scope = recipient_dec.parent.parent
        if scope.type != "statement_block" or any(
            not i._contains(scope, operation) or operation.start_byte <= recipient_dec.end_byte
            for operation in [*query_candidates, *inserts_after]
        ):
            return []
        # The registration's own return guard is not a revalidation when after
        # later executes. Contradict only an expressly claimed absent prior check.
        absent = bool(
            re.fullmatch(
                r"(?:L2 )?auto.reply (?:triggered|runs|is triggered)(?: on (?:the )?first message)? "
                r"without verifying (?:the )?sender[.!]?",
                title.strip(),
                re.I,
            )
        )
        return [
            self._record(
                KINDS[1],
                path,
                call,
                "The verified-user profile is compared with both participants of the selected match before the "
                "sender's insert. Insert errors return before this direct after registration. The callback's peer "
                "lookup derives the opposite participant from the same guarded match; its reply insert uses that "
                "participant and match. This contradicts only an absent pre-registration check, not a missing "
                "recheck inside the callback or a later membership change.",
                result="contradicted" if absent else "observed",
                ownership_proof=proof,
                registration=c._loc(call),
                insert_error_return=c._loc(intervening[0]),
                recipient_binding=c._loc(recipients[0]),
                recipient_query=c._loc(query_candidates[0]),
                reply_insert=c._loc(inserts_after[0]),
                callback_client=c._loc(admin_decs[0]),
                callback_revalidation="not_checked",
            )
        ]

    def checks_for(self, finding):
        text = c._narrative(finding)
        service = bool(
            re.search(r"service[ _-]?role", text, re.I)
            or (
                re.search(r"\b(?:ownership|cross[- ]?user|user_id|id-only)\b", text, re.I)
                and re.search(r"\b(?:filter|missing|lacks?|without|bypasses)\b", text, re.I)
            )
        )
        callback = bool(
            re.search(r"auto.reply|background|callback", text, re.I)
            and re.search(r"sender|participant|ownership|authoriz", text, re.I)
        )
        url_token = bool(re.search(r"token", text, re.I) and re.search(r"URL|query parameter|query string", text, re.I))
        if not (service or callback or url_token):
            return []
        path, start, end = finding.get("file"), finding.get("line_start"), finding.get("line_end")
        if not i._source_path(path) or type(start) is not int or type(end) is not int or not 1 <= start <= end:
            return []
        key = (path, start, end, text)
        if key in self._cache:
            return deepcopy(self._cache[key])
        if self.checks >= MAX_CHECKS:
            return []
        self.checks += 1
        try:
            data, root = self.loader._read(path)
            if end > len(data.splitlines()) or i._file_facts(root)[4]:
                return []
            fn = c._function(root, start, end)
            if fn and (len(list(g._walk(fn))) > g.MAX_FUNCTION_NODES or len(_consts(fn)) > g.MAX_LOCALS):
                return []
            records = self._service(path, root, fn, start, end, text) if service and fn else []
            if callback:
                records += self._callback(path, root, start, end, str(finding.get("title", "")))
            if url_token:
                from app.scan.url_token_assessment import url_token_checks

                records += url_token_checks(self, path, root, start, end)
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
        self._cache[key] = deepcopy(records)
        return records

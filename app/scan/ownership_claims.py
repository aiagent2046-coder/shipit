"""A bounded source counterexample to a missing message ownership guard.

This recognizes the local Supabase messages/matches/founder_profiles shape. It
does not infer foreign keys, RLS policies, successful authentication, database
state or race prevention. Unknown shapes remain unchecked; no code is run.
"""
from collections import Counter

from tree_sitter import Language, Parser
import tree_sitter_typescript

from app.scan import guard_context as g

KIND = "ownership_guard_absent"
CLAIM = "The message insert has no preceding local match-participant ownership guard."
MAX_FILE_BYTES = 256_000


def _unknown(request):
    return {**request, "claim": CLAIM, "result": "not_checked",
            "detail": "No unambiguous local message ownership counterexample was found. "
                      "Database constraints, policies and concurrent changes were not checked."}


def _const_declarations(body):
    return [dec for stmt in g._children(body) if stmt.type == "lexical_declaration"
            and any(c.type == "const" for c in stmt.children)
            for dec in g._children(stmt) if dec.type == "variable_declarator"]


def _pattern_fields(pattern):
    if not pattern or pattern.type != "object_pattern":
        return None
    fields = {}
    for field in g._children(pattern):
        if field.type == "shorthand_property_identifier_pattern":
            name, value = g._text(field), field
        elif field.type == "pair_pattern":
            key = field.child_by_field_name("key")
            if key.type != "property_identifier":
                return None
            name, value = g._text(key), field.child_by_field_name("value")
        else:
            return None
        if name in fields:
            return None
        fields[name] = value
    return fields


def _binding(node):
    return g._text(node) if node and node.type in {
        "identifier", "shorthand_property_identifier_pattern"
    } and len(node.text) <= 128 else ""


def _data_binding(dec, *, user=False):
    fields = _pattern_fields(dec.child_by_field_name("name"))
    if fields is None or "data" not in fields or set(fields) - {"data", "error"}:
        return "", ""
    data = fields["data"]
    if user:
        nested = _pattern_fields(data)
        if nested is None or set(nested) != {"user"}:
            return "", ""
        data = nested["user"]
    return _binding(data), _binding(fields.get("error"))


def _awaited(dec):
    value = g._unwrap(dec.child_by_field_name("value"))
    return g._children(value)[0] if value and value.type == "await_expression" else None


def _chain(node):
    """Return a direct nonoptional receiver/method chain, never aliases."""
    methods = []
    node = g._unwrap(node)
    while node and node.type == "call_expression":
        if node.child_by_field_name("optional_chain") or any(c.type == "?." for c in node.children):
            return "", []
        member = g._member(node.child_by_field_name("function"))
        if not member:
            return "", []
        prop = member.child_by_field_name("property")
        if not prop or prop.type != "property_identifier":
            return "", []
        methods.append((g._text(prop), g._children(node.child_by_field_name("arguments")), node))
        node = g._unwrap(member.child_by_field_name("object"))
    return g._name(node), list(reversed(methods))


def _member(node, name, field):
    member = g._member(node, field)
    return bool(member and g._name(member.child_by_field_name("object")) == name)


def _not_name(node, name):
    node = g._unwrap(node)
    return bool(node and node.type == "unary_expression"
                and g._text(node.child_by_field_name("operator")) == "!"
                and g._name(node.child_by_field_name("argument")) == name)


def _missing_return(stmt, name, error):
    if not g._exit(stmt):
        return False
    condition = g._unwrap(stmt.child_by_field_name("condition"))
    if _not_name(condition, name):
        return True
    if not error or condition.type != "binary_expression" or g._text(
            condition.child_by_field_name("operator")) != "||":
        return False
    left, right = condition.child_by_field_name("left"), condition.child_by_field_name("right")
    return ((g._name(left) == error and _not_name(right, name))
            or (g._name(right) == error and _not_name(left, name)))


def _participant_return(stmt, profile, match):
    if not g._exit(stmt):
        return False
    condition = g._unwrap(stmt.child_by_field_name("condition"))
    if not condition or condition.type != "binary_expression" or g._text(
            condition.child_by_field_name("operator")) != "&&":
        return False
    fields = []
    for side in ("left", "right"):
        comparison = g._unwrap(condition.child_by_field_name(side))
        if not comparison or comparison.type != "binary_expression" or g._text(
                comparison.child_by_field_name("operator")) != "!==":
            return False
        left, right = comparison.child_by_field_name("left"), comparison.child_by_field_name("right")
        if _member(right, profile, "id"):
            left, right = right, left
        if not _member(left, profile, "id"):
            return False
        member = g._member(right)
        if not member or g._name(member.child_by_field_name("object")) != match:
            return False
        fields.append(g._text(member.child_by_field_name("property")))
    return set(fields) == {"founder1_id", "founder2_id"}


def _query(dec, client, table, columns, column, value):
    receiver, methods = _chain(_awaited(dec))
    if receiver != client or [m[0] for m in methods] != ["from", "select", "eq", "single"]:
        return False
    source, projection, where, single = [m[1] for m in methods]
    selected = g._literal(projection[0]) if len(projection) == 1 else None
    return (len(source) == 1 and g._literal(source[0]) == table
            and selected is not None and {s.strip() for s in selected.split(",")} == columns
            and len(where) == 2 and g._literal(where[0]) == column
            and value(where[1]) and not single)


def _insert(dec):
    client, methods = _chain(_awaited(dec))
    if not client or [m[0] for m in methods] != ["from", "insert", "select", "single"]:
        return None
    source, values, select, single = [m[1] for m in methods]
    if (len(source) != 1 or g._literal(source[0]) != "messages" or len(values) != 1
            or values[0].type != "object" or select or single):
        return None
    fields = {}
    for pair in g._children(values[0]):
        if pair.type != "pair" or pair.child_by_field_name("key").type != "property_identifier":
            return None
        key = g._text(pair.child_by_field_name("key"))
        if key in fields:
            return None
        fields[key] = pair.child_by_field_name("value")
    subject = g._name(fields.get("match_id"))
    sender = g._member(fields.get("sender_id"), "id")
    profile = g._name(sender.child_by_field_name("object")) if sender else ""
    return (client, subject, profile, methods[1][2]) if subject and profile else None


def _trusted_client(root, dec, bindings):
    """Link the declared SDK import, without claiming runtime authentication."""
    value = g._unwrap(dec.child_by_field_name("value"))
    if (not value or value.type != "call_expression"
            or any(c.type == "?." for c in value.children)):
        return False
    factory = g._name(value.child_by_field_name("function"))
    if not factory or bindings[factory]:
        return False
    imports, sdk = Counter(), set()
    for stmt in root.named_children:
        if stmt.type != "import_statement":
            continue
        for node in g._walk(stmt):
            if node.type == "import_specifier":
                local = g._name(node.child_by_field_name("alias") or node.child_by_field_name("name"))
                imports[local] += 1
                if (g._literal(stmt.child_by_field_name("source")) == "@supabase/supabase-js"
                        and g._name(node.child_by_field_name("name")) == "createClient"
                        and not any(n.type == "type" for n in [*stmt.children, *node.children])):
                    sdk.add(local)
            elif node.type == "identifier" and node.parent.type in {"import_clause", "namespace_import"}:
                imports[g._name(node)] += 1
    # A top-level declaration with the same spelling also makes the import ambiguous.
    outer = list(g._walk(root, g._SKIP))
    return (factory in sdk and imports[factory] == 1
            and not g._bindings(outer)[factory])


def _proof(root, fn, own, bindings, target):
    body = fn.child_by_field_name("body")
    statements, declarations = g._children(body), _const_declarations(body)
    # Nested callbacks have their own scope; all direct inserts must be accounted for.
    inserts = [n for n in own if g._method(n, "insert")[0] is not None]
    candidates = [(dec, _insert(dec)) for dec in declarations]
    candidates = [(dec, shape) for dec, shape in candidates if shape]
    if len(inserts) != 1 or len(candidates) != 1:
        return None
    insert_dec, (client, subject, profile, insert_node) = candidates[0]
    message, _ = _data_binding(insert_dec)
    if target and target not in {client, subject, profile, message, "messages"}:
        return None
    consts = {name: dec for dec in declarations for name in g._bound(dec.child_by_field_name("name"))}
    if (any(bindings[n] != 1 or n not in consts for n in (client, subject, profile))
            or not _trusted_client(root, consts[client], bindings)):
        return None
    if any(consts[n].end_byte >= insert_dec.start_byte for n in (client, subject, profile)):
        return None
    position = statements.index(insert_dec.parent)
    if not position:
        return None
    guard = statements[position - 1]
    matches = []
    for match_dec in declarations:
        match, match_error = _data_binding(match_dec)
        if (match and bindings[match] == 1 and _participant_return(guard, profile, match)
                and _query(match_dec, client, "matches", {"id", "founder1_id", "founder2_id"},
                           "id", lambda n: g._name(n) == subject)):
            matches.append((match_dec, match, match_error))
    if len(matches) != 1:
        return None
    match_dec, match, match_error = matches[0]
    profile_dec = consts[profile]
    auth = []
    for auth_dec in declarations:
        user, error = _data_binding(auth_dec, user=True)
        auth_call = _awaited(auth_dec)
        receiver, args = g._method(auth_call, "getUser")
        if (user and bindings[user] == 1 and auth_call
                and not any(c.type == "?." for c in auth_call.children)
                and _member(receiver, client, "auth") and len(args) == 1
                and g._name(args[0]) and _query(profile_dec, client, "founder_profiles", {"id"},
                                               "user_id", lambda n: _member(n, user, "id"))):
            auth.append((auth_dec, user, error))
    if len(auth) != 1:
        return None
    auth_dec, user, user_error = auth[0]
    if not (consts[client].end_byte < auth_dec.start_byte < auth_dec.end_byte < match_dec.start_byte
            and consts[subject].end_byte < match_dec.start_byte < match_dec.end_byte < profile_dec.start_byte
            and profile_dec.end_byte < guard.start_byte):
        return None
    for dec, name, error, before in ((auth_dec, user, user_error, match_dec),
                                     (match_dec, match, match_error, profile_dec),
                                     (profile_dec, profile, "", guard)):
        if not any(dec.end_byte < stmt.start_byte < stmt.end_byte < before.start_byte
                   and _missing_return(stmt, name, error) for stmt in statements):
            return None
    # Reject local rebinding, object mutation and escapes through a bare alias or
    # function argument. Member access alone is only a source observation.
    objects = {user, profile, match, client}
    for node in own:
        if node.start_byte >= insert_dec.end_byte:
            continue
        if node.type == "identifier" and g._text(node) in objects:
            if node.parent.type in {"pair_pattern", "object_pattern"}:
                continue
            if node.parent.type == "variable_declarator" and node.parent.child_by_field_name("name") == node:
                continue
            member = g._member(node.parent)
            if not member or member.child_by_field_name("object") != node:
                # The !user / !match / !profile null checks are explicit above.
                if not _not_name(node.parent, g._text(node)):
                    return None
            elif member.parent.type == "call_expression" and member.parent.child_by_field_name("function") == member:
                if g._text(node) != client or g._text(member.child_by_field_name("property")) != "from":
                    return None
    return {"target": subject,
            "source_line_start": g._line(guard), "source_line_end": insert_dec.end_point[0] + 1,
            "source_entities": {"table": "messages", "resource_table": "matches", "profile_table": "founder_profiles",
                                "client": client, "subject": subject, "match": match, "profile": profile, "user": user,
                                "subject_field": "match_id", "sender_field": "sender_id"},
            "source_lines": {"auth": g._line(auth_dec), "match_query": g._line(match_dec),
                             "profile_query": g._line(profile_dec), "ownership_guard": g._line(guard),
                             "insert": g._line(insert_node)},
            "detail": "A same-function return guard compares the authenticated-user lookup's profile id "
                      "with both participants of the match selected by the inserted match_id. The immediately "
                      "following messages insert uses that same match_id and profile id as sender_id. "
                      "This contradicts only absence of a local ownership guard; runtime authentication, "
                      "foreign keys, RLS, successful writes and concurrent membership changes remain unverified."}


def check_source(data, path, request):
    result = _unknown(request)
    start, end = request.get("line_start"), request.get("line_end")
    if (request.get("kind") != KIND or len(data) > MAX_FILE_BYTES
            or not isinstance(request.get("target", ""), str) or len(request.get("target", "")) > 128
            or type(start) is not int or type(end) is not int
            or not 1 <= start <= end <= len(data.splitlines())
            or not path.endswith((".ts", ".tsx", ".js", ".jsx"))):
        return result
    parser = Parser(Language(tree_sitter_typescript.language_tsx() if path.endswith((".tsx", ".jsx"))
                             else tree_sitter_typescript.language_typescript()))
    root = parser.parse(data).root_node
    if root.has_error:
        return result
    nodes = []
    for node in g._walk(root):
        nodes.append(node)
        if len(nodes) > g.MAX_NODES:
            return result
    functions = [n for n in nodes if n.type in g._FUNCTIONS
                 and n.child_by_field_name("body") is not None
                 and n.child_by_field_name("body").type == "statement_block"]
    matches = [n for n in functions if g._line(n) <= start <= end <= n.end_point[0] + 1]
    if not matches:
        return result
    fn = min(matches, key=lambda n: n.end_byte - n.start_byte)
    anchor_start, anchor_end = request.get("anchor_line_start", start), request.get("anchor_line_end", end)
    if (type(anchor_start) is not int or type(anchor_end) is not int
            or not g._line(fn) <= anchor_start <= anchor_end <= fn.end_point[0] + 1
            or any(n != fn and not (n.start_byte <= fn.start_byte and n.end_byte >= fn.end_byte)
                   and g._line(n) <= end and n.end_point[0] + 1 >= start for n in functions)):
        return result
    fn_nodes = list(g._walk(fn))
    if len(fn_nodes) > g.MAX_FUNCTION_NODES:
        return result
    proof = _proof(root, fn, list(g._walk(fn.child_by_field_name("body"), g._SKIP)),
                   g._bindings(fn_nodes), request.get("target", ""))
    if proof:
        result.update(proof, result="contradicted")
    return result

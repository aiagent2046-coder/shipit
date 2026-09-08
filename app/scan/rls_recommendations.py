"""Bounded RLS declaration context for client-change recommendations.

Migration text is evidence about committed declarations, never deployed policy
state or authorization. No SQL, JavaScript, or uploaded expression is executed.
"""
from bisect import bisect_left
from collections import defaultdict
import re
import stat
import zipfile

from pglast import ast as sql, parse_sql, scan
from pglast.parser import ParseError
from tree_sitter import Language, Parser
import tree_sitter_typescript

from app.scan.secrets import is_non_production_path

MAX_FILE_BYTES = 512_000
MAX_TOTAL_BYTES = 4_000_000
MAX_FILES = 300
MAX_NODES = 80_000
MAX_EVENTS = 512
MAX_RECORDS = 64
MAX_REFERENCES = 16
SCOPE = (
    "Direct literal-table JavaScript/TypeScript query-chain syntax and top-level PostgreSQL "
    "CREATE/ALTER/DROP POLICY declarations in numbered migration files. Migration filename order "
    "is only a declared candidate sequence, not applied database state. An unqualified .from() "
    "is compared conditionally with public; client configuration and runtime binding are not verified. "
    "Policy commands do not prove access: roles, grants, predicates, restrictive policies, RLS state, "
    "JWT claims, search_path and migration application must be checked. Missing declarations do not "
    "prove missing protection. Procedural/dynamic SQL, tests and vendor files are not policy evidence."
)
_WRITE_COMMANDS = {"insert": ("INSERT",), "update": ("UPDATE",), "delete": ("DELETE",),
                   "upsert": ("INSERT", "UPDATE")}
_ALL_COMMANDS = {"SELECT", "INSERT", "UPDATE", "DELETE"}
_EXCLUDED = {"vendor", "node_modules", "venv", ".venv", "archive", "archived", "test", "tests",
             "__tests__", "fixtures", "__fixtures__", "examples", "example", "docs", "spec", "specs"}


def _identifier(value):
    # Only identifiers required for joining references are retained, never SQL
    # predicates, JS argument values, credentials, or policy expression text.
    return (value if isinstance(value, str) and 0 < len(value) <= 128
            and all(c.isalnum() or c in "_ -.$" for c in value) else None)


def _table(node):
    name = _identifier(node.relname)
    schema = _identifier(node.schemaname) if node.schemaname else None
    return (schema, name) if name and (node.schemaname is None or schema) else None


def _sql_events(source, path, limits):
    events = []
    try:
        statements = parse_sql(source)
        starts = [token.start for token in scan(source)
                  if token.name not in {"SQL_COMMENT", "C_COMMENT", "ASCII_59"}]
    except (ParseError, ValueError, RecursionError):
        limits.add("unparseable_migration_sql")
        return None
    for raw in statements:
        node = raw.stmt
        index = bisect_left(starts, raw.stmt_location)
        # pglast exposes Python character offsets, including for non-ASCII
        # comments. Skip those comments when pointing at the actual statement.
        start = starts[index] if index < len(starts) else raw.stmt_location
        line = source[:start].count("\n") + 1
        # Do not mine a DO/function string for unconditional policy statements.
        if isinstance(node, (sql.DoStmt, sql.CreateFunctionStmt)):
            limits.add("procedural_sql_not_resolved")
            continue
        kind = name = table = None
        detail = {}
        if isinstance(node, (sql.CreatePolicyStmt, sql.AlterPolicyStmt)):
            kind = "create" if isinstance(node, sql.CreatePolicyStmt) else "alter"
            table, name = _table(node.table), _identifier(node.policy_name)
            if kind == "create":
                detail["command"] = node.cmd_name.upper()
                detail["permissive"] = bool(node.permissive)
            # Roles are reduced to a fixed vocabulary; arbitrary role names and
            # all predicate literals remain outside the report.
            if node.roles:
                detail["roles"] = sorted({
                    "public" if r.roletype.name == "ROLESPEC_PUBLIC" else
                    r.rolename if r.rolename in {"anon", "authenticated", "service_role"} else "other"
                    for r in node.roles})
            detail["using_present"] = node.qual is not None
            detail["with_check_present"] = node.with_check is not None
        elif isinstance(node, sql.DropStmt) and node.removeType.name == "OBJECT_POLICY":
            for parts in node.objects:
                names = [p.sval for p in parts if isinstance(p, sql.String)]
                if len(names) not in {2, 3} or not all(_identifier(n) for n in names):
                    limits.add("unsupported_policy_identifier")
                    continue
                events.append({"event": "drop", "schema": names[0] if len(names) == 3 else None,
                               "table": names[-2], "policy": names[-1], "file": path,
                               "line": line})
            continue
        elif isinstance(node, sql.RenameStmt) and node.renameType.name in {"OBJECT_POLICY", "OBJECT_TABLE",
                                                                         "OBJECT_SCHEMA"}:
            limits.add("policy_or_table_rename_not_resolved")
        elif isinstance(node, sql.DropStmt) and node.removeType.name in {"OBJECT_TABLE", "OBJECT_SCHEMA"}:
            limits.add("table_or_schema_drop_not_resolved")
        elif isinstance(node, sql.AlterObjectSchemaStmt) and node.objectType.name == "OBJECT_TABLE":
            limits.add("table_schema_change_not_resolved")
        if kind:
            if not table or not name:
                limits.add("unsupported_policy_identifier")
                continue
            events.append({"event": kind, "schema": table[0], "table": table[1], "policy": name,
                           "file": path, "line": line,
                           **detail})
    return events


def _walk(root):
    todo = [root]
    while todo:
        node = todo.pop()
        yield node
        todo.extend(reversed(node.named_children))


def _member_call(node):
    if node is None or node.type != "call_expression" or node.child_by_field_name("optional_chain"):
        return None
    fn = node.child_by_field_name("function")
    if fn is None or fn.type != "member_expression" or fn.child_by_field_name("optional_chain"):
        return None
    prop = fn.child_by_field_name("property")
    if prop is None or prop.type != "property_identifier":
        return None
    args = node.child_by_field_name("arguments")
    return (prop.text.decode("utf-8"), fn.child_by_field_name("object"),
            [n for n in args.named_children if n.type != "comment"] if args else [])


def _literal_identifier(args):
    if len(args) != 1 or args[0].type != "string":
        return None
    # Escapes/interpolation are not reconstructed or guessed.
    if any(n.type != "string_fragment" for n in args[0].named_children):
        return None
    return _identifier(args[0].text.decode("utf-8")[1:-1])


def _operations(source, path, limits):
    parser = Parser(Language(tree_sitter_typescript.language_tsx()
                             if path.endswith((".tsx", ".jsx")) else tree_sitter_typescript.language_typescript()))
    tree = parser.parse(source)
    if tree.root_node.has_error:
        limits.add("unparseable_js_ts")
        return None
    result = []
    for count, node in enumerate(_walk(tree.root_node), 1):
        if count > MAX_NODES:
            limits.add("js_node_budget_reached")
            break
        call = _member_call(node)
        if not call or call[0] not in _WRITE_COMMANDS:
            continue
        operation, receiver, _ = call
        # Only direct .from(literal).write() chains, not aliased builders.
        origin = _member_call(receiver)
        if not origin or origin[0] != "from":
            continue
        table = _literal_identifier(origin[2])
        if not table:
            limits.add("dynamic_or_unsupported_table")
            continue
        schema_call = _member_call(origin[1])
        schema = _literal_identifier(schema_call[2]) if schema_call and schema_call[0] == "schema" else "public"
        if not schema or (schema_call and schema_call[0] != "schema"):
            limits.add("unresolved_client_schema")
            continue
        result.append({"file": path, "line": node.start_point[0] + 1,
                       "line_end": node.end_point[0] + 1, "table": table, "schema": schema,
                       "schema_basis": "explicit_schema_call" if schema_call else "conditional_default_public",
                       "operation": operation.upper(), "required_commands": list(_WRITE_COMMANDS[operation])})
        if len(result) >= MAX_RECORDS:
            limits.add("operation_limit_reached")
            break
    return result


def collect_rls_recommendations(fileobj):
    """Return bounded operation/policy references without authorization verdicts."""
    operations, migrations = [], []
    limits = set()
    used = attempted = parsed = excluded = 0
    with zipfile.ZipFile(fileobj) as archive:
        for info in sorted(archive.infolist(), key=lambda i: i.filename):
            path = info.filename
            parts = path.split("/")
            sql_file = path.lower().endswith(".sql") and "migrations" in parts
            if info.is_dir() or not (sql_file or path.endswith((".ts", ".tsx", ".js", ".jsx"))):
                continue
            if (stat.S_ISLNK(info.external_attr >> 16) or is_non_production_path(path)
                    or any(p.lower() in _EXCLUDED for p in parts)):
                excluded += 1
                continue
            if attempted >= MAX_FILES or used + info.file_size > MAX_TOTAL_BYTES:
                limits.add("scan_budget_reached")
                break
            if info.file_size > MAX_FILE_BYTES or len(path) > 512:
                limits.add("file_size_or_path_limit")
                continue
            attempted += 1
            used += info.file_size
            data = archive.read(info)
            try:
                if sql_file:
                    numbered = re.fullmatch(r"(\d+)[_-].*\.sql", parts[-1], re.I)
                    if not numbered or parts[-2] != "migrations":
                        limits.add("unnumbered_or_nested_migration")
                        continue
                    events = _sql_events(data.decode("utf-8"), path, limits)
                    parsed += events is not None
                    migrations.append((path, numbered[1], events or []))
                elif len(operations) < MAX_RECORDS:
                    found = _operations(data, path, limits)
                    parsed += found is not None
                    found = found or []
                    if len(operations) + len(found) > MAX_RECORDS:
                        limits.add("operation_limit_reached")
                    operations.extend(found[:MAX_RECORDS - len(operations)])
                else:
                    limits.add("operation_limit_reached")
            except (UnicodeError, ValueError, RecursionError):
                limits.add("unparseable_source")
    # Filename order is meaningful only within one migration directory and
    # without duplicate number prefixes. It is never the deployed order.
    roots = {path.rsplit("/", 1)[0] for path, _, _ in migrations}
    prefixes = [prefix for _, prefix, _ in migrations]
    if len(roots) > 1 or len(prefixes) != len(set(prefixes)):
        limits.add("migration_order_ambiguous")
    migrations.sort(key=lambda item: item[0].rsplit("/", 1)[-1])
    all_events = [event for _, _, events in migrations for event in events]
    if len(all_events) > MAX_EVENTS:
        limits.add("policy_event_limit_reached")
        all_events = all_events[:MAX_EVENTS]
    histories = defaultdict(list)
    active = {}
    for event in all_events:
        table_key = event["schema"], event["table"]
        key = (*table_key, event["policy"])
        histories[table_key].append(event)
        if event["event"] == "drop":
            active.pop(key, None)
        elif event["event"] == "create":
            if key in active:
                limits.add("duplicate_policy_create")
            active[key] = event
        elif key in active:
            # ALTER POLICY cannot change the command; record the altered role
            # vocabulary without interpreting either predicate's SQL body.
            active[key] = {**active[key], **{k: event[k] for k in ("roles",) if k in event}}
        else:
            limits.add("alter_without_observed_create")
    policy_limits = limits - {"operation_limit_reached", "js_node_budget_reached", "unparseable_js_ts",
                              "dynamic_or_unsupported_table", "unresolved_client_schema"}
    records = []
    for operation in operations:
        key = operation["schema"], operation["table"]
        history = histories.get(key, [])
        unqualified = histories.get((None, operation["table"]), [])
        commands = set()
        for (schema, table, _), declaration in active.items():
            if (schema, table) == key:
                commands.update(_ALL_COMMANDS if declaration["command"] == "ALL" else {declaration["command"]})
        complete = not policy_limits and not unqualified and bool(migrations)
        record_limits = sorted(policy_limits | ({"unqualified_policy_schema"} if unqualified else set()))
        evidence = history + unqualified
        if len(evidence) > MAX_REFERENCES:
            record_limits.append("policy_reference_limit")
        records.append({"kind": "rls_write_recommendation", **operation,
                        "sequence_status": "declared_filename_sequence" if complete else "incomplete_or_ambiguous",
                        "commands_in_declared_sequence": sorted(commands) if complete else None,
                        "missing_command_declarations": sorted(set(operation["required_commands"]) - commands)
                        if complete else None,
                        "policy_history": evidence[-MAX_REFERENCES:], "limitations": record_limits})
    return {"scope": SCOPE, "records": records, "parsed_files": parsed, "checked_files": attempted,
            "migration_files": len(migrations), "excluded_files": excluded, "limitations": sorted(limits)}


def rls_recommendation_context(finding, facts):
    """Contextualize a client-change suggestion; never dismiss the finding."""
    advice = str(finding.get("fix_hint", ""))[:16000]
    text = " ".join(str(finding.get(k, "")) for k in ("title", "explanation", "observation", "fix_hint"))[:32000]
    if (not re.search(r"service[\s_-]*role", text, re.I)
            or not re.search(r"\b(?:anon(?:ymous)?(?:[ -]key)?|user[ -]scoped)\b", advice, re.I)
            or not re.search(r"\b(?:use|switch|replace|client|jwt|bearer)\b", advice, re.I)):
        return []
    contexts = []
    for record in (facts.get("rls_recommendations") or {}).get("records", []):
        if record["file"] != finding.get("file"):
            continue
        contexts.append({"kind": "rls_recommendation_context", "result": "observed", **{
            k: v for k, v in record.items() if k != "kind"},
            "summary": "A literal-table write chain is present in the cited file. Before replacing a "
            "service-role client with a caller-scoped client, check applicable INSERT/UPDATE/DELETE policies "
            "for the recorded operation. SELECT policies alone do not authorize writes. Declarations for "
            "a command do not prove that their roles, predicates or grants permit this request.",
            "detail": SCOPE})
        if len(contexts) >= 8:
            break
    return contexts

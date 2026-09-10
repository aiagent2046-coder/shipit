"""SQL built by string assembly in TypeScript and JavaScript.

WHY A SECOND MODULE. app/scan/sql_injection.py answers the same question for
Python, and its docstring says why the TS/JS half was not shipped with it: the
sinks are different, the parser is different, and one rule id claiming both
while checking one would misdescribe what was examined. This is that half.

WHY IT MATTERS MORE THAN THE PYTHON ONE. Drydock audits Next.js repositories
in the main. A rule that only reads .py files therefore does not run at all on
the typical customer's code, which made the Python-only detector a correct
thing that mostly could not fire.

THE ONE DISTINCTION THE RULE TURNS ON, same as its Python sibling:

    db.query("SELECT * FROM t WHERE id = " + userId)   a defect
    db.query("SELECT " + "1")                          harmless
    sql`SELECT * FROM t WHERE id = ${userId}`          harmless, and NOT a
                                                       template literal misuse

The third is the one a regex gets wrong. A TAGGED template -- `sql`, `db.sql`,
Prisma's `$queryRaw` -- is how these libraries express a PARAMETERISED query:
the driver receives the fragments and the values separately, exactly as a
placeholder does. Reporting it would flag the fix. tree-sitter separates the
two cleanly: a tagged template is a call_expression whose template_string is a
direct child, while an interpolated argument sits inside `arguments`.

WHAT IT DOES NOT CLAIM. That a query is assembled from strings is a fact about
the source, not proof of a reachable exploit; taint across call boundaries is
not attempted, and silence is not a certificate. Only known execution sinks are
examined, so ordinary string building is left alone.

NEVER EXECUTES THE UPLOADED CODE. tree-sitter builds a syntax tree; nothing
here evaluates, imports or runs any of it.
"""

from __future__ import annotations

import zipfile
from dataclasses import dataclass
from typing import BinaryIO

import tree_sitter_typescript
from tree_sitter import Language, Parser

from app.scan.checks import CheckFinding
from app.scan.secrets import _iter_text_files, is_non_production_path

RULE_ID = "sql-injection-string-built-query"

# Call names that hand a string to a database, matched on the property alone:
# `db.query`, `client.query`, `conn.execute`, `knex.raw`, `sequelize.query`.
# Pinning the receiver would mean tracking what `db` was assigned from -- the
# taint analysis this rule deliberately does not attempt.
#
# `$queryRawUnsafe` and `$executeRawUnsafe` are Prisma's own name for "this one
# is not parameterised"; `$queryRaw` without the suffix is a tagged template and
# is safe, which the tagged-template rule below already handles.
_SINKS = frozenset({
    "query", "execute", "raw", "unsafe",
    "$queryRawUnsafe", "$executeRawUnsafe",
    "executeSql", "exec", "run", "all", "get",
    # Added after a hunt run reached for them as database method names. Both
    # were MEASURED against 5059 real files first and matched nothing, so they
    # cost no noise. `prepare` was measured at the same time and REJECTED: 7
    # hits in undici's sqlite cache store, where the interpolated value is a
    # module constant (`const VERSION = 3`) rather than input.
    "select", "fetch",
    # Wrapper names. A project that hides its driver behind a helper still
    # hands it an assembled string, and a hunt run reached for exactly these
    # spellings. Measured across 5158 files (web/src, a real Next.js repo,
    # 5000 from node_modules): zero calls, so they cost nothing.
    "executeQuery", "runQuery", "queryDatabase", "sqlQuery", "executeSQL",
})

# Sinks called as a bare function rather than a method: `executeQuery(sql)`.
# Only the unambiguous spellings -- a bare `query(x)` or `get(x)` is far too
# common in ordinary code to read as a database call, while a name containing
# both a verb and "query"/"sql" is not something you call by accident.
_BARE_SINKS = frozenset({
    "executeQuery", "runQuery", "queryDatabase", "sqlQuery", "executeSQL",
    "$queryRawUnsafe", "$executeRawUnsafe", "executeSql",
})

# Sinks whose name is common enough outside databases that the name alone is
# not evidence. `get`/`run`/`all` are node-sqlite3's API, but also half the
# verbs in JavaScript, so they only count when the argument is assembled AND
# the text looks like SQL. `fetch` and `select` are here for the same reason
# and a stronger one: `fetch` is the browser's own HTTP function, and
# `db.fetch("...")` being a query is an assumption the SQL shape has to earn.
_WEAK_SINKS = frozenset({"get", "run", "all", "exec", "execute", "fetch", "select"})

# A conservative SQL shape: a statement keyword followed by the clause that
# must accompany it. Used only to qualify the weak sinks above.
_SQL_HINTS = ("select ", "insert into", "update ", "delete from", "drop table",
              "alter table", "create table", "union select", " from ", " where ")

_SOURCE_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs")

_MAX_FILE_BYTES = 400_000
_MAX_FILES = 400
_MAX_FINDINGS = 32
_MAX_NODES = 80_000


def _text(node) -> str:
    return node.text.decode("utf-8", "replace") if node is not None else ""


def _walk(node, limit: int):
    """Depth-first over named nodes, bounded so one file cannot stall a scan."""
    todo, seen = [node], 0
    while todo:
        current = todo.pop()
        seen += 1
        if seen > limit:
            return
        yield current
        todo.extend(reversed(current.named_children))


def _looks_like_sql(text: str) -> bool:
    low = text.lower()
    return any(hint in low for hint in _SQL_HINTS)


def _unwrap(node):
    """Parentheses and TS type-only expressions preserve the runtime value."""
    while node is not None and node.type in {
        "parenthesized_expression", "as_expression", "satisfies_expression",
        "non_null_expression", "type_assertion",
    }:
        children = [child for child in node.named_children if child.type != "comment"]
        if not children:
            return None
        node = children[-1] if node.type == "type_assertion" else children[0]
    return node


def _is_literal(node, known: frozenset[str] = frozenset()) -> bool:
    node = _unwrap(node)
    if node is None:
        return False
    if node.type in {"string", "number", "true", "false", "null", "regex"}:
        return True
    if node.type == "identifier":
        return _text(node) in known
    if node.type == "template_string":
        return all(child.type != "template_substitution"
                   or all(_is_literal(expr, known) for expr in child.named_children)
                   for child in node.named_children)
    if node.type == "binary_expression":
        return (_text(node.child_by_field_name("operator")) == "+"
                and _is_literal(node.child_by_field_name("left"), known)
                and _is_literal(node.child_by_field_name("right"), known))
    if node.type == "array":
        return all(_is_literal(child, known) for child in node.named_children
                   if child.type != "comment")
    if node.type == "call_expression":
        func = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if func is not None and func.type == "member_expression" and args is not None:
            return (_text(func.child_by_field_name("property")) in {"join", "concat", "replace"}
                    and _is_literal(func.child_by_field_name("object"), known)
                    and all(_is_literal(arg, known) for arg in args.named_children
                            if arg.type != "comment"))
    return False


def _assembly_kind(node, known: frozenset[str] = frozenset()) -> str | None:
    node = _unwrap(node)
    if node is None or _is_literal(node, known):
        return None
    if node.type == "template_string":
        return "a template literal with ${...}"
    if node.type == "binary_expression" and _text(node.child_by_field_name("operator")) == "+":
        return "string concatenation with +"
    if node.type == "call_expression":
        func = node.child_by_field_name("function")
        if func is not None and func.type == "member_expression":
            name = _text(func.child_by_field_name("property"))
            if name in {"concat", "replace", "join"}:
                return f".{name}()"
    return None


def _sink_name(call) -> str | None:
    """The sink this call invokes, or None.

    A TAGGED TEMPLATE IS NOT A SINK CALL. `sql`...`` and `prisma.$queryRaw`...``
    parse as a call_expression whose template_string is a direct child rather
    than an argument, and they are the parameterised form -- the fragments and
    the values reach the driver separately. Excluding them here is the whole
    reason this rule can be run on TypeScript without reporting the fix.
    """
    if call.type != "call_expression":
        return None
    if any(c.type == "template_string" for c in call.named_children):
        return None
    func = call.child_by_field_name("function")
    if func is None:
        return None
    if func.type == "identifier":
        # A bare call: executeQuery(sql). Only the unambiguous names, see
        # _BARE_SINKS -- reading every `query(x)` as a database call would
        # report half the ordinary code in a project.
        name = _text(func)
        return name if name in _BARE_SINKS else None
    if func.type != "member_expression":
        return None
    name = _text(func.child_by_field_name("property"))
    return name if name in _SINKS else None


def _first_argument(call):
    args = call.child_by_field_name("arguments")
    if args is None:
        return None
    named = [c for c in args.named_children if c.type != "comment"]
    return named[0] if named else None


@dataclass(frozen=True)
class _Binding:
    literal: bool = False
    sql: bool = False
    assembly: tuple[int, str] | None = None


_UNKNOWN = _Binding()
_FUNCTIONS = frozenset({"function_declaration", "function_expression", "arrow_function",
                        "generator_function_declaration", "generator_function", "method_definition"})


def _pattern_names(node):
    if node is None:
        return set()
    if node.type in {"identifier", "shorthand_property_identifier_pattern"}:
        return {_text(node)}
    if node.type in {"required_parameter", "optional_parameter"}:
        return _pattern_names(node.child_by_field_name("pattern"))
    if node.type in {"assignment_pattern", "object_assignment_pattern"}:
        return _pattern_names(node.child_by_field_name("left"))
    if node.type == "pair_pattern":
        return _pattern_names(node.child_by_field_name("value"))
    if node.type in {"array_pattern", "object_pattern", "rest_pattern", "formal_parameters"}:
        return set().union(*(_pattern_names(child) for child in node.named_children))
    return set()


def _scope_writes(root):
    """Counts within one function, plus var names that are function-scoped."""
    writes, hoisted = {}, set()
    pending = list(root.named_children)
    while pending:
        node = pending.pop()
        if node.type in _FUNCTIONS:
            name = node.child_by_field_name("name")
            if name is not None:
                writes[_text(name)] = writes.get(_text(name), 0) + 1
            continue
        target = None
        if node.type == "variable_declarator":
            target = node.child_by_field_name("name")
            if node.parent.type == "variable_declaration":
                hoisted.update(_pattern_names(target))
        elif node.type in {"assignment_expression", "augmented_assignment_expression"}:
            target = node.child_by_field_name("left")
        elif node.type == "update_expression":
            target = node.child_by_field_name("argument")
        elif node.type == "for_in_statement":
            target = node.child_by_field_name("left")
        for name in _pattern_names(target):
            writes[name] = writes.get(name, 0) + 1
        pending.extend(node.named_children)
    return {name for name, count in writes.items() if count == 1}, hoisted


class _Environment:
    def __init__(self, captures=None):
        self.frames = [dict(captures), {}] if captures is not None else [{}]
        self.function_slot = len(self.frames) - 1

    def copy(self):
        result = _Environment()
        result.frames = [frame.copy() for frame in self.frames]
        result.function_slot = self.function_slot
        return result

    def visible(self):
        return {name: value for frame in self.frames for name, value in frame.items()}

    def get(self, name):
        for frame in reversed(self.frames):
            if name in frame:
                return frame[name]
        return _UNKNOWN

    def bind(self, target, value, declaration=False, function_scoped=False):
        names = _pattern_names(target)
        if target is not None and target.type != "identifier":
            value = _Binding(literal=value.literal)
        for name in names:
            if declaration:
                self.frames[self.function_slot if function_scoped else -1][name] = value
            else:
                frame = next((frame for frame in reversed(self.frames) if name in frame),
                             self.frames[self.function_slot])
                frame[name] = value
        if target is not None and target.type in {"subscript_expression", "member_expression"}:
            root = target.child_by_field_name("object")
            if root is not None and root.type == "identifier":
                self.bind(root, _UNKNOWN)


def _merge_environments(*environments):
    paths = [environment for environment in environments if environment is not None]
    if not paths:
        return None
    result = paths[0].copy()
    for index, frame in enumerate(result.frames):
        for name in set().union(*(path.frames[index] for path in paths)):
            values = [path.frames[index].get(name, _UNKNOWN) for path in paths]
            frame[name] = _Binding(
                literal=all(value.literal for value in values),
                sql=any(value.sql for value in values),
                assembly=next((value.assembly for value in values if value.assembly), None),
            )
    return result


class _QueryFlow:
    """Track current values in lexical scopes, without calling uploaded code."""

    def __init__(self):
        self.findings = set()
        self.remaining = _MAX_NODES

    def has_sql(self, node, environment):
        node = _unwrap(node)
        if node is None:
            return False
        if node.type == "identifier":
            return environment.get(_text(node)).sql
        if node.type in {"string", "template_string"}:
            return _looks_like_sql(_text(node))
        return any(self.has_sql(child, environment) for child in node.named_children)

    def value(self, node, environment):
        node = _unwrap(node)
        if node is None:
            return _UNKNOWN
        if node.type == "identifier":
            return environment.get(_text(node))
        known = frozenset(name for name, value in environment.visible().items() if value.literal)
        sql = self.has_sql(node, environment)
        if _is_literal(node, known):
            return _Binding(literal=True, sql=sql)
        kind = _assembly_kind(node, known)
        return _Binding(sql=sql, assembly=(node.start_point[0] + 1, kind) if kind else None)

    def scope(self, node, environment, stable):
        captures = {name: value for name, value in environment.visible().items()
                    if (value.literal or value.assembly) and name in stable}
        local = _Environment(captures)
        local_stable, hoisted = _scope_writes(node)
        for name in hoisted:
            local.frames[-1][name] = _UNKNOWN
        for field in ("parameters", "parameter"):
            parameters = node.child_by_field_name(field)
            for name in _pattern_names(parameters):
                local.frames[-1][name] = _UNKNOWN
        body = node.child_by_field_name("body")
        self.visit(body, local, local_stable | set(captures))

    @staticmethod
    def predeclare(node, environment):
        # let/const shadow the outer binding throughout the block, including
        # before their declaration (the temporal dead zone).
        for child in node.named_children:
            if child.type == "export_statement":
                child = child.child_by_field_name("declaration") or child
            if child.type == "lexical_declaration":
                for declaration in child.named_children:
                    environment.bind(declaration.child_by_field_name("name"), _UNKNOWN, declaration=True)
            elif child.type in _FUNCTIONS or child.type == "class_declaration":
                environment.bind(child.child_by_field_name("name"), _UNKNOWN, declaration=True)

    def visit(self, node, environment, stable):
        if node is None or environment is None or self.remaining <= 0:
            return environment
        self.remaining -= 1
        kind = node.type
        if kind in _FUNCTIONS:
            self.scope(node, environment, stable)
            return environment
        if kind in {"program", "statement_block"}:
            block = kind == "statement_block"
            if block:
                environment.frames.append({})
            self.predeclare(node, environment)
            current = environment
            for child in node.named_children:
                current = self.visit(child, current, stable)
                if current is None:
                    break
            if block:
                # Even a terminating branch must restore its own frame stack.
                environment.frames.pop()
                if current is not None and current is not environment:
                    current.frames.pop()
            return current
        if kind == "variable_declarator":
            value = node.child_by_field_name("value")
            self.visit(value, environment, stable)
            target = node.child_by_field_name("name")
            if value is not None:
                environment.bind(target, self.value(value, environment), declaration=True,
                                 function_scoped=node.parent.type == "variable_declaration")
            elif node.parent.type != "variable_declaration":
                environment.bind(target, _UNKNOWN, declaration=True)
            return environment
        if kind in {"assignment_expression", "augmented_assignment_expression"}:
            target, right = node.child_by_field_name("left"), node.child_by_field_name("right")
            before = self.value(target, environment)
            self.visit(right, environment, stable)
            value = self.value(right, environment)
            if kind == "augmented_assignment_expression":
                if _text(node.child_by_field_name("operator")) == "+=":
                    literal = before.literal and value.literal
                    value = _Binding(literal=literal, sql=before.sql or value.sql,
                                     assembly=None if literal else before.assembly or
                                     (node.start_point[0] + 1, "string concatenation with +"))
                else:
                    value = _UNKNOWN
            environment.bind(target, value)
            return environment
        if kind == "update_expression":
            environment.bind(node.child_by_field_name("argument"), _UNKNOWN)
            return environment
        if kind in {"if_statement", "ternary_expression"}:
            self.visit(node.child_by_field_name("condition"), environment, stable)
            return _merge_environments(
                self.visit(node.child_by_field_name("consequence"), environment.copy(), stable),
                self.visit(node.child_by_field_name("alternative"), environment.copy(), stable),
            )
        if kind in {"for_in_statement", "for_statement", "while_statement", "do_statement"}:
            environment.frames.append({})
            self.visit(node.child_by_field_name("initializer"), environment, stable)
            right = node.child_by_field_name("right")
            self.visit(right, environment, stable)
            entry, loop = environment.copy(), environment.copy()
            for _ in range(2):
                if kind == "for_in_statement":
                    target = node.child_by_field_name("left")
                    declaration = any(child.type in {"const", "let", "var"} for child in node.children)
                    loop.bind(target, _Binding(literal=self.value(right, loop).literal),
                              declaration=declaration,
                              function_scoped=any(child.type == "var" for child in node.children))
                self.visit(node.child_by_field_name("condition"), loop, stable)
                body = self.visit(node.child_by_field_name("body"), loop, stable)
                body = self.visit(node.child_by_field_name("increment"), body, stable)
                loop = _merge_environments(entry, body)
            loop.frames.pop()
            return loop
        if kind == "try_statement":
            body = self.visit(node.child_by_field_name("body"), environment.copy(), stable)
            handler = node.child_by_field_name("handler")
            branches = [body]
            if handler is not None:
                caught = _merge_environments(environment, body)
                caught.frames.append({})
                caught.bind(handler.child_by_field_name("parameter"), _UNKNOWN, declaration=True)
                caught = self.visit(handler.child_by_field_name("body"), caught, stable)
                if caught is not None:
                    caught.frames.pop()
                branches.append(caught)
            merged = _merge_environments(*branches)
            return self.visit(node.child_by_field_name("finalizer"), merged, stable)
        # Evaluate nested assignments and calls before consuming their values.
        for child in node.named_children:
            result = self.visit(child, environment, stable)
            if result is not None:
                environment = result
        sink = _sink_name(node)
        if sink is not None:
            argument = _unwrap(_first_argument(node))
            value = self.value(argument, environment)
            if value.assembly and (sink not in _WEAK_SINKS or value.sql):
                line, assembly = value.assembly
                if argument.type == "identifier":
                    assembly = f"{assembly} at line {line}"
                self.findings.add((node.start_point[0] + 1, sink, assembly))
        if kind == "call_expression":
            function = node.child_by_field_name("function")
            if function is not None and function.type == "member_expression":
                if _text(function.child_by_field_name("property")) in {"push", "unshift", "splice", "fill"}:
                    environment.bind(function.child_by_field_name("object"), _UNKNOWN)
        return None if kind in {"return_statement", "throw_statement"} else environment


def _findings_for(source: bytes, path: str) -> list[tuple[int, str, str]]:
    language = (tree_sitter_typescript.language_tsx()
                if path.endswith((".tsx", ".jsx"))
                else tree_sitter_typescript.language_typescript())
    root = Parser(Language(language)).parse(source).root_node
    if root.has_error:
        return []
    flow = _QueryFlow()
    stable, hoisted = _scope_writes(root)
    environment = _Environment()
    for name in hoisted:
        environment.frames[-1][name] = _UNKNOWN
    try:
        flow.visit(root, environment, stable)
    except RecursionError:
        # Parser success does not imply a recursive visitor can traverse an
        # arbitrarily deep expression. Keep the rest of the archive scannable.
        pass
    return sorted(flow.findings)


def scan_sql_injection_js(fileobj: BinaryIO) -> list[CheckFinding]:
    """One finding per built query, at most _MAX_FINDINGS per archive."""
    fileobj.seek(0)
    findings: list[CheckFinding] = []
    seen = 0

    with zipfile.ZipFile(fileobj) as zf:
        for name, text in _iter_text_files(zf):
            if seen >= _MAX_FILES or len(findings) >= _MAX_FINDINGS:
                break
            if not name.lower().endswith(_SOURCE_EXTS) or is_non_production_path(name):
                continue
            if len(text) > _MAX_FILE_BYTES:
                continue
            seen += 1

            for line, sink, kind in _findings_for(text.encode("utf-8"), name):
                if len(findings) >= _MAX_FINDINGS:
                    break
                observation = (
                    f"The query text passed to {sink}() at line {line} in {name} is built with "
                    f"{kind} rather than passed as a parameter."
                )
                findings.append(CheckFinding(
                    rule_id=RULE_ID,
                    title="Database query assembled from a string instead of parameters",
                    severity="high",
                    # Matches the Python rule. The source fact is certain --
                    # the parser saw the construct. What is uncertain is whether
                    # the interpolated value is attacker-controlled, which needs
                    # taint analysis this rule does not perform.
                    confidence=0.7,
                    category="Security",
                    file=name,
                    line=line,
                    explanation=observation + " If any part of that string comes from a request, "
                    "a form, a URL or another user-controlled source, the database receives it as "
                    "SQL rather than as data, and an attacker can change what the query does -- "
                    "read other people's rows, or delete them. Whether this particular value is "
                    "reachable from user input has NOT been verified; the string assembly is what "
                    "was observed.",
                    fix_hint="Pass the values as parameters and keep the query text a plain "
                    "literal: db.query('SELECT * FROM users WHERE id = $1', [userId]). Libraries "
                    "that offer a tagged template -- sql`...`, prisma.$queryRaw`...` -- "
                    "parameterise for you and are safe; the unsafe variants are the ones named "
                    "$queryRawUnsafe. Where a table or column name must vary, pick it from a "
                    "fixed allow-list in code rather than interpolating it.",
                ))
    return findings

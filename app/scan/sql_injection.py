"""SQL built by string assembly, where a parameter belongs.

WHY THIS EXISTS. tests/detectors/README.md names SQL injection as a gap the
corpus does not cover, and it is the defect a buyer expects a security audit to
find. Nothing else in the static stage looks for it: the secret rules read
literals, `rls.py` reads migrations, and neither notices a query whose text is
concatenated together at the call site.

WHAT IT REPORTS, AND WHAT IT DOES NOT CLAIM. One thing only: a call to a
database execution sink whose FIRST argument -- the query text -- is assembled
from something that is not a literal. That is a fact about the source. It is
NOT proof of an exploitable injection: whether the interpolated value reaches
an attacker requires taint analysis across call boundaries, which this does not
do and does not pretend to. The inverse is not claimed either -- silence here
is not a certificate that a repository is free of SQL injection. Ordinary
non-SQL string building is left alone; only known execution sinks are examined.

WHY AST, NOT A REGEX. The whole rule turns on one distinction:

    cur.execute("SELECT * FROM t WHERE id = " + user_id)    a defect
    cur.execute("SELECT " + "1")                            harmless

Both are string concatenation inside execute(). What separates them is whether
an operand is a literal, and a regex over source text cannot see that -- it
sees two plus signs. `ast` answers it exactly, and refusing to guess is the
difference between a finding an owner acts on and one they learn to ignore.

Python only, deliberately. TS/JS query building is a real defect too, but it
needs the tree-sitter path and a different sink vocabulary, and shipping half
of it under a rule id that claims both would misdescribe what was checked.

NEVER EXECUTES THE UPLOADED CODE. ast.parse builds a tree; it does not run a
module, import it, or evaluate any expression inside it.
"""

from __future__ import annotations

import ast
import zipfile
from dataclasses import dataclass
from typing import BinaryIO

from app.scan.checks import CheckFinding
from app.scan.secrets import _iter_text_files, is_non_production_path

RULE_ID = "sql-injection-string-built-query"

# The call names that hand a string to a database. Method names, matched on the
# attribute alone: `cur.execute`, `conn.execute`, `session.execute`,
# `Model.objects.raw` all arrive here as `.attr`, and pinning the receiver would
# mean tracking what `cur` was assigned from -- the same taint analysis this
# rule deliberately does not attempt.
#
# `executescript` and `executemany` are included; `fetchall` and friends are
# not, because they take no query. `raw` covers Django's raw() and the raw()
# helpers ORMs expose. `text()` is NOT here: SQLAlchemy's text() is how you
# declare a parameterised statement, and flagging it would report the fix.
_SINKS = frozenset({"execute", "executemany", "executescript", "raw", "execute_sql"})

# Bound so a generated or vendored file cannot turn one archive into a parse
# storm. 400 KB is past every hand-written module in this repository.
_MAX_FILE_BYTES = 400_000
_MAX_FILES = 400
_MAX_FINDINGS = 32


def _is_literal(node: ast.AST, known: frozenset[str] = frozenset()) -> bool:
    """A string literal, or literals combined with each other.

    `"a" + "b"` is still a literal as far as injection goes: there is no value
    from outside in it. Recursing here is what keeps the harmless half of the
    concatenation distinction out of the report.

    `", ".join(("id", "state"))` counts too, and for the same reason -- it is
    how a codebase writes a column list without a 200-character line. Every
    element must itself be a literal, so `", ".join(user_input)` does not
    qualify. Comprehensions are included because app/db.py builds its qualified
    column list with one, and the element expression is checked the same way.

    `known` carries names already proven to hold literals in this file, which
    is what lets `", ".join(_NAMES)` resolve. It defaults to empty so the
    predicate stays usable before anything has been settled.
    """
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.Name):
        return node.id in known
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return _is_literal(node.left, known) and _is_literal(node.right, known)
    if isinstance(node, ast.JoinedStr):
        return all(isinstance(v, ast.Constant)
                   or (isinstance(v, ast.FormattedValue)
                       and _is_literal(v.value, known)
                       and (v.format_spec is None or _is_literal(v.format_spec, known)))
                   for v in node.values)
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return all(_is_literal(e, known) for e in node.elts)
    if isinstance(node, ast.Dict):
        # A table-name map is how a script keeps `{table: column}` beside the
        # query it drives. Both halves must be literal; `**other` (a None key)
        # is not something to trust, so it disqualifies.
        return (all(k is not None and _is_literal(k, known) for k in node.keys)
                and all(_is_literal(v, known) for v in node.values))
    if isinstance(node, ast.Call):
        # `SEP.join(<literals>)`, the only call shape trusted here.
        if (isinstance(node.func, ast.Attribute) and node.func.attr == "join"
                and _is_literal(node.func.value, known) and len(node.args) == 1):
            return _is_literal_iterable(node.args[0], known)
        # `.items()/.keys()/.values()` on something already literal. A loop
        # over a literal dict is the same case as a loop over a literal list,
        # and audit_test_data.py's ACCOUNT_CHILDREN was reported for the want
        # of it. The receiver carries the trust, so a call on a parameter or
        # on request data qualifies for nothing.
        if (isinstance(node.func, ast.Attribute)
                and node.func.attr in {"items", "keys", "values"}
                and not node.args
                and _is_literal(node.func.value, known)):
            return True
    return False


def _is_literal_iterable(node: ast.AST, known: frozenset[str] = frozenset()) -> bool:
    """What `join` may be handed: a literal sequence, or a comprehension over one."""
    if _is_literal(node, known):
        return True
    if isinstance(node, (ast.GeneratorExp, ast.ListComp)):
        # The produced element must be literal-ish; the loop variable is bound
        # to elements of a literal sequence, so an f-string over it carries no
        # external value. Only single-generator, filter-free forms qualify.
        if len(node.generators) != 1 or node.generators[0].ifs:
            return False
        if not _is_literal(node.generators[0].iter, known):
            return False
        bound = {n.id for n in ast.walk(node.generators[0].target) if isinstance(n, ast.Name)}
        element = node.elt
        if isinstance(element, ast.JoinedStr):
            return all(isinstance(v, ast.Constant)
                       or (isinstance(v, ast.FormattedValue)
                           and isinstance(v.value, ast.Name)
                           and v.value.id in bound)
                       for v in element.values)
        return _is_literal(element, known | frozenset(bound))
    return False


def _assembly_kind(node: ast.AST, known: frozenset[str] = frozenset()) -> str | None:
    """How this query text was built, or None if it was not built at all.

    Returns a short phrase naming the construct, so the finding can say what
    the reader should look for rather than making them re-derive it.
    """
    if _is_literal(node, known):
        return None

    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return "string concatenation with +"

    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        # `"... %s" % value`. Note this is the OLD formatting operator, not a
        # driver placeholder: `cur.execute("... %s", (value,))` has no BinOp at
        # all and never reaches here, which is exactly the line between the
        # defect and its fix.
        return "%-formatting"

    if isinstance(node, ast.JoinedStr):
        return "an f-string"

    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr in {"format", "join"} and _is_literal(node.func.value, known):
            return f".{node.func.attr}()"

    return None


@dataclass(frozen=True)
class _Binding:
    literal: bool = False
    assembly: tuple[int, str] | None = None


_UNKNOWN = _Binding()
_LITERAL = _Binding(literal=True)


def _merge_states(*states: dict[str, _Binding] | None) -> dict[str, _Binding] | None:
    """Keep possible assembly paths, but trust a literal only on every path."""
    paths = [state for state in states if state is not None]
    if not paths:
        return None
    merged = {}
    for name in set().union(*paths):
        values = [state.get(name, _UNKNOWN) for state in paths]
        assembly = next((value.assembly for value in values if value.assembly), None)
        merged[name] = _Binding(all(value.literal for value in values), assembly)
    return merged


def _scope_bindings(scope: ast.AST) -> tuple[set[str], set[str]]:
    """Local names and names written once, without entering nested scopes."""
    writes: dict[str, int] = {}
    pending = list(ast.iter_child_nodes(scope))
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            writes[node.name] = writes.get(node.name, 0) + 1
            continue
        if isinstance(node, (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            continue
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            writes[node.id] = writes.get(node.id, 0) + 1
        elif isinstance(node, ast.arg):
            writes[node.arg] = writes.get(node.arg, 0) + 1
        pending.extend(ast.iter_child_nodes(node))
    # A global/nonlocal writer may run after a function was defined. Do not
    # freeze that name's earlier literal value into another function's scope.
    mutable = {name for node in ast.walk(scope)
               if isinstance(node, (ast.Global, ast.Nonlocal)) for name in node.names}
    return set(writes), {name for name, count in writes.items() if count == 1} - mutable


class _QueryFlow:
    """Bounded, source-ordered local bindings; never execute a function call."""

    def __init__(self):
        self.findings: set[tuple[int, str, str]] = set()
        self.remaining = 80_000

    @staticmethod
    def known(state):
        return frozenset(name for name, value in state.items() if value.literal)

    def value(self, node, state):
        if node is None:
            return _UNKNOWN
        if isinstance(node, ast.Name):
            return state.get(node.id, _UNKNOWN)
        if _is_literal(node, self.known(state)):
            return _LITERAL
        kind = _assembly_kind(node, self.known(state))
        return _Binding(assembly=(node.lineno, kind)) if kind else _UNKNOWN

    def assign(self, target, value, state):
        if isinstance(target, ast.Name):
            state[target.id] = value
        elif isinstance(target, (ast.Tuple, ast.List)):
            # Destructuring an unknown value must invalidate every target.
            for child in target.elts:
                self.assign(child, _LITERAL if value.literal else _UNKNOWN, state)
        elif isinstance(target, ast.Starred):
            self.assign(target.value, value, state)
        elif isinstance(target, (ast.Subscript, ast.Attribute)):
            root = target.value
            while isinstance(root, (ast.Subscript, ast.Attribute)):
                root = root.value
            if isinstance(root, ast.Name):
                state[root.id] = _UNKNOWN

    def scope(self, node, inherited):
        local, stable = _scope_bindings(node)
        state = dict(inherited)
        for name in local:
            state[name] = _UNKNOWN
        stable |= set(inherited) - local
        if isinstance(node, ast.Lambda):
            self.expression(node.body, state, stable)
        else:
            self.block(node.body, state, stable)

    def expression(self, node, state, stable):
        if node is None or self.remaining <= 0:
            return
        self.remaining -= 1
        if isinstance(node, ast.Lambda):
            self.scope(node, {k: v for k, v in state.items() if k in stable})
            return
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            inner = state.copy()
            for generator in node.generators:
                self.expression(generator.iter, inner, stable)
                self.assign(generator.target, _LITERAL if self.value(generator.iter, inner).literal
                            else _UNKNOWN, inner)
                for condition in generator.ifs:
                    self.expression(condition, inner, stable)
            for item in ([node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]):
                self.expression(item, inner, stable)
            return
        if isinstance(node, ast.NamedExpr):
            self.expression(node.value, state, stable)
            self.assign(node.target, self.value(node.value, state), state)
            return
        for child in ast.iter_child_nodes(node):
            self.expression(child, state, stable)
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            return
        if node.func.attr in _SINKS and node.args:
            argument = node.args[0]
            value = self.value(argument, state)
            if value.assembly:
                line, kind = value.assembly
                if isinstance(argument, ast.Name):
                    kind = f"{kind} at line {line}"
                self.findings.add((node.lineno, node.func.attr, kind))
        # A literal container stops being a constant after an opaque mutation.
        if node.func.attr in {"append", "extend", "insert", "update", "add", "setdefault"}:
            self.assign(node.func.value, _UNKNOWN, state)

    def block(self, statements, state, stable, captures=None):
        for node in statements:
            if self.remaining <= 0 or state is None:
                break
            self.remaining -= 1
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for expr in [*node.decorator_list, *node.args.defaults, *node.args.kw_defaults]:
                    self.expression(expr, state, stable)
                outer = captures if captures is not None else {k: v for k, v in state.items() if k in stable}
                self.scope(node, outer)
                state[node.name] = _UNKNOWN
            elif isinstance(node, ast.ClassDef):
                for expr in [*node.decorator_list, *node.bases]:
                    self.expression(expr, state, stable)
                outer = {k: v for k, v in state.items() if k in stable}
                _, class_stable = _scope_bindings(node)
                self.block(node.body, outer.copy(), class_stable, captures=outer)
                state[node.name] = _UNKNOWN
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                if node.value is None:  # An annotation alone does not rebind.
                    continue
                self.expression(node.value, state, stable)
                value = self.value(node.value, state)
                for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
                    self.assign(target, value, state)
            elif isinstance(node, ast.AugAssign):
                self.expression(node.value, state, stable)
                before, right = self.value(node.target, state), self.value(node.value, state)
                if isinstance(node.op, ast.Add):
                    value = (_LITERAL if before.literal and right.literal else
                             _Binding(assembly=before.assembly or (node.lineno, "string concatenation with +")))
                else:
                    value = _UNKNOWN
                self.assign(node.target, value, state)
            elif isinstance(node, ast.If):
                self.expression(node.test, state, stable)
                state = _merge_states(self.block(node.body, state.copy(), stable, captures),
                                      self.block(node.orelse, state.copy(), stable, captures))
            elif isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
                self.expression(node.test if isinstance(node, ast.While) else node.iter, state, stable)
                entry = state.copy()
                loop = state.copy()
                # Include a second iteration for queries assembled at the end
                # of a loop and executed at its beginning on the next pass.
                for _ in range(2):
                    if not isinstance(node, ast.While):
                        self.assign(node.target, _LITERAL if self.value(node.iter, loop).literal
                                    else _UNKNOWN, loop)
                    loop = _merge_states(entry, self.block(node.body, loop, stable, captures))
                state = self.block(node.orelse, loop, stable, captures)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    self.expression(item.context_expr, state, stable)
                    if item.optional_vars:
                        self.assign(item.optional_vars, _UNKNOWN, state)
                state = self.block(node.body, state, stable, captures)
            elif isinstance(node, (ast.Try, ast.TryStar)):
                body = self.block(node.body, state.copy(), stable, captures)
                paths = [self.block(node.orelse, body, stable, captures) if body is not None else None]
                for handler in node.handlers:
                    branch = _merge_states(state, body)
                    if handler.name:
                        branch[handler.name] = _UNKNOWN
                    paths.append(self.block(handler.body, branch, stable, captures))
                state = _merge_states(*paths)
                state = self.block(node.finalbody, state, stable, captures) if state is not None else None
            elif isinstance(node, ast.Match):
                self.expression(node.subject, state, stable)
                branches = [state]
                for case in node.cases:
                    branch = state.copy()
                    for pattern in ast.walk(case.pattern):
                        name = getattr(pattern, "name", None)
                        if isinstance(name, str):
                            branch[name] = _UNKNOWN
                    self.expression(case.guard, branch, stable)
                    branches.append(self.block(case.body, branch, stable, captures))
                state = _merge_states(*branches)
            elif isinstance(node, ast.Delete):
                for target in node.targets:
                    self.assign(target, _UNKNOWN, state)
            else:
                self.expression(node, state, stable)
                if isinstance(node, (ast.Return, ast.Raise)):
                    return None
                if isinstance(node, (ast.Break, ast.Continue)):
                    return state
        return state


def _find_in_module(tree: ast.AST) -> list[tuple[int, str, str]]:
    flow = _QueryFlow()
    _, stable = _scope_bindings(tree)
    try:
        flow.block(tree.body, {}, stable)
    except RecursionError:
        # A deeply nested uploaded expression must not abort the archive's
        # static stage. Preserve findings already established before the limit.
        pass
    return sorted(flow.findings)


def scan_sql_injection(fileobj: BinaryIO) -> list[CheckFinding]:
    """One finding per built query, at most _MAX_FINDINGS per archive."""
    fileobj.seek(0)
    findings: list[CheckFinding] = []
    seen = 0

    with zipfile.ZipFile(fileobj) as zf:
        for name, text in _iter_text_files(zf):
            if seen >= _MAX_FILES or len(findings) >= _MAX_FINDINGS:
                break
            if not name.lower().endswith(".py") or is_non_production_path(name):
                continue
            if len(text) > _MAX_FILE_BYTES:
                continue
            seen += 1
            try:
                tree = ast.parse(text)
            except (SyntaxError, ValueError, RecursionError):
                # An unparseable file is not a clean file; it is one this rule
                # could not read. Skipping is the honest answer -- the
                # alternative is a regex fallback that would reintroduce the
                # literal-vs-variable confusion ast was chosen to avoid.
                continue

            for line, sink, kind in _find_in_module(tree):
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
                    # Not critical, and not lower. The source fact is certain --
                    # ast saw the construct. What is uncertain is whether the
                    # interpolated value is attacker-controlled, which needs
                    # taint analysis across call boundaries this rule does not
                    # perform. 0.7 is that split: a real defect in the code,
                    # unproven as a reachable exploit.
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
                    fix_hint="Pass the values as parameters instead of building the string: "
                    "cur.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,)) -- the driver "
                    "then sends them separately from the SQL and they cannot change its meaning. "
                    "Keep the query text a plain literal. Where a table or column name really must "
                    "vary, select it from a fixed allow-list in code rather than interpolating it.",
                ))
    return findings

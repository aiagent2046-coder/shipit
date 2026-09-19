"""SQL built by string assembly, where a parameter belongs.

WHY THIS EXISTS. tests/detectors/README.md names SQL injection as a gap the
corpus does not cover, and it is the defect a buyer expects a security audit to
find. Nothing else in the static stage looks for it: the secret rules read
literals, `rls.py` reads migrations, and neither notices a query whose text is
concatenated together at the call site.

WHAT IT REPORTS, AND WHAT IT DOES NOT CLAIM. One thing only: a call to a
database execution sink whose FIRST argument -- the query text, possibly
through a single import-resolved sqlalchemy text() wrapper -- is assembled
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
import hashlib
import zipfile
import zlib
from dataclasses import dataclass
from typing import BinaryIO

from app.scan.checks import CheckFinding
from app.scan.claim_evidence import static_claim_evidence
from app.scan.psycopg_provenance import cursor_provenance
from app.scan.rule_coverage import RuleCoverage, mark_analysis_limit, remaining_findings, track_analysis_limits

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

# The import spellings through which sqlalchemy's text() is recognized:
# module/submodule aliases (import sqlalchemy as sa, import sqlalchemy.sql as
# sas, plain import sqlalchemy) and from-imported text. Bindings live in the
# flow state, so imports resolve lexically, in source order; any later write
# of the name (assignment, attribute store, re-import, def, except-as,
# parameter) drops the binding in exactly the scope and position it happens.
# text() is not a SINK: it constructs a statement object and runs nothing.
_TEXT_MODULES = frozenset({"sqlalchemy", "sqlalchemy.sql"})
_TEXT_FROM = frozenset({"sqlalchemy.text", "sqlalchemy.sql.text"})


def _text_import_targets(node: ast.AST):
    """Names an import binds and any proven sqlalchemy target they receive.

    Every explicit import is returned, including unrelated imports whose
    target is None: rebinding sa to another module must drop an earlier
    sqlalchemy provenance at that exact source position.
    """
    if isinstance(node, ast.Import):
        for alias in node.names:
            bound = alias.asname or alias.name.split(".")[0]
            target = None
            if alias.name in _TEXT_MODULES:
                # A plain dotted import binds its root; an as-alias binds the
                # requested dotted module directly.
                target = alias.name if alias.asname else alias.name.split(".")[0]
            yield bound, target
    elif isinstance(node, ast.ImportFrom):
        for alias in node.names:
            if alias.name == "*":
                continue
            dotted = f"{node.module}.{alias.name}" if node.module else alias.name
            yield alias.asname or alias.name, dotted if dotted in _TEXT_FROM else None

# Bound so a generated or vendored file cannot turn one archive into a parse
# storm. 400 KB is past every hand-written module in this repository.
_MAX_FILE_BYTES = 400_000
_MAX_FILES = 400
_MAX_FINDINGS = 32
_MAX_NODES = 80_000

# Machine-readable names follow the existing AST classifications. Keep the
# prose labels unchanged: they are part of the detector's legacy output.
_ASSEMBLY_KINDS = {
    "string concatenation with +": "concatenation",
    "%-formatting": "percent_format",
    "an f-string": "f_string",
    ".format()": "format_call",
    ".join()": "join_call",
}


class _AnalysisLimitReached(Exception):
    """Stop before an incompletely evaluated query can become a finding."""


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
    if isinstance(node, ast.IfExp):
        # A runtime condition may select fixed SQL fragments without adding
        # runtime data to the query. Do not resolve side effects from a final
        # state snapshot; expression() handles those in evaluation order.
        return (not any(isinstance(child, ast.NamedExpr) for child in ast.walk(node))
                and _is_literal(node.body, known) and _is_literal(node.orelse, known))
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
        # `"...{}".format(<literals>)` -- a format call on a literal template
        # whose every argument is itself a literal is still a literal string;
        # there is nothing from outside in it. A starred argument spreads an
        # unknown sequence and a `**` keyword (arg None) spreads an unknown
        # mapping, so both disqualify, as does any non-literal argument: the
        # value it carries into the query is exactly what the finding is for.
        if (isinstance(node.func, ast.Attribute) and node.func.attr == "format"
                and _is_literal(node.func.value, known)
                and not any(isinstance(arg, ast.Starred) for arg in node.args)
                and all(_is_literal(arg, known) for arg in node.args)
                and all(keyword.arg is not None and _is_literal(keyword.value, known)
                        for keyword in node.keywords)):
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
        if (not node.generators[0].is_async and isinstance(node.elt, ast.Constant)
                and node.elt.value == "?"
                and not any(isinstance(child, ast.NamedExpr) for child in ast.walk(node))):
            # Input changes the number of placeholders, never SQL characters.
            return True
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
    container: bool = False
    # The dotted import target this name is import-bound to in the current
    # scope ("sqlalchemy", "sqlalchemy.sql", "sqlalchemy.text", ...). It lives
    # in the binding state so imports resolve lexically, in source order, and
    # any later write of the name drops it.
    imported: str | None = None


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
        # An import binding is trusted only when every path agrees on it:
        # a conditional import must not prove the name anywhere.
        imported = (values[0].imported
                    if all(value.imported == values[0].imported for value in values)
                    else None)
        merged[name] = _Binding(all(value.literal for value in values), assembly,
                                all(value.container for value in values), imported)
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
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            # An import binds its name here; counting it as a write is what
            # lets an import-bound name become stable and cross into nested
            # function scopes -- and what zeroes a function-local import at
            # scope entry, to be bound again at its source position.
            for alias in node.names:
                bound = alias.asname or alias.name.split(".")[0]
                writes[bound] = writes.get(bound, 0) + 1
        pending.extend(ast.iter_child_nodes(node))
    # A global/nonlocal writer may run after a function was defined. Do not
    # freeze that name's earlier literal value into another function's scope.
    mutable = {name for node in ast.walk(scope)
               if isinstance(node, (ast.Global, ast.Nonlocal)) for name in node.names}
    containers = {target.id for node in ast.walk(scope) if isinstance(node, (ast.Assign, ast.AnnAssign))
                  and isinstance(node.value, (ast.List, ast.Dict, ast.Set))
                  for target in (node.targets if isinstance(node, ast.Assign) else [node.target])
                  if isinstance(target, ast.Name)}
    mutations = set()
    for node in ast.walk(scope):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr not in {"items", "keys", "values", "join"}:
                mutations.update(child.id for child in ast.walk(node.func.value) if isinstance(child, ast.Name))
            mutations.update(child.id for argument in [*node.args, *(kw.value for kw in node.keywords)]
                           for child in ast.walk(argument) if isinstance(child, ast.Name))
        elif isinstance(node, (ast.Subscript, ast.Attribute)) and isinstance(node.ctx, (ast.Store, ast.Del)):
            mutations.update(child.id for child in ast.walk(node.value) if isinstance(child, ast.Name))
    mutable.update(mutations & containers)
    return set(writes), {name for name, count in writes.items() if count == 1} - mutable


class _QueryFlow:
    """Bounded, source-ordered local bindings; never execute a function call."""

    def __init__(self):
        self.findings: set[tuple[int, str, str]] = set()
        self.observations: dict[tuple[int, str, str], dict] = {}
        self.remaining = _MAX_NODES

    def _text_import(self, node: ast.AST, state) -> str | None:
        """The dotted import target a func spelling resolves to, in this state."""
        if isinstance(node, ast.Name):
            return state.get(node.id, _UNKNOWN).imported
        if isinstance(node, ast.Attribute):
            base = self._text_import(node.value, state)
            return f"{base}.{node.attr}" if base else None
        return None

    def _is_text_wrapper(self, node: ast.AST, state) -> bool:
        """A single-argument, keyword-free sqlalchemy text() call, resolved here."""
        if not (isinstance(node, ast.Call) and len(node.args) == 1 and not node.keywords):
            return False
        return self._text_import(node.func, state) in _TEXT_FROM

    @staticmethod
    def known(state):
        return frozenset(name for name, value in state.items() if value.literal)

    def value(self, node, state):
        if node is None:
            return _UNKNOWN
        if isinstance(node, ast.Name):
            return state.get(node.id, _UNKNOWN)
        if isinstance(node, ast.Constant):
            return _LITERAL
        if not isinstance(node, (ast.BinOp, ast.JoinedStr, ast.Tuple, ast.List,
                                 ast.Set, ast.Dict, ast.Call, ast.IfExp)):
            return _UNKNOWN
        known = self.known(state)
        if _is_literal(node, known):
            return _Binding(literal=True, container=isinstance(node, (ast.List, ast.Set, ast.Dict)))
        kind = _assembly_kind(node, known)
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
        if node is None:
            return _UNKNOWN
        if self.remaining <= 0:
            raise _AnalysisLimitReached
        self.remaining -= 1
        if isinstance(node, ast.Lambda):
            self.scope(node, {k: v for k, v in state.items() if k in stable})
            return _UNKNOWN
        if isinstance(node, ast.IfExp):
            self.expression(node.test, state, stable)
            paths, values = [], []
            for arm in (node.body, node.orelse):
                branch = state.copy()
                values.append(self.expression(arm, branch, stable))
                paths.append(branch)
            # The arms are mutually exclusive. In particular, a walrus in
            # one arm cannot replace the value observed in the other arm.
            state.update(_merge_states(*paths))
            return _Binding(all(value.literal for value in values),
                            next((value.assembly for value in values if value.assembly), None))
        if isinstance(node, ast.BoolOp):
            self.expression(node.values[0], state, stable)
            for item in node.values[1:]:
                branch = state.copy()
                self.expression(item, branch, stable)
                # Later operands may not execute. Keep the path that skips
                # a conditional assignment as well as the path that runs it.
                state.update(_merge_states(state, branch))
            return _UNKNOWN
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            left = self.expression(node.left, state, stable)
            right = self.expression(node.right, state, stable)
            if left.literal and right.literal:
                return _LITERAL
            kind = "string concatenation with +" if isinstance(node.op, ast.Add) else "%-formatting"
            return _Binding(assembly=(node.lineno, kind))
        if isinstance(node, ast.JoinedStr):
            values = [self.expression(part, state, stable) for part in node.values]
            return (_LITERAL if all(value.literal for value in values)
                    else _Binding(assembly=(node.lineno, "an f-string")))
        if isinstance(node, ast.FormattedValue):
            value = self.expression(node.value, state, stable)
            spec = (self.expression(node.format_spec, state, stable)
                    if node.format_spec is not None else _LITERAL)
            return _LITERAL if value.literal and spec.literal else _UNKNOWN
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
            return self.value(node, state)
        if isinstance(node, ast.NamedExpr):
            value = self.expression(node.value, state, stable)
            self.assign(node.target, value, state)
            return value
        if not isinstance(node, ast.Call):
            for child in ast.iter_child_nodes(node):
                self.expression(child, state, stable)
            return self.value(node, state)
        self.expression(node.func, state, stable)
        # Python resolves the callable before evaluating its arguments. Capture
        # provenance now: a walrus inside the argument can rebind the spelling,
        # but cannot change the function object already selected for this call.
        text_wrapper = self._is_text_wrapper(node, state)
        dynamic_import = None
        if (isinstance(node.func, ast.Name)
                and node.func.id in {"setattr", "delattr"} and node.args):
            dynamic_import = self._text_import(node.args[0], state)
        arguments = [self.expression(argument, state, stable) for argument in node.args]
        for keyword in node.keywords:
            self.expression(keyword.value, state, stable)
        # Mutable lists passed to arbitrary code can be changed through aliases.
        # They cannot establish safe fragments at a later sink.
        literal_join = (isinstance(node.func, ast.Attribute) and node.func.attr == "join"
                        and isinstance(node.func.value, ast.Constant)
                        and isinstance(node.func.value.value, str) and len(node.args) == 1
                        and not node.keywords)
        for argument in [*node.args, *(kw.value for kw in node.keywords)]:
            if not literal_join:
                for child in ast.walk(argument):
                    if isinstance(child, ast.Name) and state.get(child.id, _UNKNOWN).container:
                        state[child.id] = _UNKNOWN
        # A single sqlalchemy text() wrapper is transparent: the call's value
        # is the value of its own evaluated argument, captured here in
        # evaluation order. text() over a literal stays literal (the declared
        # parameterised form); over an assembled string the assembly is what
        # the sink runs.
        if dynamic_import in _TEXT_MODULES:
            # Builtin-style dynamic member replacement destroys confidence in
            # every imported member reached through that module spelling.
            self.assign(node.args[0], _UNKNOWN, state)
        if text_wrapper:
            return arguments[0]
        if not isinstance(node.func, ast.Attribute):
            return self.value(node, state)
        if node.func.attr in _SINKS and node.args:
            argument = node.args[0]
            # Later arguments can reassign names, but cannot change the query
            # text already evaluated as the first argument.
            # The first argument may be a text() wrapper: expression()
            # returned the wrapper's own evaluated argument for it, so this
            # binding was captured at the moment the argument evaluated -- a
            # walrus in a later argument cannot change what is read here.
            value = arguments[0]
            if value.assembly:
                line, kind = value.assembly
                assembly_kind = _ASSEMBLY_KINDS[kind]
                if isinstance(argument, ast.Name):
                    kind = f"{kind} at line {line}"
                signal = (node.lineno, node.func.attr, kind)
                self.findings.add(signal)
                # Merged branches and bounded loop passes preserve a possible
                # assembly value, not proof that a runtime execution takes it.
                # The first supporting trace is enough when legacy findings
                # collapse multiple same-line observations into one signal.
                self.observations.setdefault(signal, {
                    "assembly_line": line,
                    "assembly_kind": assembly_kind,
                    "sink_line": node.lineno,
                    "sink_method": node.func.attr,
                    "flow_status": "possible_local_flow",
                })
        # A literal container stops being a constant after an opaque mutation.
        if node.func.attr in {"append", "extend", "insert", "update", "add", "setdefault"}:
            receiver = self.value(node.func.value, state)
            safe_append = (node.func.attr == "append" and receiver.literal and receiver.container
                           and len(arguments) == 1 and not node.keywords
                           and arguments[0].literal and not arguments[0].container)
            if not safe_append:
                self.assign(node.func.value, _UNKNOWN, state)
        return self.value(node, state)

    def block(self, statements, state, stable, captures=None):
        for node in statements:
            if state is None:
                break
            if self.remaining <= 0:
                raise _AnalysisLimitReached
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
                value = self.expression(node.value, state, stable)
                escaped = {child.id for child in ast.walk(node.value) if isinstance(child, ast.Name)
                           and state.get(child.id, _UNKNOWN).container}
                if escaped and isinstance(node.value, (ast.Name, ast.List, ast.Tuple, ast.Dict, ast.Set, ast.IfExp)):
                    # Refuse alias tracking rather than freezing a mutable
                    # fragment list when another name can append request data.
                    for name in escaped:
                        state[name] = _UNKNOWN
                    value = _UNKNOWN
                for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
                    if (isinstance(target, (ast.Tuple, ast.List))
                            and isinstance(node.value, (ast.Tuple, ast.List))
                            and len(target.elts) == len(node.value.elts)
                            and all(isinstance(item, ast.List) and not item.elts for item in node.value.elts)):
                        for child in target.elts:
                            self.assign(child, _Binding(literal=True, container=True), state)
                    else:
                        self.assign(target, value, state)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                # Imports bind in the scope being walked, at their position:
                # an import inside a function never proves the name at module
                # level, and one below the sink never proves it above. Every
                # explicit re-import writes its name; only recognized
                # sqlalchemy targets establish new provenance.
                if isinstance(node, ast.ImportFrom) and any(
                        alias.name == "*" for alias in node.names):
                    for name, value in tuple(state.items()):
                        if value.imported:
                            state[name] = _UNKNOWN
                for bound, target in _text_import_targets(node):
                    state[bound] = _Binding(imported=target) if target else _UNKNOWN
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


def _find_in_module(tree: ast.AST, *, observations: dict | None = None) -> list[tuple[int, str, str]]:
    """Keep legacy signals; optionally collect their source-location facts."""
    flow = _QueryFlow()
    try:
        _, stable = _scope_bindings(tree)
        flow.block(tree.body, {}, stable)
    except (RecursionError, _AnalysisLimitReached):
        # A deeply nested uploaded expression must not abort the archive's
        # static stage. Preserve findings already established before the limit.
        mark_analysis_limit()
    if observations is not None:
        observations.update(flow.observations)
    return sorted(flow.findings)


def scan_sql_injection(fileobj: BinaryIO, *, coverage: dict | None = None) -> list[CheckFinding]:
    """One finding per built query, at most _MAX_FINDINGS per archive."""
    fileobj.seek(0)
    findings: list[CheckFinding] = []
    finding_limit = remaining_findings(_MAX_FINDINGS)

    with zipfile.ZipFile(fileobj) as zf:
        # A repository-local module can shadow the installed driver. This
        # bounded source check does not resolve sys.path or import hooks.
        driver_shadowed = any(part.casefold().split(".", 1)[0] == "psycopg"
                              for info in zf.infolist() for part in info.filename.replace("\\", "/").split("/"))
        accounting = RuleCoverage(zf, extensions=(".py",), max_file_bytes=_MAX_FILE_BYTES,
                                  coverage=coverage, case_sensitive=False,
                                  exclude_symlinks=True, exclude_git_metadata=True)
        for info in accounting.files(findings, max_files=_MAX_FILES, max_findings=_MAX_FINDINGS):
            name = info.filename
            try:
                raw = zf.read(info)
            except (OSError, RuntimeError, zipfile.BadZipFile, zlib.error, EOFError, NotImplementedError):
                accounting.skip("read_error")
                continue
            try:
                text = raw.decode("utf-8")
            except UnicodeError:
                accounting.skip("decode_error")
                continue
            try:
                tree = ast.parse(text)
            except (SyntaxError, ValueError):
                # An unparseable file is not a clean file; it is one this rule
                # could not read. Skipping is the honest answer -- the
                # alternative is a regex fallback that would reintroduce the
                # literal-vs-variable confusion ast was chosen to avoid.
                accounting.skip("parse_error")
                continue
            except RecursionError:
                accounting.skip("ast_limit")
                continue

            observations: dict[tuple[int, str, str], dict] = {}
            with track_analysis_limits() as limits:
                signals = _find_in_module(tree, observations=observations)
            drivers = (cursor_provenance(tree, max_nodes=_MAX_NODES)
                       if signals and not driver_shadowed else {})
            source_digest = hashlib.sha256(raw).hexdigest()
            available = finding_limit - len(findings)
            for line, sink, kind in signals[:available]:
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
                    claim_evidence={
                        **static_claim_evidence(),
                        "observation": observation,
                        "sql_observation": {
                            "version": 2,
                            "method": "python_ast_local_flow",
                            "source_sha256": source_digest,
                            "file": name,
                            **observations[(line, sink, kind)],
                            "driver_status": "source_resolved" if (line, sink) in drivers else "unknown",
                            **({"driver_provenance": drivers[(line, sink)]} if (line, sink) in drivers else {}),
                            "input_control_status": "not_checked",
                        },
                    },
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
            if len(signals) > available:
                accounting.skip("finding_limit")
            elif limits:
                accounting.skip("analysis_limit")
            else:
                accounting.analyzed()
        accounting.finish()
    return findings

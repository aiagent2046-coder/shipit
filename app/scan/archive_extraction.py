"""Archive extraction with the fully-trusted filter explicitly requested.

tarfile extraction filters exist since Python 3.12: 'data' and 'tar' refuse
members that would escape the destination (MEASURED 2026-09-14 on 3.12.13:
both raise OutsideDestinationError for a ../ member), and zipfile sanitizes
absolute paths and .. components by itself, so neither is a sink. The
no-filter default is version-dependent -- 3.12/3.13 keep the unsafe legacy
behaviour behind a DeprecationWarning and 3.14 defaults to 'data' -- so a
static scan cannot call it unsafe. filter="fully_trusted" is the explicit
opt-out from every extraction check: MEASURED, it writes outside the
destination with no warning, on every Python that has the parameter.

WHAT IT REPORTS, AND WHAT IT DOES NOT CLAIM. One thing only: extract or
extractall with a literal filter="fully_trusted" keyword on an object
proven to come from tarfile.open -- a direct chain, or a name bound
exactly once to a tarfile.open call in the same lexical scope, before
the extraction (an assignment, or a with header whose body contains
the call). Conditional bindings must enclose the extraction in the same
branch. Deferred closures/type aliases, generic declarations, mutated
modules/receivers, a ** keyword spread, a variable or
non-literal filter, a missing filter, a rebound or shadowed receiver
name, a receiver from anywhere else and zipfile extraction are NOT
reported: none of them proves the opt-out. Where the archive bytes come
from has not been verified; the finding is the requested behaviour, not
a demonstrated escape.

NEVER EXECUTES THE UPLOADED CODE. ast.parse builds a tree; it does not
run a module, import it, or open any archive.
"""

from __future__ import annotations

import ast
import zipfile
from dataclasses import dataclass
from typing import BinaryIO

from app.scan.checks import CheckFinding
from app.scan.rule_coverage import remaining_findings, RuleCoverage
from app.scan.unsafe_deserialization import _Imports, _Scope

RULE_ID = "archive-extraction-fully-trusted"

# tarfile.open is TarFile.open; both spellings construct the archive object.
_OPEN_CALLS = frozenset({"tarfile.open", "tarfile.TarFile.open"})
_EXTRACT_MEMBERS = frozenset({"extract", "extractall"})

_MAX_FILE_BYTES = 400_000
_MAX_FILES = 400
_MAX_FINDINGS = 32
_MAX_AST_NODES = 20_000
_MAX_AST_DEPTH = 100

_CONFIDENCE = 0.9


@dataclass(frozen=True)
class _Evidence:
    line: int


@dataclass(frozen=True)
class _Binding:
    node: ast.AST
    scope: _Scope


def _open_call(node: ast.AST | None, imports: _Imports, scope: _Scope | None) -> bool:
    """node is a call the file's imports resolve to tarfile.open/TarFile.open."""
    return ("tarfile" not in imports.mutated_modules
            and isinstance(node, ast.Call) and scope is not None
            and imports.qualified(node.func, scope) in _OPEN_CALLS)


def _fully_trusted_filter(call: ast.Call) -> bool:
    """A literal filter="fully_trusted" keyword; ** spreads stay unknown.

    A ** spread can carry or override the filter at runtime, so its presence
    disqualifies the call. filter is keyword-only in every version that has
    it, so only the keyword form is recognized.
    """
    seen = False
    for keyword in call.keywords:
        if keyword.arg is None:
            return False
        if keyword.arg != "filter":
            continue
        if seen:
            return False
        seen = True
        value = keyword.value
        if not (isinstance(value, ast.Constant) and value.value == "fully_trusted"):
            return False
    return seen


def _target_names(target: ast.AST | None) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [name for element in target.elts for name in _target_names(element)]
    if isinstance(target, ast.Starred):
        return _target_names(target.value)
    return []


def _argument_names(args: ast.arguments) -> list[str]:
    names = [arg.arg for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs)]
    names += [args.vararg.arg] if args.vararg else []
    names += [args.kwarg.arg] if args.kwarg else []
    return names


def _bindings(tree: ast.Module, imports: _Imports) -> tuple[dict[str, _Binding], set[str]]:
    """Names bound exactly once to a tarfile.open call, one hop, lexical.

    A name qualifies when exactly one assignment target or with-header
    optional variable receives a tarfile.open call and nothing else in the
    file binds the name: parameters, loop and comprehension targets, except
    handlers, imports, match captures, walrus forms, other assignments and
    with headers all invalidate it. `with` headers record their statement so
    extract calls can be required to sit inside the block.
    """
    scopes = {id(call): scope for call, scope in imports.calls}
    candidates: dict[str, _Binding] = {}
    invalid: set[str] = set()

    def note(key: str, node: ast.AST, scope: _Scope | None = None) -> None:
        if key in candidates or key in invalid or scope is None:
            invalid.add(key)
        else:
            candidates[key] = _Binding(node, scope)

    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            qualifies = (isinstance(node, (ast.Assign, ast.AnnAssign))
                         and len(targets) == 1 and isinstance(targets[0], ast.Name)
                         and _open_call(node.value, imports, scopes.get(id(node.value))))
            for target in targets:
                for name in _target_names(target):
                    note(name, node, scopes.get(id(node.value)) if qualifies else None)
        elif isinstance(node, ast.NamedExpr):
            for name in _target_names(node.target):
                note(name, node)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                names = _target_names(item.optional_vars)
                qualifies = (isinstance(node, ast.With) and isinstance(item.optional_vars, ast.Name)
                             and _open_call(item.context_expr, imports, scopes.get(id(item.context_expr))))
                for name in names:
                    note(name, node, scopes.get(id(item.context_expr)) if qualifies else None)
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
            for name in _target_names(node.target):
                note(name, node)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            note(node.name, node)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            for name in _argument_names(node.args):
                note(name, node)
            if not isinstance(node, ast.Lambda):
                note(node.name, node)
        elif isinstance(node, ast.ClassDef):
            note(node.name, node)
        elif isinstance(node, ast.TypeAlias):
            for name in _target_names(node.name):
                note(name, node)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Del):
            note(node.id, node)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                note(alias.asname or alias.name.split(".")[0], node)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            invalid.update(node.names)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            note(node.name, node)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            note(node.rest, node)
    for target, _scope in imports.mutations:
        while isinstance(target, (ast.Attribute, ast.Subscript)):
            target = target.value
        if isinstance(target, ast.Name):
            invalid.add(target.id)
    return candidates, invalid


def _regions(tree: ast.Module) -> dict[int, frozenset[tuple[int, str]]]:
    """Cache enclosing statement-list regions once, within the bounded AST."""
    result: dict[int, frozenset[tuple[int, str]]] = {}
    pending = [(tree, frozenset())]
    while pending:
        node, regions = pending.pop()
        result[id(node)] = regions
        if (isinstance(node, ast.TypeAlias)
                or isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.type_params):
            # Lazy aliases and generic declarations have type-parameter scopes
            # that the shared import resolver does not model. Defaults and
            # bodies cannot reuse the surrounding module's import provenance.
            continue
        for field, value in ast.iter_fields(node):
            children = value if isinstance(value, list) else [value]
            for child in children:
                if isinstance(child, ast.AST):
                    nested = regions
                    if field in {"body", "orelse", "finalbody", "handlers", "cases"}:
                        nested = regions | {(id(node), field)}
                    pending.append((child, nested))
    return result


def _binding_reaches(binding: _Binding, call: ast.Call, scope: _Scope,
                     regions: dict[int, frozenset[tuple[int, str]]]) -> bool:
    """Same-scope, preceding binding in the same enclosing control branches."""
    if binding.scope is not scope:
        return False
    node = binding.node
    if isinstance(node, ast.With):
        if (id(node), "body") not in regions[id(call)]:
            return False
    elif (node.end_lineno, node.end_col_offset) >= (call.lineno, call.col_offset):
        return False
    current: _Scope | None = scope
    while current:
        if current.wildcard:
            return False
        current = current.parent
    return regions[id(node)] <= regions[id(call)]


def _evidence(tree: ast.Module) -> list[_Evidence]:
    imports = _Imports(tree)
    candidates, invalid = _bindings(tree, imports)
    proven = {name: node for name, node in candidates.items() if name not in invalid}
    regions = _regions(tree)
    found: list[_Evidence] = []
    for node, scope in imports.calls:
        if id(node) not in regions:
            continue
        if not isinstance(node.func, ast.Attribute) or node.func.attr not in _EXTRACT_MEMBERS:
            continue
        receiver = node.func.value
        if _open_call(receiver, imports, scope):
            proven_receiver = True
        elif isinstance(receiver, ast.Name) and receiver.id in proven:
            binding = proven[receiver.id]
            if not _binding_reaches(binding, node, scope, regions):
                continue
            proven_receiver = True
        else:
            continue
        if proven_receiver and _fully_trusted_filter(node):
            found.append(_Evidence(node.lineno))
    return found


def _bounded(tree: ast.Module) -> bool:
    pending: list[tuple[ast.AST, int]] = [(tree, 0)]
    count = 0
    while pending:
        node, depth = pending.pop()
        count += 1
        if count > _MAX_AST_NODES or depth > _MAX_AST_DEPTH:
            return False
        pending.extend((child, depth + 1) for child in ast.iter_child_nodes(node))
    return True


def scan_archive_extraction(fileobj: BinaryIO, *, coverage: dict | None = None) -> list[CheckFinding]:
    findings: list[CheckFinding] = []
    with zipfile.ZipFile(fileobj) as archive:
        accounting = RuleCoverage(archive, extensions=(".py",),
                                  max_file_bytes=_MAX_FILE_BYTES, coverage=coverage)
        for info in accounting.files(findings, max_files=_MAX_FILES, max_findings=_MAX_FINDINGS):
            raw = archive.read(info)
            if b"tarfile" not in raw:
                accounting.analyzed()
                continue
            try:
                source = raw.decode("utf-8")
            except UnicodeError:
                accounting.skip("decode_error")
                continue
            try:
                tree = ast.parse(source)
            except (SyntaxError, ValueError):
                accounting.skip("parse_error")
                continue
            except RecursionError:
                accounting.skip("ast_limit")
                continue
            if not _bounded(tree):
                accounting.skip("ast_limit")
                continue
            try:
                evidence = _evidence(tree)
            except RecursionError:
                accounting.skip("ast_limit")
                continue
            remaining = remaining_findings(_MAX_FINDINGS) - len(findings)
            findings.extend(_finding(info.filename, item) for item in evidence[:remaining])
            if len(evidence) > remaining:
                accounting.skip("finding_limit")
            else:
                accounting.analyzed()
        accounting.finish()
    return findings


def _finding(path: str, item: _Evidence) -> CheckFinding:
    return CheckFinding(
        rule_id=RULE_ID,
        title="Archive extraction explicitly opts out of safety filtering",
        severity="high",
        confidence=_CONFIDENCE,
        category="Security",
        file=path,
        line=item.line,
        explanation=(
            f"Line {item.line} extracts a tarfile archive with filter=\"fully_trusted\", the "
            "explicit opt-out from extraction checks. A member named with an absolute path or "
            "../ components then writes outside the destination on every Python that has the "
            "parameter (measured on 3.12.13: fully_trusted writes outside where 'data' and "
            "'tar' refuse the same member). Where the archive bytes come from has NOT been "
            "verified; trusted internal archives and untrusted uploads reach the same call."
        ),
        fix_hint=(
            "Drop filter=\"fully_trusted\". Pass filter=\"data\" (the 3.14 default) or "
            "filter=\"tar\", or omit the argument on Python 3.14+, and never extract an "
            "archive from an untrusted source with filtering disabled."
        ),
    )

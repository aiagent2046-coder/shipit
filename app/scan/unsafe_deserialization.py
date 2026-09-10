"""Import-resolved Python deserialization calls that require trusted inputs.

Pickle-family loads, pandas.read_pickle, jsonpickle.decode, confirmed unsafe YAML
loaders and explicit torch.load(weights_only=False) can construct arbitrary
objects. A bare Unpickler constructor is not a load; its immediate .load() is.
Marshal has a separate warning: it can return code objects without executing them.
A YAML call without Loader is version-dependent (modern PyYAML raises TypeError).
Bare torch.load is also version-dependent and remains outside this rule's scope.

Names are resolved through this file's imports, respecting lexical shadowing,
source order and stable enclosing bindings. Unknown calls, assignment aliases,
conditional imports, monkey-patched modules and custom YAML loaders remain unknown.
Input provenance, dependency versions and cross-file resolution are not checked.
AST parsing is bounded; no uploaded code is imported, called or deserialized.
"""

from __future__ import annotations

import ast
import zipfile
from dataclasses import dataclass
from typing import BinaryIO

from app.scan.checks import CheckFinding
from app.scan.secrets import is_non_production_path

RULE_ID = "unsafe-deserialization"

# Modules whose loaders execute code, mapped to whether every member counts. A
# module listed here is not a name match: the call is looked up by (module, member)
# so `yaml.load` can be judged on its Loader while `yaml.safe_load` never is.
_ALWAYS_UNSAFE = {
    "pickle": {"load", "loads", "Unpickler.load"},
    "cPickle": {"load", "loads", "Unpickler.load"},
    "_pickle": {"load", "loads", "Unpickler.load"},
    "dill": {"load", "loads", "Unpickler.load"},
    "marshal": {"load", "loads"},
    "jsonpickle": {"decode"},
    "pandas": {"read_pickle"},
}

_PICKLE_MODULES = frozenset({"pickle", "cPickle", "_pickle", "dill"})
# Only these confirmed library classes establish arbitrary-object loading. Safe,
# Base and Full loaders (including import aliases) are silent, as are unknown
# custom loaders: a name such as SafeLoader is never itself evidence of safety.
_UNSAFE_YAML_LOADERS = frozenset(f"yaml.{name}" for name in (
    "Loader", "CLoader", "UnsafeLoader", "CUnsafeLoader",
    "loader.Loader", "loader.UnsafeLoader", "cyaml.CLoader", "cyaml.CUnsafeLoader",
))
_YAML_LOADERS = frozenset({"load", "load_all"})
_YAML_UNSAFE_HELPERS = frozenset({"unsafe_load", "unsafe_load_all"})

# Mirrors the sibling scanners.
_MAX_FILE_BYTES = 400_000
_MAX_FILES = 400
_MAX_FINDINGS = 32
_MAX_AST_NODES = 20_000
_MAX_AST_DEPTH = 100


@dataclass(frozen=True)
class _Evidence:
    line: int
    what: str
    kind: str = "code"


# An import proves a name only in the scope where Python binds it. Ordinary
# assignments invalidate that fact; tracing arbitrary value aliases is out of scope.
_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)


def _position(node: ast.AST) -> tuple[int, int]:
    if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
        return node.end_lineno or node.lineno, node.end_col_offset or node.col_offset
    return getattr(node, "lineno", 0), getattr(node, "col_offset", 0)


@dataclass
class _Scope:
    node: ast.AST
    parent: "_Scope | None"
    bindings: dict[str, list[tuple[ast.AST, str]]]
    wildcard: bool = False


class _Imports(ast.NodeVisitor):
    """Collect lexical bindings, then resolve imports at individual call sites.

    Deferred functions capture only a single, unconditional outer binding. A
    later rebind, global/nonlocal writer, wildcard import or module mutation makes
    that provenance unknown. Conditional imports and assignment aliases remain
    unknown; no uploaded module or function is executed to resolve them.
    """

    def __init__(self, tree: ast.Module):
        self.scope = _Scope(tree, None, {})
        self.conditional = False
        self.calls: list[tuple[ast.Call, _Scope]] = []
        self.mutable_names: set[str] = set()
        self.mutations: list[tuple[ast.AST, _Scope]] = []
        self.mutated_modules: set[str] = set()
        self.visit(tree)
        for target, scope in self.mutations:
            root = target
            while isinstance(root, (ast.Attribute, ast.Subscript)):
                root = root.value
            qualified = self.qualified(root, scope)
            if qualified:
                self.mutated_modules.add(qualified.split(".")[0])

    def bind(self, name: str, node: ast.AST, qualified: str = "") -> None:
        self.scope.bindings.setdefault(name, []).append(
            (node, "" if self.conditional else qualified))

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            name = alias.asname or alias.name.split(".")[0]
            self.bind(name, node, alias.name if alias.asname else name)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            if alias.name == "*":
                self.scope.wildcard = True
                continue
            qualified = f"{node.module}.{alias.name}" if node.module and not node.level else ""
            self.bind(alias.asname or alias.name, node, qualified)

    def target(self, target: ast.AST, event: ast.AST) -> None:
        if isinstance(target, ast.Name):
            self.bind(target.id, event)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for child in target.elts:
                self.target(child, event)
        elif isinstance(target, ast.Starred):
            self.target(target.value, event)
        else:
            self.visit(target)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        for target in node.targets:
            self.target(target, node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)
        self.target(node.target, node)

    visit_AugAssign = visit_AnnAssign

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.bind(node.id, node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.mutations.append((node, self.scope))
        self.generic_visit(node)

    visit_Subscript = visit_Attribute

    def visit_Global(self, node: ast.Global) -> None:
        self.mutable_names.update(node.names)

    visit_Nonlocal = visit_Global

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name:
            self.bind(node.name, node)
        self.generic_visit(node)

    def visit_MatchAs(self, node: ast.MatchAs) -> None:
        if node.name:
            self.bind(node.name, node)
        self.generic_visit(node)

    visit_MatchStar = visit_MatchAs

    def visit_MatchMapping(self, node: ast.MatchMapping) -> None:
        if node.rest:
            self.bind(node.rest, node)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        # A comprehension's walrus binds in the containing non-comprehension scope.
        self.visit(node.value)
        previous = self.scope
        while isinstance(self.scope.node, _COMPREHENSIONS) and self.scope.parent:
            self.scope = self.scope.parent
        self.target(node.target, node)
        self.scope = previous

    def visit_Call(self, node: ast.Call) -> None:
        self.calls.append((node, self.scope))
        self.generic_visit(node)

    def visit_If(self, node: ast.AST) -> None:
        previous = self.conditional
        self.conditional = True
        self.generic_visit(node)
        self.conditional = previous

    visit_For = visit_If
    visit_AsyncFor = visit_If
    visit_While = visit_If
    visit_Try = visit_If
    visit_TryStar = visit_If
    visit_Match = visit_If
    visit_IfExp = visit_If

    def nested(self, node: ast.AST) -> None:
        outer = self.scope
        conditional = self.conditional
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            self.bind(node.name, node)
            for expr in node.decorator_list:
                self.visit(expr)
        if isinstance(node, ast.ClassDef):
            for expr in [*node.bases, *node.keywords]:
                self.visit(expr)
        else:
            for expr in [*node.args.defaults, *node.args.kw_defaults]:
                if expr is not None:
                    self.visit(expr)
        # Class namespaces are not enclosing lexical scopes for method bodies.
        parent = outer
        if not isinstance(node, ast.ClassDef):
            while parent and isinstance(parent.node, ast.ClassDef):
                parent = parent.parent
        self.scope = _Scope(node, parent, {})
        self.conditional = False
        if not isinstance(node, ast.ClassDef):
            for arg in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs,
                        node.args.vararg, node.args.kwarg]:
                if arg is not None:
                    self.bind(arg.arg, arg)
        body = [node.body] if isinstance(node, ast.Lambda) else node.body
        for stmt in body:
            self.visit(stmt)
        self.scope = outer
        self.conditional = conditional

    visit_FunctionDef = nested
    visit_AsyncFunctionDef = nested
    visit_ClassDef = nested
    visit_Lambda = nested

    def comprehension(self, node: ast.AST) -> None:
        outer = self.scope
        # The outermost iterable runs before the comprehension's local targets bind.
        self.visit(node.generators[0].iter)
        parent = outer
        while parent and isinstance(parent.node, ast.ClassDef):
            parent = parent.parent
        self.scope = _Scope(node, parent, {})
        for index, generator in enumerate(node.generators):
            if index:
                self.visit(generator.iter)
            self.visit(generator.target)
            for condition in generator.ifs:
                self.visit(condition)
        for value in ([node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]):
            self.visit(value)
        self.scope = outer

    visit_ListComp = comprehension
    visit_SetComp = comprehension
    visit_DictComp = comprehension
    visit_GeneratorExp = comprehension

    def name(self, name: str, node: ast.AST, scope: _Scope) -> str:
        if name in self.mutable_names:
            return ""
        current: _Scope | None = scope
        while current is not None:
            if current.wildcard:
                return ""
            events = current.bindings.get(name, [])
            if events:
                if current is not scope:
                    # Deferred execution cannot freeze an outer value that is reassigned.
                    return events[0][1] if len(events) == 1 else ""
                before = [event for event in events if _position(event[0]) < _position(node)]
                if before:
                    return max(before, key=lambda event: _position(event[0]))[1]
                # Function locals shadow enclosing imports even before assignment.
                if not isinstance(current.node, (ast.Module, ast.ClassDef)):
                    return ""
            current = current.parent
        return ""

    def qualified(self, node: ast.AST, scope: _Scope) -> str:
        if isinstance(node, ast.Name):
            return self.name(node.id, node, scope)
        if isinstance(node, ast.Attribute):
            prefix = self.qualified(node.value, scope)
            return f"{prefix}.{node.attr}" if prefix else ""
        return ""


def _loader_argument(call: ast.Call) -> ast.AST | None:
    for keyword in call.keywords:
        if keyword.arg == "Loader":
            return keyword.value
    return call.args[1] if len(call.args) > 1 else None


def _evidence(tree: ast.Module) -> list[_Evidence]:
    found: list[_Evidence] = []
    imports = _Imports(tree)
    for node, scope in imports.calls:
        target = imports.qualified(node.func, scope)
        # Constructing Unpickler does not deserialize. The immediate .load() does;
        # an instance stored in a variable remains outside this import-only trace.
        if isinstance(node.func, ast.Attribute) and node.func.attr == "load":
            constructor = node.func.value
            if isinstance(constructor, ast.Call):
                owner = imports.qualified(constructor.func, scope)
                if owner in {f"{module}.Unpickler" for module in _PICKLE_MODULES}:
                    target = owner + ".load"
        module, _, member = target.partition(".")
        if not target or module in imports.mutated_modules:
            continue
        if member in _ALWAYS_UNSAFE.get(module, ()):
            kind = "marshal" if module == "marshal" else "code"
            found.append(_Evidence(node.lineno, f"calls {target}()", kind))
        elif module == "torch" and member == "load":
            if any(keyword.arg == "weights_only" and isinstance(keyword.value, ast.Constant)
                   and keyword.value.value is False for keyword in node.keywords):
                found.append(_Evidence(node.lineno, "calls torch.load() with weights_only=False"))
        elif module == "yaml" and member in _YAML_UNSAFE_HELPERS:
            found.append(_Evidence(node.lineno, f"calls {target}()"))
        elif module == "yaml" and member in _YAML_LOADERS:
            loader = _loader_argument(node)
            if loader is None:
                # **options may supply Loader: absence cannot be established locally.
                if not any(keyword.arg is None for keyword in node.keywords):
                    found.append(_Evidence(node.lineno, f"calls {target}() without Loader", "yaml-version"))
                continue
            qualified = imports.qualified(loader, scope)
            if qualified in _UNSAFE_YAML_LOADERS:
                found.append(_Evidence(node.lineno, f"calls {target}() with Loader={qualified}"))
            # Known safe loaders and unresolved/custom loaders are not conflated.
            # The latter are expressly outside the coverage claim.
    return found


def scan_unsafe_deserialization(fileobj: BinaryIO) -> list[CheckFinding]:
    findings: list[CheckFinding] = []
    with zipfile.ZipFile(fileobj) as archive:
        infos = [info for info in archive.infolist()
                 if not info.is_dir() and info.filename.endswith(".py")
                 and info.file_size <= _MAX_FILE_BYTES
                 and not is_non_production_path(info.filename)]
        for info in infos[:_MAX_FILES]:
            if len(findings) >= _MAX_FINDINGS:
                break
            try:
                tree = ast.parse(archive.read(info).decode("utf-8"))
            except (SyntaxError, UnicodeError, ValueError, RecursionError):
                # Unparseable is "not read", not "clean"; the coverage text says so.
                continue
            pending = [(tree, 0)]
            count = 0
            while pending and count <= _MAX_AST_NODES:
                node, depth = pending.pop()
                count += 1
                if depth > _MAX_AST_DEPTH:
                    break
                pending.extend((child, depth + 1) for child in ast.iter_child_nodes(node))
            else:
                if not pending and count <= _MAX_AST_NODES:
                    for item in _evidence(tree):
                        if len(findings) >= _MAX_FINDINGS:
                            break
                        findings.append(_finding(info.filename, item))
    return findings


def _finding(path: str, item: _Evidence) -> CheckFinding:
    risk = (
        "This loader can reconstruct arbitrary Python objects and invoke code during "
        "deserialization. Malicious input could run with this process's privileges."
    )
    title = "A deserialization call requires trusted input"
    severity = "high"
    if item.kind == "marshal":
        severity = "medium"
        risk = (
            "marshal is not designed for malicious or unauthenticated data. It reconstructs "
            "Python values and may return code objects; returning a code object does not "
            "execute it. This call alone does not establish arbitrary code execution."
        )
    elif item.kind == "yaml-version":
        severity = "medium"
        title = "YAML loading relies on version-dependent Loader behavior"
        risk = (
            "Older PyYAML versions allowed implicit loaders with unsafe object construction. "
            "Modern PyYAML requires Loader and raises TypeError when it is omitted. The "
            "installed version was not resolved, so code execution is not established here."
        )
    return CheckFinding(
        rule_id=RULE_ID,
        title=title,
        severity=severity,
        confidence=0.8 if item.kind == "code" else 0.6,
        category="Security",
        file=path,
        line=item.line,
        explanation=(
            f"Line {item.line} {item.what}. {risk} "
            "Where the bytes come from has NOT been verified; trusted internal data and "
            "untrusted external data can reach the same call."
        ),
        fix_hint=(
            "Prefer json (or msgpack/cbor) with an explicit schema across trust boundaries; "
            "use yaml.safe_load for YAML values. If object serialization is unavoidable, "
            "accept only trusted producers and verify an HMAC or digital signature before "
            "loading. A checksum supplied alongside untrusted bytes does not authenticate "
            "them; a digest helps only when its expected value comes from a trusted source."
        ),
    )

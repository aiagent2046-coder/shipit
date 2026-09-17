"""Offline readers for pnpm v9 and uv v1; never resolve or install packages.

Inventory includes all locked platform/optional/dev variants. It does not say
which variants a running deployment selected. Non-registry sources stay gaps.
"""
from __future__ import annotations

import tomllib
from dataclasses import replace

import yaml

from app.sca.lockfiles import Dependency, _NPM_NAME, _NPM_VERSION, _PYPI_NAME, _PYPI_PIN, normalize_pypi

MAX_YAML_NODES = 100_000
MAX_YAML_DEPTH = 64
MAX_UV_REFERENCE_CHECKS = 100_000
MAX_UV_SCOPE_STEPS = 100_000


class _YamlLimit(ValueError):
    pass


class _LockLoader(yaml.SafeLoader):
    """Bound construction and reject aliases/merge keys/duplicate mapping keys.

    pnpm emits a plain tree. Refuse unusual YAML instead of expanding an alias
    graph or silently accepting the last of conflicting package definitions.
    Use the same pure Python loader in CPython and Pyodide.
    """
    def __init__(self, stream):
        super().__init__(stream)
        self._nodes = 0
        self._depth = 0

    def compose_node(self, parent, index):
        self._nodes += 1
        self._depth += 1
        try:
            if self._nodes > MAX_YAML_NODES or self._depth > MAX_YAML_DEPTH:
                raise _YamlLimit("YAML budget exceeded")
            if self.check_event(yaml.AliasEvent):
                raise ValueError("YAML aliases are unsupported")
            return super().compose_node(parent, index)
        finally:
            self._depth -= 1

    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise ValueError("Non-string or duplicate YAML key")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def _without_peers(value: str) -> str | None:
    """Remove only balanced pnpm peer/patch suffixes, preserving SemVer text."""
    base, sep, tail = value.partition("(")
    if not sep:
        return base
    depth = 0
    for char in "(" + tail:
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth < 0:
                return None
        elif depth == 0:
            return None
    return base if depth == 0 else None


def _npm_id(value: object) -> tuple[str, str] | None:
    if not isinstance(value, str):
        return None
    base = _without_peers(value)
    if base is None:
        return None
    name, sep, version = base.rpartition("@")
    if sep and _NPM_NAME.fullmatch(name) and _NPM_VERSION.fullmatch(version):
        return name, version
    return None


def _npm_reference(name: object, value: object) -> tuple[str, str] | None:
    if not isinstance(name, str) or not _NPM_NAME.fullmatch(name) or not isinstance(value, str):
        return None
    # Alias references carry the real package name, e.g. alias: lodash@4.17.21.
    return _npm_id(value) or _npm_id(f"{name}@{value}")


def pnpm_packages(manifest: str, text: str, out: list[Dependency]) -> str | None:
    try:
        data = yaml.load(text, Loader=_LockLoader)
    except (_YamlLimit, RecursionError):
        return "parser_limit"
    except (yaml.YAMLError, ValueError):
        return "malformed"
    if not isinstance(data, dict):
        return "malformed"
    if str(data.get("lockfileVersion")) not in {"9", "9.0"}:
        return "unsupported"
    packages = data.get("packages", {})
    importers = data.get("importers")
    snapshots = data.get("snapshots", {})
    if not all(isinstance(x, dict) for x in (packages, importers, snapshots)):
        return "malformed"
    reason = None
    resolved = {}
    for key, package in packages.items():
        identity = _npm_id(key)
        if identity is None or not isinstance(package, dict):
            reason = "unresolved"
            continue
        resolution = package.get("resolution")
        # An explicit tarball/git/directory is not evidence of npm provenance.
        if (not isinstance(resolution, dict) or set(resolution) != {"integrity"}
                or not isinstance(resolution["integrity"], str) or not resolution["integrity"]):
            reason = "unresolved"
            continue
        if package.get("name", identity[0]) != identity[0] or package.get("version", identity[1]) != identity[1]:
            reason = "unresolved"
            continue
        resolved[identity] = package
    direct = set()
    # Check dependency references as well: a truncated packages map must not
    # silently turn missing packages into an apparently complete inventory.
    for importer in importers.values():
        if not isinstance(importer, dict):
            reason = "unresolved"
            continue
        for field in ("dependencies", "devDependencies", "optionalDependencies"):
            block = importer.get(field, {})
            if not isinstance(block, dict):
                reason = "unresolved"
                continue
            for name, entry in block.items():
                ref = _npm_reference(name, entry.get("version") if isinstance(entry, dict) else None)
                if ref is None or ref not in resolved:
                    reason = "unresolved"
                else:
                    direct.add(ref)
    for key, snapshot in snapshots.items():
        if _npm_id(key) not in resolved or not isinstance(snapshot, dict):
            reason = "unresolved"
            continue
        for field in ("dependencies", "optionalDependencies"):
            block = snapshot.get(field, {})
            if not isinstance(block, dict):
                reason = "unresolved"
                continue
            for name, version in block.items():
                if _npm_reference(name, version) not in resolved:
                    reason = "unresolved"
    snapshot_ids = {_npm_id(key) for key in snapshots}
    if any(identity not in snapshot_ids for identity in resolved):
        reason = "unresolved"
    for name, version in resolved:
        out.append(Dependency("npm", name, version, manifest,
                              direct=(name, version) in direct))
    return reason


def uv_packages(manifest: str, text: str, out: list[Dependency]) -> str | None:
    try:
        data = tomllib.loads(text)
    except RecursionError:
        return "parser_limit"
    except ValueError:
        return "malformed"
    if type(data.get("version")) is not int or data["version"] != 1:
        return "unsupported"
    revision = data.get("revision", 0)
    if type(revision) is not int or revision not in range(4):
        return "unsupported"
    packages = data.get("package", [])
    if not isinstance(packages, list) or any(not isinstance(p, dict) for p in packages):
        return "malformed"
    reason = None
    direct = set()
    known = {}
    roots = [i for i, p in enumerate(packages)
             if p.get("source") in ({"virtual": "."}, {"editable": "."})]
    scope_complete = len(roots) == 1
    indices = {id(p): i for i, p in enumerate(packages)}
    edges: dict[int, set[int]] = {}
    seeds: dict[str, set[int]] = {}
    output_indices = {}
    remaining_checks = MAX_UV_REFERENCE_CHECKS
    for package in packages:
        name = package.get("name")
        if isinstance(name, str) and _PYPI_NAME.fullmatch(name):
            known.setdefault(normalize_pypi(name), []).append(package)
    for index, package in enumerate(packages):
        source = package.get("source")
        root = source in ({"virtual": "."}, {"editable": "."})
        blocks = [("", package.get("dependencies", []))]
        for field in ("optional-dependencies", "dev-dependencies"):
            groups = package.get(field, {})
            if not isinstance(groups, dict):
                reason = "unresolved"
                continue
            if field == "dev-dependencies" and groups and not root:
                # Dependency-local development groups are not a supported root.
                scope_complete = False
            blocks.extend((group if field == "dev-dependencies" else "", block)
                          for group, block in groups.items())
        for group, block in blocks:
            if remaining_checks < 0:
                break
            if not isinstance(block, list):
                reason = "unresolved"
                continue
            for ref in block:
                name = ref.get("name") if isinstance(ref, dict) else None
                if not isinstance(name, str):
                    reason = "unresolved"
                    continue
                name = normalize_pypi(name)
                candidates = known.get(name, [])
                remaining_checks -= 1 + len(candidates)
                if remaining_checks < 0:
                    break
                matches = [p for p in candidates
                           if ("version" not in ref or p.get("version") == ref["version"])
                           and ("source" not in ref or p.get("source") == ref["source"])]
                if not matches:
                    reason = "unresolved"
                if len(matches) != 1:
                    # Platform forks and underspecified references retain all
                    # pins, but cannot prove that a package is development-only.
                    scope_complete = False
                targets = {indices[id(p)] for p in matches}
                if root:
                    seeds.setdefault(group, set()).update(targets)
                else:
                    edges.setdefault(index, set()).update(targets)
                if root:
                    direct.update((name, p.get("version")) for p in matches
                                  if isinstance(p.get("version"), str))
        if root:
            continue  # The project itself is not a public PyPI dependency.
        name, version = package.get("name"), package.get("version")
        if (not isinstance(name, str) or not _PYPI_NAME.fullmatch(name)
                or not isinstance(version, str) or not _PYPI_PIN.fullmatch(version)):
            reason = "unresolved"
            continue
        if source not in ({"registry": "https://pypi.org/simple"},
                          {"registry": "https://pypi.org/simple/"}):
            reason = "unresolved"
            continue
        output_indices[len(out)] = index
        out.append(Dependency("PyPI", normalize_pypi(name), version, manifest))
    # Directness comes from the locked root's references, never version ranges
    # in pyproject.toml. Scope describes graph ownership, never a deployment's
    # selected extras/platform. Unknown graph portions cannot prove dev-only.
    scopes = (_uv_scopes(edges, seeds) if scope_complete and reason is None
              and remaining_checks >= 0 else {})
    for i, index in output_indices.items():
        dep = out[i]
        groups = scopes.get(index, set())
        development = False if "" in groups else True if groups else None
        out[i] = replace(dep, direct=(dep.name, dep.version) in direct,
                         development=development,
                         dependency_groups=tuple(sorted(group for group in groups if group)))
    return "parser_limit" if remaining_checks < 0 else reason


def _uv_scopes(edges: dict[int, set[int]], seeds: dict[str, set[int]]) -> dict[int, set[str]]:
    """Propagate root groups iteratively with a separate bounded work budget."""
    pending = [(index, group) for group, indices in seeds.items() for index in indices]
    scopes: dict[int, set[str]] = {}
    work = len(pending)
    if work > MAX_UV_SCOPE_STEPS:
        return {}
    while pending:
        index, group = pending.pop()
        reached = scopes.setdefault(index, set())
        if group in reached:
            continue
        reached.add(group)
        targets = edges.get(index, ())
        work += len(targets)
        if work > MAX_UV_SCOPE_STEPS:
            return {}  # Partial reachability is insufficient for dev-only.
        pending.extend((target, group) for target in targets)
    return scopes

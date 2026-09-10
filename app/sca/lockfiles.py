"""Read the dependencies a repository actually ships, from its own lockfiles.

WHY THE LOCKFILE AND NOT THE MANIFEST. package.json says `"lodash": "^4.17.0"`,
which names a range -- and a range is not a version, so it cannot be looked up
in a vulnerability database without guessing which member of the range the
project installed. The lockfile records the resolved version, and it is the
file the build actually installs from. That is the artefact worth asking about.

WHAT THIS MODULE DELIBERATELY DOES NOT DO. It does not resolve, upgrade, or
read the network. It answers one question -- (ecosystem, name, version, and
where that was written down) -- so the answer can be checked by reading a file.
Interpretation belongs to app/sca/osv.py and app/sca/stage.py.
"""
from __future__ import annotations

import io
import json
import re
import tomllib
import zipfile
from dataclasses import dataclass

from app.scan.secrets import is_non_production_path

# A lockfile is a machine-written file; past this size it is either generated
# by something unusual or not a lockfile at all.
MAX_LOCKFILE_BYTES = 2_000_000

# The bound is on the LOOKUP, not on the repository: every dependency costs one
# entry in a network request, and an audit must not become unbounded work
# because a submitted archive happens to be a monorepo. Raised from 300 after
# measuring this repository's own lockfile at 327 entries -- a cap that low
# truncates an ordinary monorepo, and every entry past it is silently never
# asked about. 2000 is eight batches, which the caller's own bounds already
# dwarf; what it truncates is reported, not swallowed.
MAX_DEPENDENCIES = 2000

# Root-first, so a nested lockfile (a vendored copy, a fixture) never displaces
# the one at the repository root when both are present and the cap is reached.
MAX_LOCKFILES = 6

_REQUIREMENT = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*"
    r"(?:\[[^\]]*\])?\s*"
    r"==\s*(?P<version>[A-Za-z0-9][A-Za-z0-9.!+_-]*)(?=\s|;|$)"
)

# Dependency files that cannot establish the selected versions by themselves.
# Their presence must remain visible as a gap in dependency coverage.
_UNUSABLE = ("go.mod", "go.sum")


def unusable_lockfiles(data: bytes) -> list[str]:
    """Lockfiles present in the archive that this module deliberately does not
    read, so the caller can say WHY nothing was resolved instead of reporting
    an empty dependency list as if the repository had none."""
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        return sorted(
            info.filename for info in archive.infolist()
            if not info.is_dir()
            and info.filename.rsplit("/", 1)[-1] in _UNUSABLE
            and not is_non_production_path(info.filename)
            and not _vendored(info.filename))

# Neither go.mod's minimum requirements nor go.sum's checksum history is a
# resolved build list. Replacements, exclusions and transitive requirements
# change Go's selected graph. Report unsupported coverage until such a graph
# is supplied; do not run repository code or Go tooling to construct one.
OSV_ECOSYSTEM = {
    "package-lock.json": "npm",
    "requirements.txt": "PyPI",
    "poetry.lock": "PyPI",
}

_NPM_NAME = re.compile(r"(?:@[A-Za-z0-9._-]+/)?[A-Za-z0-9._-]+$")
_NPM_VERSION = re.compile(
    r"v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")


@dataclass(frozen=True)
class Dependency:
    """One resolved dependency: what to look up, and where it is written."""
    ecosystem: str
    name: str
    version: str
    manifest: str          # archive-relative path of the lockfile it came from
    line: int = 0          # 1-based, and only where the file is line-oriented
    direct: bool = False   # named in package.json; unknown for other ecosystems
    # True when the lockfile says the package is installed for development
    # only, False when the lockfile says otherwise, and None when the format
    # does not record it. The three are kept apart because "not a production
    # dependency" and "we cannot tell" lead a reader to different actions:
    # measured on this repository's own package-lock.json, 170 of 327 entries
    # carry dev: true, so the distinction is not a formality.
    development: bool | None = None


def normalize_pypi(name: str) -> str:
    """PEP 503 normalization: `Foo_Bar` and `foo-bar` are the same project, and
    the vulnerability database stores one of the spellings, not both."""
    return re.sub(r"[-_.]+", "-", name).strip().lower()


def _looks_like_lockfile(name: str) -> bool:
    return name.rsplit("/", 1)[-1] in OSV_ECOSYSTEM


# A lockfile under one of these belongs to a dependency, not to this
# repository: reporting its packages would attribute someone else's dependency
# tree to the audited project. app/scan/secrets.py's is_non_production_path is
# about test and documentation files and does not cover this, so the ownership
# rule is stated here rather than borrowed from a predicate about something else.
_VENDORED = ("node_modules/", ".venv/", "venv/", "site-packages/", "vendor/bundle/")


def _vendored(name: str) -> bool:
    return any(segment in name for segment in _VENDORED)


def _depth(name: str) -> tuple[int, str]:
    return (name.count("/"), name)


def find_lockfiles(archive: zipfile.ZipFile) -> list[str]:
    """Lockfiles worth reading, root-first and bounded.

    A lockfile inside node_modules is a copy of someone else's, and reporting
    it would attribute a dependency to this repository that it does not ship.
    """
    found = []
    for info in archive.infolist():
        if info.is_dir():
            continue
        name = info.filename
        if not _looks_like_lockfile(name) or is_non_production_path(name):
            continue
        if _vendored(name):
            continue
        if info.file_size > MAX_LOCKFILE_BYTES:
            continue
        found.append(name)
    return sorted(found, key=_depth)[:MAX_LOCKFILES]


def _read(archive: zipfile.ZipFile, name: str) -> str:
    return archive.read(name).decode("utf-8", "replace")


def _package_location(location: str) -> str:
    """Return an installed package's name, including workspace/nested copies."""
    parts = location.split("/")
    markers = [i for i, part in enumerate(parts) if part == "node_modules"]
    if not markers:
        return ""
    candidate = "/".join(parts[markers[-1] + 1:])
    return candidate if _NPM_NAME.fullmatch(candidate) else ""


def _npm_identity(installed_name: str, entry: dict) -> tuple[str, str] | None:
    """Aliases use the real registry name, never their installation nickname."""
    version = entry.get("version")
    package = entry.get("name", installed_name)
    if isinstance(version, str) and version.startswith("npm:"):
        package, separator, version = version[4:].rpartition("@")
        if not separator:
            return None
    if (not isinstance(package, str) or not _NPM_NAME.fullmatch(package)
            or not isinstance(version, str) or not _NPM_VERSION.fullmatch(version)):
        return None
    resolved = entry.get("resolved", "")
    if isinstance(resolved, str) and resolved.startswith(("git", "file:", "link:")):
        return None
    return package, version


def _json_dependencies(name: str, text: str, direct_names: set[str],
                       out: list[Dependency]) -> str | None:
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        return "malformed"
    if not isinstance(data, dict):
        return "malformed"
    incomplete = None
    packages = data.get("packages")
    if isinstance(packages, dict):           # lockfileVersion 2 and 3
        for location, entry in packages.items():
            installed_name = _package_location(location)
            if not installed_name:
                continue                    # root or workspace directory
            if not isinstance(entry, dict):
                incomplete = "malformed"
                continue
            if entry.get("link") is True:
                continue                    # resolved workspace entry elsewhere
            identity = _npm_identity(installed_name, entry)
            if identity is None:
                incomplete = incomplete or "unresolved"
                continue
            package, version = identity
            out.append(Dependency("npm", package, version, name,
                                  direct=(location == f"node_modules/{installed_name}"
                                          and installed_name in direct_names),
                                  development=entry.get("dev") is True))
        return incomplete
    dependencies = data.get("dependencies")
    if not isinstance(dependencies, dict):
        return "malformed"
    # Version 1 nests installed dependencies recursively. Iterate explicitly so
    # repository-controlled nesting never consumes the Python call stack.
    pending = [(dependencies, True)]
    while pending:
        block, root = pending.pop()
        for installed_name, entry in block.items():
            if not isinstance(entry, dict):
                incomplete = "malformed"
                continue
            nested = entry.get("dependencies", {})
            if isinstance(nested, dict):
                pending.append((nested, False))
            else:
                incomplete = "malformed"
            identity = _npm_identity(installed_name, entry)
            if identity is None:
                incomplete = incomplete or "unresolved"
                continue
            package, version = identity
            out.append(Dependency("npm", package, version, name,
                                  direct=root and installed_name in direct_names,
                                  development=entry.get("dev") is True))
    return incomplete


def _requirement_lines(name: str, text: str, out: list[Dependency]) -> str | None:
    incomplete = None
    logical = ""
    start = 0
    for number, raw in enumerate(text.splitlines(), start=1):
        if not logical:
            start = number
        # pip removes continuations before parsing comments and requirements.
        logical += raw.rstrip().removesuffix("\\")
        if raw.rstrip().endswith("\\"):
            continue
        line = logical.split("#", 1)[0].strip()
        logical = ""
        if not line:
            continue
        if line.startswith(("--index-url", "--extra-index-url", "--no-index",
                            "--find-links", "--trusted-host", "--only-binary",
                            "--no-binary", "--prefer-binary", "--require-hashes")):
            continue
        # Includes, ranges, editable installs and URLs cannot resolve a package
        # by themselves. Preserve any other exact pins, but expose partialness.
        match = _REQUIREMENT.match(line) if "@" not in line else None
        if not match:
            incomplete = "unresolved"
            continue
        out.append(Dependency("PyPI", normalize_pypi(match.group("name")),
                              match.group("version"), name, line=start))
    if logical:
        incomplete = "malformed"             # unterminated continuation
    return incomplete


def _poetry_packages(name: str, text: str, out: list[Dependency]) -> str | None:
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return "malformed"
    packages = data.get("package")
    if not isinstance(packages, list):
        return "malformed"
    incomplete = None
    for entry in packages:
        if not isinstance(entry, dict):
            incomplete = "malformed"
            continue
        package, version = entry.get("name"), entry.get("version")
        if (not isinstance(package, str) or not package.strip()
                or not isinstance(version, str) or not version):
            incomplete = "malformed"
            continue
        source = entry.get("source")
        if source is not None and (not isinstance(source, dict)
                                   or source.get("type") in ("git", "directory", "file")):
            incomplete = incomplete or "unresolved"
            continue
        category = entry.get("category")
        out.append(Dependency("PyPI", normalize_pypi(package), version, name,
                              development=True if category == "dev" else None))
    return incomplete


def _direct_names(archive: zipfile.ZipFile, manifest_path: str) -> set[str]:
    """Names declared in the package.json beside the lockfile, if there is one.

    Only for the DIRECT flag: the lockfile already told us every version, and
    a dependency's directness changes what the reader should do about it, not
    whether it is installed.
    """
    directory = manifest_path.rsplit("/", 1)[0] if "/" in manifest_path else ""
    candidate = f"{directory}/package.json" if directory else "package.json"
    try:
        data = json.loads(_read(archive, candidate))
    except (KeyError, ValueError, RecursionError):
        return set()
    if not isinstance(data, dict):
        return set()
    names = set()
    for field in ("dependencies", "devDependencies", "optionalDependencies"):
        block = data.get(field)
        if isinstance(block, dict):
            names.update(block)
    return names


@dataclass(frozen=True)
class DependencyInventory:
    dependencies: list[Dependency]
    manifests: list[str]
    found: int
    incomplete_manifests: dict[str, str]


def collect_dependency_inventory(data: bytes) -> DependencyInventory:
    """Read independent files independently, retaining honest coverage gaps."""
    incomplete: dict[str, str] = {}
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        manifests = find_lockfiles(archive)
        selected = set(manifests)
        for info in archive.infolist():
            path = info.filename
            if info.is_dir() or is_non_production_path(path) or _vendored(path):
                continue
            if path.rsplit("/", 1)[-1] in _UNUSABLE:
                incomplete[path] = "unsupported"
            elif _looks_like_lockfile(path) and path not in selected:
                incomplete[path] = ("oversized" if info.file_size > MAX_LOCKFILE_BYTES
                                    else "truncated")
        collected: list[Dependency] = []
        for manifest in manifests:
            try:
                text = _read(archive, manifest)
                basename = manifest.rsplit("/", 1)[-1]
                if basename == "package-lock.json":
                    reason = _json_dependencies(
                        manifest, text, _direct_names(archive, manifest), collected)
                elif basename == "requirements.txt":
                    reason = _requirement_lines(manifest, text, collected)
                else:
                    reason = _poetry_packages(manifest, text, collected)
            except (KeyError, ValueError, RuntimeError, OSError, zipfile.BadZipFile):
                reason = "malformed"
            if reason:
                incomplete[manifest] = reason

    unique: dict[tuple[str, str, str], Dependency] = {}
    for dependency in collected:
        key = (dependency.ecosystem, dependency.name, dependency.version)
        kept = unique.get(key)
        if kept is None:
            unique[key] = dependency
        elif kept.development is True and dependency.development is False:
            unique[key] = dependency
    ordered = list(unique.values())
    return DependencyInventory(ordered[:MAX_DEPENDENCIES], manifests,
                               len(ordered), incomplete)


def collect_dependencies(data: bytes) -> tuple[list[Dependency], list[str], int]:
    """Compatibility view; scan stages use inventory to retain coverage gaps."""
    inventory = collect_dependency_inventory(data)
    return inventory.dependencies, inventory.manifests, inventory.found

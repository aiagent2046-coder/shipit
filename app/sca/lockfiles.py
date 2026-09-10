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
# because a submitted archive happens to be a monorepo.
MAX_DEPENDENCIES = 300

# Root-first, so a nested lockfile (a vendored copy, a fixture) never displaces
# the one at the repository root when both are present and the cap is reached.
MAX_LOCKFILES = 6

_REQUIREMENT = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*"
    r"(?:\[[^\]]*\])?\s*"
    r"==\s*(?P<version>[A-Za-z0-9][A-Za-z0-9.!+_-]*)"
)

_GO_SUM = re.compile(r"^(?P<module>\S+)\s+(?P<version>v\S+)\s+(?P<hash>h1:\S+)$")

OSV_ECOSYSTEM = {
    "package-lock.json": "npm",
    "requirements.txt": "PyPI",
    "poetry.lock": "PyPI",
    "go.sum": "Go",
}


@dataclass(frozen=True)
class Dependency:
    """One resolved dependency: what to look up, and where it is written."""
    ecosystem: str
    name: str
    version: str
    manifest: str          # archive-relative path of the lockfile it came from
    line: int = 0          # 1-based, and only where the file is line-oriented
    direct: bool = False   # named in package.json; unknown for other ecosystems


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


def _json_dependencies(name: str, text: str, direct_names: set[str],
                       out: list[Dependency]) -> None:
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        return                      # unreadable lockfile is not an empty one
    if not isinstance(data, dict):
        return
    packages = data.get("packages")
    if isinstance(packages, dict):          # lockfileVersion 2 and 3
        for location, entry in packages.items():
            if not isinstance(entry, dict) or not location.startswith("node_modules/"):
                continue
            version = entry.get("version")
            if not isinstance(version, str) or not version:
                continue
            # `node_modules/a/node_modules/b` is b -- the last segment names the
            # package, and the earlier ones only say who depends on it.
            dep_name = location.rsplit("node_modules/", 1)[-1]
            out.append(Dependency("npm", dep_name, version, name,
                                  direct=dep_name in direct_names))
        return
    dependencies = data.get("dependencies")
    if isinstance(dependencies, dict):      # lockfileVersion 1
        for dep_name, entry in dependencies.items():
            if not isinstance(entry, dict):
                continue
            version = entry.get("version")
            if isinstance(version, str) and version:
                out.append(Dependency("npm", dep_name, version, name,
                                      direct=dep_name in direct_names))


def _requirement_lines(name: str, text: str, out: list[Dependency]) -> None:
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].rstrip()
        if not line or line.lstrip().startswith("-") or "@" in line:
            # Options (-r, -e), comments and direct references carry no
            # resolvable version, and a URL is not a version either.
            continue
        if line.endswith("\\"):
            continue                     # a hash continuation, not a package
        match = _REQUIREMENT.match(line)
        if not match:
            continue                     # a range (>=, ~=) is not a version
        out.append(Dependency("PyPI", normalize_pypi(match.group("name")),
                              match.group("version"), name, line=number))


def _poetry_packages(name: str, text: str, out: list[Dependency]) -> None:
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return
    for entry in data.get("package", []) or []:
        if not isinstance(entry, dict):
            continue
        package, version = entry.get("name"), entry.get("version")
        if isinstance(package, str) and isinstance(version, str) and version:
            out.append(Dependency("PyPI", normalize_pypi(package), version, name))


def _go_sum_lines(name: str, text: str, out: list[Dependency]) -> None:
    for number, raw in enumerate(text.splitlines(), start=1):
        match = _GO_SUM.match(raw.strip())
        if not match:
            continue
        # Each module appears twice: the module itself and its go.mod. The
        # go.mod entry is the same version, so counting it would double every
        # lookup and every finding.
        if match.group("version").endswith("/go.mod"):
            continue
        out.append(Dependency("Go", match.group("module"), match.group("version"),
                              name, line=number))


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


def collect_dependencies(data: bytes) -> tuple[list[Dependency], list[str]]:
    """(dependencies, lockfiles read), deduplicated and capped.

    Two lockfiles may record the same package at the same version -- a
    monorepo's root and a workspace, say. That is one dependency to look up,
    and reporting it twice would double-count one advisory.
    """
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        manifests = find_lockfiles(archive)
        collected: list[Dependency] = []
        for manifest in manifests:
            text = _read(archive, manifest)
            basename = manifest.rsplit("/", 1)[-1]
            if basename == "package-lock.json":
                _json_dependencies(manifest, text, _direct_names(archive, manifest),
                                   collected)
            elif basename == "requirements.txt":
                _requirement_lines(manifest, text, collected)
            elif basename == "poetry.lock":
                _poetry_packages(manifest, text, collected)
            elif basename == "go.sum":
                _go_sum_lines(manifest, text, collected)

    unique: dict[tuple[str, str, str], Dependency] = {}
    for dependency in collected:
        unique.setdefault(
            (dependency.ecosystem, dependency.name, dependency.version), dependency)
    ordered = list(unique.values())
    return ordered[:MAX_DEPENDENCIES], manifests

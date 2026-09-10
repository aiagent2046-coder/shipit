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
    r"==\s*(?P<version>[A-Za-z0-9][A-Za-z0-9.!+_-]*)"
)

# Files that ARE lockfiles but cannot answer "what is installed", so their
# presence must not read as "the dependencies were checked and look fine":
# go.sum lists every module version the build ever verified, not the build.
_UNUSABLE = ("go.sum",)


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

# go.mod's require directive, in both shapes it is written:
#     require github.com/x/y v1.2.3
#     require ( github.com/x/y v1.2.3 // indirect ... )
_GO_REQUIRE_SINGLE = re.compile(
    r"^\s*require\s+(?P<module>\S+)\s+(?P<version>v\S+)\s*(?://.*)?$")
_GO_REQUIRE_ENTRY = re.compile(
    r"^\s*(?P<module>[^\s()]+)\s+(?P<version>v\S+)\s*$")

OSV_ECOSYSTEM = {
    "package-lock.json": "npm",
    "requirements.txt": "PyPI",
    "poetry.lock": "PyPI",
    # go.sum is NOT in this map on purpose: it is a checksum log of every
    # module version the build ever verified, not a statement of what is
    # installed. It is read only to CONFIRM a version go.mod already named --
    # see _go_mod.
    "go.mod": "Go",
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
    """'node_modules/x', 'apps/web/node_modules/x', 'node_modules/a/node_modules/x'
    -> 'x'; '' when the entry is not an installed package.

    The LAST `node_modules/` segment names the package and everything before it
    says who installed it: the root, a workspace that resolved its own copy, or
    a package that nested one. Reading only the first shape silently skipped
    every workspace-resolved and nested package, which is under-reporting that
    looks exactly like a clean dependency tree.
    """
    marker = "node_modules/"
    if marker not in location:
        return ""                   # the root, or a workspace's own directory
    return location.rsplit(marker, 1)[1]


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
            if not isinstance(entry, dict) or "version" not in entry:
                continue
            version = entry.get("version")
            if not isinstance(version, str) or not version:
                continue
            dep_name = _package_location(location)
            if not dep_name:
                continue            # the root project or a workspace directory
            out.append(Dependency("npm", dep_name, version, name,
                                  direct=dep_name in direct_names,
                                  development=entry.get("dev") is True))
        return
    dependencies = data.get("dependencies")
    if isinstance(dependencies, dict):      # lockfileVersion 1
        for dep_name, entry in dependencies.items():
            if not isinstance(entry, dict):
                continue
            version = entry.get("version")
            if isinstance(version, str) and version:
                out.append(Dependency("npm", dep_name, version, name,
                                      direct=dep_name in direct_names,
                                      development=entry.get("dev") is True))


def _requirement_lines(name: str, text: str, out: list[Dependency]) -> None:
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].rstrip()
        if not line:
            continue
        # A pip-compile pin ENDS with the continuation backslash and its hashes
        # follow on their own lines:
        #
        #     annotated-doc==0.0.5 \
        #         --hash=sha256:117bac... \
        #
        # Skipping every line that ends with a backslash -- which is what this
        # did -- therefore skipped every package in the file this project
        # generates for itself: 37 pins read as 0 dependencies. The backslash is
        # removed here and the `--hash` lines that follow are dropped by the
        # option check below.
        line = line.rstrip("\\").rstrip()
        if not line or line.lstrip().startswith("-"):
            # Options (-r, -e, --hash), comments and direct references carry no
            # resolvable version, and a URL is not a version either.
            continue
        if "@" in line:
            continue
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
            # Poetry 1.x wrote `category = "dev"`; poetry 2.x stopped. Absence
            # is therefore "not recorded", not "production".
            category = entry.get("category")
            out.append(Dependency("PyPI", normalize_pypi(package), version, name,
                                  development=True if category == "dev" else None))


def _go_mod_packages(name: str, text: str, out: list[Dependency]) -> None:
    """The Go dependencies the build actually uses.

    go.mod is the source, NOT go.sum. go.sum is a checksum log: it holds an
    entry for every module version the build ever verified, including versions
    that were later upgraded away, so reading it reports retired software as an
    installed dependency -- measured here with a two-line file, where a module
    named `retired` came back as a finding. Both shapes of the require
    directive are read, since both are written by `go mod tidy`:

        require github.com/x/y v1.2.3
        require (
            github.com/x/y v1.2.3 // indirect
        )
    """
    in_block = False
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("//", 1)[0].rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("require ("):
            in_block = True
            continue
        if in_block:
            if stripped.startswith(")"):
                in_block = False
                continue
            match = _GO_REQUIRE_ENTRY.match(stripped)
            if match:
                out.append(Dependency("Go", match.group("module"),
                                      match.group("version"), name, line=number))
            continue
        match = _GO_REQUIRE_SINGLE.match(stripped)
        if match:
            out.append(Dependency("Go", match.group("module"),
                                  match.group("version"), name, line=number))


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


def collect_dependencies(data: bytes) -> tuple[list[Dependency], list[str], int]:
    """(dependencies, lockfiles read, found before the cap), deduplicated.

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
            elif basename == "go.mod":
                _go_mod_packages(manifest, text, collected)

    unique: dict[tuple[str, str, str], Dependency] = {}
    for dependency in collected:
        key = (dependency.ecosystem, dependency.name, dependency.version)
        kept = unique.get(key)
        if kept is None:
            unique[key] = dependency
        elif kept.development is True and dependency.development is False:
            # The same package recorded as both a development and a production
            # dependency: it IS in the production install, so the weaker claim
            # must not win just because it was read first.
            unique[key] = dependency
    ordered = list(unique.values())
    return ordered[:MAX_DEPENDENCIES], manifests, len(ordered)

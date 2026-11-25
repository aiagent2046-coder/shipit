"""Bottom layer of app.sca: the dependency model and the parsing primitives
every lockfile format parser (npm, pip, poetry, bun, pnpm, uv) builds on.

This module imports nothing from the package, so the format parsers and the
inventory dispatcher in `lockfiles` can both sit above it without forming a
module cycle: lockfiles -> {bun_lock, resolved_locks} -> lockfile_primitives.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass

# A lockfile is a machine-written file; past this size it is either generated
# by something unusual or not a lockfile at all.
MAX_LOCKFILE_BYTES = 2_000_000

_NPM_NAME = re.compile(r"(?:@[A-Za-z0-9._-]+/)?[A-Za-z0-9._-]+$")
_NPM_VERSION = re.compile(
    r"v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
_PYPI_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?\Z")
_PYPI_PIN = re.compile(r"[0-9][A-Za-z0-9.!+_-]*\Z")


@dataclass(frozen=True)
class DependencyOccurrence:
    """One selected manifest's aggregate evidence for a resolved package pin."""
    manifest: str
    line: int = 0
    direct: bool = False
    development: bool | None = None
    dependency_groups: tuple[str, ...] = ()


@dataclass(frozen=True)
class Dependency:
    """One resolved dependency: what to look up, and where it is written."""
    ecosystem: str
    name: str
    version: str
    manifest: str          # archive-relative path of the lockfile it came from
    line: int = 0          # 1-based, and only where the file is line-oriented
    direct: bool = False   # named in a manifest or a supported lockfile root
    # True when the lockfile says the package is installed for development
    # only, False when the lockfile says otherwise, and None when the format
    # does not record it. The three are kept apart because "not a production
    # dependency" and "we cannot tell" lead a reader to different actions:
    # measured on this repository's own package-lock.json, 170 of 327 entries
    # carry dev: true, so the distinction is not a formality.
    development: bool | None = None
    # Lockfile-declared development groups; no guess from package names.
    dependency_groups: tuple[str, ...] = ()
    # At most MAX_LOCKFILES selected manifests. Empty on legacy stored data:
    # the representative still exists, but other locations were not recorded.
    occurrences: tuple[DependencyOccurrence, ...] = ()


def _json_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _invalid_json_constant(value: str):
    raise ValueError("Non-finite JSON constant")


def _load_json(text: str):
    # Conflicting entries must not silently erase a pin or select a version.
    return json.loads(text, object_pairs_hook=_json_object, parse_constant=_invalid_json_constant)


def normalize_pypi(name: str) -> str:
    """PEP 503 normalization: `Foo_Bar` and `foo-bar` are the same project, and
    the vulnerability database stores one of the spellings, not both."""
    return re.sub(r"[-_.]+", "-", name).strip().lower()

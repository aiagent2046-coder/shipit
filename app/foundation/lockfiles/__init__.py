"""Lockfile inventory: what dependencies a repository actually ships.

The format parsers (npm/pip/poetry here, bun in bun_lock, pnpm/uv in
resolved_locks) and the dependency model in lockfile_primitives. Moved
from app/sca/ during the import-cycles fix phase: archive parsing is
bottom-layer material that both scan and sca consume.
"""
from __future__ import annotations

from app.foundation.lockfiles import bun_lock, lockfile_primitives, lockfiles, resolved_locks  # noqa: F401
from app.foundation.lockfiles.lockfiles import (  # noqa: F401  (re-exported)
    MAX_DEPENDENCIES,
    MAX_EXCLUDED_MANIFESTS,
    MAX_LOCKFILES,
    OSV_ECOSYSTEM,
    Dependency,
    DependencyOccurrence,
    collect_dependencies,
    collect_dependency_inventory,
    dependency_exclusion_reason,
    dependency_occurrences,
    normalize_pypi,
    occurrence_evidence,
    occurrence_summary,
    unusable_lockfiles,
)

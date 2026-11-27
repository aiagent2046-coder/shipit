"""Archive member name classification: what counts as source, what as
attached evidence.

Bottom layer shared by the scan engine (file scope, secrets, snapshots)
and the ingest stack detector. Extracted from app/scan/file_scope.py
during the import-cycles fix phase: ingest must not reach up into scan.
"""
from __future__ import annotations

from pathlib import PurePosixPath


def is_binary_evidence_path(name: str) -> bool:
    """Only the reserved envelope, at root or below one repository wrapper.

    Imported labels are observations, not project source. Neighbouring files
    and deeper paths remain eligible for ordinary source/secret scanning.
    """
    path = PurePosixPath(name.replace("\\", "/"))
    return (not path.is_absolute() and ".." not in path.parts and len(path.parts) in (2, 3)
            and path.parts[-2:] == (".drydock-evidence", "ghidra.json"))


def source_archive_names(names: list[str]) -> list[str]:
    """Keep source listings independent of attached evidence and its empty parents."""
    evidence = {name for name in names if is_binary_evidence_path(name)}
    if not evidence:
        return names
    parents = {str(parent) for name in evidence
               for parent in PurePosixPath(name.replace("\\", "/")).parents if str(parent) != "."}
    source = [name for name in names if name not in evidence]
    # Explicit ZIP directory entries have no source bytes. Drop only envelope
    # ancestors with no remaining files, never a directory containing neighbours.
    occupied = {str(parent) for name in source if not name.endswith("/")
                for parent in PurePosixPath(name.replace("\\", "/")).parents}
    return [name for name in source if not (
        name.endswith("/") and str(PurePosixPath(name.replace("\\", "/"))) in parents - occupied)]

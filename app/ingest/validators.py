"""Validation of user-supplied ZIP archives before extraction.

User code is treated as hostile. An archive must pass every check here
before a single byte is written to disk.
"""

from __future__ import annotations

import stat
import zipfile
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import BinaryIO

# Hard limits (see shipit-architecture.md, section 2.1)
MAX_ARCHIVE_BYTES = 50 * 1024 * 1024        # 50 MB compressed
MAX_UNCOMPRESSED_BYTES = 500 * 1024 * 1024  # 500 MB total after extraction
MAX_FILE_COUNT = 5_000
# Per-entry compression ratio above this, for entries larger than the
# floor, is treated as a zip bomb. Legitimate source code stays well
# below 100x; crafted bombs reach 1000x+.
MAX_COMPRESSION_RATIO = 100
RATIO_CHECK_FLOOR_BYTES = 1 * 1024 * 1024   # only check ratio for entries > 1 MB


class ArchiveValidationError(Exception):
    """Archive rejected. `reason` is a stable machine-readable code."""

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


@dataclass(frozen=True)
class ArchiveReport:
    file_count: int
    total_uncompressed_bytes: int
    symlink_count: int = 0


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    """Unix mode is stored in the top 16 bits of external_attr."""
    mode = info.external_attr >> 16
    return stat.S_ISLNK(mode)


def _is_unsafe_path(name: str) -> bool:
    """Reject absolute paths, drive letters, and `..` traversal."""
    path = PurePosixPath(name.replace("\\", "/"))
    if path.is_absolute():
        return True
    if len(name) >= 2 and name[1] == ":":  # windows drive, e.g. C:...
        return True
    return ".." in path.parts


def validate_zip(fileobj: BinaryIO, size_bytes: int) -> ArchiveReport:
    """Validate an uploaded ZIP without extracting it.

    Raises ArchiveValidationError with one of the reasons:
      too_large, not_a_zip, too_many_files, unsafe_path, zip_bomb.
    Symlink entries are skipped and counted, never extracted.
    """
    if size_bytes > MAX_ARCHIVE_BYTES:
        raise ArchiveValidationError(
            "too_large", f"{size_bytes} > {MAX_ARCHIVE_BYTES}"
        )

    try:
        zf = zipfile.ZipFile(fileobj)
    except zipfile.BadZipFile as exc:
        raise ArchiveValidationError("not_a_zip", str(exc)) from exc

    with zf:
        infos = zf.infolist()

        if len(infos) > MAX_FILE_COUNT:
            raise ArchiveValidationError(
                "too_many_files", f"{len(infos)} > {MAX_FILE_COUNT}"
            )

        total_uncompressed = 0
        symlink_count = 0
        for info in infos:
            if _is_symlink(info):
                # Legit repos contain symlinks (seen in real GitHub zipballs).
                # We never extract to disk, so skipping is safe; extraction
                # code (Fix Packs, sandbox) MUST also skip these entries.
                symlink_count += 1
                continue

            if _is_unsafe_path(info.filename):
                raise ArchiveValidationError("unsafe_path", info.filename)

            total_uncompressed += info.file_size

            if (
                info.file_size > RATIO_CHECK_FLOOR_BYTES
                and info.compress_size > 0
                and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO
            ):
                raise ArchiveValidationError(
                    "zip_bomb",
                    f"{info.filename}: ratio "
                    f"{info.file_size // max(info.compress_size, 1)}x",
                )

        if total_uncompressed > MAX_UNCOMPRESSED_BYTES:
            raise ArchiveValidationError(
                "zip_bomb",
                f"total uncompressed {total_uncompressed} "
                f"> {MAX_UNCOMPRESSED_BYTES}",
            )

    return ArchiveReport(
        file_count=len(infos) - symlink_count,
        total_uncompressed_bytes=total_uncompressed,
        symlink_count=symlink_count,
    )

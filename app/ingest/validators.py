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
# Raised from 5,000, which was rejecting ordinary repositories rather than
# abusive ones. Measured: react/react is 7,841 entries and 40 MB unpacked,
# and the whole static scan takes 3.7 s at a 5 MB peak -- roughly 0.5 ms an
# entry. openclaw/openclaw is 31,403 and NousResearch/hermes-agent 8,703;
# three of the four most-starred real codebases tried were refused on size,
# none of them on anything a scanner would have struggled with.
#
# Nothing about LLM spend changes: select_files in app/scan/llm_scan.py fills
# a fixed MAX_TOTAL_CHARS budget per rubric, so the prompt is the same size
# for a 500-file repo and a 50,000-file one. Only CPU scales, linearly.
#
# The bound stays because MAX_ARCHIVE_BYTES and MAX_UNCOMPRESSED_BYTES do not
# cover an archive of a million empty entries: that passes both byte limits
# and still makes the scanner iterate a million times. 50,000 puts the worst
# case near 25 s of CPU, well inside the worker's 300 s lease (renewed by a
# heartbeat every 100 s), while admitting every real repository measured.
MAX_FILE_COUNT = 50_000
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

        # Directory entries are not files and must not spend the budget. A
        # GitHub zipball carries one per directory -- 640 of react/react's
        # 7,841 entries, 8% of a limit meant to bound scanning work that a
        # directory entry does not cause. The same count is reported to the
        # caller as `file_count` and shown to the user as "files scanned",
        # where counting directories was simply wrong.
        files = [i for i in infos if not i.is_dir()]

        if len(files) > MAX_FILE_COUNT:
            raise ArchiveValidationError(
                "too_many_files", f"{len(files)} > {MAX_FILE_COUNT}"
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
        file_count=len(files) - symlink_count,
        total_uncompressed_bytes=total_uncompressed,
        symlink_count=symlink_count,
    )

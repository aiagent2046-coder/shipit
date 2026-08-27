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
# The largest a SINGLE entry may expand to. Bounds the same harm the total
# below bounds, one file at a time: what costs memory and disk is expanded
# bytes, and nothing else about an entry matters here.
#
# THIS REPLACED A COMPRESSION-RATIO CHECK, and the reason is worth keeping.
# That check refused any entry over 1 MB whose ratio exceeded 100x, with a
# comment asserting "legitimate source code stays well below 100x".
# payloadcms/payload disproves it: test/uploads/2mb.jpg is a synthetic 2 MB
# upload fixture that compresses to about 3.5 KB -- 605x -- and the whole
# repository was refused as a zip bomb over it. A file-upload library needs
# such a fixture; the customer cannot delete it to buy an audit.
#
# Ratio was a proxy for expansion and a poor one in both directions: it fired
# on a harmless 2 MB fixture and stayed silent on a 400 MB entry at 99x, which
# is the one that actually hurts. Bounding the expansion directly fires on the
# second and not the first.
#
# 100 MB because the total permits 500 MB across every entry: one file taking
# a fifth of that is not source, and it is fifty times the largest legitimate
# entry measured (that 2 MB fixture). Raising it is safe while the total holds;
# what must not happen is going back to judging an entry by its ratio.
MAX_UNCOMPRESSED_ENTRY_BYTES = 100 * 1024 * 1024


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


# End of Central Directory record: signature, then 16 bytes of counts and
# offsets, then a variable-length comment. The comment is bounded at 64 KiB,
# so the record starts somewhere in the last 64 KiB + 22 bytes.
_EOCD_SIG = b"PK\x05\x06"
_EOCD_MIN = 22
_EOCD_MAX_COMMENT = 0xFFFF
# ZIP64: the classic record cannot express more than 65535 entries, so it
# stores 0xFFFF and the real count lives in the ZIP64 record, found through a
# locator sitting immediately before the classic one.
_ZIP64_LOCATOR_SIG = b"PK\x06\x07"
_ZIP64_EOCD_SIG = b"PK\x06\x06"
_ZIP64_LOCATOR_LEN = 20


def _declared_entry_count(fileobj: BinaryIO, size_bytes: int) -> int | None:
    """Entry count read from the archive's trailer, without parsing entries.

    zipfile.ZipFile materialises a ZipInfo for every entry inside its
    constructor, so a count check placed after it has already paid for the
    thing it is meant to refuse. Measured: 560,000 empty entries packed into
    49 MB -- comfortably under MAX_ARCHIVE_BYTES -- cost 3.8 s of CPU and
    315 MB of RSS before validation could say a word, and identically so at
    the old 5,000 cap as at the current one, because the limit was never what
    bounded it.

    Reading the trailer costs a few hundred bytes and answers the same
    question. Returns None when the trailer cannot be parsed, and the caller
    then falls through to the old path: a malformed archive is zipfile's
    business to reject, and a parse bug here must never refuse a real upload.
    """
    # Only the trailer is read, never the archive. Reading it whole to find a
    # 22-byte record would allocate another MAX_ARCHIVE_BYTES per request --
    # trading the cost this function exists to avoid for a different one.
    window = min(size_bytes, _EOCD_MAX_COMMENT + _EOCD_MIN + _ZIP64_LOCATOR_LEN)
    fileobj.seek(size_bytes - window)
    tail = fileobj.read(window)

    start = tail.rfind(_EOCD_SIG)
    if start < 0 or len(tail) - start < _EOCD_MIN:
        return None
    count = int.from_bytes(tail[start + 10:start + 12], "little")
    if count != 0xFFFF:
        return count

    # ZIP64. The locator ends where the classic record begins.
    loc = start - _ZIP64_LOCATOR_LEN
    if loc < 0 or tail[loc:loc + 4] != _ZIP64_LOCATOR_SIG:
        return None
    z64_offset = int.from_bytes(tail[loc + 8:loc + 16], "little")
    if z64_offset < 0 or z64_offset + 40 > size_bytes:
        return None
    fileobj.seek(z64_offset)
    record = fileobj.read(40)
    if len(record) < 40 or record[:4] != _ZIP64_EOCD_SIG:
        return None
    return int.from_bytes(record[32:40], "little")


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

    # Refuse an absurd entry count from the trailer, BEFORE zipfile builds an
    # object per entry. Compared against the total rather than the file-only
    # count the check below uses, because directories cannot be told apart
    # without reading the entries -- which is the cost being avoided. An
    # archive whose TOTAL entries exceed the file budget is over it either
    # way, so nothing legitimate is refused here that would have passed later.
    try:
        declared = _declared_entry_count(fileobj, size_bytes)
    except (OSError, ValueError):
        declared = None   # unseekable or truncated: let zipfile have its say
    finally:
        fileobj.seek(0)
    if declared is not None and declared > MAX_FILE_COUNT:
        raise ArchiveValidationError(
            "too_many_files", f"{declared} > {MAX_FILE_COUNT}"
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

            if info.file_size > MAX_UNCOMPRESSED_ENTRY_BYTES:
                raise ArchiveValidationError(
                    "zip_bomb",
                    f"{info.filename}: {info.file_size} bytes uncompressed "
                    f"> {MAX_UNCOMPRESSED_ENTRY_BYTES}",
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

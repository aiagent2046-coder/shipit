"""Tests for archive validation: every rejection path must fire.

Malicious archives are crafted in-memory — no fixtures on disk.
"""

import io
import zipfile

import pytest

from app.ingest.validators import (
    MAX_ARCHIVE_BYTES,
    MAX_FILE_COUNT,
    ArchiveValidationError,
    validate_zip,
)


def make_zip(entries: dict[str, bytes]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    buf.seek(0)
    return buf


def make_symlink_zip() -> io.BytesIO:
    """Entry whose unix mode marks it as a symlink to /etc/passwd."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo("app/evil_link")
        info.external_attr = (0o120777 << 16)  # lrwxrwxrwx
        zf.writestr(info, "/etc/passwd")
    buf.seek(0)
    return buf


def size_of(buf: io.BytesIO) -> int:
    return buf.getbuffer().nbytes


def test_valid_small_archive_passes():
    buf = make_zip({"app/main.py": b"print('ok')\n", "README.md": b"# hi"})
    report = validate_zip(buf, size_bytes=size_of(buf))
    assert report.file_count == 2


def test_oversized_upload_rejected_before_parsing():
    buf = io.BytesIO(b"irrelevant")
    with pytest.raises(ArchiveValidationError) as exc:
        validate_zip(buf, size_bytes=MAX_ARCHIVE_BYTES + 1)
    assert exc.value.reason == "too_large"


def test_not_a_zip_rejected():
    buf = io.BytesIO(b"definitely not a zip file")
    with pytest.raises(ArchiveValidationError) as exc:
        validate_zip(buf, size_bytes=size_of(buf))
    assert exc.value.reason == "not_a_zip"


def test_too_many_files_rejected():
    entries = {f"f{i}.txt": b"x" for i in range(MAX_FILE_COUNT + 1)}
    buf = make_zip(entries)
    with pytest.raises(ArchiveValidationError) as exc:
        validate_zip(buf, size_bytes=size_of(buf))
    assert exc.value.reason == "too_many_files"


def test_symlink_entries_skipped_and_counted_not_rejected():
    # Real GitHub zipballs contain symlinks; we never extract, so we
    # skip and count them instead of losing the whole archive.
    buf = make_symlink_zip()
    report = validate_zip(buf, size_bytes=size_of(buf))
    assert report.symlink_count == 1
    assert report.file_count == 0


@pytest.mark.parametrize(
    "bad_name",
    ["../../etc/cron.d/evil", "/etc/passwd", "src/../../escape.py", "C:\\boot.ini"],
)
def test_path_traversal_rejected(bad_name):
    buf = make_zip({bad_name: b"x", "ok.txt": b"y"})
    with pytest.raises(ArchiveValidationError) as exc:
        validate_zip(buf, size_bytes=size_of(buf))
    assert exc.value.reason == "unsafe_path"


def test_zip_bomb_by_ratio_rejected():
    # 200 MB of zeros compresses ~1000x: > 1 MB entry, ratio >> 100.
    bomb = b"\x00" * (200 * 1024 * 1024)
    buf = make_zip({"bomb.bin": bomb})
    assert size_of(buf) < MAX_ARCHIVE_BYTES  # passes the size gate...
    with pytest.raises(ArchiveValidationError) as exc:
        validate_zip(buf, size_bytes=size_of(buf))
    assert exc.value.reason == "zip_bomb"  # ...but not the ratio gate


def test_zip_bomb_by_total_uncompressed_rejected():
    # Many entries, each individually under the ratio floor (1 MB),
    # but summing to > 500 MB uncompressed.
    entry = b"\x00" * (1024 * 1024 - 1)  # just under the per-entry floor
    entries = {f"part{i}.bin": entry for i in range(520)}
    buf = make_zip(entries)
    with pytest.raises(ArchiveValidationError) as exc:
        validate_zip(buf, size_bytes=size_of(buf))
    assert exc.value.reason == "zip_bomb"


def test_normal_compressible_source_not_flagged_as_bomb():
    # Realistic case: a big lockfile compresses well but stays far
    # below 100x because integrity hashes are unique per entry.
    import hashlib
    lines = [
        b'{"name":"pkg%d","integrity":"sha512-%s"}\n'
        % (i, hashlib.sha256(str(i).encode()).hexdigest().encode())
        for i in range(30_000)
    ]
    buf = make_zip({"package-lock.json": b"".join(lines)})
    report = validate_zip(buf, size_bytes=size_of(buf))
    assert report.file_count == 1


def test_directory_entries_do_not_spend_the_file_budget():
    """A zipball carries one entry per directory. They cause no scanning work,
    so counting them against MAX_FILE_COUNT rejects archives for the wrong
    reason -- 640 of react/react's 7,841 entries are directories.
    """
    entries = {f"d{i}/": b"" for i in range(200)}
    entries.update({f"d{i}/f.txt": b"x" for i in range(200)})
    buf = make_zip(entries)

    report = validate_zip(buf, size_bytes=size_of(buf))

    assert report.file_count == 200, (
        "file_count is shown to the user as 'files scanned'; directories are "
        "not files")


def test_a_real_large_repository_is_accepted():
    """The regression this limit change exists for.

    react/react is 7,201 files in 640 directories and was refused outright at
    the old cap of 5,000 -- not for anything a scanner struggles with (the
    full static scan of it runs in 3.7 s) but for having the file count of an
    ordinary large project. Sized to that shape rather than to a round number
    so it keeps meaning something if the cap moves again.
    """
    entries = {f"pkg{i}/": b"" for i in range(640)}
    entries.update({f"pkg{i % 640}/f{i}.ts": b"export const x = 1\n"
                    for i in range(7_201)})
    buf = make_zip(entries)

    report = validate_zip(buf, size_bytes=size_of(buf))

    assert report.file_count == 7_201

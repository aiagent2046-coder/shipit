"""Hostile and degenerate input: the audit ingests untrusted ZIPs, so the
static stage must degrade predictably -- a controlled error or a partial
result, never a crash with an unexpected type and never silently 'clean'
where nothing was read.
"""

from __future__ import annotations

import io
import stat
import warnings
import zipfile

import pytest

from tests.detector_samples import SAMPLES

from app.ingest.validators import ArchiveValidationError, validate_zip
from app.scan.static import run_static_scan

from .conftest import make_zip

KEY = SAMPLES["STRIPE"]


def test_non_zip_input_raises_the_controlled_error():
    with pytest.raises(ArchiveValidationError) as exc:
        run_static_scan(io.BytesIO(b"this is not a zip archive"))
    assert exc.value.reason == "not_a_zip"


@pytest.mark.parametrize("path", ["../evil.ts", "/abs/secret.ts", "src/../../evil.ts", "C:/secret.ts"])
def test_unsafe_paths_are_rejected_before_findings(path):
    with pytest.raises(ArchiveValidationError) as exc:
        run_static_scan(make_zip({path: f'const K = "{KEY}"'}))
    assert exc.value.reason == "unsafe_path"


def test_oversized_file_is_skipped_not_scanned():
    """An unread file must be counted as excluded, never as examined."""
    body = "x" * (1024 * 1024 + 100) + f'\nconst K = "{KEY}"\n'
    out = run_static_scan(make_zip({"src/big.ts": body}))
    assert not any(f["rule_id"] == "stripe-live-key" for f in out["findings"])
    assert out["secrets_coverage"]["files_scanned"] == 0
    assert out["secrets_coverage"]["exclusions"] == {"file_size_limit": 1}
    assert "0/1 files scanned" in out["coverage"]["secrets"]


def test_invalid_utf8_source_does_not_crash():
    out = run_static_scan(make_zip({
        "src/bad.ts": b"\xff\xfe\x00\x01" + f'const K = "{KEY}"'.encode()
    }))
    assert isinstance(out["findings"], list)


def test_empty_archive_is_scored_not_crash():
    out = run_static_scan(make_zip({}))
    assert 0.0 <= out["score"]["total"] <= 10.0


def test_archive_of_only_directories_is_fine():
    out = run_static_scan(make_zip({"src/": "", "app/": ""}))
    assert isinstance(out["findings"], list)


@pytest.mark.parametrize("second", ["src/config.ts", "src/./config.ts", "src//config.ts", r"src\config.ts"])
@pytest.mark.parametrize("same_contents", [True, False])
def test_duplicate_entry_names_are_rejected_before_scoring(second, same_contents):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("src/config.ts", f'const K = "{KEY}"')
        # Suppress only the warning for the exact duplicate, not scan failures.
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", message="Duplicate name:")
            zf.writestr(second, f'const K = "{KEY}"' if same_contents else 'export const K = null')
    raw = buf.getvalue()
    for check in (lambda b: validate_zip(b, size_bytes=len(raw)), run_static_scan):
        with pytest.raises(ArchiveValidationError) as exc:
            check(io.BytesIO(raw))
        assert exc.value.reason == "duplicate_path"


def test_different_directories_can_hold_the_same_basename():
    out = run_static_scan(make_zip({"a/config.ts": "export const x = 1", "b/config.ts": "export const x = 2"}))
    assert out["secrets_coverage"]["files_scanned"] == 2


def test_repeated_directory_records_do_not_duplicate_files():
    buf = io.BytesIO()
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message="Duplicate name:")
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("src/", "")
            zf.writestr("src/", "")
            zf.writestr("src/config.ts", f'const K = "{KEY}"')
    out = run_static_scan(io.BytesIO(buf.getvalue()))
    assert sum(f["rule_id"] == "stripe-live-key" for f in out["findings"]) == 1


@pytest.mark.parametrize("kind", ["directory", "symlink"])
@pytest.mark.parametrize("reversed_order", [False, True])
def test_non_file_entries_cannot_shadow_a_source_file(kind, reversed_order):
    other = zipfile.ZipInfo("src/config.ts/" if kind == "directory" else "src/config.ts")
    if kind == "symlink":
        other.create_system = 3
        other.external_attr = (stat.S_IFLNK | 0o777) << 16
    entries = [(zipfile.ZipInfo("src/config.ts"), "const x = 1"), (other, "")]
    buf = io.BytesIO()
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message="Duplicate name:")
        with zipfile.ZipFile(buf, "w") as zf:
            for entry, body in reversed(entries) if reversed_order else entries:
                zf.writestr(entry, body)
    with pytest.raises(ArchiveValidationError) as exc:
        run_static_scan(io.BytesIO(buf.getvalue()))
    assert exc.value.reason == "duplicate_path"

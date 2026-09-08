"""Excluded or partially decoded input must not acquire an examined verdict."""
import io
import stat
import zipfile

from app.scan.secrets import MAX_SCANNED_FILE_BYTES
from app.scan.static import run_static_scan

from .conftest import make_zip


def test_secret_read_accounting_reconciles_every_file():
    raw = make_zip({
        "src/": "",
        "src/good.ts": "export const x = 1",
        "src/large.ts": "x" * (MAX_SCANNED_FILE_BYTES + 1),
        "node_modules/vendor/index.js": "const x = 1",
        "logo.png": b"image",
        "src/binary.dat": b"\x00binary",
        "src/lossy.ts": b"\xffexport const x = 2",
    })
    out = run_static_scan(raw)
    coverage = out["secrets_coverage"]
    assert coverage == {
        "files_total": 6, "files_read": 3, "files_scanned": 2, "lossy_decoded_files": 1,
        "exclusions": {"file_size_limit": 1, "excluded_directory": 1, "excluded_extension": 1, "binary_content": 1},
    }
    assert coverage["files_total"] == coverage["files_scanned"] + sum(coverage["exclusions"].values())
    assert "2/6 files scanned" in out["coverage"]["secrets"]
    assert "files with invalid UTF-8 bytes omitted: 1" in out["coverage"]["secrets"]


def test_symlink_payload_is_not_read_or_reported_as_scanned():
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, "w") as z:
        entry = zipfile.ZipInfo("src/link.ts")
        entry.create_system = 3
        entry.external_attr = (stat.S_IFLNK | 0o777) << 16
        z.writestr(entry, "/outside/source.ts")
    coverage = run_static_scan(io.BytesIO(raw.getvalue()))["secrets_coverage"]
    assert coverage["files_total"] == 1
    assert coverage["files_read"] == coverage["files_scanned"] == 0
    assert coverage["exclusions"] == {"symlink": 1}


def test_no_input_has_zero_examined_files():
    coverage = run_static_scan(make_zip({}))["secrets_coverage"]
    assert coverage["files_total"] == coverage["files_scanned"] == 0

"""Synthetic source fixtures: no uploaded code is executed or opened.

The load-bearing tests:

  * only a literal filter="fully_trusted" on an import-proven tarfile.open
    object's extract/extractall is a finding; the empirical ground is the
    3.12.13 measurement (fully_trusted writes outside the destination,
    data and tar raise OutsideDestinationError, zipfile sanitizes);
  * every corpus negative is MUTATED in the one place that removes the
    property it pins, and the rule must fire on the result;
  * the product's own code is scanned.
"""
import io
import zipfile
from pathlib import Path

import pytest

from app.scan.archive_extraction import RULE_ID, scan_archive_extraction
from app.scan.static import run_static_scan

REPO_ROOT = Path(__file__).resolve().parent.parent

POSITIVE = ('import tarfile\n'
            'with tarfile.open(upload) as tar:\n'
            '    tar.extractall(dest, filter="fully_trusted")\n')


def archive(files: dict[str, str] | str, path: str = "repo/app/x.py") -> io.BytesIO:
    if isinstance(files, str):
        files = {path: files}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, text in files.items():
            z.writestr(name, text)
    buf.seek(0)
    return buf


def test_the_explicit_opt_out_is_a_high_severity_finding():
    findings = [f for f in run_static_scan(archive(POSITIVE))["findings"] if f["rule_id"] == RULE_ID]
    assert len(findings) == 1
    f = findings[0]
    assert "extractall" in POSITIVE.splitlines()[f["line"] - 1]
    assert f["severity"] == "high"
    assert f["confidence"] == 0.9
    assert f["category"] == "Security"
    assert f["source"] == "static"
    assert f["verification_status"] == "unverified"
    assert "fully_trusted" in f["explanation"]


@pytest.mark.parametrize("source", [
    # a with-bound archive, a chained call and a direct extract all qualify
    'import tarfile\ntarfile.open(p).extractall(d, filter="fully_trusted")\n',
    'import tarfile\ntar = tarfile.open(p)\ntar.extractall(d, filter="fully_trusted")\n',
    'import tarfile\nwith tarfile.open(p) as tar:\n    tar.extract(m, filter="fully_trusted")\n',
    # import aliases resolve through the file's imports
    'from tarfile import open as tar_open\nwith tar_open(p) as t:\n    t.extractall(d, filter="fully_trusted")\n',
    'import tarfile\nwith tarfile.TarFile.open(p) as t:\n    t.extractall(d, filter="fully_trusted")\n',
])
def test_proven_tars_with_the_literal_opt_out_are_reported(source):
    assert len(scan_archive_extraction(archive(source))) == 1


@pytest.mark.parametrize("source", [
    # the safe filters, measured: they refuse members escaping the destination
    'import tarfile\nwith tarfile.open(p) as t:\n    t.extractall(d, filter="data")\n',
    'import tarfile\nwith tarfile.open(p) as t:\n    t.extractall(d, filter="tar")\n',
    # no filter at all: version-dependent default, not proven
    'import tarfile\nwith tarfile.open(p) as t:\n    t.extractall(d)\n',
    # a variable filter is unresolved
    'import tarfile\nwith tarfile.open(p) as t:\n    t.extractall(d, filter=mode)\n',
    # a ** spread can carry or override the filter at runtime
    'import tarfile\nwith tarfile.open(p) as t:\n    t.extractall(d, **options)\n',
    # a rebound name loses its provenance
    'import tarfile\nt = tarfile.open(p)\nt = other\nt.extractall(d, filter="fully_trusted")\n',
    # a parameter receiver is not proven to come from tarfile.open
    'import tarfile\ndef f(t, d):\n    t.extractall(d, filter="fully_trusted")\n',
    # zipfile sanitizes paths itself and has no filter parameter
    'import zipfile\nwith zipfile.ZipFile(p) as z:\n    z.extractall(d)\n',
    # a with-bound name used outside its block is not proven to hold the archive
    'import tarfile\nwith tarfile.open(p) as t:\n    pass\nt.extractall(d, filter="fully_trusted")\n',
    # an unimported receiver has no provenance
    't.extractall(d, filter="fully_trusted")\n',
    "not valid python (",
])
def test_shapes_this_rule_does_not_report(source):
    assert scan_archive_extraction(archive(source)) == []


CORPUS_NEGATIVES = REPO_ROOT / "tests" / "detectors" / RULE_ID / "negative"
MUTATIONS: dict[str, tuple[str, str, str]] = {
    "filter-data": ("app/unpack.py", 'filter="data"', 'filter="fully_trusted"'),
    "no-filter": ("app/unpack.py", "tar.extractall(dest)",
                  'tar.extractall(dest, filter="fully_trusted")'),
    "filter-variable": ("app/unpack.py", "filter=mode", 'filter="fully_trusted"'),
    "rebound-name": ("app/unpack.py", "tar = other\n", ""),
    "call-outside-with-block": ("app/unpack.py",
                                "    pass\ntar.extractall(dest, filter=\"fully_trusted\")",
                                "    tar.extractall(dest, filter=\"fully_trusted\")"),
}


def test_every_corpus_negative_has_a_mutation():
    on_disk = {case.name for case in CORPUS_NEGATIVES.iterdir() if case.is_dir()}
    assert on_disk == set(MUTATIONS), f"no mutation for: {on_disk - set(MUTATIONS)}"


@pytest.mark.parametrize("case", sorted(MUTATIONS))
def test_each_corpus_negative_goes_silent_for_its_stated_reason(case):
    relative, old, new = MUTATIONS[case]
    case_dir = CORPUS_NEGATIVES / case
    files = {p.relative_to(case_dir).as_posix().removesuffix(".fixture"): p.read_text()
             for p in case_dir.rglob("*.fixture")}
    assert scan_archive_extraction(archive(files)) == [], "the untouched case must be silent"
    assert old in files[relative], f"mutation anchor is gone from {relative}"
    files[relative] = files[relative].replace(old, new, 1)
    assert scan_archive_extraction(archive(files)), "the mutation must make the rule fire"


def test_the_product_own_code_reports_nothing():
    """A false-positive guard: shipit does not extract archives with fully_trusted."""
    python = {p.relative_to(REPO_ROOT).as_posix(): p.read_text()
              for p in sorted((REPO_ROOT / "app").rglob("*.py")) if "__pycache__" not in p.parts}
    assert scan_archive_extraction(archive(python)) == []

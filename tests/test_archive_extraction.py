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


def test_same_receiver_name_in_independent_functions_keeps_both_provenances():
    source = ('import tarfile\n'
              'def unpack_one(path, dest):\n'
              '    tar = tarfile.open(path)\n'
              '    tar.extractall(dest, filter="fully_trusted")\n'
              'def unpack_two(path, dest):\n'
              '    tar = tarfile.open(path)\n'
              '    tar.extractall(dest, filter="fully_trusted")\n')
    assert [finding.line for finding in scan_archive_extraction(archive(source))] == [4, 7]


def test_a_shadowed_setattr_name_does_not_hide_a_proven_direct_chain():
    source = ('import tarfile\n'
              'def setattr(*args):\n'
              '    pass\n'
              'setattr(tarfile, "open", custom_open)\n'
              'tarfile.open(path).extractall(dest, filter="fully_trusted")\n')
    assert [finding.line for finding in scan_archive_extraction(archive(source))] == [5]


@pytest.mark.parametrize("source,mutation", [
    ('import tarfile\n'
     'setattr(tarfile, "open", custom_open)\n'
     'tarfile.open(path).extractall(dest, filter="fully_trusted")\n',
     'setattr(tarfile, "open", custom_open)\n'),
    ('import tarfile\n'
     'tar = tarfile.open(path)\n'
     'setattr(tar, "extractall", custom_extractall)\n'
     'tar.extractall(dest, filter="fully_trusted")\n',
     'setattr(tar, "extractall", custom_extractall)\n'),
    ('from unittest.mock import patch\n'
     'import tarfile\n'
     'with patch.object(tarfile, "open", custom_open):\n'
     '    tarfile.open(path).extractall(dest, filter="fully_trusted")\n',
     'with patch.object(tarfile, "open", custom_open):\n    '),
])
def test_dynamic_mutations_are_silent_until_the_mutation_is_removed(source, mutation):
    assert scan_archive_extraction(archive(source)) == []
    assert mutation in source
    assert len(scan_archive_extraction(archive(source.replace(mutation, "", 1)))) == 1


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
    "python-filter-from-a-sibling-scope": ("app/unpack.py", "filter=mode",
                                          'filter="fully_trusted"'),
    "rebound-name": ("app/unpack.py", "tar = other\n", ""),
    "call-outside-with-block": ("app/unpack.py",
                                "    pass\ntar.extractall(dest, filter=\"fully_trusted\")",
                                "    tar.extractall(dest, filter=\"fully_trusted\")"),
    "call-before-binding": ("app/unpack.py",
                            't.extractall(dest, filter="fully_trusted")\nt = tarfile.open(source)',
                            't = tarfile.open(source)\nt.extractall(dest, filter="fully_trusted")'),
    "binding-in-other-scope": ("app/unpack.py", '\nt.extractall(', '\n    t.extractall('),
    "patched-open": ("app/unpack.py", 'tarfile.open = custom_open\n', ''),
    "dynamic-setattr-open": ("app/unpack.py", 'setattr(tarfile, "open", custom_open)\n', ''),
    "dynamic-setattr-receiver": ("app/unpack.py", 'setattr(tar, "extractall", custom_extractall)\n', ''),
    "dynamic-patch-object": ("app/unpack.py",
                             'with patch.object(tarfile, "open", custom_open):\n    ', ''),
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


_BIND = 'import tarfile\nt = tarfile.open(p)\n'
_SINK = 't.extractall(d, filter="fully_trusted")\n'


@pytest.mark.parametrize("source,old,new", [
    (_BIND + 'def t():\n    pass\n' + _SINK, 'def t():\n    pass\n', ''),
    (_BIND + 'class t:\n    pass\n' + _SINK, 'class t:\n    pass\n', ''),
    (_BIND + 'type t = object\n' + _SINK, 'type t = object\n', ''),
    (_BIND + 'del t\n' + _SINK, 'del t\n', ''),
    (_BIND + 't.extractall = custom\n' + _SINK, 't.extractall = custom\n', ''),
    ('import tarfile\ntarfile.open = custom\ntarfile.open(p).extractall(d, filter="fully_trusted")\n',
     'tarfile.open = custom\n', ''),
    (_BIND + 'from plugin import *\n' + _SINK, 'from plugin import *\n', ''),
    ('import tarfile\ndef f():\n    t = tarfile.open(p)\n' + _SINK,
     '\n' + _SINK, '\n    ' + _SINK),
    ('import tarfile\nclass C:\n    t = tarfile.open(p)\n' + _SINK,
     '\n' + _SINK, '\n    ' + _SINK),
    ('import tarfile\n' + _SINK + 't = tarfile.open(p)\n',
     _SINK + 't = tarfile.open(p)\n', 't = tarfile.open(p)\n' + _SINK),
    ('import tarfile\nif enabled:\n    t = tarfile.open(p)\n' + _SINK,
     '\n' + _SINK, '\n    ' + _SINK),
    ('import tarfile\nwith tarfile.open(p) as t, t.extractall(d, filter="fully_trusted"):\n    pass\n',
     ', t.extractall(d, filter="fully_trusted"):\n    pass', ':\n    ' + _SINK.rstrip()),
    ('import tarfile\nwith tarfile.open(p) as (t, other):\n    ' + _SINK,
     '(t, other)', 't'),
    ('import tarfile\nwith tarfile.open(p) as t:\n    def later():\n        ' + _SINK,
     '    def later():\n        ', '    '),
    (_BIND + 'type Alias[t] = ' + _SINK, 'type Alias[t] = ', ''),
    ('import tarfile\ntype Alias[tarfile] = tarfile.open(p).extractall(d, filter="fully_trusted")\n',
     'type Alias[tarfile] = ', ''),
    ('import tarfile\ndef f[tarfile]():\n    tarfile.open(p).extractall(d, filter="fully_trusted")\n',
     '[tarfile]', ''),
    ('import tarfile\nclass C[tarfile]:\n    tarfile.open(p).extractall(d, filter="fully_trusted")\n',
     '[tarfile]', ''),
    ('import tarfile\ndef f[tarfile](value=tarfile.open(p).extractall(d, filter="fully_trusted")):\n    pass\n',
     '[tarfile]', ''),
])
def test_unproven_receiver_regressions_fire_only_after_restoring_the_binding(source, old, new):
    assert scan_archive_extraction(archive(source)) == []
    assert old in source
    restored = source.replace(old, new, 1)
    assert len(scan_archive_extraction(archive(restored))) == 1


@pytest.mark.parametrize("source", [
    'import tarfile\ndef f():\n    t = tarfile.open(p)\n    ' + _SINK,
    'import tarfile\nif enabled:\n    t = tarfile.open(p)\n    ' + _SINK,
    _BIND + 'if enabled:\n    ' + _SINK,
    'import tarfile\nfor p in paths:\n    with tarfile.open(p) as t:\n        ' + _SINK,
])
def test_enclosing_control_flow_keeps_proven_receivers(source):
    assert len(scan_archive_extraction(archive(source))) == 1

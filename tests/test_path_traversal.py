"""Synthetic source fixtures: no uploaded code is imported, run or opened.

The load-bearing tests:

  * every corpus negative is MUTATED in the one place that removes the property it
    pins, and the rule must fire on the result;
  * every negative on disk has a mutation;
  * the product's own code is scanned with its premise asserted -- shipit opens,
    joins and serves files in dozens of places, so the silence below is silence over
    code that touches the filesystem, not silence over an empty archive.
"""
import io
import re
import zipfile
from pathlib import Path

import pytest

from app.scan.path_traversal import RULE_ID, scan_path_traversal
from app.scan.static import run_static_scan

REPO_ROOT = Path(__file__).resolve().parent.parent

POSITIVE = '''from fastapi import APIRouter, Depends
import os

router = APIRouter()
UPLOAD_DIR = "/srv/uploads"


@router.get("/download/{name}")
async def download(name: str):
    return open(os.path.join(UPLOAD_DIR, name)).read()
'''


def archive(files: dict[str, str] | str, path: str = "repo/app/files.py") -> io.BytesIO:
    if isinstance(files, str):
        files = {path: files}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, text in files.items():
            z.writestr(name, text)
    buf.seek(0)
    return buf


def test_a_path_built_from_caller_input_is_a_high_severity_signal():
    source = POSITIVE
    findings = [f for f in run_static_scan(archive(source))["findings"] if f["rule_id"] == RULE_ID]
    assert len(findings) == 1
    f = findings[0]
    assert "open(os.path.join(" in source.splitlines()[f["line"] - 1]
    assert f["severity"] == "high"
    assert f["confidence"] == 0.8
    assert f["category"] == "Security"
    assert f["source"] == "static"
    assert f["verification_status"] == "unverified"
    assert "traced only inside this function" in f["explanation"]


@pytest.mark.parametrize("source", [
    # containment inside the expression
    POSITIVE.replace("os.path.join(UPLOAD_DIR, name)", "os.path.join(UPLOAD_DIR, secure_filename(name))"),
    POSITIVE.replace("os.path.join(UPLOAD_DIR, name)", "os.path.join(UPLOAD_DIR, os.path.basename(name))"),
    # a literal path, with the caller's name used for something else
    POSITIVE.replace("os.path.join(UPLOAD_DIR, name)", 'os.path.join(UPLOAD_DIR, "report.csv")'),
    # the path is injected configuration, not a request input
    POSITIVE.replace("async def download(name: str):",
                     "async def download(name: str = Depends(get_path)):"),
    # built by a call the trace does not follow
    POSITIVE.replace("open(os.path.join(UPLOAD_DIR, name))", "open(build_path(name))"),
    # a file opened without touching the caller's value at all
    "import os\nUPLOAD = '/srv'\n\n\ndef job():\n    return open(os.path.join(UPLOAD, 'x.txt')).read()\n",
    "not valid python (",
])
def test_shapes_this_rule_does_not_report(source):
    assert scan_path_traversal(archive(source)) == []


def test_a_check_before_the_sink_counts_and_one_after_it_does_not():
    """The reason the rule walks statements in order.

    `candidate.resolve()` normalises without restricting; only the comparison
    constrains, and only if it runs first.
    """
    guarded = '''from fastapi import APIRouter
from pathlib import Path

router = APIRouter()
BASE = "/srv/uploads"


@router.get("/read/{name}")
async def read_it(name: str):
    candidate = (Path(BASE) / name).resolve()
    if not candidate.is_relative_to(BASE):
        raise ValueError("escape")
    return candidate.read_text()
'''
    after = guarded.replace(
        '    if not candidate.is_relative_to(BASE):\n        raise ValueError("escape")\n', "")
    assert scan_path_traversal(archive(guarded)) == []
    assert scan_path_traversal(archive(after)), "without the check the read must be reported"


def test_resolve_alone_is_not_containment():
    """`resolve()` is the shape a naive vocabulary mistakes for a check."""
    source = '''from fastapi import APIRouter
from pathlib import Path

router = APIRouter()
BASE = "/srv/uploads"


@router.get("/read/{name}")
async def read_it(name: str):
    return (Path(BASE) / name).resolve().read_text()
'''
    assert scan_path_traversal(archive(source))


# case name -> (file, the one change that removes the property the case pins)
CORPUS_NEGATIVES = REPO_ROOT / "tests" / "detectors" / RULE_ID / "negative"
MUTATIONS: dict[str, tuple[str, str, str]] = {
    "secure-filename-and-basename": ("app/safe_files.py", "secure_filename(name)", "name"),
    "containment-check-before-the-sink": (
        "app/resolved.py",
        '    if not candidate.is_relative_to(UPLOAD_DIR):\n        raise ValueError("escape")\n',
        ""),
    "literal-path": ("app/fixed.py", '"summary.csv"', "name"),
    "path-injected-by-a-dependency": ("app/configured.py", "Depends(get_path)", "Query(...)"),
    "helper-builds-the-path": ("app/indirect.py", "build_path(name)",
                              "os.path.join(UPLOAD_DIR, name)"),
    "input-used-as-content-not-a-path": ("app/write_content.py",
                                         'os.path.join(UPLOAD_DIR, "notes.txt")',
                                         "os.path.join(UPLOAD_DIR, name)"),
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
    assert scan_path_traversal(archive(files)) == [], "the untouched case must be silent"
    assert old in files[relative], f"mutation anchor is gone from {relative}"
    files[relative] = files[relative].replace(old, new, 1)
    assert scan_path_traversal(archive(files)), "the mutation must make the rule fire"


def test_the_product_own_code_reports_nothing():
    """A false-positive guard whose premise is asserted.

    shipit works with files constantly -- uploads, spools, report artifacts, served
    bundles -- so a rule that fired on our own routes would be unusable. If this ever
    fails, read the reported line before touching the rule.
    """
    sources = {p.relative_to(REPO_ROOT).as_posix(): p.read_text()
               for p in sorted((REPO_ROOT / "app").rglob("*.py")) if "__pycache__" not in p.parts}
    text = "\n".join(sources.values())
    file_calls = len(re.findall(r"\bopen\(", text)) + len(re.findall(r"Path\(", text)) \
        + len(re.findall(r"os\.path\.join", text))
    assert file_calls > 40, f"expected the product to work with files; found {file_calls}"
    assert scan_path_traversal(archive(sources)) == []

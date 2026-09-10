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
from werkzeug.utils import secure_filename
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
    POSITIVE.replace("os.path.join(UPLOAD_DIR, name)",
                     "os.path.join(UPLOAD_DIR, secure_filename(os.path.basename(name)))"),
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


def route(body: str, extra: str = "", parameters: str = "name: str") -> str:
    return ("from fastapi import APIRouter\nfrom pathlib import Path, PurePath\n"
            "from werkzeug.utils import secure_filename\nimport os\nimport shutil\n"
            "router = APIRouter()\nBASE = '/srv/uploads'\n" + extra
            + f"@router.get('/file')\ndef handle({parameters}):\n" + body)


@pytest.mark.parametrize("body", [
    "    (Path(BASE) / name).write_text('fixed content')\n",
    "    (Path(BASE) / name).write_bytes(b'fixed content')\n",
    "    return (Path(BASE) / name).open('r')\n",
    "    return (Path(BASE) / name).read_text('utf-8')\n",
    "    return open(file=os.path.join(BASE, name)).read()\n",
    "    os.rename(os.path.join(BASE, name), '/srv/archive/file')\n",
    "    os.rename(src='/srv/source', dst=os.path.join(BASE, name))\n",
    "    shutil.copyfile('/srv/source', os.path.join(BASE, name))\n",
    "    shutil.copyfile(src=os.path.join(BASE, name), dst='/srv/archive/file')\n",
    "    Path('/srv/source').rename(target=Path(BASE) / name)\n",
    "    return (Path(BASE) / name).with_suffix('.txt').read_text()\n",
    "    return (Path(BASE) / name).with_name('fixed.txt').read_text()\n",
    "    return (Path(BASE) / name).with_stem('fixed').read_text()\n",
    "    return Path(BASE).joinpath('subdir', name).read_text()\n",
    "    return Path(BASE, name).read_text()\n",
    "    return (Path(BASE) / name).resolve(False).read_text()\n",
    "    return open(os.path.join(BASE, name), encoding=os.path.basename('utf-8')).read()\n",
    "    return open(os.path.join(BASE, secure_filename(name), name)).read()\n",
    "    shutil.rmtree(os.path.join(BASE, os.path.basename(name)))\n",
])
def test_real_filesystem_signatures_and_transforms(body):
    findings = scan_path_traversal(archive(route(body)))
    assert len(findings) == 1
    assert findings[0].line == len(route(body).splitlines())


@pytest.mark.parametrize("body", [
    "    (Path(BASE) / 'fixed.txt').write_text(name)\n",
    "    (Path(BASE) / 'fixed.txt').write_bytes(name.encode())\n",
    "    return str(Path(name))\n",
    "    return PurePath(name)\n",
    "    return (PurePath(BASE) / name).name\n",
    "    return open(os.path.join(BASE, secure_filename(name))).read()\n",
])
def test_contents_and_pure_construction_are_not_filesystem_paths(body):
    assert scan_path_traversal(archive(route(body))) == []


@pytest.mark.parametrize("check", [
    "    if not p.is_relative_to(BASE):\n        print('escape')\n",
    "    if p.is_relative_to(BASE):\n        print('inside')\n",
    "    if p.is_relative_to(BASE):\n        return 'inside'\n",
    "    if os.path.commonprefix([str(p), BASE]) != BASE:\n        raise ValueError('escape')\n",
    "    if validate_path(p):\n        print('validated')\n",
])
def test_only_an_enforcing_containment_branch_suppresses_the_later_sink(check):
    body = "    p = (Path(BASE) / name).resolve()\n" + check + "    return p.read_text()\n"
    assert len(scan_path_traversal(archive(route(body)))) == 1


@pytest.mark.parametrize("check", [
    "    if not p.is_relative_to(BASE):\n        raise ValueError('escape')\n",
    "    if not p.is_relative_to(BASE):\n        return 'escape'\n",
    "    p.relative_to(BASE)\n",
])
def test_known_normalized_path_with_enforced_containment(check):
    body = "    p = Path(BASE) / name\n    p = p.resolve()\n" + check + "    return p.read_text()\n"
    assert scan_path_traversal(archive(route(body))) == []


@pytest.mark.parametrize("body", [
    "    p = Path(BASE) / name\n    if not p.is_relative_to(BASE):\n        raise ValueError('escape')\n"
    "    return p.read_text()\n",
    "    p = (Path(BASE) / name).resolve()\n    if not p.is_relative_to(BASE):\n"
    "        return p.read_text()\n    return 'inside'\n",
    "    p = (Path(BASE) / name).resolve()\n    if not p.is_relative_to(BASE):\n"
    "        raise ValueError('escape')\n    p = Path(BASE) / other\n    return p.read_text()\n",
    "    p = (Path(BASE) / name).resolve()\n    if not p.is_relative_to(BASE):\n"
    "        raise ValueError('escape')\n    return (Path('/other') / name).read_text()\n",
    "    p = (Path(BASE) / name).resolve()\n    if not p.is_relative_to(other):\n"
    "        raise ValueError('escape')\n    return p.read_text()\n",
])
def test_containment_preserves_path_identity_normalization_and_fixed_base(body):
    assert len(scan_path_traversal(archive(route(body, parameters="name: str, other: str")))) == 1


def test_positive_branch_can_read_inside_while_rejecting_outside():
    body = ("    p = (Path(BASE) / name).resolve()\n    if p.is_relative_to(BASE):\n"
            "        return p.read_text()\n    raise ValueError('escape')\n")
    assert scan_path_traversal(archive(route(body))) == []


@pytest.mark.parametrize("extra, body, parameters", [
    ("def open(value):\n    return value\n", "    return open(name)\n", "name: str"),
    ("", "    return open(name)\n", "name: str, open: str"),
    ("from custom import Path\n", "    return Path(name).read_text()\n", "name: str"),
    ("", "    return client.write_text(name)\n", "name: str, client: object"),
])
def test_unknown_or_shadowed_filesystem_targets_do_not_acquire_library_provenance(extra, body, parameters):
    assert scan_path_traversal(archive(route(body, extra, parameters))) == []


def test_sanitizer_alias_is_proven_and_cannot_sanitize_an_unrelated_raw_component():
    source = route("    return open(os.path.join(BASE, clean(name), other)).read()\n",
                   "from werkzeug.utils import secure_filename as clean\n", "name: str, other: str")
    findings = scan_path_traversal(archive(source))
    assert len(findings) == 1
    assert "assembled from other," in findings[0].explanation


def test_a_context_manager_that_swallows_the_rejection_does_not_establish_containment():
    body = ("    p = (Path(BASE) / name).resolve()\n    with suppress(ValueError):\n"
            "        p.relative_to(BASE)\n    return p.read_text()\n")
    assert len(scan_path_traversal(archive(route(body, "from contextlib import suppress\n")))) == 1


def test_import_rebinding_drops_path_receiver_provenance():
    body = "    p = Path(name)\n    import custom as p\n    return p.read_text()\n"
    assert scan_path_traversal(archive(route(body))) == []


def test_future_local_assignment_does_not_misclassify_an_unbound_builtin_as_a_sink():
    body = "    open(name)\n    open = custom\n"
    assert scan_path_traversal(archive(route(body))) == []


@pytest.mark.parametrize("operator", ["join", "division"])
@pytest.mark.parametrize("initial", ["name", "'x'"])
def test_path_expansion_is_bounded_before_allocation_in_the_real_static_pipeline(monkeypatch, operator, initial):
    from app.scan import path_traversal as detector
    from app.scan.outbound_url import _MAX_SLOTS, _MAX_TEMPLATE_BYTES

    original = detector._path_skeleton
    seen = []

    def observe(expr, state):
        result = original(expr, state)
        if result is not None:
            assert len(result[0]) <= _MAX_TEMPLATE_BYTES
            assert len(result[1]) <= _MAX_SLOTS
            seen.append((len(result[0]), len(result[1])))
        return result

    monkeypatch.setattr(detector, "_path_skeleton", observe)
    # 15 doublings suffice to reproduce the old limit violation safely.
    body = f"    v0 = {initial if operator == 'join' else f'Path({initial})'}\n"
    for i in range(1, 16):
        expression = f"os.path.join(v{i-1}, v{i-1})" if operator == "join" else f"v{i-1} / v{i-1}"
        body += f"    v{i} = {expression}\n"
    body += "    return open(v15).read()\n"
    run_static_scan(archive(route(body)))
    assert seen
    if initial == "name":
        assert max(slots for _, slots in seen) == _MAX_SLOTS
    else:
        assert max(size for size, _ in seen) > _MAX_TEMPLATE_BYTES // 4

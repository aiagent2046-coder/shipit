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
    assert "at most one eligible same-file helper" in f["explanation"]


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
    # the value crosses a DEFINITION boundary: a local helper's parameter is not
    # the handler's parameter, and the helper is callable from anywhere in the
    # file, so connecting them needs a call graph this rule does not build
    "sink-inside-a-local-helper": ("app/files.py",
                                   "    def read(p):\n"
                                   "        return open(os.path.join(UPLOAD_DIR, p)).read()\n"
                                   "\n"
                                   "    return read(name)",
                                   "    return open(os.path.join(UPLOAD_DIR, name)).read()"),
    # a resolvable helper with nothing request-derived to trace
    "helper-called-with-a-literal": (
        "app/files.py",
        '@router.get("/get-file")\nasync def get_file():\n    return open(get_file_path("index.html")).read()',
        '@router.get("/get-file/{name}")\nasync def get_file(name: str):\n    return open(get_file_path(name)).read()'),
    # the name no longer means the declaration: resolving it would be a guess
    "rebound-helper": ("app/files.py", "get_file_path = build_path_elsewhere\n\n\n", ""),
    # one transition, no call graph: the second hop stays opaque
    "two-hop-helpers": ("app/files.py", "open(outer(name))", "open(inner(name))"),
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


# Hunt round 2: nineteen model rewrites of this rule's positives moved the join
# -- or the whole sink -- into a same-file module-level helper, and every one
# escaped the "unknown helpers stop this trace" boundary. A helper declared
# exactly once, undecorated and never rebound is now followed through ONE
# transition: its body is traced, and a single return is read as the call's.
HELPER_SOURCE = '''from fastapi import APIRouter
import os

router = APIRouter()
UPLOAD_DIR = "/srv/uploads"


def get_file_path(name):
    return os.path.join(UPLOAD_DIR, name)


@router.get("/get-file/{name}")
async def get_file(name: str):
    return open(get_file_path(name)).read()
'''


def test_a_same_file_helper_returning_the_callers_path_is_traced():
    findings = scan_path_traversal(archive(HELPER_SOURCE))
    assert len(findings) == 1
    assert "assembled from name" in findings[0].explanation


def test_a_sink_inside_a_same_file_helper_is_traced():
    source = '''from fastapi import APIRouter
import shutil

router = APIRouter()
BASE = "/srv/uploads"


def move_file(source):
    shutil.copy(source, "/var/dest")


@router.post("/import/{source}")
async def handler(source: str):
    move_file(source)
    return {"ok": True}
'''
    findings = scan_path_traversal(archive(source))
    assert len(findings) == 1
    assert findings[0].line == 9
    assert "assembled from source" in findings[0].explanation


@pytest.mark.parametrize("source", [
    # the helper is called with a literal: its body holds nothing request-derived
    HELPER_SOURCE.replace(
        '@router.get("/get-file/{name}")\nasync def get_file(name: str):\n'
        '    return open(get_file_path(name)).read()',
        '@router.get("/get-file")\nasync def get_file():\n'
        '    return open(get_file_path("index.html")).read()'),
    # the name no longer means the declaration
    HELPER_SOURCE.replace('UPLOAD_DIR = "/srv/uploads"\n',
                          'UPLOAD_DIR = "/srv/uploads"\nget_file_path = build_path_elsewhere\n'),
    # a decorated helper is not a plain function: a decorator can change the callable
    HELPER_SOURCE.replace("def get_file_path(name):", "@cache\ndef get_file_path(name):"),
    # two hops are not followed: this is not a call graph
    HELPER_SOURCE.replace(
        "def get_file_path(name):\n    return os.path.join(UPLOAD_DIR, name)",
        "def get_file_path(name):\n    return build_name(name)\n\n\n"
        "def build_name(name):\n    return os.path.join(UPLOAD_DIR, name)"),
    # a *args helper stays opaque: mapping the parameters would be guessing
    HELPER_SOURCE.replace("def get_file_path(name):", "def get_file_path(*args):"),
])
def test_unresolvable_helper_shapes_stay_silent(source):
    assert scan_path_traversal(archive(source)) == []


def test_helper_resolution_is_budgeted(monkeypatch):
    """A generated archive cannot turn helper resolution into a scan bomb: past
    the budget, resolution stops and the remaining helpers stay opaque."""
    from app.scan import path_traversal as detector
    monkeypatch.setattr(detector, "_MAX_HELPER_RESOLUTIONS", 1)
    helpers = "\n\n".join(
        f"def helper_{index}(value):\n    return open(value).read()\n" for index in range(3))
    calls = "\n".join(f"    helper_{index}(name)" for index in range(3))
    source = ("from fastapi import APIRouter\nimport os\nrouter = APIRouter()\n"
              + helpers
              + "\n\n@router.get('/x')\nasync def h(name: str):\n" + calls + "\n")
    assert len(scan_path_traversal(archive(source))) == 1


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


@pytest.mark.parametrize(("helper", "body", "expected"), [
    # All arguments are read before any same-named parameter is bound.
    ('def h(name, value):\n    return os.path.join("/srv", value)\n',
     '    return open(h("safe", name)).read()', 1),
    ('def h(safe, value):\n    return os.path.join("/srv", value)\n',
     '    safe="safe"\n    return open(h(name, safe)).read()', 0),
    # Free globals/imports belong to the helper's module, not the handler.
    ('name="safe"\ndef h(value):\n    return os.path.join("/srv", name)\n',
     '    return open(h(name)).read()', 0),
    ('def h(value):\n    return os.path.join("/srv", value)\n',
     '    os=None\n    return open(h(name)).read()', 1),
    # Defaults are frozen at definition time, even if the module name changes.
    ('name="safe"\ndef h(value, filename=name):\n    return os.path.join("/srv", filename)\n'
     'name=unresolved\n', '    return open(h(name)).read()', 0),
    ('def h(value, filename="safe"):\n    return os.path.join("/srv", filename)\n',
     '    return open(h("safe", filename=name)).read()', 1),
    # A local store shadows builtins throughout the helper, including before it.
    ('def h(value):\n    open(value)\n    open=unknown\n', '    return h(name)', 0),
    ('def h(value):\n    open(value)\n', '    return h(name)', 1),
    # A coroutine/generator call does not execute the filesystem operation.
    ('async def h(value):\n    return open(value).read()\n', '    return h(name)', 0),
    ('def h(value):\n    yield open(value).read()\n', '    return h(name)', 0),
    # Positional-only parameters cannot be filled with keywords.
    ('def h(value, /):\n    return os.path.join("/srv", value)\n',
     '    return open(h(value=name)).read()', 0),
    ('def h(value, /):\n    return os.path.join("/srv", value)\n',
     '    return open(h(name)).read()', 1),
    # A global declaration means the callable may be replaced at request time.
    ('def h(value):\n    return os.path.join("/srv", value)\n'
     'def replace():\n    global h\n    h=other\n',
     '    return open(h(name)).read()', 0),
])
def test_helper_calls_preserve_python_scope_and_argument_binding(helper, body, expected):
    source = ('from fastapi import APIRouter\nimport os\nrouter=APIRouter()\n'
              + helper + '\n@router.get("/x")\nasync def route(name: str):\n' + body + '\n')
    assert len(scan_path_traversal(archive(source))) == expected


def test_helper_return_expansion_obeys_the_file_budget(monkeypatch):
    from app.scan import path_traversal as detector
    monkeypatch.setattr(detector, "_MAX_HELPER_RESOLUTIONS", 1)
    source = HELPER_SOURCE.replace(
        '    return open(get_file_path(name)).read()',
        '    open(get_file_path(name)).read()\n    open(get_file_path(name)).read()')
    coverage = {}
    assert len(scan_path_traversal(archive(source), coverage=coverage)) == 1
    assert coverage["skip_reasons"]["analysis_limit"] == 1


@pytest.mark.parametrize("sink", ['open(identity(p)).read()', 'q = identity(p)\n    q.read_text()',
                                  'read_path(p)'])
def test_helper_identity_preserves_resolved_containment(sink):
    source = ('from fastapi import APIRouter\nfrom pathlib import Path\nrouter=APIRouter()\n'
              'BASE="/srv/uploads"\ndef identity(path):\n    return path\n'
              'def read_path(path):\n    return path.read_text()\n'
              '@router.get("/x")\nasync def route(name: str):\n'
              '    p=(Path(BASE)/name).resolve()\n'
              '    if not p.is_relative_to(BASE):\n        raise ValueError()\n    '
              + sink + '\n')
    assert scan_path_traversal(archive(source)) == []
    unsafe = source.replace('    if not p.is_relative_to(BASE):\n        raise ValueError()\n', '')
    assert len(scan_path_traversal(archive(unsafe))) == 1


def test_helper_global_import_rebinding_is_unresolved():
    source = HELPER_SOURCE.replace('    return open(get_file_path(name)).read()',
                                  '    global os\n    os = wrapper\n'
                                  '    return open(get_file_path(name)).read()')
    assert scan_path_traversal(archive(source)) == []



def test_nested_route_cannot_resolve_a_shadowing_local_helper_as_the_module_helper():
    source = HELPER_SOURCE[:HELPER_SOURCE.index('@router.get')] + (
        'def register():\n'
        '    def get_file_path(value):\n        return "safe"\n'
        '    @router.get("/nested")\n'
        '    async def nested(name: str):\n'
        '        return open(get_file_path(name)).read()\n')
    assert scan_path_traversal(archive(source)) == []
    assert len(scan_path_traversal(archive(source.replace(
        '    def get_file_path(value):\n        return "safe"\n', '')))) == 1



def test_helper_arguments_with_assignment_expressions_remain_unresolved():
    source = HELPER_SOURCE.replace('def get_file_path(name):', 'def get_file_path(ignored, name):')
    source = source.replace('get_file_path(name)', 'get_file_path((name := "safe"), name)')
    assert scan_path_traversal(archive(source)) == []
    assert len(scan_path_traversal(archive(source.replace('(name := "safe")', '"safe"')))) == 1

"""Synthetic source fixtures: no uploaded code is imported, run or opened.

The load-bearing tests:

  * every corpus negative is MUTATED in the one place that removes the property it
    pins, and the rule must fire on the result;
  * every negative on disk has a mutation;
  * the product's own code is scanned. shipit has no RedirectResponse in its own
    routes, so that guard is vacuous for recognition -- it only catches a future
    false positive -- and is documented as such rather than reading as coverage.
"""
import io
import zipfile
from pathlib import Path

import pytest

from app.scan.open_redirect import RULE_ID, scan_open_redirect
from app.scan.static import run_static_scan

REPO_ROOT = Path(__file__).resolve().parent.parent

POSITIVE = '''from fastapi import APIRouter
from starlette.responses import RedirectResponse

router = APIRouter()


@router.get("/go")
async def go(next: str):
    return RedirectResponse(url=next)
'''


def archive(files: dict[str, str] | str, path: str = "repo/app/go.py") -> io.BytesIO:
    if isinstance(files, str):
        files = {path: files}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, text in files.items():
            z.writestr(name, text)
    buf.seek(0)
    return buf


def test_a_redirect_targeting_a_caller_authority_is_a_high_severity_signal():
    findings = [f for f in run_static_scan(archive(POSITIVE))["findings"] if f["rule_id"] == RULE_ID]
    assert len(findings) == 1
    f = findings[0]
    assert "RedirectResponse" in POSITIVE.splitlines()[f["line"] - 1]
    assert f["severity"] == "high"
    assert f["confidence"] == 0.7
    assert f["category"] == "Security"
    assert f["source"] == "static"
    assert f["verification_status"] == "unverified"
    assert "host" in f["explanation"]


@pytest.mark.parametrize("source", [
    # a fixed relative path stays on the same origin
    POSITIVE.replace("url=next", '"/dashboard"'),
    # the caller fills only the path, not the host
    POSITIVE.replace("url=next", 'f"/users/{next}"'),
    # a fixed absolute host the code chose
    POSITIVE.replace("url=next", '"https://ours.com/cb"'),
    # built by a call the trace does not follow
    POSITIVE.replace("url=next", "build_url(next)"),
    # a recognised local check on the address
    "from fastapi import APIRouter\nfrom starlette.responses import RedirectResponse\n\n"
    "router = APIRouter()\n\n\n@router.get('/go')\nasync def go(next: str):\n"
    "    if next.startswith('https://ours.com'):\n        return RedirectResponse(next)\n"
    "    raise ValueError()\n",
    "not valid python (",
])
def test_shapes_this_rule_does_not_report(source):
    assert scan_open_redirect(archive(source)) == []


# case name -> (file, the one change that removes the property the case pins)
CORPUS_NEGATIVES = REPO_ROOT / "tests" / "detectors" / RULE_ID / "negative"
MUTATIONS: dict[str, tuple[str, str, str]] = {
    "literal-path": ("app/dash.py", 'RedirectResponse("/dashboard")', "RedirectResponse(next)"),
    "caller-in-path": ("app/users.py", 'f"/users/{user_id}"', 'f"https://{user_id}/x"'),
    "whitelisted-host": ("app/safe.py",
                         "    if next.startswith(\"https://ours.com\"):\n        return RedirectResponse(next)\n"
                         "    raise ValueError()",
                         "    return RedirectResponse(next)"),
    "helper-builds-url": ("app/indirect.py", "build_url(next)", '"https://" + next'),
    "fixed-authority": ("app/fixed.py", '"https://ours.com/cb"', '"https://" + next'),
    "httpresponse-location": ("app/loc.py",
                              'HTTPResponse(302, headers={"Location": target})',
                              "RedirectResponse(url=target)"),
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
    assert scan_open_redirect(archive(files)) == [], "the untouched case must be silent"
    assert old in files[relative], f"mutation anchor is gone from {relative}"
    files[relative] = files[relative].replace(old, new, 1)
    assert scan_open_redirect(archive(files)), "the mutation must make the rule fire"


def test_the_product_own_code_reports_nothing():
    """VACUOUS by premise: shipit has no RedirectResponse in its own routes.

    This guard catches a future false positive only -- it does not exercise
    recognition, because there is no redirect sink in our code to recognise.
    """
    sources = {p.relative_to(REPO_ROOT).as_posix(): p.read_text()
               for p in sorted((REPO_ROOT / "app").rglob("*.py")) if "__pycache__" not in p.parts}
    assert scan_open_redirect(archive(sources)) == []

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
    POSITIVE.replace("url=next", 'f"/users/{next}?callback=https://ours.com"'),
    # a fixed absolute host the code chose
    POSITIVE.replace("url=next", '"https://ours.com/cb"'),
    # built by a call the trace does not follow
    POSITIVE.replace("url=next", "build_url(next)"),
    # a recognised local check on the address
    "from fastapi import APIRouter\nfrom starlette.responses import RedirectResponse\n\n"
    "router = APIRouter()\n\n\n@router.get('/go')\nasync def go(next: str):\n"
    "    if next in ('https://ours.com/cb', 'https://ours.com/home'):\n        return RedirectResponse(next)\n"
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
                         "    if next in (\"https://ours.com/cb\", \"https://ours.com/home\"):\n"
                         "        return RedirectResponse(next)\n"
                         "    raise ValueError()",
                         "    return RedirectResponse(next)"),
    "helper-builds-url": ("app/indirect.py", "build_url(next)", '"https://" + next'),
    "fixed-authority": ("app/fixed.py", '"https://ours.com/cb"', '"https://" + next'),
    "httpresponse-location": ("app/loc.py",
                              'Response(status_code=302, headers={"Location": target})',
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


def handler(body: str) -> str:
    return POSITIVE[:POSITIVE.index("    return")] + body


@pytest.mark.parametrize("expression", ['"/" + next', 'f"/{next}"'])
def test_one_leading_slash_can_still_redirect_to_a_caller_host(expression):
    from urllib.parse import urlsplit
    from starlette.responses import RedirectResponse

    # A real framework response demonstrates why this is a positive, without
    # making a network request or executing code supplied by an upload.
    response = RedirectResponse("/" + "/evil.example")
    assert urlsplit(response.headers["location"]).netloc == "evil.example"
    findings = scan_open_redirect(archive(handler(f"    return RedirectResponse({expression})\n")))
    assert len(findings) == 1
    assert findings[0].rule_id == RULE_ID
    assert scan_open_redirect(archive(handler('    return RedirectResponse("/users/" + next)\n'))) == []


@pytest.mark.parametrize(("target", "destination_host"), [
    ("https://ours.com.evil.example", "ours.com.evil.example"),
    ("https://ours.com@evil.example", "evil.example"),
])
def test_prefix_allowlist_accepts_a_different_host_and_must_not_suppress(target, destination_host):
    from urllib.parse import urlsplit
    from starlette.responses import RedirectResponse

    # The unsafe prefix guard is scanner input below; the runtime oracle checks
    # where Starlette actually sends these concrete lookalike destinations.
    response = RedirectResponse(target)
    assert urlsplit(response.headers["location"]).hostname == destination_host
    assert destination_host != "ours.com"
    source = handler('    if next.startswith("https://ours.com"):\n'
                     '        return RedirectResponse(next)\n    raise ValueError()\n')
    assert len(scan_open_redirect(archive(source))) == 1


@pytest.mark.parametrize("body", [
    '    if next != "https://ours.com/cb":\n        raise ValueError()\n    return RedirectResponse(next)\n',
    '    if next not in ("https://ours.com/cb", "/home"):\n'
    '        raise ValueError()\n    return RedirectResponse(next)\n',
    '    if next == "https://ours.com/cb" or next == "/home":\n'
    '        return RedirectResponse(next)\n    raise ValueError()\n',
])
def test_exact_destinations_are_accepted_only_on_the_constrained_path(body):
    assert scan_open_redirect(archive(handler(body))) == []


@pytest.mark.parametrize("body", [
    '    if next == "https://ours.com/cb":\n'
    '        return RedirectResponse("/home")\n    return RedirectResponse(next)\n',
    '    if next == "https://ours.com/cb" or enabled:\n        return RedirectResponse(next)\n',
    '    if next.startswith("/"):\n        return RedirectResponse(next)\n',
    '    if next.startswith("https://"):\n        return RedirectResponse(next)\n',
    '    if next in "https://ours.com/cb":\n        return RedirectResponse(next)\n',
    '    validate_url(next)\n    return RedirectResponse(next)\n',
    '    assert next == "https://ours.com/cb"\n    return RedirectResponse(next)\n',
])
def test_weak_unresolved_or_optimizable_checks_leave_a_signal(body):
    assert len(scan_open_redirect(archive(handler(body)))) == 1

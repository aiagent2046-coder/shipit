"""Synthetic source fixtures: no uploaded code and no live requests are executed.

Three tests here carry the weight:

  * every corpus negative is MUTATED in the one place that removes the property
    it pins, and the rule must fire on the result;
  * every negative on disk has a mutation (silence alone proves nothing);
  * the product's own app/ is scanned. It reports ZERO findings, and the premise
    is asserted first. Note what that test can and cannot show: app/ makes 26
    outbound calls and NONE of them from inside a route handler (they live in
    helpers such as app/ingest/github_fetch.py, which this rule declares out of
    scope), so this is a false-positive guard, not evidence that the rule
    recognises a real defect. Recognition is proven by the corpus and the hunt.
"""
import io
import re
import zipfile
from pathlib import Path

import pytest

from app.scan.outbound_url import RULE_ID, scan_outbound_url
from app.scan.static import run_static_scan

REPO_ROOT = Path(__file__).resolve().parent.parent

POSITIVE = '''from fastapi import APIRouter
import httpx

router = APIRouter()


@router.get("/proxy/{host}")
async def proxy(host: str):
    return httpx.get(f"http://{host}/status").json()
'''


def archive(files: dict[str, str] | str, path: str = "repo/app/routes.py") -> io.BytesIO:
    if isinstance(files, str):
        files = {path: files}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, text in files.items():
            z.writestr(name, text)
    buf.seek(0)
    return buf


def test_outbound_call_built_from_request_input_is_a_high_severity_signal():
    source = POSITIVE
    findings = [f for f in run_static_scan(archive(source))["findings"] if f["rule_id"] == RULE_ID]
    assert len(findings) == 1
    f = findings[0]
    # The line is the CALL, so the owner does not have to find it in the handler.
    assert "httpx.get(" in source.splitlines()[f["line"] - 1]
    assert f["severity"] == "high"
    assert f["confidence"] == 0.7
    assert f["category"] == "Security"
    assert f["source"] == "static"
    assert f["verification_status"] == "unverified"
    assert "traced only inside this function" in f["explanation"]


@pytest.mark.parametrize("source", [
    # the host is a literal and only the path varies -- the shape a text scan
    # cannot tell from the positive above
    POSITIVE.replace('f"http://{host}/status"', 'f"https://api.example.com/status/{host}"'),
    # a check on the value is visible in the same function
    POSITIVE.replace("    return httpx.get(", "    validate_public_host(host)\n    return httpx.get("),
    # a guarded branch inspects the value
    POSITIVE.replace("    return httpx.get(",
                     '    if not host.startswith("api."):\n        raise ValueError("no")\n'
                     "    return httpx.get("),
    # the base is configuration injected by a dependency, not something the
    # caller sent
    POSITIVE.replace("async def proxy(host: str):",
                     "async def proxy(host: str = Depends(get_base_url)):"),
    # the URL is assembled by a call the rule cannot see into
    POSITIVE.replace('f"http://{host}/status"', "build_url(host)"),
    # urljoin with a literal base: the caller controls the path, not the host
    POSITIVE.replace('httpx.get(f"http://{host}/status").json()',
                     'httpx.get(urljoin("https://docs.example.com/", host)).text'),
    # no route decorator: the parameter is whatever the author passed
    POSITIVE.replace('@router.get("/proxy/{host}")', "@router_get"),
    # the value is not in the address at all
    POSITIVE.replace('f"http://{host}/status"', '"https://api.example.com/status"'),
    # outbound call in a helper, which the trace does not follow
    POSITIVE.replace("    return httpx.get(", "    return fetch_target("),
    "not valid python (",
])
def test_shapes_this_rule_does_not_report(source):
    assert scan_outbound_url(archive(source)) == []


def test_a_presence_check_is_not_a_check_on_the_address():
    """`if host is None: raise` is about whether a value arrived, not about where
    the request goes. Reporting it is honest -- the finding claims no check on the
    ADDRESS was visible -- and the hunt's rewrite of the positive fixture is
    exactly this shape."""
    source = POSITIVE.replace("async def proxy(host: str):",
                              "async def proxy(host: str | None = None):").replace(
        "    return httpx.get(",
        '    if host is None:\n        raise ValueError("missing")\n    return httpx.get(')
    assert scan_outbound_url(archive(source))


def test_examples_are_excluded_and_no_code_is_executed(tmp_path):
    marker = tmp_path / "must-not-exist"
    source = POSITIVE + f"\nopen({str(marker)!r}, 'w').write('executed')\n"
    assert scan_outbound_url(archive(source, "repo/tests/fixture.py")) == []
    assert scan_outbound_url(archive(source))
    assert not marker.exists()


# case name -> (file, the one change that removes the property the case pins)
CORPUS_NEGATIVES = REPO_ROOT / "tests" / "detectors" / RULE_ID / "negative"
MUTATIONS: dict[str, tuple[str, str, str]] = {
    "fixed-host-variable-path": ("app/items.py", 'f"https://api.example.com/items/{sku}"',
                                 'f"https://{sku}.example.com/items"'),
    "validated-by-call": ("app/proxy.py", "validate_public_host(host)", "log_host(host)"),
    "guarded-branch-inspects-url": ("app/fetch.py",
                                    'if not url.startswith("https://api.example.com/"):',
                                    "if not url:"),
    "base-url-from-dependency": ("app/health.py", "base_url: str = Depends(get_base_url)",
                                 "base_url: str = Query(...)"),
    "helper-builds-the-url": ("app/go.py", "httpx.get(build_url(url)).text",
                              'httpx.get(f"http://{url}/x").text'),
    "literal-url": ("app/ping.py", '"https://api.example.com/ping"', 'f"https://{host}/ping"'),
    "urljoin-with-literal-base": ("app/docs.py", 'urljoin("https://docs.example.com/", name)',
                                  'urljoin(f"https://{name}/", "docs")'),
    # an allowlist check is a real check; a truthiness test is not
    "comparison-against-allowed-hosts": ("app/proxy.py", "if host not in ALLOWED_HOSTS:",
                                         "if not host:"),
    # configuration is not caller input
    "base-url-from-config": ("app/client.py", "base_url=settings.API_URL",
                             'base_url=f"http://{host}"'),
    # a validating call in the middle of the chain is why it stays silent
    "value-passed-through-a-check": ("app/proxy.py", "url = validate_url(host)",
                                     "url = build_url(host)"),
}


def test_every_corpus_negative_has_a_mutation():
    """A negative with no mutation above is pinned by silence alone, and silence
    is the one thing silence cannot prove."""
    on_disk = {case.name for case in CORPUS_NEGATIVES.iterdir() if case.is_dir()}
    assert on_disk == set(MUTATIONS), f"no mutation for: {on_disk - set(MUTATIONS)}"


@pytest.mark.parametrize("case", sorted(MUTATIONS))
def test_each_corpus_negative_goes_silent_for_its_stated_reason(case):
    relative, old, new = MUTATIONS[case]
    case_dir = CORPUS_NEGATIVES / case
    files = {p.relative_to(case_dir).as_posix().removesuffix(".fixture"): p.read_text()
             for p in case_dir.rglob("*.fixture")}
    assert scan_outbound_url(archive(files)) == [], "the untouched case must be silent"
    assert old in files[relative], f"mutation anchor is gone from {relative}"
    files[relative] = files[relative].replace(old, new, 1)
    assert scan_outbound_url(archive(files)), "the mutation must make the rule fire"


def test_the_product_own_code_reports_nothing():
    """A false-positive guard, with its own premise asserted.

    If this ever fires, read the reported line before touching the rule: either
    the product really does hand caller input to a client, or the rule grew a
    false positive. What it does NOT show is recognition -- see the module
    docstring above.
    """
    sources = [p.read_text() for p in (REPO_ROOT / "app").rglob("*.py")]
    outbound = re.compile(r"httpx\.(?:get|post|put|patch|delete|stream|request|Client|AsyncClient)"
                          r"|requests\.(?:get|post|put|patch|delete)|\burlopen\(|\burlretrieve\(")
    calls = sum(len(outbound.findall(source)) for source in sources)
    assert calls >= 20, f"the product should still make outbound calls; found {calls}"
    files = {p.relative_to(REPO_ROOT).as_posix(): p.read_text()
             for p in sorted((REPO_ROOT / "app").rglob("*.py")) if "__pycache__" not in p.parts}
    assert scan_outbound_url(archive(files)) == []

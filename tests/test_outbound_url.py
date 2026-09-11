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
    POSITIVE.replace("from fastapi import APIRouter", "from fastapi import APIRouter, Depends").replace(
        "async def proxy(host: str):", "async def proxy(host: str = Depends(get_base_url)):"),
    # the URL is assembled by a call the rule cannot see into
    POSITIVE.replace('f"http://{host}/status"', "build_url(host)"),
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
    "urljoin-with-literal-base": ("app/docs.py", 'urljoin("https://docs.example.com/", "docs/" + name)',
                                  'urljoin("https://docs.example.com/", name)'),
    # an allowlist check is a real check; a truthiness test is not
    "comparison-against-allowed-hosts": ("app/proxy.py", "if host not in ALLOWED_HOSTS:",
                                         "if not host:"),
    # configuration is not caller input
    "base-url-from-config": ("app/client.py", "base_url=settings.API_URL",
                             'base_url=f"http://{host}"'),
    # a validating call in the middle of the chain is why it stays silent
    "value-passed-through-a-check": ("app/proxy.py", "url = validate_url(host)",
                                     'url = f"http://{host}/status"'),
    "checked-model-field": ("app/fetch.py", "if payload.target not in ALLOWED_URLS:",
                             "if not payload.target:"),
    "stripped-fixed-host-path": ("app/fetch.py", '"https://api.example.test/items/" + item',
                                 '"https://" + item + "/items"'),
    # same boundary as the file-sink rule's local-helper case: the address is built
    # inside a definition whose parameter is not the handler's
    "address-inside-a-local-helper": ("app/client.py",
                                      "    def fetch(target):\n"
                                      '        return httpx.get(f"http://{target}/status")\n'
                                      "\n"
                                      "    return fetch(host)",
                                      '    return httpx.get(f"http://{host}/status")'),
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


@pytest.mark.parametrize("url", [
    'urljoin("https://docs.example.com/", host)',
    'urljoin(base="https://docs.example.com/", url=host)',
    'urljoin("https://docs.example.com/", "/" + host)',
    '"https://{target}/status".format(target=host)',
    '"https://{1}/status/{0}".format("fixed-path", host)',
    '"https://{0}/status/{0}".format(host)',
    '"https://%(target)s/status" % {"target": host}',
    '"https://%s/%s" % (host, "fixed-path")',
    '"https://" + host + "/status"',
])
def test_supported_url_assembly_preserves_the_caller_controlled_authority(url):
    source = 'from urllib.parse import urljoin\n' + POSITIVE.replace('f"http://{host}/status"', url)
    assert len(scan_outbound_url(archive(source))) == 1


@pytest.mark.parametrize("url", [
    'urljoin("https://docs.example.com/", "docs/" + host)',
    'urljoin(host, "https://docs.example.com/fixed")',
    'urljoin(host, f"https://docs.example.com/{host}")',
    '"https://{target}/status/{path}".format(path=host, target="fixed.example")',
    '"https://{1}/status/{0}".format(host, "fixed.example")',
    '"https://%(target)s/%(path)s" % {"path": host, "target": "fixed.example"}',
    '"https://%s/%s" % ("fixed.example", host)',
    'f"https://{normalise(host)}/status"',
    '"https://%s/status" % normalise(host)',
])
def test_safe_or_unknown_assembly_does_not_fabricate_a_host_origin(url):
    source = 'from urllib.parse import urljoin\n' + POSITIVE.replace('f"http://{host}/status"', url)
    assert scan_outbound_url(archive(source)) == []


def test_literal_base_urljoin_can_be_overridden_without_any_network_request():
    from urllib.parse import urljoin, urlsplit

    supplied = "//other.example/status"
    assert urlsplit(urljoin("https://docs.example.com/", supplied)).hostname == "other.example"
    source = 'from urllib.parse import urljoin\n' + POSITIVE.replace('f"http://{host}/status"',
        'urljoin("https://docs.example.com/", host)')
    assert scan_outbound_url(archive(source))


@pytest.mark.parametrize("body, expected", [
    ('url = f"https://api.example.com/{host}"\nreturn httpx.get(url)', False),
    ('url = f"https://{host}/status"\nreturn httpx.get(url)', True),
    ('url = host\nurl = "https://fixed.example/status"\nreturn httpx.get(url)', False),
    ('url = "https://fixed.example/status"\nurl = host\nreturn httpx.get(url)', True),
    ('url = normalise(host)\nreturn httpx.get(url)', False),
    ('validate_host(host)\nreturn httpx.get(host)', False),
    ('result = httpx.get(host)\nvalidate_host(host)\nreturn result', True),
    ('def checker():\n    validate_host(host)\nreturn httpx.get(host)', True),
    ('def helper(host):\n    return httpx.get(host)\nreturn "OK"', False),
    ('if host in ALLOWED_HOSTS:\n    log_host(host)\nreturn httpx.get(host)', True),
    ('if host not in ALLOWED_HOSTS:\n    raise ValueError()\nreturn httpx.get(host)', False),
    ('if host in ALLOWED_HOSTS:\n    return httpx.get(host)\nreturn "no"', False),
    ('if flag:\n    validate_host(host)\nreturn httpx.get(host)', True),
    ('validate_host(host)\nhost = request.query_params["host"]\nreturn httpx.get(host)', True),
    ('url = host\nvalidate_host(url)\nreturn httpx.get(host)', False),
])
def test_local_trace_respects_assignments_and_the_executed_check_order(body, expected):
    source = POSITIVE.replace('from fastapi import APIRouter', 'from fastapi import APIRouter, Request')
    source = source.replace('async def proxy(host: str):', 'async def proxy(host: str, request: Request):')
    source = source.replace('    return httpx.get(f"http://{host}/status").json()',
                            '\n'.join('    ' + line for line in body.splitlines()))
    assert bool(scan_outbound_url(archive(source))) is expected


@pytest.mark.parametrize("imports, statement", [
    ("import httpx as net", "return net.get(host)"),
    ("from httpx import get as fetch", "return fetch(host)"),
    ("from urllib.request import urlopen as fetch", "return fetch(host)"),
    ("import requests", 'return requests.request("GET", host)'),
    ("import httpx", 'return httpx.stream("GET", host)'),
    ("from httpx import request as fetch", 'return fetch("GET", host)'),
    ("from httpx import Client as Transport", "client = Transport()\nreturn client.get(host)"),
    ("import httpx", "with httpx.Client() as transport:\n    return transport.get(host)"),
    ("import httpx", "transport = httpx.Client()\nreturn transport.request(method='GET', url=host)"),
    ("import http.client as hc", "return hc.HTTPConnection(host=host)"),
])
def test_http_client_provenance_and_method_url_positions(imports, statement):
    source = POSITIVE.replace('import httpx', imports).replace('    return httpx.get(f"http://{host}/status").json()',
        '\n'.join('    ' + line for line in statement.splitlines()))
    assert scan_outbound_url(archive(source))


@pytest.mark.parametrize("imports, statement", [
    ("", "return session.get(host)"),
    ("", "return Client(host)"),
    ("from database import Client", "return Client(host)"),
    ("from helpers import urlopen", "return urlopen(host)"),
    ("from database import Session", "client = Session()\nreturn client.get(host)"),
    ("import httpx", "client = httpx.Client()\nclient = database\nreturn client.get(host)"),
    ("import httpx", "httpx = payload\nreturn httpx.get(host)"),
    ("import httpx", "return httpx.Client(host)"),
    ("import httpx", "return httpx.get('https://fixed.example/', endpoint=host)"),
])
def test_similarly_named_non_http_objects_are_not_outbound_sinks(imports, statement):
    source = POSITIVE.replace('import httpx', imports).replace('    return httpx.get(f"http://{host}/status").json()',
        '\n'.join('    ' + line for line in statement.splitlines()))
    assert scan_outbound_url(archive(source)) == []


@pytest.mark.parametrize("signature, expected", [
    ('host: str = "fixed.example"', True),
    ('*, host: str = Query(...)', True),
    ('host: str = Depends(config), *, page: int = 1', False),
    ('host: str, *, other: str = Depends(config)', True),
    ('host: Annotated[str, Depends(config)]', False),
    ('host: Annotated[str, Security(config)]', False),
    ('host: str = Inject(config)', False),
])
def test_parameter_defaults_and_dependencies_are_classified_by_provenance(signature, expected):
    source = ('from typing import Annotated\n'
              'from fastapi import Depends, Depends as Inject, Security, Query\n' + POSITIVE)
    source = source.replace('host: str):', signature + '):')
    assert bool(scan_outbound_url(archive(source))) is expected


@pytest.mark.parametrize("body, expected", [
    ('return httpx.get(request.query_params["url"])', True),
    ('value = request.query_params.get("url")\nreturn httpx.get(value)', True),
    ('body = await request.json()\nreturn httpx.get(body["url"])', True),
    ('value = payload.request.query_params["url"]\nreturn httpx.get(value)', False),
    ('value = normalise(request.query_params["url"])\nreturn httpx.get(value)', False),
])
def test_request_reads_require_a_recognised_request_and_stop_at_unknown_calls(body, expected):
    source = POSITIVE.replace('from fastapi import APIRouter', 'from fastapi import APIRouter, Request')
    source = source.replace('async def proxy(host: str):', 'async def proxy(request: Request):')
    source = source.replace('    return httpx.get(f"http://{host}/status").json()',
                            '\n'.join('    ' + line for line in body.splitlines()))
    assert bool(scan_outbound_url(archive(source))) is expected


def test_an_unrelated_get_decorator_does_not_establish_a_fastapi_route():
    source = POSITIVE.replace('router = APIRouter()', 'router = Registry()')
    assert scan_outbound_url(archive(source)) == []


def test_constructor_finding_describes_configuration_without_claiming_network_execution():
    source = POSITIVE.replace('httpx.get(f"http://{host}/status")', 'httpx.Client(base_url=host)')
    finding = scan_outbound_url(archive(source))[0]
    assert "client address configured" in finding.explanation
    assert "not proof that a request was sent" in finding.explanation


def test_findings_are_capped_even_inside_a_single_handler():
    source = POSITIVE.replace('    return httpx.get(f"http://{host}/status").json()',
                             '    httpx.get(host)\n' * 50)
    assert len(scan_outbound_url(archive(source))) == 32


def test_deep_ast_is_skipped_without_recursing_into_the_rule():
    source = POSITIVE.replace('f"http://{host}/status"', ' + '.join(['host'] * 150))
    assert scan_outbound_url(archive(source)) == []


def test_local_string_expansion_is_bounded():
    # Repeated concatenation can expand exponentially even in a tiny source file.
    source = POSITIVE.replace('    return httpx.get(f"http://{host}/status").json()',
                             '    url = host\n' + '    url = url + url\n' * 30 + '    return httpx.get(url)')
    assert scan_outbound_url(archive(source)) == []


@pytest.mark.parametrize("body", [
    'for host in ["fixed.example"]:\n    httpx.get(host)',
    'return [httpx.get(host) for host in ["fixed.example"]]',
    'try:\n    operation()\nexcept Exception as host:\n    return httpx.get(host)',
    'match payload:\n    case {"url": host}:\n        return httpx.get(host)',
])
def test_complex_inner_bindings_do_not_reuse_an_outer_parameter_origin(body):
    source = POSITIVE.replace('    return httpx.get(f"http://{host}/status").json()',
                             '\n'.join('    ' + line for line in body.splitlines()))
    assert scan_outbound_url(archive(source)) == []


def test_annotated_request_keeps_request_object_provenance():
    source = ('from typing import Annotated\n' + POSITIVE).replace(
        'from fastapi import APIRouter', 'from fastapi import APIRouter, Request')
    source = source.replace('host: str', 'request: Annotated[Request, "metadata"]')
    source = source.replace('f"http://{host}/status"', 'request.query_params["url"]')
    assert scan_outbound_url(archive(source))


def test_oversized_ast_node_budget_is_skipped_before_handler_analysis():
    source = 'unused = [' + ','.join(['0'] * 20_000) + ']\n' + POSITIVE
    assert scan_outbound_url(archive(source)) == []


@pytest.mark.parametrize("rebind", [
    'class httpx:\n    pass',
    'if enabled:\n    httpx = other_client',
    'httpx, item = payload',
    'del httpx',
    'try:\n    operation()\nexcept Exception as httpx:\n    pass',
])
def test_module_rebinding_invalidates_imported_http_client_provenance(rebind):
    source = POSITIVE.replace('router = APIRouter()', rebind + '\n\nrouter = APIRouter()')
    assert scan_outbound_url(archive(source)) == []


def test_a_class_shadowing_a_router_does_not_leave_route_provenance():
    source = POSITIVE.replace('router = APIRouter()', 'router = APIRouter()\n\nclass router:\n    pass')
    assert scan_outbound_url(archive(source)) == []


def test_lexically_declared_factory_routes_keep_their_own_request_inputs():
    source = '''from fastapi import FastAPI
import httpx


def create_app(configured_host):
    app = FastAPI()

    @app.get("/fetch")
    async def fetch(host: str):
        return httpx.get(host)

    @app.get("/configured")
    async def configured():
        return httpx.get(configured_host)

    return app
'''
    findings = scan_outbound_url(archive(source))
    assert len(findings) == 1
    assert 'httpx.get(host)' in source.splitlines()[findings[0].line - 1]


def test_a_factory_argument_shadowing_httpx_is_not_an_imported_client():
    source = '''from fastapi import FastAPI
import httpx


def create_app(httpx):
    app = FastAPI()

    @app.get("/fetch")
    async def fetch(host: str):
        return httpx.get(host)

    return app
'''
    assert scan_outbound_url(archive(source)) == []


@pytest.mark.parametrize("body, expected", [
    ('validate_email(request.query_params.get("email"))\nreturn httpx.get(request.query_params.get("url"))', True),
    ('body = await request.json()\nvalidate_tenant(body["tenant"])\nreturn httpx.get(body["url"])', True),
    ('url = request.query_params.get("url")\nvalidate_url(url)\nreturn httpx.get(url)', False),
    ('url = request.query_params.get("url")\nvalidate_url(url)\nreturn httpx.get(request.query_params["url"])', False),
    ('body = await request.json()\nurl = body["url"]\nvalidate_url(url)\nreturn httpx.get(body["url"])', False),
])
def test_checking_one_request_field_does_not_validate_an_unrelated_field(body, expected):
    source = POSITIVE.replace('from fastapi import APIRouter', 'from fastapi import APIRouter, Request')
    source = source.replace('async def proxy(host: str):', 'async def proxy(request: Request):')
    source = source.replace('    return httpx.get(f"http://{host}/status").json()',
                             '\n'.join('    ' + line for line in body.splitlines()))
    assert bool(scan_outbound_url(archive(source))) is expected


MODEL_ROUTE = '''from fastapi import FastAPI, Depends, Request
from pydantic import BaseModel
import httpx

app = FastAPI()

class FetchPayload(BaseModel):
    target: str
    replacement: str
    label: str = "fetch"

@app.post("/fetch")
def fetch(payload: FetchPayload):
    BODY
'''


def model_route(body: str) -> str:
    return MODEL_ROUTE.replace("    BODY", "\n".join("    " + line for line in body.splitlines()))


@pytest.mark.parametrize("body, expected", [
    ('return httpx.get(payload.target)', True),
    ('validate_url(payload.target)\nreturn httpx.get(payload.target)', False),
    ('validate_url(payload.target)\nreturn httpx.get(payload.replacement)', True),
    ('if payload.target not in ALLOWED_URLS:\n    raise ValueError()\nreturn httpx.get(payload.target)', False),
    ('validate_url(payload.target)\npayload.target = payload.replacement\nreturn httpx.get(payload.target)', True),
    ('saved = payload.target\nvalidate_url(saved)\npayload.target = payload.replacement\n'
     'return httpx.get(saved)', False),
    ('shared = payload\nvalidate_url(payload.target)\nshared.target = payload.replacement\n'
     'return httpx.get(payload.target)', True),
    ('shared = payload\nshared = build_payload()\nreturn httpx.get(shared.target)', False),
    ('payload.target = "https://fixed.example.test/status"\nreturn httpx.get(payload.target)', False),
    ('payload.target = normalize(payload.replacement)\nreturn httpx.get(payload.target)', False),
    ('payload = build_payload()\nreturn httpx.get(payload.target)', False),
    ('from settings import payload\nreturn httpx.get(payload.target)', False),
    ('del payload.target\nreturn httpx.get(payload.target)', False),
    ('for item in items:\n    payload.target = normalize(item)\nreturn httpx.get(payload.target)', False),
    ('payload.label = "changed"\nreturn httpx.get(payload.target)', True),
    ('return httpx.get("https://api.example.test/" + payload.target.strip())', False),
    ('return httpx.get(payload.target.strip())', True),
    ('return httpx.get(payload.undeclared)', False),
])
def test_model_fields_preserve_separate_sources_and_mutation_order(body, expected):
    assert bool(scan_outbound_url(archive(model_route(body)))) is expected


@pytest.mark.parametrize("imports, base, signature, expected", [
    ('from pydantic import BaseModel as Model', 'Model', 'payload: FetchPayload', True),
    ('import pydantic as pd', 'pd.BaseModel', 'payload: FetchPayload', True),
    ('from pydantic import BaseModel', 'BaseModel', 'payload: "FetchPayload"', True),
    ('from typing import Annotated\nfrom pydantic import BaseModel', 'BaseModel',
     'payload: Annotated[FetchPayload, "body"]', True),
    ('from pydantic import BaseModel', 'BaseModel', 'payload: FetchPayload = Depends(config)', False),
    ('from local_models import BaseModel', 'BaseModel', 'payload: FetchPayload', False),
    ('from pydantic import BaseModel\nBaseModel = custom_base', 'BaseModel', 'payload: FetchPayload', False),
    ('from pydantic import BaseModel\nclass BaseModel:\n    pass', 'BaseModel', 'payload: FetchPayload', False),
    ('from pydantic import BaseModel\nstr = CustomString', 'BaseModel', 'payload: FetchPayload', False),
    ('from pydantic import BaseModel', 'BaseModel, CustomBase', 'payload: FetchPayload', False),
    ('from pydantic import BaseModel', 'BaseModel', 'payload: UnrelatedObject', False),
])
def test_model_annotations_require_local_declaration_and_unshadowed_import_origin(imports, base, signature, expected):
    source = model_route('return httpx.get(payload.target)').replace('from pydantic import BaseModel', imports)
    source = source.replace('class FetchPayload(BaseModel):', f'class FetchPayload({base}):')
    source = source.replace('payload: FetchPayload):', signature + '):')
    assert bool(scan_outbound_url(archive(source))) is expected


def test_private_pydantic_attributes_are_not_request_body_fields():
    source = model_route('return httpx.get(payload._target)').replace('    target: str', '    _target: str')
    assert scan_outbound_url(archive(source)) == []


def test_many_model_parameters_do_not_expand_an_unbounded_field_product():
    source = model_route('return httpx.get(last.target)')
    parameters = ', '.join(f'value{index}: FetchPayload' for index in range(100)) + ', last: FetchPayload'
    source = source.replace('payload: FetchPayload):', parameters + '):')
    # The late parameter exceeds the bounded field trace; no uploaded code is
    # called and no inherited field provenance is fabricated for that parameter.
    assert scan_outbound_url(archive(source)) == []


@pytest.mark.parametrize("body, signature, expected", [
    ('return httpx.get(request.query_params["url"].strip())', 'request: Request', True),
    ('value = request.query_params.get("url")\nreturn httpx.get(value.strip())', 'request: Request', True),
    ('return httpx.get(request.headers["target"].strip().strip())', 'request: Request', True),
    ('return httpx.get(host.strip())', 'host: str', True),
    ('validate_url(host)\nreturn httpx.get(host.strip())', 'host: str', False),
    ('return httpx.get((" https://api.example.test/" + host).strip())', 'host: str', False),
    ('return httpx.get(host.strip())', 'host: UnknownObject', False),
    ('return httpx.get(host.strip())', 'host', False),
    ('host = build_value()\nreturn httpx.get(host.strip())', 'host: str', False),
    ('return httpx.get(request.query_params.get("url", custom).strip())', 'request: Request', False),
    ('return httpx.get(request.query_params.get("url", default=custom).strip())', 'request: Request', False),
    ('body = await request.json()\nreturn httpx.get(body["url"].strip())', 'request: Request', False),
    ('return httpx.get(host.strip("https:/"))', 'host: str', False),
    ('return httpx.get(host.replace("x", "y"))', 'host: str', False),
    ('httpx = LocalClient()\nreturn httpx.get(host.strip())', 'host: str', False),
])
def test_strip_only_preserves_known_string_sources_without_becoming_a_validator(body, signature, expected):
    source = POSITIVE.replace('from fastapi import APIRouter', 'from fastapi import APIRouter, Request')
    source = source.replace('host: str):', signature + '):')
    source = source.replace('    return httpx.get(f"http://{host}/status").json()',
                            '\n'.join('    ' + line for line in body.splitlines()))
    assert bool(scan_outbound_url(archive(source))) is expected

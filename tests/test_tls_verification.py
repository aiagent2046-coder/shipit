"""Synthetic source fixtures: no uploaded code, no network and no live TLS handshake.

The load-bearing tests:

  * every corpus negative is MUTATED in the one place that removes the property it
    pins, and the rule must fire on the result -- silence alone proves nothing;
  * every negative on disk has a mutation;
  * the product's own code is scanned, with its premise asserted, and it must
    report nothing. Our own `app/` contains `verify=True` (the correct form the
    rule reads) and a `verify=None` PARAMETER DEFAULT, which is not a call that
    disables anything -- so the silence is not silence over an empty archive.
"""

import io
import re
import zipfile
from pathlib import Path

import pytest

from app.scan.static import run_static_scan
from app.scan.tls_verification import RULE_ID, scan_tls_verification

REPO_ROOT = Path(__file__).resolve().parent.parent

POSITIVE = """import requests


def fetch(url):
    return requests.get(url, verify=False).json()
"""


def archive(files: dict[str, str] | str, path: str = "repo/app/client.py") -> io.BytesIO:
    if isinstance(files, str):
        files = {path: files}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, text in files.items():
            z.writestr(name, text)
    buf.seek(0)
    return buf


def test_disabled_verification_is_a_high_severity_finding():
    source = POSITIVE
    findings = [f for f in run_static_scan(archive(source))["findings"] if f["rule_id"] == RULE_ID]
    assert len(findings) == 1
    f = findings[0]
    assert "verify=False" in source.splitlines()[f["line"] - 1]
    assert f["severity"] == "high"
    assert f["confidence"] == 0.9
    assert f["category"] == "Security"
    assert f["source"] == "static"
    assert f["verification_status"] == "unverified"
    assert "Why verification was turned off has NOT been read" in f["explanation"]


@pytest.mark.parametrize(
    "source",
    [
        # asked for explicitly
        POSITIVE.replace("verify=False", "verify=True"),
        # the recommended fix: trust a specific authority
        POSITIVE.replace("verify=False", "verify='/etc/ssl/certs/internal-ca.pem'"),
        # None means the library default, which is verification ON
        POSITIVE.replace("verify=False", "verify=None"),
        # a variable holding a boolean is not a literal switch, and guessing its value
        # is exactly what this rule does not do
        POSITIVE.replace("verify=False", "verify=settings.VERIFY"),
        # related but not the claim: the parameter is a plain default in a signature
        "def check(*, verify=None):\n    return verify\n",
        "not valid python (",
    ],
)
def test_shapes_this_rule_does_not_report(source):
    assert scan_tls_verification(archive(source)) == []


def test_javascript_literals_and_their_negatives():
    def scan(name: str, text: str):
        return scan_tls_verification(archive({name: text}))

    assert scan("web/src/lib/a.ts", 'import https from "node:https"; new https.Agent({ rejectUnauthorized: false });')
    assert scan("web/src/lib/b.ts", "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';")
    # asked for, mentioned in a comment, and mentioned inside a string
    assert scan("web/src/lib/c.ts", "new https.Agent({ rejectUnauthorized: true });") == []
    assert scan("web/src/lib/d.ts", "// rejectUnauthorized: false\n") == []
    assert scan("web/src/lib/e.ts", 'const DOC = "rejectUnauthorized: false";') == []


# case name -> (file, the one change that removes the property the case pins)
CORPUS_NEGATIVES = REPO_ROOT / "tests" / "detectors" / RULE_ID / "negative"
MUTATIONS: dict[str, tuple[str, str, str]] = {
    "verify-true": ("app/ok.py", "verify=True", "verify=False"),
    "verify-ca-bundle": ("app/ok_bundle.py", "verify=CA_BUNDLE", "verify=False"),
    "verify-none-is-library-default": ("app/ok_default.py", "verify=None", "verify=False"),
    "verify-mode-cert-required": ("app/ctx_ok.py", "ssl.CERT_REQUIRED", "ssl.CERT_NONE"),
    "reject-unauthorized-true": ("web/src/lib/agent_ok.ts", "rejectUnauthorized: true", "rejectUnauthorized: false"),
    "commented-out-literal": (
        "web/src/lib/notes.ts",
        "// new https.Agent({ rejectUnauthorized: false });",
        "new https.Agent({ rejectUnauthorized: false });",
    ),
    # turning TLS off is not turning verification off; the verification switch must fire
    "use-ssl-false-is-a-different-claim": (
        "app/plain_http.py",
        '"http://internal.example/"',
        '"https://internal.example/", ssl=False',
    ),
}


def test_every_corpus_negative_has_a_mutation():
    on_disk = {case.name for case in CORPUS_NEGATIVES.iterdir() if case.is_dir()}
    assert on_disk == set(MUTATIONS), f"no mutation for: {on_disk - set(MUTATIONS)}"


@pytest.mark.parametrize("case", sorted(MUTATIONS))
def test_each_corpus_negative_goes_silent_for_its_stated_reason(case):
    relative, old, new = MUTATIONS[case]
    case_dir = CORPUS_NEGATIVES / case
    files = {
        p.relative_to(case_dir).as_posix().removesuffix(".fixture"): p.read_text() for p in case_dir.rglob("*.fixture")
    }
    assert scan_tls_verification(archive(files)) == [], "the untouched case must be silent"
    assert old in files[relative], f"mutation anchor is gone from {relative}"
    files[relative] = files[relative].replace(old, new, 1)
    assert scan_tls_verification(archive(files)), "the mutation must make the rule fire"


def test_the_product_own_code_reports_nothing():
    """A false-positive guard whose premise is asserted.

    The product is itself a Next.js repository, so this rule reads our own web
    source as well as our Python. If it ever fires, read the reported line before
    touching the rule: either we really did disable verification somewhere, or the
    rule grew a false positive.
    """
    sources = {}
    for base in ("app", "web/src", "scripts"):
        for path in sorted((REPO_ROOT / base).rglob("*")):
            if path.suffix not in {".py", ".ts", ".tsx", ".js", ".mjs", ".cjs"}:
                continue
            rel = path.relative_to(REPO_ROOT).as_posix()
            if "node_modules" in rel or "__pycache__" in rel:
                continue
            sources[rel] = path.read_text()
    text = "\n".join(sources.values())
    # Premise: the rule has something to read, in both directions it must get right.
    assert re.search(r"verify=True", text), "the correct form should still be in our code"
    assert re.search(r"verify=None", text), "the parameter default that must not fire"
    assert len(sources) > 200, f"expected the whole product, saw {len(sources)} files"
    assert scan_tls_verification(archive(sources)) == []


@pytest.mark.parametrize(
    "source",
    [
        'def render_document(*, verify=True):\n    return "preview"\nrender_document(verify=False)',
        'import logging, ssl\nlogging.info("Constant: %s", ssl.CERT_NONE)',
        'import httpx\nhttpx.get("https://example.com", ssl_validation=False)',
        'import requests\nrequests.get("https://example.com", verify_ssl=False)',
        "import aiohttp\naiohttp.TCPConnector(use_ssl=False)",
        'import requests\ndef f(requests):\n    requests.get("https://example.com", verify=False)',
        'import requests\nrequests = other\nrequests.get("https://example.com", verify=False)',
        'import requests\ndef f():\n    requests.get("https://example.com", verify=False)\nrequests = other',
        'import requests\ndef f():\n    requests.get("https://example.com", verify=False)\n    requests = other',
        'import requests\nrequests.get = other\nrequests.get("https://example.com", verify=False)',
        'import requests as rq\nrq2 = rq\nrq2.get = other\nrq.get("https://example.com", verify=False)',
        'from . import requests\nrequests.get("https://example.com", verify=False)',
        "import ssl\ncontext = other()\ncontext.verify_mode = ssl.CERT_NONE",
        "import ssl\nssl._create_unverified_context(cert_reqs=ssl.CERT_REQUIRED, check_hostname=True)",
        "import ssl\nssl._create_unverified_context(**unknown)",
        "import httpx\nhttpx.Client(verify=0)",
        'import httpx\nclient = httpx.Client()\nclient.get("https://example.com", verify=False)',
        'import requests\n(requests := other)\nrequests.get("https://example.com", verify=False)',
        'import requests\n[requests.get("https://example.com", verify=False) for requests in clients]',
    ],
)
def test_python_unrelated_shadowed_and_invalid_apis_are_not_tls_evidence(source):
    assert scan_tls_verification(archive(source)) == []


@pytest.mark.parametrize(
    "source",
    [
        'import requests as rq\nrq.get("https://example.com", verify=False)',
        'from requests import get as fetch\nfetch("https://example.com", verify=False)',
        "import requests\nsession = requests.Session()\nalias = session\nalias.verify = False",
        "import httpx as client\nclient.AsyncClient(verify=False)",
        "from aiohttp import TCPConnector as Connector\nConnector(ssl=False)",
        "import aiohttp\n"
        "async def f():\n    async with aiohttp.ClientSession() as session:\n"
        '        await session.get("https://example.com", ssl=False)',
        "from ssl import SSLContext, PROTOCOL_TLS, CERT_NONE as NO_CERT\n"
        "ctx = SSLContext(PROTOCOL_TLS)\nctx.verify_mode = NO_CERT",
        "import ssl as s\ncontext = s._create_stdlib_context(cert_reqs=s.CERT_NONE)",
        "from ssl import _create_unverified_context as unverified\ncontext = unverified()",
        "import ssl, urllib3\nclient = urllib3.PoolManager(cert_reqs=ssl.CERT_NONE)",
        'from tornado.httpclient import HTTPRequest\nrequest = HTTPRequest("https://example.com", validate_cert=False)',
        'from elasticsearch import Elasticsearch\nclient = Elasticsearch("https://example.com", verify_certs=False)',
    ],
)
def test_python_supported_import_and_constructor_aliases_preserve_real_settings(source):
    assert len(scan_tls_verification(archive(source))) == 1


@pytest.mark.parametrize(
    "source",
    [
        "/*\nrejectUnauthorized: false\n*/\nexport const enabled = true;",
        "export const enabled = true; /* rejectUnauthorized: false */",
        "export const documentation = `\nNever set rejectUnauthorized: false\n`;",
        "export type Policy = { rejectUnauthorized: false };",
        "export interface Policy { rejectUnauthorized: false }",
        "const pattern = /rejectUnauthorized: false/;",
        "const NODE_TLS_REJECT_UNAUTHORIZED = 0;",
        'process.env.NODE_TLS_REJECT_UNAUTHORIZED = "01";',
        "process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0x1;",
        "const options = { rejectUnauthorized: false }; unrelated(options);",
        'import https from "node:https"; function make(https) { return new https.Agent({rejectUnauthorized:false}); }',
        'import https from "node:https"; https = other; new https.Agent({rejectUnauthorized:false});',
        'import https from "node:https"; '
        "function make() {return new https.Agent({rejectUnauthorized:false});} https = other;",
        'import https from "node:https"; https.Agent = other; new https.Agent({rejectUnauthorized:false});',
        'function f(process) { process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; }',
        'const process = other; process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";',
        'function f(require) { const https = require("https"); return new https.Agent({rejectUnauthorized:false}); }',
        'import type https from "node:https"; new https.Agent({rejectUnauthorized:false});',
        'import https from "node:https"; new https.Agent({rejectUnauthorized:false, rejectUnauthorized:true});',
        'import https from "node:https"; new https.Agent({rejectUnauthorized:false, ...unknown});',
        'import https from "node:https"; '
        "const options={rejectUnauthorized:false}; options.rejectUnauthorized=true; new https.Agent(options);",
        'import https from "node:https"; { new https.Agent({rejectUnauthorized:false}); const https = other; }',
        "new https.Agent({rejectUnauthorized:false});",
    ],
)
def test_js_non_code_unknown_and_shadowed_receivers_are_not_tls_evidence(source):
    assert scan_tls_verification(archive(source, "repo/app/client.ts")) == []


@pytest.mark.parametrize(
    "source",
    [
        'import https from "node:https"; new https.Agent({\nrejectUnauthorized:\nfalse\n});',
        'import https from "node:https"; new https.Agent({"rejectUnauthorized": false});',
        'import https from "node:https"; '
        'const doc="rejectUnauthorized: false"; new https.Agent({rejectUnauthorized:false});',
        'import {Agent as SecureAgent} from "node:https"; new SecureAgent({rejectUnauthorized:false});',
        'import * as secure from "https"; const Agent = secure.Agent; new Agent({rejectUnauthorized:false});',
        'const https = require("https"); new https.Agent({rejectUnauthorized:false});',
        'const { Agent: SecureAgent } = require("node:https"); new SecureAgent({rejectUnauthorized:false});',
        'import https from "https"; '
        "const options={rejectUnauthorized:false}; const alias=options; new https.Agent(alias);",
        'import https from "https"; new https.Agent({...unknown, rejectUnauthorized: false});',
        'import tls from "node:tls"; tls.connect({host:"example.com", rejectUnauthorized:false});',
        'import https from "https"; const agent = new https.Agent(); agent.options.rejectUnauthorized = false;',
        'import https from "https"; https.globalAgent.options.rejectUnauthorized = false;',
        'process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0";',
        'import process from "node:process"; process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";',
        'import {env as environment} from "node:process"; environment.NODE_TLS_REJECT_UNAUTHORIZED = "0";',
        "process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0;",
        'import https from "https"; export const make = () => new https.Agent({rejectUnauthorized:false});',
        'import https from "https"; const text = `${new https.Agent({rejectUnauthorized:false})}`;',
    ],
)
def test_js_parsed_literals_and_aliases_preserve_real_settings(source):
    assert len(scan_tls_verification(archive(source, "repo/app/client.ts"))) == 1


def test_hostname_only_has_a_distinct_claim_and_fix():
    import ssl

    context = ssl.create_default_context()
    context.check_hostname = False
    assert context.verify_mode == ssl.CERT_REQUIRED
    source = "import ssl\ncontext = ssl.create_default_context()\ncontext.check_hostname = False"
    (finding,) = scan_tls_verification(archive(source))
    assert "hostname" in finding.title.lower()
    assert "Certificate-chain validation may still be enabled" in finding.explanation
    assert "accepts ANY certificate" not in finding.explanation
    assert "check_hostname=True" in finding.fix_hint


def test_limits_and_malformed_syntax_do_not_execute_or_expand_the_scan():
    assert (
        scan_tls_verification(
            archive('import https from "https"; new https.Agent({rejectUnauthorized:false}); }', "repo/app/client.ts")
        )
        == []
    )
    assert scan_tls_verification(archive("#" * 400_001 + "\n" + POSITIVE)) == []
    sources = {f"repo/app/client{index}.py": POSITIVE for index in range(40)}
    assert len(scan_tls_verification(archive(sources))) == 32
    sources = {f"repo/app/empty{index}.py": "" for index in range(400)}
    sources["repo/app/last.py"] = POSITIVE
    assert scan_tls_verification(archive(sources)) == []


@pytest.mark.parametrize(
    "source",
    [
        'import https from "node:https"; class LocalAgent {constructor(options){}}; '
        "let client=https; {client={Agent:LocalAgent};} new client.Agent({rejectUnauthorized:false});",
        'import https from "node:https"; const options={rejectUnauthorized:false}; '
        "{options.rejectUnauthorized=true;} new https.Agent(options);",
        'import https from "node:https"; const options={rejectUnauthorized:false}; '
        "{const alias=options; {alias.rejectUnauthorized=true;}} new https.Agent(options);",
    ],
)
def test_js_block_writes_and_object_alias_mutations_reach_the_outer_scope(source):
    assert scan_tls_verification(archive(source, "repo/app/client.ts")) == []


@pytest.mark.parametrize(
    "source",
    [
        'import requests\nfrom adapter import *\nrequests.get("https://example.com", verify=False)',
        'import requests\nif enabled:\n    from adapter import *\nrequests.get("https://example.com", verify=False)',
        'import requests\ndef fetch():\n    requests.get("https://example.com", verify=False)\nfrom adapter import *',
    ],
)
def test_python_wildcard_import_invalidates_previous_client_provenance(source):
    assert scan_tls_verification(archive(source)) == []


@pytest.mark.parametrize(
    "source",
    [
        'import https from "node:https"; const options={rejectUnauthorized:false}; '
        "{const options={rejectUnauthorized:true}; options.rejectUnauthorized=true;} new https.Agent(options);",
        'import https from "node:https"; let client; {client=https;} new client.Agent({rejectUnauthorized:false});',
        'import https from "node:https"; new https.Agent({"reject\\u0055nauthorized":false});',
        'process.env["NODE_TLS_REJECT_UN\\u0041UTHORIZED"] = "0";',
    ],
)
def test_js_block_locals_and_escaped_settings_preserve_real_tls_evidence(source):
    assert len(scan_tls_verification(archive(source, "repo/app/client.ts"))) == 1


def test_python_explicit_import_after_wildcard_restores_provenance():
    source = 'from adapter import *\nimport requests\nrequests.get("https://example.com", verify=False)'
    assert len(scan_tls_verification(archive(source))) == 1

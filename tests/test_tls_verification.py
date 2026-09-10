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

POSITIVE = '''import requests


def fetch(url):
    return requests.get(url, verify=False).json()
'''


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


@pytest.mark.parametrize("source", [
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
])
def test_shapes_this_rule_does_not_report(source):
    assert scan_tls_verification(archive(source)) == []


def test_javascript_literals_and_their_negatives():
    def scan(name: str, text: str):
        return scan_tls_verification(archive({name: text}))

    assert scan("web/src/lib/a.ts", "new https.Agent({ rejectUnauthorized: false });")
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
    "reject-unauthorized-true": ("web/src/lib/agent_ok.ts", "rejectUnauthorized: true",
                                 "rejectUnauthorized: false"),
    "commented-out-literal": ("web/src/lib/notes.ts", "// rejectUnauthorized: false was removed in v2",
                              "rejectUnauthorized: false was removed in v2"),
    # turning TLS off is not turning verification off; the verification switch must fire
    "use-ssl-false-is-a-different-claim": ("app/plain_http.py", "use_ssl=False", "ssl=False"),
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

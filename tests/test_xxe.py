"""Synthetic source fixtures: no uploaded code is imported, run or opened.

The load-bearing tests:

  * parse/fromstring report only when resolve_entities=True is proven via
    parser=XMLParser(resolve_entities=True); iterparse via a direct keyword;
  * a missing resolve_entities argument, False/'internal', a reassigned
    etree.parse, the stdlib xml modules and defusedxml are not sinks;
  * every corpus negative is MUTATED in the one place that removes the property
    it pins, and the rule must fire on the result;
  * every negative on disk has a mutation;
  * the product's own code is scanned. shipit parses Python and tree-sitter
    grammar, not XML, so that guard is vacuous for recognition -- it only catches
    a future false positive -- and is documented as such.
"""
import io
import zipfile
from pathlib import Path

import pytest

from app.scan.xxe import RULE_ID, scan_unsafe_xml_parse
from app.scan.static import run_static_scan

REPO_ROOT = Path(__file__).resolve().parent.parent

POSITIVE = "from lxml import etree\netree.parse(source, parser=etree.XMLParser(resolve_entities=True))\n"
ITERPARSE_POSITIVE = "from lxml import etree\netree.iterparse(source, resolve_entities=True)\n"


def archive(files: dict[str, str] | str, path: str = "repo/app/x.py") -> io.BytesIO:
    if isinstance(files, str):
        files = {path: files}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, text in files.items():
            z.writestr(name, text)
    buf.seek(0)
    return buf


def test_a_parse_resolving_external_entities_is_high_severity():
    findings = [f for f in run_static_scan(archive(POSITIVE))["findings"] if f["rule_id"] == RULE_ID]
    assert len(findings) == 1
    f = findings[0]
    assert "etree.parse" in POSITIVE.splitlines()[f["line"] - 1]
    assert f["severity"] == "high"
    assert f["confidence"] == 0.9
    assert f["category"] == "Security"
    assert f["source"] == "static"
    assert f["verification_status"] == "unverified"
    assert "resolve_entities=True" in f["explanation"]


def test_iterparse_with_resolve_entities_true_is_reported():
    assert len(scan_unsafe_xml_parse(archive(ITERPARSE_POSITIVE))) == 1


def test_an_import_alias_is_the_same_lxml_call():
    source = ("from lxml import etree as ET\n"
              "ET.fromstring(data, parser=ET.XMLParser(resolve_entities=True))\n")
    assert len(scan_unsafe_xml_parse(archive(source))) == 1


@pytest.mark.parametrize("source", [
    # stdlib ElementTree does not resolve external entities
    "import xml.etree.ElementTree as ET\nET.parse(path)\n",
    # defusedxml is the hardened package
    "from defusedxml import ElementTree as ET\nET.parse(path)\n",
    # xml.sax does not resolve external entities on Python 3.7.1+
    "import xml.sax\nxml.sax.parseString(data, handler)\n",
    # xml.dom.minidom does not resolve external entities on supported Python
    "import xml.dom.minidom\nxml.dom.minidom.parse(path)\n",
    # a missing resolve_entities argument is not proven unsafe (default is 'internal' on lxml 5.0+)
    "from lxml import etree\netree.parse(source)\n",
    # an explicit resolve_entities='internal' does not resolve external entities
    "from lxml import etree\netree.parse(source, parser=etree.XMLParser(resolve_entities='internal'))\n",
    # an inline parser with resolve_entities=False disables the resolution
    "from lxml import etree\netree.parse(source, parser=etree.XMLParser(resolve_entities=False))\n",
    # a direct resolve_entities=False keyword on iterparse disables it too
    "from lxml import etree\netree.iterparse(source, resolve_entities=False)\n",
    # a non-lxml parser object is not proven unsafe
    "from lxml import etree\nparser = etree.XMLParser(resolve_entities=True)\netree.parse(source, parser=parser)\n",
    # not an XML parse at all
    "import json\njson.loads(data)\n",
    "not valid python (",
])
def test_shapes_this_rule_does_not_report(source):
    assert scan_unsafe_xml_parse(archive(source)) == []


def test_a_reassigned_parse_is_not_reported():
    source = ("from lxml import etree\n"
              "etree.parse = custom\n"
              "etree.parse(source, parser=etree.XMLParser(resolve_entities=True))\n")
    assert scan_unsafe_xml_parse(archive(source)) == []


CORPUS_NEGATIVES = REPO_ROOT / "tests" / "detectors" / RULE_ID / "negative"
MUTATIONS: dict[str, tuple[str, str, str]] = {
    "stdlib-etree": ("app/safe.py",
                     "import xml.etree.ElementTree as ET\nET.parse(path)",
                     "from lxml import etree as ET\nET.parse(path, parser=ET.XMLParser(resolve_entities=True))"),
    "defusedxml": ("app/safe.py",
                   "from defusedxml import ElementTree as ET\nET.parse(path)",
                   "from lxml import etree as ET\nET.parse(path, parser=ET.XMLParser(resolve_entities=True))"),
    "sax": ("app/handler.py",
            "import xml.sax\nxml.sax.parseString(data, handler)",
            "from lxml import etree\netree.fromstring(data, parser=etree.XMLParser(resolve_entities=True))"),
    "minidom": ("app/doc.py",
                "import xml.dom.minidom\nxml.dom.minidom.parse(path)",
                "from lxml import etree\netree.parse(path, parser=etree.XMLParser(resolve_entities=True))"),
    "no-xml": ("app/json.py",
               "import json\njson.loads(data)",
               "from lxml import etree\netree.parse(data, parser=etree.XMLParser(resolve_entities=True))"),
    "lxml-default": ("app/safe.py",
                     "etree.parse(source)",
                     "etree.parse(source, parser=etree.XMLParser(resolve_entities=True))"),
    "lxml-internal": ("app/safe.py",
                      "resolve_entities='internal'",
                      "resolve_entities=True"),
    "lxml-resolve-entities-false": ("app/safe.py",
                                    "resolve_entities=False",
                                    "resolve_entities=True"),
    "lxml-iterparse-false": ("app/safe.py",
                             "resolve_entities=False",
                             "resolve_entities=True"),
    "mutated-parse": ("app/safe.py",
                      "etree.parse = custom\n",
                      ""),
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
    assert scan_unsafe_xml_parse(archive(files)) == [], "the untouched case must be silent"
    assert old in files[relative], f"mutation anchor is gone from {relative}"
    files[relative] = files[relative].replace(old, new, 1)
    assert scan_unsafe_xml_parse(archive(files)), "the mutation must make the rule fire"


def test_the_product_own_code_reports_nothing():
    """VACUOUS by premise: shipit parses Python and grammar, not XML.

    This guard catches a future false positive only -- it does not exercise
    recognition, because there is no XML parse in our code to recognise.
    """
    sources = {p.relative_to(REPO_ROOT).as_posix(): p.read_text()
               for p in sorted((REPO_ROOT / "app").rglob("*.py")) if "__pycache__" not in p.parts}
    assert scan_unsafe_xml_parse(archive(sources)) == []

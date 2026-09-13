"""Scan synthetic Python source without importing or executing its XML operations.

The tests pin supported lxml API forms, explicit configuration, import provenance,
and conservative omissions. Negative corpus mutations establish that changing the
relevant configuration or binding restores a finding. They do not prove an
exploit: XML contents, their origin, deployment versions and runtime behaviour
are deliberately outside this source-only rule.
"""
import io
import zipfile
from pathlib import Path

import pytest

from app.scan.xxe import RULE_ID, scan_unsafe_xml_parse
from app.scan.static import run_static_scan

REPO_ROOT = Path(__file__).resolve().parent.parent
IMPORT = "from lxml import etree\n"
PARSER = "etree.XMLParser(resolve_entities=True)"
POSITIVE = IMPORT + f"etree.parse(source, parser={PARSER})\n"


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
    assert "lxml < 5.0" not in f["explanation"]


@pytest.mark.parametrize("call", [
    f"etree.parse(source, parser={PARSER})",
    f"etree.parse(source, {PARSER})",
    f"etree.fromstring(data, parser={PARSER})",
    f"etree.fromstring(data, {PARSER})",
    f"etree.parse(source=source, parser={PARSER}, base_url='urn:fixture')",
    f"etree.fromstring(text=data, parser={PARSER}, base_url='urn:fixture')",
    "etree.iterparse(source, resolve_entities=True)",
    "etree.iterparse(source=source, resolve_entities=True)",
    "etree.iterparse(source, events=('end',), html=False, resolve_entities=True)",
])
def test_valid_api_forms_consume_explicit_entity_configuration(call):
    findings = scan_unsafe_xml_parse(archive(IMPORT + call + "\n"))
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].confidence == 0.9


@pytest.mark.parametrize("source", [
    "import lxml.etree\nlxml.etree.parse(source, lxml.etree.XMLParser(resolve_entities=True))\n",
    "import lxml.etree as ET\nET.fromstring(data, ET.XMLParser(resolve_entities=True))\n",
    "from lxml import etree as ET\nET.fromstring(data, parser=ET.XMLParser(resolve_entities=True))\n",
    "from lxml.etree import parse as read_xml, XMLParser as Parser\nread_xml(source, Parser(resolve_entities=True))\n",
    "from lxml.etree import iterparse as read_xml\nread_xml(source, resolve_entities=True)\n",
])
def test_import_spellings_preserve_lxml_provenance(source):
    assert len(scan_unsafe_xml_parse(archive(source))) == 1


@pytest.mark.parametrize("call", [
    "etree.parse(source)",
    "etree.fromstring(data)",
    "etree.iterparse(source)",
    "etree.parse(source, parser=etree.XMLParser())",
    "etree.parse(source, parser=etree.XMLParser(resolve_entities=False))",
    "etree.parse(source, etree.XMLParser(resolve_entities=False))",
    'etree.fromstring(data, etree.XMLParser(resolve_entities="internal"))',
    "etree.iterparse(source, resolve_entities=False)",
    'etree.iterparse(source, resolve_entities="internal")',
    "etree.iterparse(source, resolve_entities=enabled)",
    "etree.parse(source, parser=etree.XMLParser(resolve_entities=enabled))",
    "etree.parse(source, parser=parser)",
    "etree.parse(source, parser=custom_parser(resolve_entities=True))",
    "etree.parse(source, parser=etree.HTMLParser())",
    "etree.iterparse(source, html=True, resolve_entities=True)",
    "etree.iterparse(source, html=mode, resolve_entities=True)",
    "etree.XMLParser(resolve_entities=True)",
])
def test_defaults_disabled_and_unknown_configuration_do_not_become_findings(call):
    assert scan_unsafe_xml_parse(archive(IMPORT + call + "\n")) == []


@pytest.mark.parametrize("call", [
    "etree.parse(source, resolve_entities=True)",
    "etree.fromstring(data, resolve_entities=True)",
    f"etree.iterparse(source, parser={PARSER})",
    f"etree.iterparse(source, parser={PARSER}, resolve_entities=True)",
    f"etree.parse(source, {PARSER}, parser={PARSER})",
    f"etree.fromstring(data, parser={PARSER}, parser={PARSER})",
    f"etree.parse(*sources, parser={PARSER})",
    f"etree.fromstring(data, {PARSER}, **options)",
    "etree.iterparse(source, resolve_entities=True, **options)",
    "etree.iterparse(*sources, resolve_entities=True)",
    "etree.iterparse(source, resolve_entities=True, resolve_entities=False)",
    "etree.parse(source, parser=etree.XMLParser(resolve_entities=True, **options))",
    "etree.parse(source, parser=etree.XMLParser(*options, resolve_entities=True))",
    "etree.parse(source, parser=etree.XMLParser(resolve_entities=True, resolve_entities=False))",
    "etree.parse(source, parser=etree.XMLParser(True, resolve_entities=True))",
    f"etree.parse(parser={PARSER})",
    f"etree.fromstring(parser={PARSER})",
    "etree.iterparse(resolve_entities=True)",
    f"etree.parse(source, {PARSER}, 'urn:fixture')",
    f"etree.fromstring(data, {PARSER}, 'urn:fixture')",
    f"etree.parse(source, {PARSER}, extra, another)",
    f"etree.parse(source, parser={PARSER}, resolve_entities=True)",
])
def test_invalid_or_ambiguous_api_shapes_do_not_establish_entity_resolution(call):
    # ast.parse accepts duplicate keywords; that alone does not make a call valid.
    assert scan_unsafe_xml_parse(archive(IMPORT + call + "\n")) == []


@pytest.mark.parametrize("source", [
    IMPORT + "def parse_feed(etree):\n    return etree.parse(source, parser=etree.XMLParser(resolve_entities=True))\n",
    IMPORT + "etree = custom_module\n" + f"etree.parse(source, parser={PARSER})\n",
    "from lxml.etree import parse, XMLParser\nXMLParser = custom_parser\n"
    "parse(source, parser=XMLParser(resolve_entities=True))\n",
    "from lxml.etree import parse, XMLParser\nparse = custom_parse\n"
    "parse(source, parser=XMLParser(resolve_entities=True))\n",
    "from lxml.etree import parse, XMLParser\ndef read(XMLParser):\n"
    "    return parse(source, XMLParser(resolve_entities=True))\n",
    IMPORT + "etree.parse = custom_parse\n" + f"etree.parse(source, parser={PARSER})\n",
    IMPORT + "etree.XMLParser = custom_parser\n" + f"etree.parse(source, parser={PARSER})\n",
    "import lxml.etree\nlxml.etree.XMLParser = custom_parser\n"
    "lxml.etree.parse(source, lxml.etree.XMLParser(resolve_entities=True))\n",
    "from lxml.etree import parse, XMLParser\ndef read():\n"
    "    return parse(source, XMLParser(resolve_entities=True))\nXMLParser = custom_parser\n",
])
def test_shadowing_rebinding_and_monkeypatching_invalidate_import_evidence(source):
    assert scan_unsafe_xml_parse(archive(source)) == []


@pytest.mark.parametrize("source", [
    "import xml.etree.ElementTree as ET\nET.parse(path)\n",
    "from defusedxml import ElementTree as ET\nET.parse(path)\n",
    "import xml.sax\nxml.sax.parseString(data, handler)\n",
    "import xml.dom.minidom\nxml.dom.minidom.parse(path)\n",
    "import json\njson.loads(data)\n",
    "not valid python (",
])
def test_other_parsers_and_unparseable_source_are_outside_this_rule(source):
    assert scan_unsafe_xml_parse(archive(source)) == []


CORPUS_NEGATIVES = REPO_ROOT / "tests" / "detectors" / RULE_ID / "negative"
MUTATIONS: dict[str, tuple[str, str, str]] = {
    "stdlib-etree": ("app/safe.py", "import xml.etree.ElementTree as ET\nET.parse(path)", POSITIVE.strip()),
    "defusedxml": ("app/safe.py", "from defusedxml import ElementTree as ET\nET.parse(path)", POSITIVE.strip()),
    "sax": ("app/handler.py", "import xml.sax\nxml.sax.parseString(data, handler)", POSITIVE.strip()),
    "minidom": ("app/doc.py", "import xml.dom.minidom\nxml.dom.minidom.parse(path)", POSITIVE.strip()),
    "no-xml": ("app/json.py", "import json\njson.loads(data)", POSITIVE.strip()),
    "lxml-resolve-entities-false": ("app/safe.py", "resolve_entities=False", "resolve_entities=True"),
    "lxml-iterparse-false": ("app/safe.py", "resolve_entities=False", "resolve_entities=True"),
    "lxml-default": ("app/safe.py", "etree.parse(source)", f"etree.parse(source, parser={PARSER})"),
    "lxml-internal": ("app/safe.py", "resolve_entities='internal'", "resolve_entities=True"),
    "lxml-positional-false": ("app/safe.py", "resolve_entities=False", "resolve_entities=True"),
    "lxml-parser-variable": ("app/feed.py", "parser=parser", f"parser={PARSER}"),
    "lxml-constructor-only": ("app/feed.py", f"parser = {PARSER}", f"etree.parse(source, {PARSER})"),
    "lxml-iterparse-html": ("app/feed.py", "html=True", "html=False"),
    "lxml-shadowed-module": ("app/feed.py", "def parse_feed(etree):", "def parse_feed():"),
    "lxml-rebound-constructor": ("app/feed.py", "XMLParser = custom_parser\n", ""),
    "mutated-parse": ("app/safe.py", "etree.parse = custom\n", ""),
    "lxml-invalid-direct-keyword": ("app/feed.py", "etree.parse(source, resolve_entities=True)",
                                    f"etree.parse(source, parser={PARSER})"),
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
    findings = scan_unsafe_xml_parse(archive(files))
    assert len(findings) == 1, "the mutation must establish one explicit entity configuration"
    assert findings[0].severity == "high"


def test_the_product_own_code_reports_nothing():
    """VACUOUS by premise: shipit parses Python and grammar, not XML.

    This guard catches a future false positive only -- it does not exercise
    recognition, because there is no XML parse in our code to recognise.
    """
    sources = {p.relative_to(REPO_ROOT).as_posix(): p.read_text()
               for p in sorted((REPO_ROOT / "app").rglob("*.py")) if "__pycache__" not in p.parts}
    assert scan_unsafe_xml_parse(archive(sources)) == []

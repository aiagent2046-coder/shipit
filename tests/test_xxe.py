"""Synthetic source fixtures: no uploaded code is imported, run or opened.

The load-bearing tests:

  * every corpus negative is MUTATED in the one place that removes the property it
    pins, and the rule must fire on the result;
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

POSITIVE = "from lxml import etree\netree.parse(source)\n"


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
    assert f["confidence"] == 0.8
    assert f["category"] == "Security"
    assert f["source"] == "static"
    assert f["verification_status"] == "unverified"
    assert "external entities" in f["explanation"]


@pytest.mark.parametrize("source", [
    # stdlib ElementTree does not resolve external entities
    "import xml.etree.ElementTree as ET\nET.parse(path)\n",
    # defusedxml is the hardened package
    "from defusedxml import ElementTree as ET\nET.parse(path)\n",
    # an inline parser with resolve_entities=False disables the resolution
    "from lxml import etree\netree.parse(source, parser=etree.XMLParser(resolve_entities=False))\n",
    # not an XML parse at all
    "import json\njson.loads(data)\n",
    "not valid python (",
])
def test_shapes_this_rule_does_not_report(source):
    assert scan_unsafe_xml_parse(archive(source)) == []


def test_an_import_alias_is_the_same_lxml_call():
    assert len(scan_unsafe_xml_parse(archive("from lxml import etree as ET\nET.fromstring(data)\n"))) == 1


CORPUS_NEGATIVES = REPO_ROOT / "tests" / "detectors" / RULE_ID / "negative"
MUTATIONS: dict[str, tuple[str, str, str]] = {
    "stdlib-etree": ("app/safe.py",
                     "import xml.etree.ElementTree as ET",
                     "from lxml import etree as ET"),
    "defusedxml": ("app/safe.py",
                   "from defusedxml import ElementTree as ET",
                   "from lxml import etree as ET"),
    "lxml-resolve-entities-false": ("app/safe.py",
                                    ", parser=etree.XMLParser(resolve_entities=False)",
                                    ""),
    "no-xml": ("app/json.py",
               "import json\njson.loads(data)",
               "from lxml import etree\netree.parse(data)"),
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

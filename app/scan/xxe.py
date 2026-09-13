"""Import-resolved Python XML parses proven to resolve external entities.

The stdlib xml modules -- xml.etree.ElementTree, xml.sax, xml.dom.minidom and
xml.dom.pulldom -- do NOT resolve external entities on supported Python
(3.7.1+), so they are not sinks. lxml.etree resolves external entities only
when resolve_entities is set to True; the default changed to 'internal'
(external entities NOT resolved) in lxml 5.0 for XMLParser and in lxml 6.1.0
for iterparse/ETCompatXMLParser. A static scan cannot know the installed lxml
version, so the rule reports only what is proven unsafe on every version:

  * resolve_entities=True -- for parse/fromstring via
    parser=etree.XMLParser(resolve_entities=True), for iterparse as a direct
    keyword.

A missing resolve_entities argument, resolve_entities=False or 'internal', a
non-lxml parser object, and a mutated module (etree.parse reassigned) are NOT
reported: none of them proves external entities are resolved. Names are
resolved through the file's imports with the same lexical-scope machinery as
the deserialization rule, so an import alias (from lxml import etree as ET) is
the same call and a shadowed or reassigned name loses its provenance.
Cross-file resolution, conditional imports, monkey-patching and a parser
object stored in a variable then passed later are not resolved. No uploaded
code is imported or executed.
"""

from __future__ import annotations

import ast
import zipfile
from dataclasses import dataclass
from typing import BinaryIO

from app.scan.checks import CheckFinding
from app.scan.rule_coverage import RuleCoverage
from app.scan.unsafe_deserialization import _Imports

RULE_ID = "unsafe-xml-parse"

# lxml.etree is the only XXE-prone parser left: the stdlib xml.* modules do not
# resolve external entities on supported Python (>= 3.7.1).
_XXE_SINKS = {
    "lxml.etree": {"parse", "fromstring", "iterparse"},
}

_MAX_FILE_BYTES = 400_000
_MAX_FILES = 400
_MAX_FINDINGS = 32
_MAX_AST_NODES = 20_000
_MAX_AST_DEPTH = 100

_CONFIDENCE = 0.9


@dataclass(frozen=True)
class _Evidence:
    line: int
    what: str


def _is_true(value: ast.AST) -> bool:
    return isinstance(value, ast.Constant) and value.value is True


def _parser_resolve_entities_true(call: ast.Call, imports: _Imports, scope) -> bool:
    """parse/fromstring take resolve_entities only via parser=XMLParser(...)."""
    for keyword in call.keywords:
        if keyword.arg != "parser":
            continue
        parser = keyword.value
        if not isinstance(parser, ast.Call):
            continue  # a parser object stored in a variable -> not proven
        if imports.qualified(parser.func, scope) != "lxml.etree.XMLParser":
            continue  # a non-lxml parser -> not proven
        return any(_is_true(pkw.value) for pkw in parser.keywords if pkw.arg == "resolve_entities")
    return False


def _direct_resolve_entities_true(call: ast.Call) -> bool:
    """iterparse takes resolve_entities as a direct keyword."""
    return any(_is_true(kw.value) for kw in call.keywords if kw.arg == "resolve_entities")


def _evidence(tree: ast.Module) -> list[_Evidence]:
    found: list[_Evidence] = []
    imports = _Imports(tree)
    for node, scope in imports.calls:
        target = imports.qualified(node.func, scope)
        module, _, member = target.rpartition(".")
        if not target or target.split(".")[0] in imports.mutated_modules:
            continue
        if member not in _XXE_SINKS.get(module, ()):
            continue
        if member in ("parse", "fromstring"):
            proven = _parser_resolve_entities_true(node, imports, scope)
        elif member == "iterparse":
            proven = _direct_resolve_entities_true(node)
        else:
            continue
        if proven:
            found.append(_Evidence(node.lineno, f"calls {target}(resolve_entities=True)"))
    return found


def scan_unsafe_xml_parse(fileobj: BinaryIO, *, coverage: dict | None = None) -> list[CheckFinding]:
    findings: list[CheckFinding] = []
    with zipfile.ZipFile(fileobj) as archive:
        accounting = RuleCoverage(archive, extensions=(".py",),
                                  max_file_bytes=_MAX_FILE_BYTES, coverage=coverage)
        for info in accounting.files(findings, max_files=_MAX_FILES, max_findings=_MAX_FINDINGS):
            raw = archive.read(info)
            if b"xml" not in raw and b"etree" not in raw and b"lxml" not in raw:
                accounting.analyzed()
                continue
            try:
                source = raw.decode("utf-8")
            except UnicodeError:
                accounting.skip("decode_error")
                continue
            try:
                tree = ast.parse(source)
            except (SyntaxError, ValueError):
                accounting.skip("parse_error")
                continue
            except RecursionError:
                accounting.skip("ast_limit")
                continue
            pending = [(tree, 0)]
            count = 0
            bounded = True
            while pending:
                node, depth = pending.pop()
                count += 1
                if count > _MAX_AST_NODES or depth > _MAX_AST_DEPTH:
                    bounded = False
                    break
                pending.extend((child, depth + 1) for child in ast.iter_child_nodes(node))
            if not bounded:
                accounting.skip("ast_limit")
                continue
            try:
                evidence = _evidence(tree)
            except RecursionError:
                accounting.skip("ast_limit")
                continue
            remaining = _MAX_FINDINGS - len(findings)
            findings.extend(_finding(info.filename, item) for item in evidence[:remaining])
            if len(evidence) > remaining:
                accounting.skip("finding_limit")
            else:
                accounting.analyzed()
        accounting.finish()
    return findings


def _finding(path: str, item: _Evidence) -> CheckFinding:
    return CheckFinding(
        rule_id=RULE_ID,
        title="XML is parsed with external entity resolution explicitly enabled",
        severity="high",
        confidence=_CONFIDENCE,
        category="Security",
        file=path,
        line=item.line,
        explanation=(
            f"Line {item.line} {item.what}. resolve_entities=True makes lxml resolve external "
            "entities on every version, so an attacker-controlled XML document can read local "
            "files, probe the internal network or force a billion-laughs expansion. Where the "
            "bytes come from has NOT been verified; trusted internal data and untrusted external "
            "data can reach the same call."
        ),
        fix_hint=(
            "Parse XML with xml.etree.ElementTree (which does not resolve external entities) or "
            "the defusedxml package. For lxml, drop resolve_entities=True (the default is "
            "'internal' on lxml 5.0+/6.1.0+, which does not resolve external entities), or pass "
            "resolve_entities=False explicitly."
        ),
    )

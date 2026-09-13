"""Import-resolved Python XML parses that do not protect against external entities.

lxml and the stdlib ``xml.dom.minidom``, ``xml.sax`` and ``xml.dom.pulldom``
modules resolve external entities by default, so an XML document an attacker
controls can read local files (``<!ENTITY x SYSTEM "file:///etc/passwd">``),
probe the internal network, or trigger a billion-laughs expansion. This rule
reports a parse through one of those modules unless the lxml call passes an
explicit ``parser=XMLParser(resolve_entities=False)``.

``xml.etree.ElementTree`` (the stdlib ``ET``) and the ``defusedxml`` package are
the safe alternatives and are NOT sinks. Names are resolved through the file's
imports with the same lexical-scope machinery as the deserialization rule, so
an import alias (``from lxml import etree as ET``) is the same call, and a
shadowed or reassigned name loses its provenance. Cross-file resolution,
conditional imports, monkey-patching and a parser object stored in a variable
then passed later are not resolved. No uploaded code is imported or executed.
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

# Modules whose XML parsers resolve external entities by default (XXE-prone),
# mapped to the members that perform the parse.
_XXE_SINKS = {
    "lxml.etree": {"parse", "fromstring", "iterparse"},
    "xml.dom.minidom": {"parse", "parseString"},
    "xml.sax": {"parse", "parseString"},
    "xml.dom.pulldom": {"parse", "parseString"},
}

_MAX_FILE_BYTES = 400_000
_MAX_FILES = 400
_MAX_FINDINGS = 32
_MAX_AST_NODES = 20_000
_MAX_AST_DEPTH = 100


@dataclass(frozen=True)
class _Evidence:
    line: int
    what: str


def _safe_lxml_parser(call: ast.Call, imports: _Imports, scope) -> bool:
    """True only for an inline parser=XMLParser(resolve_entities=False)."""
    for keyword in call.keywords:
        if keyword.arg != "parser":
            continue
        parser = keyword.value
        if isinstance(parser, ast.Call) and imports.qualified(parser.func, scope) == "lxml.etree.XMLParser":
            if any(pkw.arg == "resolve_entities" and isinstance(pkw.value, ast.Constant)
                   and pkw.value.value is False for pkw in parser.keywords):
                return True
    return False


def _evidence(tree: ast.Module) -> list[_Evidence]:
    found: list[_Evidence] = []
    imports = _Imports(tree)
    for node, scope in imports.calls:
        target = imports.qualified(node.func, scope)
        module, _, member = target.rpartition(".")
        if not target or module in imports.mutated_modules:
            continue
        if member in _XXE_SINKS.get(module, ()):
            if module == "lxml.etree" and _safe_lxml_parser(node, imports, scope):
                continue
            found.append(_Evidence(node.lineno, f"calls {target}()"))
    return found


def scan_unsafe_xml_parse(fileobj: BinaryIO, *, coverage: dict | None = None) -> list[CheckFinding]:
    findings: list[CheckFinding] = []
    with zipfile.ZipFile(fileobj) as archive:
        accounting = RuleCoverage(archive, extensions=(".py",),
                                  max_file_bytes=_MAX_FILE_BYTES, coverage=coverage)
        for info in accounting.files(findings, max_files=_MAX_FILES, max_findings=_MAX_FINDINGS):
            raw = archive.read(info)
            if b"xml" not in raw:
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
        title="XML is parsed without protection against external entities",
        severity="high",
        confidence=0.8,
        category="Security",
        file=path,
        line=item.line,
        explanation=(
            f"Line {item.line} {item.what}. This parser resolves external entities by default, so an "
            "attacker-controlled XML document can read local files, probe the internal network or force "
            "a billion-laughs expansion. Where the bytes come from has NOT been verified; trusted "
            "internal data and untrusted external data can reach the same call."
        ),
        fix_hint=(
            "Parse XML with xml.etree.ElementTree (which does not resolve external entities) or the "
            "defusedxml package. For lxml, pass parser=etree.XMLParser(resolve_entities=False) and "
            "disable network access in the parser. Never parse untrusted XML with minidom, sax or "
            "pulldom."
        ),
    )

"""Import-resolved Python XML parses that may resolve external entities (XXE).

The stdlib XML modules -- xml.etree.ElementTree, xml.sax, xml.dom.minidom and
xml.dom.pulldom -- do NOT resolve external entities on supported Python
(3.7.1+), so they are not sinks. The only remaining risk is lxml.etree, whose
``resolve_entities`` default changed across versions: before lxml 5.0 it was
True (external entities resolved); from 5.0 it is 'internal' (external entities
are NOT resolved). A call is flagged when external entities can be resolved:

  * ``resolve_entities=True`` -- explicitly unsafe on every lxml version
    (HIGH confidence);
  * no ``resolve_entities`` argument -- unsafe on lxml < 5.0, safe on >= 5.0.
    The installed version is not known to a static scan, so the finding is
    MEDIUM confidence.

``resolve_entities=False`` -- inline (``parser=XMLParser(resolve_entities=False)``)
or as a direct keyword on parse/fromstring/iterparse -- is safe and not a sink.
Names are resolved through the file's imports with the same lexical-scope
machinery as the deserialization rule, so an import alias
(``from lxml import etree as ET``) is the same call, and a shadowed or
reassigned name loses its provenance. Cross-file resolution, conditional
imports, monkey-patching and a parser object stored in a variable then passed
later are not resolved. No uploaded code is imported or executed.
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

# resolve_entities=True is a deliberate, version-independent opt-in; a missing
# argument is version-dependent (unsafe only before lxml 5.0).
_CONF_EXPLICIT = 0.9
_CONF_DEFAULT = 0.5


@dataclass(frozen=True)
class _Evidence:
    line: int
    what: str
    confidence: float


def _lxml_resolve_entities(call: ast.Call, imports: _Imports, scope) -> bool | None:
    """True/False for an explicit resolve_entities argument, else None.

    Recognises both forms:
      parse(src, resolve_entities=False)            (direct keyword)
      parse(src, parser=XMLParser(resolve_entities=False))  (inline parser)
    A non-constant value is treated as unknown (None), never as safe.
    """
    # Direct keyword on the parse call itself.
    for keyword in call.keywords:
        if keyword.arg == "resolve_entities":
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, bool):
                return keyword.value.value
            return None
    # Inline parser=XMLParser(resolve_entities=...).
    for keyword in call.keywords:
        if keyword.arg != "parser":
            continue
        parser = keyword.value
        if isinstance(parser, ast.Call) and imports.qualified(parser.func, scope) == "lxml.etree.XMLParser":
            for pkw in parser.keywords:
                if pkw.arg == "resolve_entities":
                    if isinstance(pkw.value, ast.Constant) and isinstance(pkw.value.value, bool):
                        return pkw.value.value
    return None


def _evidence(tree: ast.Module) -> list[_Evidence]:
    found: list[_Evidence] = []
    imports = _Imports(tree)
    for node, scope in imports.calls:
        target = imports.qualified(node.func, scope)
        module, _, member = target.rpartition(".")
        if not target or module in imports.mutated_modules:
            continue
        if member not in _XXE_SINKS.get(module, ()):
            continue
        flag = _lxml_resolve_entities(node, imports, scope)
        if flag is False:
            continue  # explicit resolve_entities=False -> safe on every version
        if flag is True:
            found.append(_Evidence(node.lineno, f"calls {target}(resolve_entities=True)", _CONF_EXPLICIT))
        else:
            found.append(_Evidence(
                node.lineno,
                f"calls {target}() without resolve_entities (unsafe on lxml < 5.0)",
                _CONF_DEFAULT,
            ))
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
    if item.confidence >= _CONF_EXPLICIT:
        explanation = (
            f"Line {item.line} {item.what}. resolve_entities=True makes lxml resolve external "
            "entities on every version, so an attacker-controlled XML document can read local "
            "files, probe the internal network or force a billion-laughs expansion. Where the "
            "bytes come from has NOT been verified; trusted internal data and untrusted external "
            "data can reach the same call."
        )
    else:
        explanation = (
            f"Line {item.line} {item.what}. Before lxml 5.0 the resolve_entities default was True "
            "(external entities resolved); from 5.0 it is 'internal' (external entities NOT "
            "resolved). The installed lxml version is not known to a static scan, so this may or "
            "may not resolve external entities. Where the bytes come from has NOT been verified."
        )
    return CheckFinding(
        rule_id=RULE_ID,
        title="XML is parsed without protection against external entities",
        severity="high" if item.confidence >= _CONF_EXPLICIT else "medium",
        confidence=item.confidence,
        category="Security",
        file=path,
        line=item.line,
        explanation=explanation,
        fix_hint=(
            "Parse XML with xml.etree.ElementTree (which does not resolve external entities) or "
            "the defusedxml package. For lxml, pass resolve_entities=False (or "
            "parser=etree.XMLParser(resolve_entities=False)) and disable network access in the "
            "parser."
        ),
    )

"""Import-resolved lxml calls that explicitly enable external entity resolution.

Only literal ``resolve_entities=True`` is reported: on an inline XMLParser
consumed by parse/fromstring (positional or keyword parser), or directly on
iterparse in XML mode. Constructing a parser alone does not consume XML.

Defaults and unknown configurations are not findings. XMLParser changed its
default to 'internal' in lxml 5.0; iterparse and ETCompatXMLParser did so only
in 6.1.0 (https://lxml.de/6.1/changes-6.1.0.html). Dependency versions are not
inferred. False and 'internal' disable external entity expansion in this
configuration, but do not prove overall XML safety.

Lexical imports, aliases, shadowing and module writes use the deserialization
rule's resolver. Observed module writes invalidate provenance. Conditional
imports, cross-file/dynamic mutations, parser variables, custom parsers and
resolvers, set_default_parser, feed/close, and XInclude are not resolved.
The stdlib XML APIs and other libraries are outside this rule's scope.
Input trust, execution and runtime controls are not verified. No uploaded
code is imported or executed; no finding does not establish safety.
"""

from __future__ import annotations

import ast
import zipfile
from dataclasses import dataclass
from enum import Enum
from typing import BinaryIO

from app.scan.checks import CheckFinding
from app.scan.rule_coverage import RuleCoverage
from app.scan.unsafe_deserialization import _Imports

RULE_ID = "unsafe-xml-parse"

_XXE_SINKS = {
    "lxml.etree": {"parse", "fromstring", "iterparse"},
}

_MAX_FILE_BYTES = 400_000
_MAX_FILES = 400
_MAX_FINDINGS = 32
_MAX_AST_NODES = 20_000
_MAX_AST_DEPTH = 100

_CONF_EXPLICIT = 0.9

# Recognised API shapes, not a claim that every accepted option/value is valid
# in every lxml release. Expanded/duplicate or unsupported arguments stay unknown.
_XML_PARSER_OPTIONS = frozenset({
    "encoding", "attribute_defaults", "dtd_validation", "load_dtd", "no_network",
    "decompress", "ns_clean", "recover", "schema", "huge_tree", "remove_blank_text",
    "resolve_entities", "remove_comments", "remove_pis", "strip_cdata", "collect_ids",
    "target", "compact",
})
_ITERPARSE_OPTIONS = frozenset({
    "source", "events", "tag", "attribute_defaults", "dtd_validation", "load_dtd",
    "no_network", "remove_blank_text", "compact", "resolve_entities", "remove_comments",
    "remove_pis", "strip_cdata", "encoding", "html", "recover", "huge_tree", "schema", "chunk_size",
})


class _EntityResolution(Enum):
    ENABLED = "enabled"
    DISABLED = "disabled"
    DEFAULT = "default"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True)
class _Evidence:
    line: int
    target: str


def _keywords(call: ast.Call, allowed: frozenset[str]) -> dict[str, ast.AST] | None:
    keywords: dict[str, ast.AST] = {}
    if any(isinstance(arg, ast.Starred) for arg in call.args):
        return None
    for keyword in call.keywords:
        if keyword.arg not in allowed or keyword.arg in keywords:
            return None
        keywords[keyword.arg] = keyword.value
    return keywords


def _entity_option(keywords: dict[str, ast.AST]) -> _EntityResolution:
    if "resolve_entities" not in keywords:
        return _EntityResolution.DEFAULT
    value = keywords["resolve_entities"]
    if isinstance(value, ast.Constant):
        if value.value is True:
            return _EntityResolution.ENABLED
        if value.value is False or value.value == "internal":
            return _EntityResolution.DISABLED
    return _EntityResolution.UNRESOLVED


def _lxml_resolve_entities(call: ast.Call, member: str, imports: _Imports, scope) -> _EntityResolution:
    if member == "iterparse":
        keywords = _keywords(call, _ITERPARSE_OPTIONS)
        # Keep the first positional source or keyword source only; other
        # positional options are outside this deliberately bounded trace.
        if keywords is None or len(call.args) > 1 or bool(call.args) == ("source" in keywords):
            return _EntityResolution.UNRESOLVED
        html = keywords.get("html")
        if html is not None and not (isinstance(html, ast.Constant) and html.value is False):
            return _EntityResolution.UNRESOLVED
        return _entity_option(keywords)

    source_name = "source" if member == "parse" else "text"
    # base_url is keyword-only, despite its display in some generated docs.
    parameters = (source_name, "parser")
    keywords = _keywords(call, frozenset((*parameters, "base_url")))
    if keywords is None or len(call.args) > len(parameters):
        return _EntityResolution.UNRESOLVED
    if any(name in keywords for name in parameters[:len(call.args)]):
        return _EntityResolution.UNRESOLVED
    if not call.args and source_name not in keywords:
        return _EntityResolution.UNRESOLVED
    parser = call.args[1] if len(call.args) > 1 else keywords.get("parser")
    if parser is None or (isinstance(parser, ast.Constant) and parser.value is None):
        return _EntityResolution.DEFAULT
    if not isinstance(parser, ast.Call) or imports.qualified(parser.func, scope) != "lxml.etree.XMLParser":
        return _EntityResolution.UNRESOLVED
    options = _keywords(parser, _XML_PARSER_OPTIONS)
    if parser.args or options is None:
        return _EntityResolution.UNRESOLVED
    return _entity_option(options)


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
        if _lxml_resolve_entities(node, member, imports, scope) is _EntityResolution.ENABLED:
            found.append(_Evidence(node.lineno, target))
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
    if item.target.endswith(".iterparse"):
        configuration = "passes resolve_entities=True directly in XML mode"
        fix = "Pass resolve_entities=False and no_network=True directly to etree.iterparse()."
    else:
        configuration = "receives an inline etree.XMLParser(resolve_entities=True)"
        fix = "Pass parser=etree.XMLParser(resolve_entities=False, no_network=True) to this parse call."
    return CheckFinding(
        rule_id=RULE_ID,
        title="XML parsing explicitly enables external entity resolution",
        severity="high",
        confidence=_CONF_EXPLICIT,
        category="Security",
        file=path,
        line=item.line,
        explanation=(
            f"Line {item.line} calls {item.target} and {configuration}. This explicitly enables "
            "external entity expansion. If attacker-controlled XML reaches this call and runtime "
            "controls allow access, external entities may expose local file contents or access "
            "other resources. Input trust, execution, installed libraries, custom resolvers and "
            "network access have not been verified."
        ),
        fix_hint=fix + " Check input trust and whether external entities are required before changing XML handling.",
    )

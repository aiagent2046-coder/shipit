"""Bounded, source-only detector for LLM SDK clients configured with dangerouslyAllowBrowser=true.

OpenAI, Anthropic, Groq and Mistral JavaScript/TypeScript SDKs refuse to run in a
browser environment by default because bundling the client exposes its API key or
allows arbitrary visitor traffic against the account. Passing
``dangerouslyAllowBrowser: true`` explicitly disables that guard.

Only recognized SDK module imports/requires, their constructor aliases, and
one-hop local options objects are resolved. Unknown classes, non-boolean or
false values, spread overrides, and cross-file configuration remain silent.
Target code is never executed.
"""

from __future__ import annotations

import ast
from collections import Counter
from dataclasses import dataclass
from typing import Any, BinaryIO
import zipfile

import tree_sitter_typescript
from tree_sitter import Language, Parser

from app.scan.checks import CheckFinding
from app.scan.rule_coverage import RuleCoverage, remaining_findings

RULE_ID = "llm-client-browser-exposed"
_JS_FILE_SUFFIXES = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")
_MAX_FILE_BYTES = 400_000
_MAX_FILES = 400
_MAX_FINDINGS = 32
_MAX_NODES = 20_000
_MAX_DEPTH = 100

_FUNCTIONS = {
    "function_declaration",
    "function_expression",
    "arrow_function",
    "generator_function",
    "generator_function_declaration",
    "method_definition",
}
_TYPES = {
    "type_alias_declaration",
    "interface_declaration",
    "type_annotation",
    "type_arguments",
    "type_parameters",
    "ambient_declaration",
}

# SDK package -> recognized constructor exports (first is the default export).
_SDK_PACKAGES: dict[str, tuple[str, ...]] = {
    "openai": ("OpenAI", "AzureOpenAI"),
    "@anthropic-ai/sdk": ("Anthropic", "AnthropicBedrock", "AnthropicVertex"),
    "groq-sdk": ("Groq",),
    "@mistralai/mistralai": ("Mistral",),
}
_OPTION_KEY = "dangerouslyAllowBrowser"


def _normalize_sdk_module(raw: str) -> str:
    for pkg in _SDK_PACKAGES:
        if raw == pkg or raw.startswith(pkg + "/"):
            return pkg
    return ""


def _text(node) -> str:
    return node.text.decode("utf-8", "replace") if node is not None else ""


def _unwrap(node):
    while node is not None and node.type in {
        "parenthesized_expression",
        "as_expression",
        "satisfies_expression",
        "non_null_expression",
        "type_assertion",
    }:
        children = [child for child in node.named_children if child.type != "comment"]
        if not children:
            return None
        node = children[-1] if node.type == "type_assertion" else children[0]
    return node


def _string(node) -> str | None:
    node = _unwrap(node)
    if node is None or node.type != "string":
        return None
    try:
        value = ast.literal_eval(_text(node))
        return value if isinstance(value, str) else None
    except (ValueError, SyntaxError):
        return None


def _property(node) -> str:
    if node is None:
        return ""
    if node.type in {"property_identifier", "identifier"}:
        return _text(node)
    return _string(node) or ""


def _pattern_names(node) -> set[str]:
    if node is None:
        return set()
    if node.type in {"identifier", "shorthand_property_identifier_pattern", "type_identifier"}:
        return {_text(node)}
    if node.type in {"required_parameter", "optional_parameter"}:
        return _pattern_names(node.child_by_field_name("pattern"))
    if node.type in {"pair_pattern", "assignment_pattern", "object_assignment_pattern"}:
        return _pattern_names(node.child_by_field_name("value") or node.child_by_field_name("left"))
    if node.type in {"object_pattern", "array_pattern", "rest_pattern", "formal_parameters"}:
        return set().union(*(_pattern_names(child) for child in node.named_children))
    return set()


@dataclass(frozen=True)
class _Value:
    sdk: str = ""
    ctor: str = ""
    options: Any = None
    bool_literal: bool | None = None


_UNKNOWN = _Value()


def _is_true_value(node, bindings: dict[str, _Value]) -> bool:
    node = _unwrap(node)
    if node is None:
        return False
    if node.type == "true":
        return True
    if node.type in {"identifier", "shorthand_property_identifier"}:
        resolved = bindings.get(_text(node), _UNKNOWN)
        return resolved.bool_literal is True
    return False


def js_evidence(text: str, tsx: bool = False, *, incomplete_reason: dict[str, str] | None = None):
    if text.isascii() and "\\" not in text and _OPTION_KEY not in text:
        return []
    parser = Parser(
        Language(tree_sitter_typescript.language_tsx() if tsx else tree_sitter_typescript.language_typescript())
    )
    tree = parser.parse(text.encode("utf-8"))
    if tree.root_node.has_error:
        if incomplete_reason is not None:
            incomplete_reason["reason"] = "parse_error"
        return []
    pending, count = [(tree.root_node, 0)], 0
    while pending:
        node, depth = pending.pop()
        count += 1
        if count > _MAX_NODES or depth > _MAX_DEPTH:
            if incomplete_reason is not None:
                incomplete_reason["reason"] = "ast_limit"
            return []
        pending.extend((child, depth + 1) for child in node.named_children)

    found: list[tuple[int, str]] = []

    def emit(node, label: str):
        if len(found) < _MAX_FINDINGS:
            found.append((node.start_point[0] + 1, label))
        elif incomplete_reason is not None:
            incomplete_reason["reason"] = "finding_limit"

    def resolve(node, bindings: dict[str, _Value]) -> _Value:
        node = _unwrap(node)
        if node is None:
            return _UNKNOWN
        if node.type == "true":
            return _Value(bool_literal=True)
        if node.type == "false":
            return _Value(bool_literal=False)
        if node.type == "identifier":
            return bindings.get(_text(node), _UNKNOWN)
        if node.type == "object":
            return _Value(options=node)
        if node.type in {"member_expression", "subscript_expression"}:
            base = resolve(node.child_by_field_name("object"), bindings)
            prop = _property(node.child_by_field_name("property") or node.child_by_field_name("index"))
            allowed = _SDK_PACKAGES.get(base.sdk, ())
            if base.sdk and not base.ctor and (prop in allowed or prop == "default"):
                ctor_name = allowed[0] if prop == "default" else prop
                return _Value(sdk=base.sdk, ctor=ctor_name)
            return _UNKNOWN
        if node.type == "call_expression":
            callee = resolve(node.child_by_field_name("function"), bindings)
            args = node.child_by_field_name("arguments")
            values = [child for child in args.named_children if child.type != "comment"] if args else []
            if callee.sdk == "builtin:require" and len(values) == 1:
                pkg = _normalize_sdk_module(_string(values[0]) or "")
                if pkg:
                    default_ctor = _SDK_PACKAGES[pkg][0]
                    return _Value(sdk=pkg, ctor=default_ctor)
        return _UNKNOWN

    def true_browser_option(value: _Value, bindings: dict[str, _Value]):
        if value.options is None:
            return None
        selected = None
        for child in value.options.named_children:
            if child.type == "comment":
                continue
            if child.type == "pair":
                key = _property(child.child_by_field_name("key"))
                if key == _OPTION_KEY:
                    val = child.child_by_field_name("value")
                    selected = child if _is_true_value(val, bindings) else None
                elif not key:
                    selected = None
            elif child.type == "shorthand_property_identifier":
                if _text(child) == _OPTION_KEY:
                    selected = child if _is_true_value(child, bindings) else None
            elif child.type == "spread_element":
                selected = None
        return selected

    def import_bindings(node) -> dict[str, _Value]:
        if any(child.type == "type" for child in node.children):
            return {}
        pkg = _normalize_sdk_module(_string(node.child_by_field_name("source")) or "")
        clause = next((child for child in node.named_children if child.type == "import_clause"), None)
        result: dict[str, _Value] = {}
        if clause is None:
            return result
        allowed = _SDK_PACKAGES.get(pkg, ())
        default_ctor = allowed[0] if allowed else ""
        for child in clause.named_children:
            if child.type == "identifier":
                result[_text(child)] = _Value(sdk=pkg, ctor=default_ctor) if pkg else _UNKNOWN
            elif child.type == "namespace_import":
                name = next((part for part in child.named_children if part.type == "identifier"), None)
                if name is not None:
                    result[_text(name)] = _Value(sdk=pkg) if pkg else _UNKNOWN
            elif child.type == "named_imports":
                for part in child.named_children:
                    if any(token.type == "type" for token in part.children):
                        continue
                    name = part.child_by_field_name("name")
                    alias = part.child_by_field_name("alias") or name
                    if alias is None or name is None:
                        continue
                    orig = _text(name)
                    if pkg and (orig in allowed or orig == "default"):
                        ctor_name = default_ctor if orig == "default" else orig
                        result[_text(alias)] = _Value(sdk=pkg, ctor=ctor_name)
                    else:
                        result[_text(alias)] = _UNKNOWN
        return result

    def bound(nodes) -> Counter[str]:
        counts: Counter[str] = Counter()
        pending_nodes = list(nodes)
        while pending_nodes:
            node = pending_nodes.pop()
            if node.type in _TYPES:
                continue
            if node.type in _FUNCTIONS or node.type in {"class_declaration", "abstract_class_declaration"}:
                name = node.child_by_field_name("name")
                if name is None:
                    name = next((c for c in node.named_children if c.type in {"identifier", "type_identifier"}), None)
                if name is not None:
                    counts[_text(name)] += 1
                continue
            if node.type in {"variable_declarator", "assignment_expression", "augmented_assignment_expression"}:
                counts.update(_pattern_names(node.child_by_field_name("name") or node.child_by_field_name("left")))
            elif node.type == "import_statement":
                counts.update(import_bindings(node).keys())
                continue
            pending_nodes.extend(node.named_children)
        return counts

    def invalidate(value: _Value, bindings: dict[str, _Value]):
        for name, known in list(bindings.items()):
            if (value.sdk and known.sdk == value.sdk) or (
                value.options is not None and known.options == value.options
            ):
                bindings.pop(name, None)

    def assign(target, value, bindings: dict[str, _Value]):
        target = _unwrap(target)
        if target is None:
            return
        origin = resolve(value, bindings)
        if target.type == "identifier":
            bindings[_text(target)] = origin
        elif target.type == "object_pattern":
            allowed = _SDK_PACKAGES.get(origin.sdk, ())
            default_ctor = allowed[0] if allowed else ""
            for child in target.named_children:
                if child.type == "pair_pattern":
                    key = _property(child.child_by_field_name("key"))
                    destination = child.child_by_field_name("value")
                else:
                    key, destination = _text(child), child
                if destination is not None and destination.type in {
                    "identifier",
                    "shorthand_property_identifier_pattern",
                }:
                    if origin.sdk and (key in allowed or key == "default"):
                        ctor_name = default_ctor if key == "default" else key
                        bindings[_text(destination)] = _Value(sdk=origin.sdk, ctor=ctor_name)
                    else:
                        bindings[_text(destination)] = _UNKNOWN
                else:
                    for name in _pattern_names(destination):
                        bindings[name] = _UNKNOWN
        elif target.type in {"member_expression", "subscript_expression"}:
            invalidate(resolve(target.child_by_field_name("object"), bindings), bindings)
        else:
            for name in _pattern_names(target):
                bindings[name] = _UNKNOWN

    def lexical_names(nodes) -> set[str]:
        names: set[str] = set()
        for node in nodes:
            if node.type == "lexical_declaration":
                for child in node.named_children:
                    if child.type == "variable_declarator":
                        names.update(_pattern_names(child.child_by_field_name("name")))
            elif node.type in {
                "function_declaration",
                "generator_function_declaration",
                "class_declaration",
                "abstract_class_declaration",
            }:
                name = node.child_by_field_name("name")
                if name is None:
                    name = next((c for c in node.named_children if c.type in {"identifier", "type_identifier"}), None)
                if name is not None:
                    names.add(_text(name))
        return names

    def scope(nodes, inherited: dict[str, _Value], parameters=(), local=False, block_scope=False):
        counts = bound(nodes)
        bindings = inherited.copy()
        if local or block_scope:
            for name in lexical_names(nodes) if block_scope else counts:
                bindings.pop(name, None)
        for name in parameters:
            bindings.pop(name, None)
        deferred = []

        def expression(node, state: dict[str, _Value]):
            if node is None or node.type in _TYPES or node.type in {"comment", "string", "regex"}:
                return
            if node.type == "statement_block":
                declarations = lexical_names(node.named_children)
                completed = scope(node.named_children, state, block_scope=True)
                for name in set(state) | set(completed):
                    if name not in declarations:
                        if name in completed:
                            state[name] = completed[name]
                        else:
                            state.pop(name, None)
                return
            if node.type in _FUNCTIONS:
                name = node.child_by_field_name("name")
                if name is not None:
                    state.pop(_text(name), None)
                deferred.append(node)
                return
            if node.type in {"class_declaration", "abstract_class_declaration", "class"}:
                name = node.child_by_field_name("name")
                if name is None:
                    name = next((c for c in node.named_children if c.type in {"identifier", "type_identifier"}), None)
                if name is not None:
                    state.pop(_text(name), None)
                body = node.child_by_field_name("body")
                if body is not None:
                    for member in body.named_children:
                        expression(member, state)
                return
            if node.type == "template_string":
                for child in node.named_children:
                    if child.type == "template_substitution":
                        expression(child, state)
                return
            if node.type in {"assignment_expression", "augmented_assignment_expression"}:
                value = node.child_by_field_name("right")
                expression(value, state)
                assign(
                    node.child_by_field_name("left"),
                    value if node.type == "assignment_expression" else None,
                    state,
                )
                return
            if node.type == "new_expression":
                callee = resolve(node.child_by_field_name("constructor"), state)
                args = node.child_by_field_name("arguments")
                if callee.sdk and callee.ctor and args is not None:
                    values = [c for c in args.named_children if c.type != "comment"]
                    if values and values[0].type != "spread_element":
                        option = true_browser_option(resolve(values[0], state), state)
                        if option is not None:
                            emit(option, f"passes dangerouslyAllowBrowser=true to new {callee.ctor}(...)")
            if node.type == "variable_declarator":
                value = node.child_by_field_name("value")
                expression(value, state)
                assign(node.child_by_field_name("name"), value, state)
                return
            if node.type == "import_statement":
                state.update(import_bindings(node))
                return
            if node.type in {
                "if_statement",
                "for_statement",
                "for_in_statement",
                "while_statement",
                "do_statement",
                "try_statement",
                "switch_statement",
            }:
                for child in node.named_children:
                    branch = state.copy()
                    for name in _pattern_names(child.child_by_field_name("parameter")) | _pattern_names(
                        node.child_by_field_name("left")
                    ):
                        branch.pop(name, None)
                    expression(child, branch)
                for name in bound([node]):
                    state.pop(name, None)
                todo = list(node.named_children)
                while todo:
                    child = todo.pop()
                    if child.type in _FUNCTIONS:
                        continue
                    if child.type in {"assignment_expression", "augmented_assignment_expression"}:
                        target = child.child_by_field_name("left")
                        if target is not None and target.type in {"member_expression", "subscript_expression"}:
                            assign(target, None, state)
                    todo.extend(child.named_children)
                return
            for child in node.named_children:
                expression(child, state)

        for node in nodes:
            expression(node, bindings)
        stable = {name: value for name, value in bindings.items() if counts[name] <= 1}
        for function in deferred:
            params = function.child_by_field_name("parameters") or function.child_by_field_name("parameter")
            names = _pattern_names(params)
            body = function.child_by_field_name("body")
            if body is not None:
                scope(body.named_children if body.type == "statement_block" else [body], stable, names, local=True)
        return bindings

    scope(
        tree.root_node.named_children,
        {"require": _Value(sdk="builtin:require")},
        local=True,
    )
    return found


def scan_llm_browser_client(fileobj: BinaryIO, *, coverage: dict | None = None) -> list[CheckFinding]:
    findings: list[CheckFinding] = []
    seen: set[tuple[str, int, str]] = set()
    with zipfile.ZipFile(fileobj) as archive:
        accounting = RuleCoverage(
            archive,
            extensions=_JS_FILE_SUFFIXES,
            max_file_bytes=_MAX_FILE_BYTES,
            coverage=coverage,
        )
        for info in accounting.files(findings, max_files=_MAX_FILES, max_findings=_MAX_FINDINGS):
            incomplete: dict[str, str] = {}
            try:
                text = archive.read(info).decode("utf-8")
            except UnicodeError:
                accounting.skip("decode_error")
                continue
            try:
                evidence = js_evidence(
                    text,
                    tsx=info.filename.endswith((".tsx", ".jsx")),
                    incomplete_reason=incomplete,
                )
            except (SyntaxError, ValueError):
                accounting.skip("parse_error")
                continue
            except RecursionError:
                accounting.skip("ast_limit")
                continue
            for line, what in evidence:
                key = (info.filename, line, what)
                if key in seen:
                    continue
                if len(findings) >= remaining_findings(_MAX_FINDINGS):
                    incomplete["reason"] = "finding_limit"
                    break
                seen.add(key)
                findings.append(_finding(info.filename, line, what))
            if incomplete:
                accounting.skip(incomplete["reason"])
            else:
                accounting.analyzed()
        accounting.finish()
    return findings


def _finding(path: str, line: int, what: str) -> CheckFinding:
    return CheckFinding(
        rule_id=RULE_ID,
        title="LLM SDK client explicitly enables browser execution",
        severity="high",
        confidence=0.9,
        category="Security",
        file=path,
        line=line,
        explanation=(
            f"Line {line} {what}. "
            "The SDK refuses browser execution by default because instantiating a client in "
            "browser-delivered code exposes its API credential or allows visitors to make direct "
            "requests against the account. Whether this file is bundled for the browser, whether "
            "the credential is a live provider key, and whether a proxy restricts requests have "
            "not been verified."
        ),
        fix_hint=(
            "Move the LLM SDK call to a server-side route or backend worker that reads the API key "
            "from server environment variables, and remove dangerouslyAllowBrowser: true. If the "
            "client is intentionally used with a user-supplied key (BYOK), document that contract "
            "and ensure no server key is passed."
        ),
    )

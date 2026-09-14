"""Bounded syntax checks for JS/TS DOM HTML injection; no source is executed.

A literal string/template or an earlier, visible, unambiguous const literal is
silent. Comments and strings are syntax nodes, not declarations or sinks.
Sanitizers, input trust, custom DOM-like receivers and cross-file bindings are
unresolved. Native parser absence fails the check rather than claiming coverage.
"""
from __future__ import annotations

import zipfile

from app.scan.rule_coverage import remaining_findings
from typing import BinaryIO

from app.scan.checks import CheckFinding
from app.scan.rule_coverage import RuleCoverage
from app.scan.vue_template import VueParseError, extract_vue

RULE_ID = "xss-unsafe-html-injection"
_JS_FILE_SUFFIXES = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".vue")
_MAX_FILE_BYTES = 400_000
_MAX_FILES = 400
_MAX_FINDINGS = 32
_MAX_NODES = 20_000
_MAX_DEPTH = 100


def _parser(tsx: bool):
    # Lazy imports let the engine withhold this check when native grammars fail.
    try:
        from tree_sitter import Language, Parser
        import tree_sitter_typescript
    except ImportError:
        raise ImportError("Native JavaScript grammar unavailable") from None
    language = (tree_sitter_typescript.language_tsx() if tsx
                else tree_sitter_typescript.language_typescript())
    return Parser(Language(language))


def _nodes(root):
    pending, nodes = [(root, 0)], []
    while pending:
        node, depth = pending.pop()
        if len(nodes) >= _MAX_NODES or depth > _MAX_DEPTH:
            raise ValueError("ast_limit")
        nodes.append(node)
        pending.extend((child, depth + 1) for child in reversed(node.named_children))
    return nodes


def _text(node):
    return node.text.decode("utf-8") if node is not None else ""


def _literal(node):
    return node is not None and (
        node.type == "string" or
        (node.type == "template_string" and
         not any(child.type == "template_substitution" for child in node.named_children))
    )


def _declarations(nodes):
    """Only globally unique names are eligible for one-hop suppression.

    This is intentionally narrower than general symbol resolution: parameters,
    destructuring, imports and mutations invalidate the name. The remaining
    declaration must also precede the use and have a containing lexical scope.
    """
    declared, invalid = {}, set()
    for node in nodes:
        if node.type == "variable_declarator":
            name = node.child_by_field_name("name")
            if name is not None and name.type == "identifier":
                key = _text(name)
                if key in declared:
                    invalid.add(key)
                declared[key] = node
            elif name is not None:
                invalid.update(_text(n) for n in _nodes(name)
                               if n.type in {"identifier", "shorthand_property_identifier_pattern"})
        elif node.type in {"formal_parameters", "import_clause", "catch_clause"}:
            # Catch body names invalidate conservatively as well.
            invalid.update(_text(n) for n in _nodes(node) if n.type == "identifier")
        elif node.type == "for_in_statement":
            # for-in/of binds its left side directly, without a variable_declarator.
            target = node.child_by_field_name("left")
            if target is not None:
                invalid.update(_text(n) for n in _nodes(target)
                               if n.type in {"identifier", "shorthand_property_identifier_pattern"})
        elif node.type == "arrow_function":
            parameter = node.child_by_field_name("parameter")
            if parameter is not None:
                invalid.add(_text(parameter))
        elif node.type in {"function_declaration", "class_declaration"}:
            invalid.add(_text(node.child_by_field_name("name")))
        elif node.type in {"assignment_expression", "augmented_assignment_expression", "update_expression"}:
            target = node.child_by_field_name("left") or node.child_by_field_name("argument")
            if target is not None:
                invalid.update(_text(n) for n in _nodes(target) if n.type == "identifier")
    return {name: node for name, node in declared.items() if name not in invalid}


def _static_value(value, use, declarations):
    if isinstance(value, list):
        return all(_static_value(argument, use, declarations) for argument in value)
    if _literal(value):
        return True
    if value is None or value.type != "identifier":
        return False
    declaration = declarations.get(_text(value))
    if declaration is None or declaration.end_byte > use.start_byte:
        return False
    if declaration.parent.type != "lexical_declaration" or not _text(declaration.parent).startswith("const "):
        return False
    if not _literal(declaration.child_by_field_name("value")):
        return False
    scope = declaration.parent.parent
    # Loop-local declarations must not leak out of their loop body.
    parent = use.parent
    while parent is not None:
        if parent == scope:
            return True
        parent = parent.parent
    return False


def _sink(node):
    if node.type in {"assignment_expression", "augmented_assignment_expression"}:
        if node.type == "augmented_assignment_expression" and _text(node.child_by_field_name("operator")) != "+=":
            return None, None
        left = node.child_by_field_name("left")
        if left is not None and left.type == "member_expression":
            prop = _text(left.child_by_field_name("property"))
            if prop in {"innerHTML", "outerHTML"}:
                return "inner-outer-html-assignment", node.child_by_field_name("right")
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        args = [n for n in arguments.named_children if n.type != "comment"] if arguments else []
        if function is not None and function.type == "member_expression":
            prop = _text(function.child_by_field_name("property"))
            receiver = _text(function.child_by_field_name("object"))
            if receiver == "document" and prop in {"write", "writeln"} and args:
                return "document-write", args
            if prop == "insertAdjacentHTML" and len(args) >= 2:
                return "insert-adjacent-html", args[1]
    if node.type == "jsx_attribute" and node.named_children:
        if _text(node.named_children[0]) == "dangerouslySetInnerHTML":
            for child in node.named_children[1:]:
                if child.type != "jsx_expression":
                    continue
                for obj in child.named_children:
                    if obj.type != "object":
                        continue
                    value = None
                    for pair in obj.named_children:
                        if pair.type == "pair" and _text(pair.child_by_field_name("key")) in {
                            "__html", "\"__html\"", "'__html'"
                        }:
                            value = pair.child_by_field_name("value")
                        elif pair.type == "shorthand_property_identifier" and _text(pair) == "__html":
                            value = pair
                        elif pair.type == "spread_element" and value is not None:
                            # A later spread may replace the known __html value.
                            value = pair
                    if value is not None:
                        return "dangerously-set-inner-html", value
    return None, None


def _javascript_candidates(raw, parser):
    root = parser.parse(raw).root_node
    if root.has_error:
        raise VueParseError("parse_error")
    nodes = _nodes(root)
    declarations = _declarations(nodes)
    candidates = []
    for node in nodes:
        sink, value = _sink(node)
        if sink is not None and value is not None and not _static_value(value, node, declarations):
            candidates.append((node.start_point[0] + 1, sink))
    return candidates, len(nodes)


def _vue_candidates(source, parsers):
    expressions, scripts, node_count = extract_vue(source, max_nodes=_MAX_NODES, max_depth=_MAX_DEPTH)
    candidates = []
    for expression in expressions:
        # A wrapping expression forbids a directive value from introducing
        # declarations/statements. HTML entities have already been decoded once.
        raw = ("(" + expression.value + "\n)").encode("utf-8")
        root = parsers[False].parse(raw).root_node
        if root.has_error:
            raise VueParseError("parse_error")
        nodes = _nodes(root)
        node_count += len(nodes)
        if node_count > _MAX_NODES:
            raise VueParseError("ast_limit")
        statements = [n for n in root.named_children if n.type != "comment"]
        if len(statements) != 1 or statements[0].type != "expression_statement":
            raise VueParseError("parse_error")
        value = statements[0].named_children[0]
        while value.type == "parenthesized_expression":
            children = [n for n in value.named_children if n.type != "comment"]
            if len(children) != 1:
                raise VueParseError("parse_error")
            value = children[0]
        if not _literal(value):
            candidates.append((expression.line, "vue-v-html"))
    for script in scripts:
        # Separate programs prevent a literal in one block from incorrectly
        # suppressing a sink in the other block's different compilation scope.
        raw = script.value.encode("utf-8")
        script_candidates, count = _javascript_candidates(raw, parsers[script.tsx])
        node_count += count
        if node_count > _MAX_NODES:
            raise VueParseError("ast_limit")
        candidates.extend((line + script.line - 1, sink) for line, sink in script_candidates)
    return sorted(candidates)


def scan_xss(fileobj: BinaryIO, *, coverage: dict | None = None) -> list[CheckFinding]:
    parsers = {False: _parser(False), True: _parser(True)}
    findings: list[CheckFinding] = []
    with zipfile.ZipFile(fileobj) as archive:
        accounting = RuleCoverage(archive, extensions=_JS_FILE_SUFFIXES,
                                  max_file_bytes=_MAX_FILE_BYTES, coverage=coverage)
        for info in accounting.files(findings, max_files=_MAX_FILES, max_findings=_MAX_FINDINGS):
            raw = archive.read(info)
            try:
                source = raw.decode("utf-8")
                if info.filename.endswith(".vue"):
                    candidates = _vue_candidates(source, parsers)
                else:
                    candidates, _ = _javascript_candidates(
                        raw, parsers[info.filename.endswith((".jsx", ".tsx"))])
            except UnicodeError:
                accounting.skip("decode_error")
                continue
            except VueParseError as exc:
                accounting.skip(str(exc))
                continue
            except ValueError:
                accounting.skip("ast_limit")
                continue
            for line, sink in candidates:
                if len(findings) >= remaining_findings(_MAX_FINDINGS):
                    accounting.skip("finding_limit")
                    accounting.finish()
                    return findings
                findings.append(_finding(info.filename, line, sink))
            accounting.analyzed()
        accounting.finish()
    return findings


def _finding(path: str, line: int, sink: str) -> CheckFinding:
    return CheckFinding(
        rule_id=RULE_ID,
        title="HTML is injected into the DOM from a value that is not a fixed string",
        severity="high",
        confidence=0.7,
        category="Security",
        file=path,
        line=line,
        explanation=(
            f"Line {line} hands {_describe(sink)} a value that is not a fixed string literal. "
            "If that value can carry attacker-controlled text, it can inject markup and script "
            "into the page -- script execution under the visitor's origin, token theft, and DOM "
            "corruption. Whether the value was sanitized, whether it is actually reachable, and "
            "whether the sink runs have NOT been verified; the rule reads only that a non-literal "
            "value reaches an HTML-injection sink."
        ),
        fix_hint=(
            "Use Vue interpolation ({{ value }}) or v-text for plain text. If HTML is required, "
            "sanitize it with an explicit allowlist before v-html. A helper or sanitizer call "
            "alone does not establish that its policy is safe."
            if sink == "vue-v-html" else
            "Use textContent (or React's normal children / setText) for anything that is text, not "
            "markup. If you must insert HTML, sanitize the value first (DOMPurify with an allowlist, "
            "or an equivalent) and prefer a template or component that never builds HTML by string. "
            "For React, avoid dangerouslySetInnerHTML unless the content is already trusted."
        ),
    )


def _describe(sink: str) -> str:
    return {
        "vue-v-html": "Vue v-html",
        "dangerously-set-inner-html": "dangerouslySetInnerHTML",
        "inner-outer-html-assignment": "innerHTML/outerHTML",
        "document-write": "document.write",
        "insert-adjacent-html": "insertAdjacentHTML",
    }.get(sink, sink)

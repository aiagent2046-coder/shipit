"""Unsafe HTML injection into the DOM, read as text with quote/comment tracking.

JS/TS/JSX/TSX is read as source text, not executed and not tree-parsed, so this
rule is portable to the offline browser engine (no native grammar). Four sinks
inject HTML into the DOM, and a caller whose value is not a fixed string literal
can inject markup and script:

  * ``dangerouslySetInnerHTML={{ __html: value }}`` -- React's explicit escape
    hatch, the only way to inject raw HTML in React;
  * ``element.innerHTML = value`` / ``element.outerHTML = value`` (including the
    ``+=`` compound append);
  * ``document.write(value)`` / ``document.writeln(value)``;
  * ``element.insertAdjacentHTML(position, value)``.

A value is read as STATIC and stays silent only when it is a single- or
double-quoted string with no concatenation, or a template literal with no
``${`` interpolation. A ``const`` bound one hop earlier to such a literal
(``const html = "<b>fixed</b>"; el.innerHTML = html``) is also static -- a
``let``/``var`` is not, because it can be reassigned to a dynamic value. What
the rule cannot see, and names rather than guesses:

  * it does not know whether a dynamic value was sanitized (DOMPurify, a custom
    escape) -- a sanitized variable is still reported, because the provenance of
    the sanitization is not traced;
  * ``textContent``/``innerText`` are NOT sinks (text, not markup) and are
    silent; ``setAttribute("innerHTML", ...)`` is not a sink either;
  * framework template bindings -- Angular ``[innerHTML]``, Vue ``v-html``,
    Svelte ``innerHTML={...}``, jQuery ``.html(...)`` -- are a different spelling
    and outside this rule's claim, which reads the DOM property and the React
    escape hatch;
  * a sink split across lines, or a template literal whose interpolation
    contains another sink, is not reconstructed across the boundary.

Only the code parts of each line are matched: string literals and ``//`` and
``/* */`` comments are skipped, so ``const doc = "dangerouslySetInnerHTML"`` is
documentation, not a decision. No uploaded code is executed.
"""

from __future__ import annotations

import re
import zipfile
from typing import BinaryIO

from app.scan.checks import CheckFinding
from app.scan.rule_coverage import RuleCoverage

RULE_ID = "xss-unsafe-html-injection"
_JS_FILE_SUFFIXES = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")
_MAX_FILE_BYTES = 400_000
_MAX_FILES = 400
_MAX_FINDINGS = 32

# Each entry is (name, sink marker, how the value follows the marker). The value
# is read from the ORIGINAL line after the marker's end, so a string literal on
# the right-hand side is not lost to the code-segment split.
_SINKS = (
    ("dangerously-set-inner-html",
     re.compile(r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:"), "colon"),
    ("inner-outer-html-assignment",
     re.compile(r"\.(?:innerHTML|outerHTML)\s*\+?="), "assign"),
    ("document-write",
     re.compile(r"document\.write(?:ln)?\s*\("), "first_arg"),
    ("insert-adjacent-html",
     re.compile(r"\.insertAdjacentHTML\s*\("), "second_arg"),
)


def _code_segments(text: str) -> list[tuple[int, list[tuple[int, int]]]]:
    """Per line, the (start, end) spans that are code, not string or comment.

    String literals (``'`` ``"`` `` ` `` with backslash escapes), ``//`` line
    comments and ``/* ... */`` block comments (which may span lines) are removed
    so a sink spelled inside any of them is not matched. Only the SINK MARKER is
    matched against these spans; the value is read from the original line.
    """
    result: list[tuple[int, list[tuple[int, int]]]] = []
    in_block_comment = False
    for line_no, line in enumerate(text.splitlines(), start=1):
        segments: list[tuple[int, int]] = []
        seg_start = 0
        i = 0
        n = len(line)
        while i < n:
            if in_block_comment:
                end = line.find("*/", i)
                if end == -1:
                    i = n
                    seg_start = n
                    break
                i = end + 2
                in_block_comment = False
                seg_start = i
                continue
            char = line[i]
            if char in ("'", '"', "`"):
                if seg_start < i:
                    segments.append((seg_start, i))
                quote = char
                i += 1
                while i < n:
                    if line[i] == "\\":
                        i += 2
                        continue
                    if line[i] == quote:
                        i += 1
                        break
                    i += 1
                seg_start = i
                continue
            if char == "/" and i + 1 < n:
                if line[i + 1] == "/":
                    if seg_start < i:
                        segments.append((seg_start, i))
                    seg_start = n
                    i = n
                    break
                if line[i + 1] == "*":
                    if seg_start < i:
                        segments.append((seg_start, i))
                    end = line.find("*/", i + 2)
                    if end == -1:
                        in_block_comment = True
                        seg_start = n
                        i = n
                        break
                    i = end + 2
                    seg_start = i
                    continue
            i += 1
        if seg_start < n:
            segments.append((seg_start, n))
        result.append((line_no, segments))
    return result


def _is_static_literal(value: str) -> bool:
    """A value stays silent only as a plain '...' or "..." string, or a
    template literal with no interpolation.

    A single/double-quoted string is static unless a ``+`` concatenates it; a
    template literal (`` ` ``) is static only without ``${`` -- an interpolation
    makes it dynamic by construction.
    """
    value = value.strip()
    if not value:
        return False
    if value[0] in ("'", '"'):
        return "+" not in value
    if value[0] == "`":
        return "${" not in value
    return False


# A `const name = "<literal>"` (or a template without an interpolation) that a
# sink may reference one hop later. Only `const` is bound, and only the
# whole-literal form: `let`/`var` may be reassigned to a dynamic value, and a
# concatenation or a call is never static -- the binding is a convenience for
# the honest static case (a theme script, a fixed template), never a claim that
# a name is safe.
_STATIC_ASSIGN = re.compile(
    r"const\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*"
    r"(?P<value>[\"'][^\"']*[\"']|`[^`$]*`)"
)


def _static_bindings(text: str) -> dict[str, str]:
    return {match.group("name"): match.group("value") for match in _STATIC_ASSIGN.finditer(text)}


def _value_after(line: str, pos: int, kind: str) -> str:
    """The value expression following a sink marker, from the original line."""
    tail = line[pos:].lstrip()
    if kind == "assign":
        return tail.split(";", 1)[0].strip()
    if kind == "colon":
        end = min((idx for ch in "}," if (idx := tail.find(ch)) != -1), default=len(tail))
        return tail[:end].strip()
    if kind == "first_arg":
        end = min((idx for ch in ",)" if (idx := tail.find(ch)) != -1), default=len(tail))
        return tail[:end].strip()
    if kind == "second_arg":
        comma = tail.find(",")
        if comma == -1:
            return ""
        rest = tail[comma + 1:].lstrip()
        end = rest.find(")") if ")" in rest else len(rest)
        return rest[:end].strip()
    return ""


def scan_xss(fileobj: BinaryIO, *, coverage: dict | None = None) -> list[CheckFinding]:
    findings: list[CheckFinding] = []
    with zipfile.ZipFile(fileobj) as archive:
        accounting = RuleCoverage(archive, extensions=_JS_FILE_SUFFIXES,
                                  max_file_bytes=_MAX_FILE_BYTES, coverage=coverage)
        for info in accounting.files(findings, max_files=_MAX_FILES, max_findings=_MAX_FINDINGS):
            raw = archive.read(info)
            if not any(marker in raw for marker in
                       (b"innerHTML", b"outerHTML", b"document.write", b"dangerouslySetInnerHTML",
                        b"insertAdjacentHTML")):
                accounting.analyzed()
                continue
            try:
                text = raw.decode("utf-8")
            except UnicodeError:
                accounting.skip("decode_error")
                continue
            lines = text.splitlines()
            bindings = _static_bindings(text)
            for line_no, segments in _code_segments(text):
                line = lines[line_no - 1]
                for start, end in segments:
                    segment = line[start:end]
                    for name, pattern, kind in _SINKS:
                        for match in pattern.finditer(segment):
                            if len(findings) >= _MAX_FINDINGS:
                                accounting.skip("finding_limit")
                                accounting.finish()
                                return findings
                            value = _value_after(line, start + match.end(), kind)
                            if not value:
                                continue
                            if _is_static_literal(value):
                                continue
                            if value in bindings and _is_static_literal(bindings[value]):
                                continue
                            findings.append(_finding(info.filename, line_no, name))
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
            "Use textContent (or React's normal children / setText) for anything that is text, not "
            "markup. If you must insert HTML, sanitize the value first (DOMPurify with an allowlist, "
            "or an equivalent) and prefer a template or component that never builds HTML by string. "
            "For React, avoid dangerouslySetInnerHTML unless the content is already trusted."
        ),
    )


def _describe(sink: str) -> str:
    return {
        "dangerously-set-inner-html": "dangerouslySetInnerHTML",
        "inner-outer-html-assignment": "innerHTML/outerHTML",
        "document-write": "document.write",
        "insert-adjacent-html": "insertAdjacentHTML",
    }.get(sink, sink)

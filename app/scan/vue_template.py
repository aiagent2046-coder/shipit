"""Bounded, non-executing Vue SFC extraction for the HTML-injection check.

This is deliberately a limited HTML-template reader, not a Vue compiler. Only
quoted/unquoted attributes of real template tags are examined. Raw blocks,
comments, interpolated text and v-pre subtrees cannot manufacture directives.
Unsupported preprocessors and malformed structure fail coverage explicitly.
"""
from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass
from html import unescape
import re

_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]*")
_ATTR = re.compile(r"[^\s=<>/'\"]+")
_UNQUOTED = re.compile(r"[^\s\"'`=<>]+")
_VOID = frozenset("area base br col embed hr img input link meta param source track wbr".split())


class VueParseError(ValueError):
    pass


@dataclass(frozen=True)
class VueExpression:
    value: str
    line: int


@dataclass(frozen=True)
class VueScript:
    value: str
    line: int
    tsx: bool


def extract_vue(source: str, *, max_nodes: int, max_depth: int):
    """Return v-html expressions and script bodies; never execute source."""
    expressions, scripts = [], []
    stack: list[tuple[str, bool]] = []
    pos, tokens, templates, script_kinds = 0, 0, 0, set()
    size = len(source)
    newlines = [i for i, char in enumerate(source) if char == "\n"]

    def line_at(offset):
        return bisect_right(newlines, offset - 1) + 1

    def tick():
        nonlocal tokens
        tokens += 1
        if tokens > max_nodes or len(stack) > max_depth:
            raise VueParseError("ast_limit")

    def tag(start):
        """Read one tag with bounded, quote-aware attribute tokenization."""
        closing = source.startswith("</", start)
        i = start + (2 if closing else 1)
        name_match = _NAME.match(source, i)
        if not name_match:
            raise VueParseError("parse_error")
        name, i = name_match.group(), name_match.end()
        attrs = {}
        self_closing = False
        while i < size:
            tick()
            before_space = i
            while i < size and source[i].isspace():
                i += 1
            if source.startswith("/>", i):
                self_closing, i = True, i + 2
                break
            if i < size and source[i] == ">":
                i += 1
                break
            if closing or i == before_space:
                raise VueParseError("parse_error")
            attr = _ATTR.match(source, i)
            if not attr:
                raise VueParseError("parse_error")
            key, at, i = attr.group(), i, attr.end()
            if key in attrs:
                raise VueParseError("parse_error")
            while i < size and source[i].isspace():
                i += 1
            value = None
            after_name = attr.end()
            if i < size and source[i] == "=":
                i += 1
                while i < size and source[i].isspace():
                    i += 1
                if i >= size:
                    raise VueParseError("parse_error")
                if source[i] in "\"'":
                    quote, i = source[i], i + 1
                    end = source.find(quote, i)
                    if end < 0:
                        raise VueParseError("parse_error")
                    value, i = source[i:end], end + 1
                else:
                    match = _UNQUOTED.match(source, i)
                    if not match:
                        raise VueParseError("parse_error")
                    value, i = match.group(), match.end()
            else:
                i = after_name
            attrs[key] = (unescape(value) if value is not None else None, at)
        else:
            raise VueParseError("parse_error")
        if closing and self_closing:
            raise VueParseError("parse_error")
        return name, attrs, closing, self_closing, i

    while pos < size:
        tick()
        if source.startswith("<!--", pos):
            end = source.find("-->", pos + 4)
            if end < 0:
                raise VueParseError("parse_error")
            pos = end + 3
            continue
        if stack and not stack[-1][1] and source.startswith("{{", pos):
            # Vue text interpolation is not markup. Skip it even when a quoted
            # example contains an apparent v-html tag.
            end = source.find("}}", pos + 2)
            if end < 0:
                raise VueParseError("parse_error")
            pos = end + 2
            continue
        if source[pos] != "<":
            if not stack and not source[pos].isspace():
                raise VueParseError("parse_error")
            # Advance to a structural delimiter rather than ticking per byte.
            following = [x for x in (source.find("<", pos + 1),
                                     source.find("{{", pos + 1)) if x >= 0]
            end = min(following) if following else size
            if not stack and source[pos:end].strip():
                raise VueParseError("parse_error")
            pos = end
            continue
        name, attrs, closing, self_closing, end = tag(pos)
        if closing:
            if not stack or stack[-1][0] != name:
                raise VueParseError("parse_error")
            stack.pop()
            pos = end
            continue
        root_block = not stack
        if root_block:
            if name == "template":
                templates += 1
                if templates > 1:
                    raise VueParseError("parse_error")
                if "src" in attrs or attrs.get("lang", ("html",))[0] != "html":
                    raise VueParseError("unsupported_vue_template")
            else:
                # Vue SFC top-level non-template blocks are raw text. Never
                # interpret examples in JavaScript, CSS or custom blocks as HTML.
                if self_closing:
                    body_end, block_end = end, end
                else:
                    match = re.search(r"</" + re.escape(name) + r"\s*>", source[end:])
                    if not match:
                        raise VueParseError("parse_error")
                    body_end, block_end = end + match.start(), end + match.end()
                if name == "script":
                    lang = attrs.get("lang", ("js",))[0]
                    if "src" in attrs or lang not in {"js", "ts", "jsx", "tsx", "javascript", "typescript"}:
                        raise VueParseError("unsupported_vue_script")
                    kind = "setup" in attrs
                    if kind in script_kinds:
                        raise VueParseError("parse_error")
                    script_kinds.add(kind)
                    scripts.append(VueScript(source[end:body_end], line_at(end),
                                             lang in {"jsx", "tsx"}))
                pos = block_end
                continue
        pre = (stack[-1][1] if stack else False) or (not root_block and "v-pre" in attrs)
        html_attrs = [key for key in attrs if key == "v-html" or key.startswith(("v-html.", "v-html:"))]
        if len(html_attrs) > 1:
            raise VueParseError("parse_error")
        if not root_block and not pre and html_attrs:
            value, at = attrs[html_attrs[0]]
            if value is None or not value.strip():
                raise VueParseError("parse_error")
            expressions.append(VueExpression(value, line_at(at)))
        if name in {"script", "style", "textarea", "title"} and stack and not self_closing:
            match = re.search(r"</" + name + r"\s*>", source[end:])
            if not match:
                raise VueParseError("parse_error")
            pos = end + match.end()
            continue
        if not self_closing and name not in _VOID:
            stack.append((name, pre))
            if len(stack) > max_depth:
                raise VueParseError("ast_limit")
        pos = end
    if stack:
        raise VueParseError("parse_error")
    return expressions, scripts, tokens

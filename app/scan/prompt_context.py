"""Conservative source excerpts. Parse source as data; never import or execute it.

An excerpt is not a complete module. Definitions retained here are complete,
but dynamic dispatch and cross-module name resolution remain unverified.
"""
from __future__ import annotations

import ast
import io
from pathlib import PurePosixPath
import posixpath
import re
import tokenize
from typing import Iterable

from app.scan.secrets import is_non_production_path


MAX_EXCERPT_SOURCE_CHARS = 2_000_000
OMITTED_MARKER = "[... omitted original lines {start}-{end}; omitted code may contain guards or dependencies ...]"
EXCERPT_NOTICE = (
    "[Partial source excerpt: original line numbers are preserved. Never infer "
    "that a guard or dependency is absent from omitted code.]"
)


class PromptExcerpt(str):
    """Selected original lines plus their source coordinates, not renumbered code."""

    line_numbers: tuple[int, ...]
    omitted_ranges: tuple[tuple[int, int], ...]

    def __new__(cls, content: str, line_numbers: tuple[int, ...],
                omitted_ranges: tuple[tuple[int, int], ...]):
        result = super().__new__(cls, content)
        result.line_numbers = line_numbers
        result.omitted_ranges = omitted_ranges
        return result


def numbered_lines(text: str) -> str:
    """Render gutters only for actual source; omission notices are never source."""
    if not isinstance(text, PromptExcerpt):
        return "\n".join(f"{number}\t{line}" for number, line in enumerate(text.splitlines(), 1))
    rows = [(number, f"{number}\t{line}")
            for number, line in zip(text.line_numbers, text.splitlines(), strict=True)]
    rows.extend((start, OMITTED_MARKER.format(start=start, end=end))
                for start, end in text.omitted_ranges)
    return EXCERPT_NOTICE + "\n" + "\n".join(row for _, row in sorted(rows))


def _start(node: ast.AST) -> int:
    return min([node.lineno, *(decorator.lineno for decorator in getattr(node, "decorator_list", []))])


def _code_tokens(lines: list[str], node: ast.AST) -> str:
    """Ignore comments and docstrings, retaining executable literals such as SQL."""
    ignored: set[int] = set()
    for child in ast.walk(node):
        body = getattr(child, "body", None)
        if isinstance(body, list) and body and isinstance(body[0], ast.Expr):
            value = body[0].value
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                ignored.update(range(body[0].lineno, body[0].end_lineno + 1))
    start, end = _start(node), node.end_lineno
    fragment = "\n".join(lines[start - 1:end])
    tokens = tokenize.generate_tokens(io.StringIO(fragment).readline)
    return " ".join(token.string for token in tokens
                    if token.type not in {tokenize.COMMENT, tokenize.ENCODING}
                    and token.start[0] + start - 1 not in ignored)


def python_excerpt(path: str, text: str, keywords: re.Pattern[str],
                   limit: int) -> PromptExcerpt | None:
    """Keep complete relevant top-level definitions and their local name closure.

    All other module statements (imports, assignments, configuration guards,
    decorators' containing definitions when referenced, dispatch statements)
    are preserved. Name references are deliberately conservative: all matching
    definitions are retained, even when a local name might shadow them.
    Unsupported, ambiguous-to-parse or over-budget source falls back to None.
    """
    if not path.endswith(".py") or len(text) <= limit or len(text) > MAX_EXCERPT_SOURCE_CHARS or limit <= 0:
        return None
    try:
        tree = ast.parse(text)
        lines = text.splitlines()
        definitions = {index: node for index, node in enumerate(tree.body)
                       if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
        selected = set(range(len(tree.body))) - set(definitions)
        relevant = {index for index, node in definitions.items()
                    if keywords.search(_code_tokens(lines, node))}
        if not relevant:
            return None
        selected.update(relevant)
        while True:
            names = {node.id for index in selected for node in ast.walk(tree.body[index])
                     if isinstance(node, ast.Name)}
            # Decorators, defaults, annotation expressions and nested bodies
            # all contribute names. Never assume that a same-name candidate
            # cannot be called merely because another definition comes later.
            closure = {index for index, node in definitions.items() if node.name in names}
            if closure <= selected:
                break
            selected.update(closure)
    except (SyntaxError, ValueError, RecursionError, tokenize.TokenError, IndentationError):
        return None
    lines = text.splitlines()
    retained = {number for index in selected
                for number in range(_start(tree.body[index]), tree.body[index].end_lineno + 1)}
    if not retained or len(retained) == len(lines):
        return None
    # Preserve blank separators without inflating omissions into dozens of
    # meaningless whitespace notices. Source comments remain explicitly omitted.
    retained.update(number for number, line in enumerate(lines, 1) if not line.strip())
    omitted: list[tuple[int, int]] = []
    for number in range(1, len(lines) + 1):
        if number in retained:
            continue
        if omitted and omitted[-1][1] == number - 1:
            omitted[-1] = (omitted[-1][0], number)
        else:
            omitted.append((number, number))
    if not omitted:
        return None
    numbers = tuple(sorted(retained))
    # splitlines() discards a final empty row; the terminating newline keeps
    # one selected trailing blank line aligned with its source coordinate.
    content = "\n".join(lines[number - 1] for number in numbers) + "\n"
    if len(content) > limit:
        return None
    return PromptExcerpt(content, numbers, tuple(omitted))


def _module_stem(path: str) -> str:
    name = PurePosixPath(path).name
    for suffix in (".tsx", ".jsx", ".py", ".ts", ".js", ".mjs", ".cjs"):
        if name.endswith(suffix):
            return name[:-len(suffix)]
    return ""


def related_test(path: str, production_paths: Iterable[str], text: str = "") -> bool:
    """Exact module-name or static-import evidence, never rubric keyword overlap."""
    if not is_non_production_path(path):
        return False
    sources = {p for p in production_paths if not is_non_production_path(p)}
    stems = {_module_stem(p) for p in sources} - {"", "index", "__init__", "main"}
    stem = _module_stem(path)
    normalized = re.sub(r"^(?:test_|spec_)", "", stem)
    normalized = re.sub(r"(?:_test|_spec|\.test|\.spec)$", "", normalized)
    if normalized != stem and normalized in stems:
        return True
    if not text:
        return False
    references: set[str] = set()
    modules = {str(PurePosixPath(p).with_suffix("")) for p in sources}
    if path.endswith(".py"):
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError, RecursionError):
            return False
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                references.update(alias.name.replace(".", "/") for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                module = (node.module or "").replace(".", "/")
                if node.level:
                    parent = str(PurePosixPath(path).parent)
                    for _ in range(node.level - 1):
                        parent = str(PurePosixPath(parent).parent)
                    module = posixpath.normpath(posixpath.join(parent, module))
                if module:
                    references.add(module)
                    references.update(module + "/" + alias.name for alias in node.names)
    else:
        # Anchored import statements only; do not match arbitrary quoted text
        # or require() spellings embedded in comments or string literals.
        for match in re.finditer(r"(?m)^\s*import\s+(?:[^\n;]*?\s+from\s+)?['\"]([^'\"\n]+)['\"]", text):
            reference = match.group(1)
            if not reference.startswith("."):
                continue
            module = posixpath.normpath(posixpath.join(str(PurePosixPath(path).parent), reference))
            references.add(str(PurePosixPath(module).with_suffix("")) if _module_stem(module) else module)
    return any(source == reference or source.endswith("/" + reference)
               for source in modules for reference in references if reference)

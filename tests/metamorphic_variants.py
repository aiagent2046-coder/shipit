"""Metamorphic variants of corpus sources: deterministic, no model.

The relation every transform encodes: an edit that cannot change what the
code IS must not change what the audit SAYS. This is the deterministic
replacement for the LLM escape hunt (scripts/hunt_detector_escapes.py) --
the classes the hunt found are pinned here as generators, so they keep
firing on every rule instead of once per hunt round.

Design rules, each learned from the hunt or measured by this generator:

- a variant that no longer parses is DISCARDED before scanning and reported
  as `unparseable` -- a broken rewrite is a broken probe, never an escape;
- renames touch only identifier spans the parser found (Python) or names
  proven not to be property keys/attributes (JS) -- renaming inside a
  string or a property key changes what the code IS;
- there is deliberately NO key_case transform for JS option objects.
  MEASURED: all 7 incidents it produced were the scanner being RIGHT on a
  changed program. JavaScript option names are case-sensitive -- Express
  silently ignores `{ HttpOnly: true }` and leaves the cookie readable by
  scripts (a real defect), and express-session ignores `{ HttpOnly: false }`
  and keeps its safe default. Renaming an option key is a predicted-change
  edit, not an invariant one. (Header spellings like `Set-Cookie: ...
  HttpOnly` ARE case-variant vocabulary and are pinned by the corpus.)
- new names are neutral (`holder_*`): a rename that introduces a
  credential word changes the verdict for a correct reason (see
  test_renaming_a_local_variable_changes_nothing).

Invariant kind only. Predicted-change transforms (literal -> unresolvable
name must SILENCE the cookie rule) already live in the golden corpus as
negative cases; this module generates the other half: everything that must
NOT change the verdict.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Any, Callable

import tree_sitter_typescript
from tree_sitter import Language, Parser

# The same grammar the JS/TS scanners parse with (app/scan/cookie_flags_js.py).
_JS_PARSERS = (
    Parser(Language(tree_sitter_typescript.language_typescript())),
    Parser(Language(tree_sitter_typescript.language_tsx())),
)


# --------------------------------------------------------------------------
# language dispatch
# --------------------------------------------------------------------------

LANGS_BY_SUFFIX = {
    ".py": "python",
    ".js": "js",
    ".jsx": "js",
    ".mjs": "js",
    ".cjs": "js",
    ".ts": "js",
    ".tsx": "js",
}


def language_of(path: str) -> str | None:
    for suffix, lang in LANGS_BY_SUFFIX.items():
        if path.endswith(suffix):
            return lang
    return None


# --------------------------------------------------------------------------
# edit plumbing (offsets from the AST, never string guessing)
# --------------------------------------------------------------------------


def _line_starts(text: str) -> list[int]:
    starts = [0]
    for line in text.splitlines(keepends=True):
        starts.append(starts[-1] + len(line))
    return starts


def _span(starts: list[int], node: Any) -> tuple[int, int]:
    return (
        starts[node.lineno - 1] + node.col_offset,
        starts[node.end_lineno - 1] + node.end_col_offset,
    )


def _apply_edits(text: str, edits: list[tuple[int, int, str]]) -> str:
    out = text
    for start, end, repl in sorted(edits, key=lambda e: (e[0], e[1]), reverse=True):
        out = out[:start] + repl + out[end:]
    return out


def _py_parse(text: str) -> ast.Module | None:
    try:
        return ast.parse(text)
    except SyntaxError:
        return None


def _js_parses(text: str) -> bool:
    raw = text.encode()
    # JSX lives in .js/.jsx/.tsx alike, and the scanners pick the grammar the
    # same way: accept a variant if EITHER grammar parses it clean.
    return any(not p.parse(raw).root_node.has_error for p in _JS_PARSERS)


def _indent_of(line: str) -> str:
    return line[: len(line) - len(line.lstrip())]


def _hoistable_literal(node: Any, text: str, starts: list[int]) -> bool:
    """A name/key-shaped literal we can move verbatim: one line, identifier-ish.

    Paths and URLs are deliberately excluded: a route literal is vocabulary
    the route readers consume (auth_read), and hoisting it into a variable
    changes what the code SAYS to them -- the cookie rule documents exactly
    this boundary ("the value is a name, not a literal ... it does not
    guess"), so a hoisted path would be a predicted change, not an escape.
    """
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and re.fullmatch(r"[A-Za-z0-9_.\-]{4,}", node.value) is not None
        and node.end_lineno == node.lineno
        and text[_span(starts, node)[0]] in "\"'"
    )


def _enclosing_stmt(tree: ast.Module, target: Any) -> ast.stmt | None:
    lo, hi = target.lineno, target.end_lineno
    containing = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.stmt)
        and node.lineno <= lo
        and node.end_lineno is not None
        and node.end_lineno >= hi
    ]
    if not containing:
        return None
    return min(
        containing,
        key=lambda s: ((s.end_lineno or s.lineno) - s.lineno, s.col_offset),
    )


# --------------------------------------------------------------------------
# Python transforms
# --------------------------------------------------------------------------


def py_local_const(text: str) -> str | None:
    """Move one call's string literal into a local above its statement.

    The hunt's first-round escape class: the cookie NAME held in a local
    const escaped 8/8 rewrites until the scanner learned to read bindings.
    """
    tree = _py_parse(text)
    if tree is None:
        return None
    starts = _line_starts(text)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for part in [*node.args, *(k.value for k in node.keywords)]:
            if _hoistable_literal(part, text, starts):
                stmt = _enclosing_stmt(tree, part)
                if stmt is None:
                    continue  # a decorator literal is no hoist candidate
                line = text.splitlines()[stmt.lineno - 1]
                lit = text[_slice(starts, part)]
                s, _ = _span(starts, part)
                line_start = starts[stmt.lineno - 1]
                return _apply_edits(text, [
                    (line_start, line_start, f"{_indent_of(line)}holder_a = {lit}\n"),
                    (s, s + len(lit), "holder_a"),
                ])
    return None


def _slice(starts: list[int], node: Any) -> slice:
    s, e = _span(starts, node)
    return slice(s, e)


def py_concat_split(text: str) -> str | None:
    """Split a literal into two concatenated halves: "abcdef" -> "abc" + "def"."""
    tree = _py_parse(text)
    if tree is None:
        return None
    starts = _line_starts(text)
    for node in ast.walk(tree):
        if not _hoistable_literal(node, text, starts):
            continue
        s, e = _span(starts, node)
        token = text[s:e]
        quote, inner = token[0], token[1:-1]
        if len(inner) < 6 or quote in inner or "\\" in inner or "\n" in inner:
            continue
        cut = len(inner) // 2
        repl = f"{quote}{inner[:cut]}{quote} + {quote}{inner[cut:]}{quote}"
        return _apply_edits(text, [(s, e, repl)])
    return None


def py_block_nest(text: str) -> str | None:
    """Wrap the first call-bearing single-line statement in `if True:`."""
    tree = _py_parse(text)
    if tree is None:
        return None
    starts = _line_starts(text)
    for node in ast.walk(tree):
        if not isinstance(node, ast.stmt) or node.lineno != node.end_lineno:
            continue
        if not any(isinstance(child, ast.Call) for child in ast.walk(node)):
            continue
        s, e = _span(starts, node)
        inner = text[s:e]
        line = text.splitlines()[node.lineno - 1]
        indent = _indent_of(line)
        repl = f"if True:\n{indent}    {inner}"
        return _apply_edits(text, [(s, e, repl)])
    return None


def py_rename_locals(text: str) -> str | None:
    """Rename parameters and assigned locals to neutral names.

    Name spans come from the AST, so strings and attribute names are never
    touched. A name used as an attribute is left alone entirely. MODULE-level
    bindings are excluded: a module constant (a Django setting, a router) is
    API vocabulary other readers consume, and renaming it changes what the
    code IS. The claim is only about function-local names and parameters.
    """
    tree = _py_parse(text)
    if tree is None:
        return None
    starts = _line_starts(text)
    attributes = {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    in_function: set[int] = set()
    for owner in ast.walk(tree):
        if isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            for node in ast.walk(owner):
                in_function.add(id(node))
    candidates: list[str] = []
    for node in ast.walk(tree):
        name = None
        if isinstance(node, ast.arg):
            name = node.arg
        elif (
            isinstance(node, ast.Name)
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and id(node) in in_function
        ):
            name = node.id
        if name and name not in attributes and name not in candidates:
            candidates.append(name)
    renames = {old: f"holder_{i + 1}" for i, old in enumerate(candidates[:6])}
    if not renames:
        return None
    edits: list[tuple[int, int, str]] = []
    for node in ast.walk(tree):
        span: tuple[int, int] | None = None
        if isinstance(node, ast.Name) and node.id in renames:
            span = _span(starts, node)
        elif isinstance(node, ast.arg) and node.arg in renames:
            # An annotated arg's node span covers `path: str`, not `path` --
            # the name alone is the edit. (The first draft compared the whole
            # span to the rename map, skipped every annotated parameter and
            # produced variants calling undefined names.)
            start, _ = _span(starts, node)
            span = (start, start + len(node.arg))
        if span is None:
            continue
        s, e = span
        old = text[s:e]
        if old in renames:
            edits.append((s, e, renames[old]))
    return _apply_edits(text, edits) if edits else None


def py_dead_branch(text: str) -> str | None:
    """Insert an unreachable decoy block after imports (or the docstring)."""
    tree = _py_parse(text)
    if tree is None:
        return None
    starts = _line_starts(text)
    insert_line = 0
    body = list(tree.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(
        body[0].value, ast.Constant
    ):
        insert_line = body[0].end_lineno or body[0].lineno
    for node in body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            insert_line = max(insert_line, node.end_lineno or node.lineno)
    pos = starts[insert_line]
    return _apply_edits(text, [(pos, pos, 'if False:\n    holder_z = "decoy"\n\n')])


def py_comment_shift(text: str) -> str | None:
    """Prepend a comment: a comment cannot change what code is."""
    return "# reviewed\n\n" + text


# --------------------------------------------------------------------------
# JS/TS transforms (line-oriented; every result is parse-verified)
# --------------------------------------------------------------------------

_JS_LITERAL = re.compile(r"\"(?:[^\"\\\n]|\\.){4,}\"|'(?:[^'\\\n]|\\.){4,}'")
_JS_BINDING = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)")
_JS_FUNC_PARAMS = re.compile(r"function\s*[A-Za-z_$]*\s*\(([^)]*)\)")
_JS_ARROW_PARAMS = re.compile(r"(?:\(|([A-Za-z_$][\w$]*))\s*=>")
_JS_STRINGS_COMMENTS = re.compile(
    r"\"(?:[^\"\\\n]|\\.)*\"|'(?:[^'\\\n]|\\.)*'|`(?:[^`\\]|\\.)*`"
    r"|//[^\n]*|/\*.*?\*/",
    re.S,
)


def _mask_js_literals_and_comments(text: str) -> str:
    """Blank strings and comments with spaces, preserving every offset.

    Matches found in the MASKED text are guaranteed to be code: anything
    inside a literal or a comment has been blanked away.
    """
    return _JS_STRINGS_COMMENTS.sub(
        lambda m: " " * (m.end() - m.start()), text
    )

def js_local_const(text: str) -> str | None:
    """Hoist one call-site literal into a local const above its line."""
    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith(("import", "export", "//", "*", "/*")):
            continue
        for match in _JS_LITERAL.finditer(line):
            before, after = line[: match.start()], line[match.end():]
            if before.rstrip().endswith(":") or after.lstrip().startswith(":"):
                continue  # property key, not a value
            lit = match.group(0)
            if "/" in lit:
                continue  # a path literal is route vocabulary, not a value
            indent = _indent_of(line)
            lines[index] = (
                before + "holder_a" + after
            )
            lines.insert(index, f"{indent}const holder_a = {lit};\n")
            return "".join(lines)
    return None


def js_numeric_bool(text: str) -> str | None:
    """`httpOnly: false` -> `httpOnly: 0`: the number 0 is a false."""
    out, count = re.subn(r"(:\s*)false\b", r"\g<1>0", text, count=1)
    return out if count else None


def js_rename_locals(text: str) -> str | None:
    """Rename simple bindings and parameters to neutral names.

    A name used as a property key or after a dot is left alone: renaming
    those changes what the code is. String literals and comments are masked
    before matching, so a module name inside `require("express")` is never
    touched -- the first draft renamed it and produced garbage escapes.
    """
    masked = _mask_js_literals_and_comments(text)
    candidates: list[str] = []
    for pattern in (_JS_BINDING,):
        for match in pattern.finditer(masked):
            if match.group(1) not in candidates:
                candidates.append(match.group(1))
    for pattern in (_JS_FUNC_PARAMS,):
        for match in pattern.finditer(masked):
            for part in match.group(1).split(","):
                name = part.strip()
                if re.fullmatch(r"[A-Za-z_$][\w$]*", name) and name not in candidates:
                    candidates.append(name)
    renames = {}
    for name in candidates:
        if re.search(rf"\.{name}\b", masked) or re.search(
            rf"(?<![\w$]){name}\s*:", masked
        ):
            continue
        renames[name] = f"holder_{len(renames) + 1}"
        if len(renames) >= 6:
            break
    if not renames:
        return None
    out = text
    ordered = sorted(renames, key=len, reverse=True)
    names_pattern = re.compile(
        r"(?<![\w$.])(" + "|".join(map(re.escape, ordered)) + r")(?![\w$])"
    )
    edits = [
        (m.start(), m.end(), renames[m.group(1)])
        for m in names_pattern.finditer(masked)
    ]
    return _apply_edits(out, edits) if edits else None


def js_block_nest(text: str) -> str | None:
    """Wrap the first brace-free statement line in `if (true) { ... }`."""
    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped.endswith(";") or "{" in stripped or "}" in stripped:
            continue
        if stripped.startswith(("import", "export", "//", "/*", "*")):
            continue
        if stripped.startswith(("const ", "let ")):
            # `const`/`let` are BLOCK-scoped in JavaScript: wrapping the
            # declaration while the uses stay outside breaks the program
            # (ReferenceError at run time). MEASURED: this produced garbage
            # escapes on exactly those cases. `var` is function-scoped and
            # safe to wrap, so only const/let declarations are skipped.
            continue
        indent = _indent_of(line)
        lines[index] = (
            f"{indent}if (true) {{\n{indent}    {stripped}\n{indent}}}\n"
        )
        return "".join(lines)
    return None


def js_dead_branch(text: str) -> str | None:
    """Insert an unreachable decoy statement at the top."""
    return 'if (false) { const holder_z = "decoy"; }\n' + text


def js_comment_shift(text: str) -> str | None:
    """Prepend a comment: a comment cannot change what code is."""
    return "// reviewed\n\n" + text


# --------------------------------------------------------------------------
# registry + case application
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Transform:
    id: str
    lang: str
    fn: Callable[[str], str | None]
    note: str = ""


TRANSFORMS: tuple[Transform, ...] = (
    Transform("local_const", "python", py_local_const, "literal -> local (hunt r1)"),
    Transform("concat_split", "python", py_concat_split),
    Transform("block_nest", "python", py_block_nest),
    Transform("rename_locals", "python", py_rename_locals, "hunt r1 receiver names"),
    Transform("dead_branch", "python", py_dead_branch),
    Transform("comment_shift", "python", py_comment_shift),
    Transform("local_const", "js", js_local_const, "literal -> local (hunt r1)"),
    Transform("numeric_bool", "js", js_numeric_bool, "httpOnly: 0 (hunt r3)"),
    Transform("rename_locals", "js", js_rename_locals, "res -> outgoingRes (hunt r1)"),
    Transform("block_nest", "js", js_block_nest),
    Transform("dead_branch", "js", js_dead_branch),
    Transform("comment_shift", "js", js_comment_shift),
)


@dataclass
class VariantResult:
    status: str  # "applied" | "not-applicable" | "unparseable"
    entries: dict[str, str] = field(default_factory=dict)
    changed_files: list[str] = field(default_factory=list)


def variant_entries(
    entries: dict[str, str], transform: Transform
) -> VariantResult:
    """Apply one transform to every file of its language in a case.

    The transform runs per file and must change exactly the files it applies
    to; a file whose variant stops parsing aborts the whole variant.
    """
    out = dict(entries)
    changed: list[str] = []
    for path, body in entries.items():
        if language_of(path) != transform.lang:
            continue
        rewritten = transform.fn(body)
        if rewritten is None or rewritten == body:
            continue
        if transform.lang == "python":
            ok = _py_parse(rewritten) is not None
        else:
            ok = _js_parses(rewritten)
        if not ok:
            return VariantResult("unparseable", changed_files=[path])
        out[path] = rewritten
        changed.append(path)
    if not changed:
        return VariantResult("not-applicable")
    return VariantResult("applied", entries=out, changed_files=changed)

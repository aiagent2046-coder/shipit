"""Mechanical CORS / SQLi rewrites for Fix Pack plans.

Complements secret scrubbing: source-preserving transforms over repo-relative
file bodies. Callers run ``_validate_syntax`` before accepting a rewrite
into ``plan.files``.

CORS: lockdown of allow-any-origin + credentials shapes (FastAPI, Express,
Flask, raw headers).

SQLi: only single-call sites where a dynamic SQL string is passed straight
into ``execute`` / ``query`` — rewritten to a parameterized form. Anything
that needs multi-statement understanding is left alone.
"""

from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass

import tree_sitter_javascript
import tree_sitter_typescript
from tree_sitter import Language, Parser


@dataclass(frozen=True)
class StaticFix:
    rule_id: str
    title: str
    file: str
    detail: str


# These placeholders require customer configuration before the PR is merged.
# Keep that consequence explicit in every reported fix.
_CORS_DETAILS = {
    "fastapi": (
        'replaced FastAPI allow_origins=["*"] with the placeholder '
        "http://localhost:3000 — set your real origin before merging"
    ),
    "express": (
        "replaced Express wildcard origin with process.env.CORS_ORIGIN "
        "(falls back to http://localhost:3000 — set CORS_ORIGIN)"
    ),
    "flask": (
        "replaced Flask CORS origins='*' with the placeholder "
        "http://localhost:3000 — set your real origin before merging"
    ),
    "header": (
        "replaced Access-Control-Allow-Origin * with the placeholder "
        "http://localhost:3000 — set your real origin before merging"
    ),
}
_SAFE_ORIGIN = "http://localhost:3000"
_ORIGIN_HEADER = "access-control-allow-origin"
_CRED_HEADER = "access-control-allow-credentials"
# Each edit targets a value node; its byte coordinates come from a parser.
_CorsEdit = tuple[int, int, str, str]


def apply_cors_fixes(files: dict[str, str]) -> tuple[dict[str, str], list[StaticFix]]:
    """Return {path: new_text} and fix records for files that changed."""
    updates: dict[str, str] = {}
    fixes: list[StaticFix] = []
    for path, text in files.items():
        if _skip_path(path):
            continue
        new_text, detail = _fix_cors_in_text(path, text)
        if new_text is not None and new_text != text:
            updates[path] = new_text
            fixes.append(StaticFix(
                rule_id="cors-open-credentials",
                title="Overly permissive CORS with credentials",
                file=path,
                detail=detail,
            ))
    return updates, fixes


def _python_cors_edits(text: str) -> list[_CorsEdit]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return []
    data = text.encode("utf-8")
    line_offsets = [0] + [match.end() for match in re.finditer(rb"\r\n|\r|\n", data)]
    edits: list[_CorsEdit] = []

    def replace(node: ast.AST, value: str, kind: str) -> None:
        edits.append((line_offsets[node.lineno - 1] + node.col_offset,
                      line_offsets[node.end_lineno - 1] + node.end_col_offset,
                      value, kind))

    def literal(node: ast.AST | None, value: object) -> bool:
        return isinstance(node, ast.Constant) and type(node.value) is type(value) and node.value == value

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            # Pair options within one call, never with text in another call,
            # a docstring, a comment, or a nested string example.
            options = {kw.arg: kw.value for kw in node.keywords if kw.arg}
            origins = options.get("allow_origins")
            if (literal(options.get("allow_credentials"), True)
                    and isinstance(origins, ast.List) and len(origins.elts) == 1
                    and literal(origins.elts[0], "*")):
                replace(origins, f'["{_SAFE_ORIGIN}"]', "fastapi")
            origins = options.get("origins")
            if literal(options.get("supports_credentials"), True) and literal(origins, "*"):
                replace(origins, f'"{_SAFE_ORIGIN}"', "flask")
        elif isinstance(node, ast.Dict):
            if any(key is None for key in node.keys):
                continue  # Unpacked values may override the apparent headers.
            options = {key.value.lower(): value for key, value in zip(node.keys, node.values)
                       if isinstance(key, ast.Constant) and isinstance(key.value, str)}
            origin = options.get(_ORIGIN_HEADER)
            credentials = options.get(_CRED_HEADER)
            if literal(origin, "*") and literal(credentials, "true"):
                replace(origin, f'"{_SAFE_ORIGIN}"', "header")
    return edits


def _javascript_cors_edits(path: str, text: str) -> list[_CorsEdit]:
    data = text.encode("utf-8")
    if len(data) > 256_000:
        return []
    is_json = path.endswith(".json")
    if is_json:
        try:
            json.loads(text)
        except (ValueError, RecursionError):
            return []
        # JSON objects are JS expressions, but at statement level braces can
        # mean a block. The wrapper is used only for parsing, never persisted.
        data = b"(" + data + b")"
    try:
        grammar = (tree_sitter_typescript.language_tsx() if path.endswith(".tsx")
                   else tree_sitter_typescript.language_typescript() if path.endswith(".ts")
                   else tree_sitter_javascript.language())
        root = Parser(Language(grammar)).parse(data).root_node
    except (ValueError, OverflowError):
        return []
    if root.has_error:
        return []
    edits: list[_CorsEdit] = []
    pending = [root]

    def raw(node) -> str:
        return data[node.start_byte:node.end_byte].decode("utf-8")

    def string_value(node) -> str | None:
        if node is None or node.type != "string":
            return None
        # The relevant option names and values need no escape sequences.
        value = raw(node)[1:-1]
        return value if "\\" not in value else None

    def replace(node, value: str, kind: str) -> None:
        offset = 1 if is_json else 0
        edits.append((node.start_byte - offset, node.end_byte - offset, value, kind))

    while pending:
        node = pending.pop()
        pending.extend(node.named_children)
        if node.type != "object":
            continue
        if any(child.type not in {"pair", "comment"} for child in node.named_children):
            continue  # Spreads/accessors can override a literal option.
        options = {}
        for pair in node.named_children:
            if pair.type != "pair":
                continue
            key = pair.child_by_field_name("key")
            value = pair.child_by_field_name("value")
            if key is None or value is None:
                continue
            name = string_value(key) if key.type == "string" else raw(key)
            if name is not None:
                options[name.lower()] = value
        origin = options.get("origin")
        cred = options.get("credentials")
        if (not is_json and origin is not None and cred is not None and cred.type == "true"
                and (origin.type == "true" or string_value(origin) == "*")):
            replace(origin, f"process.env.CORS_ORIGIN || '{_SAFE_ORIGIN}'", "express")
        origin = options.get(_ORIGIN_HEADER)
        cred = options.get(_CRED_HEADER)
        if string_value(origin) == "*" and string_value(cred) == "true":
            replace(origin, f'"{_SAFE_ORIGIN}"', "header")
    return edits


def _nginx_cors_edits(text: str) -> list[_CorsEdit]:
    # Tokenize complete strings (including multiline examples) and comments
    # before recognizing directives. Pair headers only within the same block.
    token_re = re.compile(
        r"(?P<comment>\#[^\r\n]*)|(?P<string>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')"
        r"|(?P<delimiter>[{};])|(?P<word>[^\s{};\"'\#]+)", re.DOTALL,
    )
    stack = [0]
    next_scope = 0
    statement: list[re.Match[str]] = []
    directives: list[tuple[int, str, re.Match[str]]] = []
    previous_end = 0
    for token in token_re.finditer(text):
        if text[previous_end:token.start()].strip():
            return []  # Unmatched quote or another unsupported token.
        previous_end = token.end()
        if token.lastgroup == "comment":
            continue
        value = token.group()
        if token.lastgroup != "delimiter":
            statement.append(token)
        elif value == "{":
            next_scope += 1
            stack.append(next_scope)
            statement = []
        elif value == "}":
            if len(stack) == 1 or statement:
                return []
            stack.pop()
        else:
            if (len(statement) in {3, 4} and statement[0].group() == "add_header"
                    and (len(statement) == 3 or statement[3].group() == "always")):
                name = statement[1].group().lower()
                if name in {_ORIGIN_HEADER, _CRED_HEADER}:
                    directives.append((stack[-1], name, statement[2]))
            statement = []
    if len(stack) != 1 or statement or text[previous_end:].strip():
        return []
    credential_scopes = {scope for scope, name, value in directives
                         if name == _CRED_HEADER and value.group().strip("\"'").lower() == "true"}
    return [(len(text[:value.start()].encode("utf-8")), len(text[:value.end()].encode("utf-8")),
             f'"{_SAFE_ORIGIN}"', "header")
            for scope, name, value in directives if scope in credential_scopes
            and name == _ORIGIN_HEADER and value.group().strip("\"'") == "*"]


def _fix_cors_in_text(path: str, text: str) -> tuple[str | None, str]:
    lower = path.lower()
    if lower.endswith(".py"):
        edits = _python_cors_edits(text)
    elif lower.endswith((".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".json")):
        edits = _javascript_cors_edits(lower, text)
    elif lower.endswith(".conf"):
        edits = _nginx_cors_edits(text)
    else:
        # Documentation and unsupported syntaxes cannot supply executable
        # CORS evidence. Leave them untouched instead of guessing at syntax.
        return None, ""
    if not edits:
        return None, ""
    out = text.encode("utf-8")
    for start, end, value, _kind in sorted(edits, reverse=True):
        out = out[:start] + value.encode("utf-8") + out[end:]
    detail = "; ".join(dict.fromkeys(_CORS_DETAILS[kind] for _, _, _, kind in edits))
    return out.decode("utf-8"), detail


_PY_EXECUTE_FSTRING = re.compile(
    r"""(?P<prefix>\.\s*execute\s*\(\s*)f(?P<q>[\"'])(?P<sql>.*?)(?P=q)(?P<suffix>\s*\))""",
    re.IGNORECASE | re.DOTALL,
)

_PY_USER_IN_SQL = re.compile(
    r"\{[^}]*(?:request\.|req\.|args\[|kwargs\[|params\.|query\.)[^}]*\}",
    re.IGNORECASE,
)

_JS_QUERY_TEMPLATE = re.compile(
    r"""(?P<prefix>\.\s*(?:query|execute)\s*\(\s*)`(?P<sql>[^`]*\$\{[^}]*(?:req\.|request\.|params\.|query\.|body\.)[^}]*\}[^`]*)`(?P<suffix>\s*\))""",
    re.IGNORECASE,
)


def apply_sqli_fixes(files: dict[str, str]) -> tuple[dict[str, str], list[StaticFix]]:
    updates: dict[str, str] = {}
    fixes: list[StaticFix] = []
    for path, text in files.items():
        if _skip_path(path):
            continue
        new_text, detail = _fix_sqli_in_text(path, text)
        if new_text is not None and new_text != text:
            updates[path] = new_text
            fixes.append(StaticFix(
                rule_id="sqli-dynamic-execute",
                title="Dynamic SQL passed to execute/query",
                file=path,
                detail=detail,
            ))
    return updates, fixes


def _fix_sqli_in_text(path: str, text: str) -> tuple[str | None, str]:
    lower = path.lower()
    out = text
    details: list[str] = []

    if lower.endswith(".py"):
        def _py_sub(m: re.Match[str]) -> str:
            sql = m.group("sql")
            if not _PY_USER_IN_SQL.search(sql):
                return m.group(0)
            binds: list[str] = []

            def _repl_expr(em: re.Match[str]) -> str:
                binds.append(em.group(0)[1:-1].strip())
                return "%s"

            new_sql = _PY_USER_IN_SQL.sub(_repl_expr, sql)
            if not binds:
                return m.group(0)
            bind_tuple = ", ".join(binds)
            details.append("parameterized Python execute() call")
            return (
                f'{m.group("prefix")}"{new_sql}", ({bind_tuple},){m.group("suffix")}'
            )

        out2 = _PY_EXECUTE_FSTRING.sub(_py_sub, out)
        if out2 != out:
            out = out2

    if lower.endswith((".js", ".ts", ".jsx", ".tsx")):
        def _js_sub(m: re.Match[str]) -> str:
            sql = m.group("sql")
            binds: list[str] = []

            def _repl_expr(em: re.Match[str]) -> str:
                binds.append(em.group(1).strip())
                return "?"

            new_sql = re.sub(r"\$\{([^}]+)\}", _repl_expr, sql)
            if not binds:
                return m.group(0)
            bind_list = ", ".join(binds)
            details.append("parameterized JS query/execute call")
            return (
                f'{m.group("prefix")}"{new_sql}", [{bind_list}]{m.group("suffix")}'
            )

        out2 = _JS_QUERY_TEMPLATE.sub(_js_sub, out)
        if out2 != out:
            out = out2

    if not details:
        return None, ""
    return out, "; ".join(dict.fromkeys(details))


def _skip_path(path: str) -> bool:
    lower = path.lower().replace("\\", "/")
    if any(
        part in lower
        for part in (
            "/node_modules/", "/.git/", "/vendor/", "/dist/", "/build/",
            "/.venv/", "/venv/", "/__pycache__/", "/.next/",
            "/migrations/", "/alembic/versions/",
            "/tests/", "/test/", "/__tests__/", "/spec/",
        )
    ):
        return True
    base = lower.rsplit("/", 1)[-1]
    if base.startswith("test_") or base.endswith("_test.py"):
        return True
    return False

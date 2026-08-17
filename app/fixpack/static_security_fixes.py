"""Mechanical CORS / SQLi rewrites for Fix Pack plans.

Complements secret scrubbing: pure text transforms over repo-relative
file bodies. Callers run ``_validate_syntax`` before accepting a rewrite
into ``plan.files``.

CORS: lockdown of allow-any-origin + credentials shapes (FastAPI, Express,
Flask, raw headers).

SQLi: only single-call sites where a dynamic SQL string is passed straight
into ``execute`` / ``query`` — rewritten to a parameterized form. Anything
that needs multi-statement understanding is left alone.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class StaticFix:
    rule_id: str
    title: str
    file: str
    detail: str


_FASTAPI_ORIGINS_STAR = re.compile(
    r"(allow_origins\s*=\s*)\[\s*[\"']\*[\"']\s*\]",
    re.IGNORECASE,
)
_FASTAPI_CRED = re.compile(r"allow_credentials\s*=\s*True", re.IGNORECASE)

_EXPRESS_ORIGIN_TRUE = re.compile(
    r"(origin\s*:\s*)true\b",
    re.IGNORECASE,
)
_EXPRESS_ORIGIN_STAR = re.compile(
    r"(origin\s*:\s*)[\"']\*[\"']",
    re.IGNORECASE,
)
_EXPRESS_CRED = re.compile(r"credentials\s*:\s*true", re.IGNORECASE)

_FLASK_ORIGINS_STAR = re.compile(
    r"(origins\s*=\s*)[\"']\*[\"']",
    re.IGNORECASE,
)
_FLASK_CRED = re.compile(r"supports_credentials\s*=\s*True", re.IGNORECASE)

_HEADER_ORIGIN_STAR = re.compile(
    r"(Access-Control-Allow-Origin[\"'\s:=]+)[\"']?\*",
    re.IGNORECASE,
)
_HEADER_CRED_TRUE = re.compile(
    r"Access-Control-Allow-Credentials[\"'\s:=]+[\"']?true",
    re.IGNORECASE,
)

_CORS_SAFE_ORIGIN_PY = '["http://localhost:3000"]'
_CORS_SAFE_ORIGIN_JS = "process.env.CORS_ORIGIN || 'http://localhost:3000'"
_CORS_SAFE_ORIGIN_HEADER = "http://localhost:3000"


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


def _fix_cors_in_text(path: str, text: str) -> tuple[str | None, str]:
    changed = False
    details: list[str] = []
    out = text

    if _FASTAPI_CRED.search(out) and _FASTAPI_ORIGINS_STAR.search(out):
        out2, n = _FASTAPI_ORIGINS_STAR.subn(
            r"\1" + _CORS_SAFE_ORIGIN_PY, out, count=1,
        )
        if n:
            out = out2
            changed = True
            details.append("pinned FastAPI allow_origins away from `*`")

    if _EXPRESS_CRED.search(out):
        if _EXPRESS_ORIGIN_TRUE.search(out):
            out2, n = _EXPRESS_ORIGIN_TRUE.subn(
                r"\1" + _CORS_SAFE_ORIGIN_JS, out, count=1,
            )
            if n:
                out = out2
                changed = True
                details.append("replaced Express origin:true with env-based origin")
        if _EXPRESS_ORIGIN_STAR.search(out):
            out2, n = _EXPRESS_ORIGIN_STAR.subn(
                r"\1" + _CORS_SAFE_ORIGIN_JS, out, count=1,
            )
            if n:
                out = out2
                changed = True
                details.append("replaced Express origin:'*' with env-based origin")

    if _FLASK_CRED.search(out) and _FLASK_ORIGINS_STAR.search(out):
        out2, n = _FLASK_ORIGINS_STAR.subn(
            r'\1"http://localhost:3000"', out, count=1,
        )
        if n:
            out = out2
            changed = True
            details.append("pinned Flask CORS origins away from `*`")

    if _HEADER_CRED_TRUE.search(out) and _HEADER_ORIGIN_STAR.search(out):
        out2, n = _HEADER_ORIGIN_STAR.subn(
            r"\1" + _CORS_SAFE_ORIGIN_HEADER, out, count=1,
        )
        if n:
            out = out2
            changed = True
            details.append("replaced Access-Control-Allow-Origin * with localhost")

    if not changed:
        return None, ""
    return out, "; ".join(details)


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

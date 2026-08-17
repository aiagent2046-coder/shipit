"""SQLi proof template (static).

Scans workspace source for high-confidence SQL injection sinks: dynamic
SQL built via string concatenation / interpolation with request- or
user-shaped identifiers nearby.

This is a heuristic, not a runtime exploit. It exists so Proof-of-Exploit
can verify that a Fix Pack (or manual patch) removed the dangerous sink
the same way ``secrets_leak`` verifies secret removal — offline, no
network, no docker.
"""

from __future__ import annotations

import io
import re
import time
import zipfile

from app.proof.types import ExploitAttempt

_SOURCE_SUFFIXES = (
    ".py", ".ts", ".tsx", ".js", ".jsx", ".go", ".java", ".kt",
    ".rb", ".php", ".cs", ".sql",
)

_SKIP_DIR_PARTS = (
    "node_modules/", ".git/", "vendor/", "dist/", "build/",
    ".venv/", "venv/", "__pycache__/", ".next/", "coverage/",
    "migrations/", "alembic/versions/",
)

_USER_HINT = (
    r"(?:request\.|req\.|params\.|query\.|body\.|form\."
    r"|args\.|kwargs\.|input\(|user_id|username|search"
    r"|filter|req\b|ctx\.|headers\.)"
)

_SQL_HEAD = (
    r"(?:SELECT|INSERT|UPDATE|DELETE|REPLACE|CALL|EXEC(?:UTE)?)"
)

_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "sqli-python-fstring",
        re.compile(
            rf"(?:f[\"'].*{_SQL_HEAD}\b.*\{{\s*{_USER_HINT}"
            rf"|[\"'].*{_SQL_HEAD}\b.*[\"']\s*%\s*(?:\(|{_USER_HINT})"
            rf"|[\"'].*{_SQL_HEAD}\b.*[\"']\.format\()",
            re.IGNORECASE,
        ),
    ),
    (
        "sqli-python-concat",
        re.compile(
            rf"[\"'].*\b{_SQL_HEAD}\b.*[\"']\s*\+\s*{_USER_HINT}",
            re.IGNORECASE,
        ),
    ),
    (
        "sqli-python-execute-dynamic",
        re.compile(
            rf"(?:\.execute|\.executemany)\(\s*(?:f[\"']|[\"'][^\"]*\+|\"\"\".*\{{\s*{_USER_HINT})",
            re.IGNORECASE,
        ),
    ),
    (
        "sqli-js-template",
        re.compile(
            rf"`[^`]*\b{_SQL_HEAD}\b[^`]*\${{\s*(?:req\.|request\.|params\.|query\.|body\.|user)",
            re.IGNORECASE,
        ),
    ),
    (
        "sqli-js-concat",
        re.compile(
            rf"[\"'`][^\"'`]*\b{_SQL_HEAD}\b[^\"'`]*[\"'`]\s*\+\s*(?:req\.|request\.|params\.|query\.|body\.)",
            re.IGNORECASE,
        ),
    ),
    (
        "sqli-raw-query-helper",
        re.compile(
            rf"(?:\.raw\(|\.query\(|knex\.raw\(|prisma\.\$queryRawUnsafe\()"
            rf"\s*(?:f?[\"'`]|.*{_USER_HINT})",
            re.IGNORECASE,
        ),
    ),
)


def run(zip_bytes: bytes, **_: object) -> ExploitAttempt:
    started = time.monotonic()
    try:
        hits = _scan(zip_bytes)
    except Exception as exc:  # noqa: BLE001
        return ExploitAttempt(
            template_id="sqli",
            status="error",
            success=False,
            detail=f"sqli scan failed: {type(exc).__name__}",
            evidence={},
            duration_ms=_ms(started),
        )

    samples = [
        {
            "file": h["file"],
            "line": h["line"],
            "rule_id": h["rule_id"],
            "snippet": h["snippet"],
        }
        for h in hits[:5]
    ]
    success = len(hits) > 0
    if success:
        detail = f"found {len(hits)} likely SQL injection sink(s)"
        status = "success"
    else:
        detail = "no high-confidence SQL injection sinks found"
        status = "failure"

    return ExploitAttempt(
        template_id="sqli",
        status=status,  # type: ignore[arg-type]
        success=success,
        detail=detail,
        evidence={
            "finding_count": len(hits),
            "samples": samples,
        },
        duration_ms=_ms(started),
    )


def _scan(zip_bytes: bytes) -> list[dict[str, object]]:
    hits: list[dict[str, object]] = []
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for info in zf.infolist():
            name = info.filename
            if info.is_dir() or not _is_source(name):
                continue
            if any(part in name for part in _SKIP_DIR_PARTS):
                continue
            if info.file_size > 512_000:
                continue
            try:
                text = zf.read(info).decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                continue
            for rule_id, pattern in _PATTERNS:
                for match in pattern.finditer(text):
                    line = text.count("\n", 0, match.start()) + 1
                    snippet = re.sub(r"\s+", " ", match.group(0))[:120]
                    hits.append({
                        "file": name,
                        "line": line,
                        "rule_id": rule_id,
                        "snippet": snippet,
                    })
    return hits


def _is_source(name: str) -> bool:
    lower = name.lower()
    return any(lower.endswith(sfx) for sfx in _SOURCE_SUFFIXES)


def _ms(started: float) -> int:
    return max(0, int((time.monotonic() - started) * 1000))

"""Open-CORS proof template (static).

Scans workspace source for dangerously permissive CORS configuration:
allow-any-origin combined with credentials, or equivalent framework
shortcuts that reflect the request Origin while enabling credentials.

No HTTP runtime is required — same posture as ``secrets_leak``. A
successful attempt means at least one high-confidence open-CORS pattern
is present; a clean workspace yields failure (exploit did not work).
"""

from __future__ import annotations

import io
import re
import time
import zipfile

from app.proof.types import ExploitAttempt

_SOURCE_SUFFIXES = (
    ".py", ".ts", ".tsx", ".js", ".jsx", ".go", ".rs", ".java",
    ".kt", ".rb", ".php", ".cs", ".json", ".yml", ".yaml", ".toml",
    ".env", ".conf", ".cfg",
)

_SKIP_DIR_PARTS = (
    "node_modules/", ".git/", "vendor/", "dist/", "build/",
    ".venv/", "venv/", "__pycache__/", ".next/", "coverage/",
)

_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "cors-fastapi-star-credentials",
        re.compile(
            r"CORSMiddleware[\s\S]{0,400}?"
            r"(allow_origins\s*=\s*\[\s*[\"']\*[\"']\s*\]"
            r"|allow_origin_regex\s*=\s*[\"']\.\*[\"'])"
            r"[\s\S]{0,200}?"
            r"allow_credentials\s*=\s*True",
            re.IGNORECASE,
        ),
    ),
    (
        "cors-fastapi-credentials-star",
        re.compile(
            r"CORSMiddleware[\s\S]{0,400}?"
            r"allow_credentials\s*=\s*True"
            r"[\s\S]{0,200}?"
            r"(allow_origins\s*=\s*\[\s*[\"']\*[\"']\s*\]"
            r"|allow_origin_regex\s*=\s*[\"']\.\*[\"'])",
            re.IGNORECASE,
        ),
    ),
    (
        "cors-express-origin-true-credentials",
        re.compile(
            r"cors\s*\(\s*\{[\s\S]{0,300}?"
            r"origin\s*:\s*true"
            r"[\s\S]{0,200}?"
            r"credentials\s*:\s*true",
            re.IGNORECASE,
        ),
    ),
    (
        "cors-express-star-credentials",
        re.compile(
            r"cors\s*\(\s*\{[\s\S]{0,300}?"
            r"origin\s*:\s*[\"']\*[\"']"
            r"[\s\S]{0,200}?"
            r"credentials\s*:\s*true",
            re.IGNORECASE,
        ),
    ),
    (
        "cors-header-star-with-credentials",
        re.compile(
            r"(Access-Control-Allow-Origin[\"'\s:=]+[\"']?\*"
            r"[\s\S]{0,240}?"
            r"Access-Control-Allow-Credentials[\"'\s:=]+[\"']?true"
            r"|Access-Control-Allow-Credentials[\"'\s:=]+[\"']?true"
            r"[\s\S]{0,240}?"
            r"Access-Control-Allow-Origin[\"'\s:=]+[\"']?\*)",
            re.IGNORECASE,
        ),
    ),
    (
        "cors-flask-star-supports-credentials",
        re.compile(
            r"CORS\s*\([^)]{0,200}?"
            r"(origins\s*=\s*[\"']\*[\"']|resources\s*=\s*[\"']\*[\"'])"
            r"[^)]{0,200}?"
            r"supports_credentials\s*=\s*True",
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
            template_id="cors_open",
            status="error",
            success=False,
            detail=f"cors scan failed: {type(exc).__name__}",
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
        detail = f"found {len(hits)} open-CORS pattern(s) with credentials"
        status = "success"
    else:
        detail = "no open-CORS + credentials patterns found"
        status = "failure"

    return ExploitAttempt(
        template_id="cors_open",
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

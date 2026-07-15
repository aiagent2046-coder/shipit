"""Secrets scanning over a validated ZIP, without extracting to disk.

Design rules:
- Findings NEVER contain the secret value — only file, line, rule and
  a masked preview (first 4 chars + length). See security checklist.
- Rules are high-precision by default; broad heuristics get lower
  confidence so scoring stays honest.
- Interface is rule-based so an external source (e.g. gitleaks rules)
  can be merged in later without changing callers.
"""

from __future__ import annotations

import json
import re
import stat
import zipfile
from dataclasses import dataclass
from typing import BinaryIO, Iterator

MAX_SCANNED_FILE_BYTES = 1 * 1024 * 1024  # skip huge files: minified bundles etc.

_SKIP_DIRS = ("node_modules/", ".git/", "dist/", ".next/", "build/", "venv/", ".venv/")
_SKIP_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf",
    ".woff", ".woff2", ".ttf", ".eot", ".zip", ".gz", ".map",
    ".lock",  # lockfiles: huge, hash-heavy, no secrets by convention
)

# Documentation/example context: a credential-shaped string inside a
# blog post, docs page, or test fixture is far more likely a fabricated
# teaching example than a live secret (seen for real: a QA-tutorials
# site scored 0.0 because its articles contain example passwords and a
# sample private key). Findings there are NOT dropped — a real key
# pasted into docs is still a leak — but severity is capped at medium
# and confidence damped, so one tutorial can't zero out the whole score.
_DOC_SEGMENTS = frozenset((
    "blog", "docs", "doc", "content", "posts", "articles",
    "examples", "example", "fixtures", "__fixtures__", "samples",
))
_DOC_SUFFIXES = (".md", ".mdx")
_DOC_CONFIDENCE_FACTOR = 0.35
_DOC_SEVERITY_CAP = {"critical": "medium", "high": "medium"}

# Database migrations are the opposite of documentation context: a
# secret there is committed, applied state — anon JWTs, cron shared
# secrets and SMTP passwords in supabase/migrations/ showed up as a
# systemic pattern across real Lovable exports. Confidence is raised,
# and migration context always wins over doc-context damping (a path
# like examples/migrations/ is still a migration).
_MIGRATION_SEGMENTS = frozenset(("migrations", "migration"))
_MIGRATION_MIN_CONFIDENCE = 0.9

# Test-fixture context: a credential-shaped string in a test-setup file
# that *also* self-labels as a placeholder (seen for real: a jest.setup.ts
# with `ANTHROPIC_API_KEY: ... || 'sk-ant-api03-test-placeholder-not-real-key'`
# and a `...placeholder_sig_for_unit_tests` JWT). Damped exactly like doc
# context — capped, not dropped — because a test file is NOT inherently
# safe: a real leaked key can live there too. So unlike doc context (path
# alone), this requires BOTH a test path AND the value itself carrying a
# placeholder marker, so a genuine secret in a test file stays flagged.
_TEST_PATH_SEGMENTS = frozenset(("__tests__", "__mocks__", "test", "tests"))
_TEST_SETUP_FILENAMES = frozenset(("jest.setup.ts", "jest.setup.js"))
_TEST_FILE_SUFFIXES = (".test.ts", ".test.js", ".spec.ts", ".spec.js")
_PLACEHOLDER_MARKERS = (
    "placeholder",
    "not-real",
    "not_real",
    "fake",
    "dummy",
    "test-only",
    "test_only",
)


def _is_migration_context(name: str) -> bool:
    return any(seg.lower() in _MIGRATION_SEGMENTS for seg in name.split("/")[:-1])


def _is_test_fixture_path(name: str) -> bool:
    lower = name.lower()
    base = lower.rsplit("/", 1)[-1]
    if base in _TEST_SETUP_FILENAMES or lower.endswith(_TEST_FILE_SUFFIXES):
        return True
    return any(seg in _TEST_PATH_SEGMENTS for seg in lower.split("/")[:-1])


def _value_has_placeholder_marker(value: str) -> bool:
    low = value.lower()
    return any(marker in low for marker in _PLACEHOLDER_MARKERS)


def _is_test_fixture_context(name: str, value: str) -> bool:
    # AND, not OR: the path signal narrows to test files, the value signal
    # confirms the match is a deliberate placeholder rather than a real leak.
    return _is_test_fixture_path(name) and _value_has_placeholder_marker(value)


def _is_doc_context(name: str) -> bool:
    if name.lower().endswith(_DOC_SUFFIXES):
        return True
    return any(seg.lower() in _DOC_SEGMENTS for seg in name.split("/")[:-1])


@dataclass(frozen=True)
class SecretRule:
    id: str
    title: str
    pattern: re.Pattern
    severity: str      # critical | high | medium | low
    confidence: float  # 0..1


RULES: tuple[SecretRule, ...] = (
    SecretRule(
        "aws-access-key-id", "AWS Access Key ID",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "critical", 0.95,
    ),
    SecretRule(
        "github-pat", "GitHub personal access token",
        re.compile(r"\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,255})\b"),
        "critical", 0.95,
    ),
    SecretRule(
        "stripe-live-key", "Stripe live secret key",
        re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"), "critical", 0.95,
    ),
    SecretRule(
        "anthropic-api-key", "Anthropic API key",
        re.compile(r"\bsk-ant-api03-[A-Za-z0-9_\-]{20,}\b"), "critical", 0.95,
    ),
    SecretRule(
        "telegram-bot-token", "Telegram bot token",
        re.compile(r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b"), "critical", 0.9,
    ),
    SecretRule(
        "private-key-block", "Private key material",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
        "critical", 0.95,
    ),
    SecretRule(
        "jwt-in-code", "JWT committed to code",
        re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
        "high", 0.6,
    ),
    SecretRule(
        # Systemic Lovable-export pattern, confirmed on real repos:
        # migrations declare PL/pgSQL variables like
        #   v_cron_secret text := 'hunter2...';
        # The generic-assignment rule misses these because a type
        # annotation sits between the name and the assignment.
        "sql-secret-assignment", "Hardcoded secret in SQL/PLpgSQL assignment",
        re.compile(
            r"(?i)\b\w*(?:secret|password|api[_-]?key|service[_-]?role)\w*\s+"
            r"(?:text|varchar(?:\(\d+\))?|character varying)\s*:?=\s*'[^']{8,}'"
        ),
        "high", 0.7,
    ),
    SecretRule(
        "generic-assignment", "Hardcoded credential assignment",
        re.compile(
            r"(?i)\b(api[_-]?key|secret|password|service[_-]?role)\b"
            r"\s*[:=]\s*['\"][^'\"\s]{12,}['\"]"
        ),
        "high", 0.5,
    ),
)


@dataclass(frozen=True)
class SecretFinding:
    rule_id: str
    title: str
    severity: str
    confidence: float
    file: str
    line: int
    masked: str  # e.g. "AKIA****(20 chars)" — value itself is never stored


def _mask(value: str) -> str:
    return f"{value[:4]}****({len(value)} chars)"


def _iter_text_files(zf: zipfile.ZipFile) -> Iterator[tuple[str, str]]:
    for info in zf.infolist():
        name = info.filename
        if info.is_dir() or info.file_size > MAX_SCANNED_FILE_BYTES:
            continue
        if stat.S_ISLNK(info.external_attr >> 16):
            continue
        if any(part in name for part in _SKIP_DIRS):
            continue
        if name.lower().endswith(_SKIP_SUFFIXES):
            continue
        data = zf.read(info)
        if b"\x00" in data[:4096]:  # binary sniff
            continue
        yield name, data.decode("utf-8", errors="ignore")


def _jwt_severity(token: str) -> tuple[str, float, str]:
    """Supabase keys are JWTs with a `role` claim: anon is public by
    design (every Lovable app ships it client-side), service_role is a
    full RLS bypass. Decode the payload to tell them apart."""
    import base64
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        role = data.get("role", "")
    except Exception:
        return "high", 0.6, "JWT committed to code"
    if role == "service_role":
        return "critical", 0.95, "Supabase service_role key committed — full RLS bypass"
    if role == "anon":
        return "low", 0.3, "Supabase anon key in code (public by design, informational)"
    return "high", 0.6, "JWT committed to code"


def scan_secrets(fileobj: BinaryIO) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    with zipfile.ZipFile(fileobj) as zf:
        for name, text in _iter_text_files(zf):
            for lineno, line in enumerate(text.splitlines(), start=1):
                for rule in RULES:
                    m = rule.pattern.search(line)
                    if not m:
                        continue
                    severity, confidence, title = (
                        rule.severity, rule.confidence, rule.title
                    )
                    if rule.id == "jwt-in-code":
                        severity, confidence, title = _jwt_severity(m.group(0))
                    # Supabase anon key is public by design; migration
                    # context must NOT re-escalate it (that produced a
                    # wall of 40+ scary-but-false "admin login" rows in
                    # a real report). Tag it with its own rule_id so the
                    # report can collapse and translate it correctly.
                    is_anon = title.startswith("Supabase anon key")
                    effective_rule_id = "supabase-anon-key" if is_anon else rule.id
                    if _is_migration_context(name) and not is_anon:
                        confidence = max(confidence, _MIGRATION_MIN_CONFIDENCE)
                        title = f"{title} (committed database migration)"
                    elif _is_doc_context(name) and not is_anon:
                        severity = _DOC_SEVERITY_CAP.get(severity, severity)
                        confidence = round(confidence * _DOC_CONFIDENCE_FACTOR, 2)
                        title = f"{title} (documentation/example context)"
                    elif _is_test_fixture_context(name, m.group(0)) and not is_anon:
                        severity = _DOC_SEVERITY_CAP.get(severity, severity)
                        confidence = round(confidence * _DOC_CONFIDENCE_FACTOR, 2)
                        title = f"{title} (test fixture/placeholder context)"
                    findings.append(SecretFinding(
                        rule_id=effective_rule_id,
                        title=title,
                        severity=severity,
                        confidence=confidence,
                        file=name,
                        line=lineno,
                        masked=_mask(m.group(0)),
                    ))
    return findings

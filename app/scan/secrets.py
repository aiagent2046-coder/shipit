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

import re
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
        if any(part in name for part in _SKIP_DIRS):
            continue
        if name.lower().endswith(_SKIP_SUFFIXES):
            continue
        data = zf.read(info)
        if b"\x00" in data[:4096]:  # binary sniff
            continue
        yield name, data.decode("utf-8", errors="ignore")


def scan_secrets(fileobj: BinaryIO) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    with zipfile.ZipFile(fileobj) as zf:
        for name, text in _iter_text_files(zf):
            for lineno, line in enumerate(text.splitlines(), start=1):
                for rule in RULES:
                    m = rule.pattern.search(line)
                    if m:
                        findings.append(SecretFinding(
                            rule_id=rule.id,
                            title=rule.title,
                            severity=rule.severity,
                            confidence=rule.confidence,
                            file=name,
                            line=lineno,
                            masked=_mask(m.group(0)),
                        ))
    return findings

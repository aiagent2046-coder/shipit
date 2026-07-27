"""Tests for the CI secret scanner .github/scripts/scan-added-secrets.py.

The script lives outside the importable package and has a hyphenated name, so
it is loaded by path. Each newly added pattern gets one positive (a
format-valid but deliberately fake sample) and one negative (a look-alike that
must NOT match, e.g. a bare variable name or a too-short value) so a future
loosening that reintroduces false positives fails here.

All samples are synthetic. No real project secret appears in this file.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path


_MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / ".github"
    / "scripts"
    / "scan-added-secrets.py"
)

_SPEC = importlib.util.spec_from_file_location(
    "scan_added_secrets",
    _MODULE_PATH,
)
assert _SPEC is not None and _SPEC.loader is not None
scan_added_secrets = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(scan_added_secrets)


def signatures(content: bytes) -> set[str]:
    """Signature names that fire on a blob of (already added) line content."""
    return {
        name
        for name, pattern in scan_added_secrets.PATTERNS
        if pattern.search(content)
    }


# --- Self-exclusion allowlist --------------------------------------------

def test_scanner_and_its_test_file_are_excluded():
    # These files exist to enumerate secret formats, so the diff scan must skip
    # them or the scanner trips on its own definitions/fixtures. The third is
    # the log-redaction suite, which cannot test masking without carrying a
    # fake secret of each shape. This test runs PATTERNS in-process (like every
    # test here), so it keeps working even though the files it names are
    # excluded from the git-diff scan.
    assert scan_added_secrets.EXCLUDED_PATHS == {
        ".github/scripts/scan-added-secrets.py",
        "tests/test_scan_added_secrets.py",
        "tests/test_logging_config.py",
    }


# --- Anthropic API key (sk-ant-api03-...) --------------------------------

def test_anthropic_key_detected():
    sample = b"ANTHROPIC_API_KEY=sk-ant-api03-" + b"a" * 24
    assert "anthropic-api-key" in signatures(sample)


def test_anthropic_lookalike_not_detected():
    # Bare variable name, and a truncated prefix well under the 20-char body.
    assert "anthropic-api-key" not in signatures(b"ANTHROPIC_API_KEY=")
    assert "anthropic-api-key" not in signatures(b"# e.g. sk-ant-api03-xxxx")


# --- AITunnel API key (sk-aitunnel-...) ----------------------------------

def test_aitunnel_key_detected():
    sample = b"AITUNNEL_API_KEY=sk-aitunnel-" + b"Z" * 24
    assert "aitunnel-api-key" in signatures(sample)


def test_aitunnel_lookalike_not_detected():
    assert "aitunnel-api-key" not in signatures(b"AITUNNEL_API_KEY=")
    assert "aitunnel-api-key" not in signatures(b"see sk-aitunnel-short")


# --- Telegram bot token (<8-10 digits>:<35 chars>) -----------------------

def test_telegram_token_detected():
    sample = b"TELEGRAM_BOT_TOKEN=123456789:" + b"A" * 35
    assert "telegram-bot-token" in signatures(sample)


def test_telegram_lookalike_not_detected():
    # A time value, a bare var, a ratio, and a too-long digit run: none are
    # an 8-10 digit id followed by exactly 35 token chars.
    assert "telegram-bot-token" not in signatures(b"start=00:00:00 done")
    assert "telegram-bot-token" not in signatures(b"TELEGRAM_BOT_TOKEN=")
    assert "telegram-bot-token" not in signatures(b"ratio 1234567890:1234")
    # Second half longer than 35 chars must not match (trailing boundary).
    assert "telegram-bot-token" not in signatures(b"123456789:" + b"A" * 36)


# --- PostgreSQL URL with embedded password -------------------------------

def test_postgres_url_with_password_detected():
    sample = b"DATABASE_URL=postgresql://appuser:s3cr3tPass@db.example.com:5432/app"
    assert "postgres-url-password" in signatures(sample)
    # The scheme-less "postgres://" spelling is covered too.
    short = b"postgres://u:p4ssw0rd@host/db"
    assert "postgres-url-password" in signatures(short)


def test_postgres_url_without_password_not_detected():
    # Bare variable name; host:port with no userinfo; user with no password.
    assert "postgres-url-password" not in signatures(b"DATABASE_URL=")
    assert "postgres-url-password" not in signatures(
        b"postgresql://localhost:5432/app"
    )
    assert "postgres-url-password" not in signatures(
        b"postgres://readonly@replica/db"
    )

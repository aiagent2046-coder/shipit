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


def test_hex_secret_assignment_detected():
    """The leak this pattern was added for: on 2026-08-02 a live
    USDT_POLL_TOKEN was pasted into a regression test out of a journal line and
    CI passed, because no pattern here described a bare hex string."""
    leaked = b"a" * 64
    assert "hex-secret-assignment" in signatures(b'    SECRET = "' + leaked + b'"')
    # The shapes it has to cover: shell assignment, an env line, YAML, and a
    # name where the secret word is a suffix rather than the whole name.
    assert "hex-secret-assignment" in signatures(b"USDT_POLL_TOKEN='" + leaked + b"'")
    assert "hex-secret-assignment" in signatures(b'api_key: "' + leaked + b'"')
    assert "hex-secret-assignment" in signatures(b'API_KEY_PEPPER = "' + leaked + b'"')


def test_hex_lookalike_not_detected():
    """Why the pattern keys on the NAME. A bare 32+ hex literal is a SHA-256
    digest, a git object id, a checksum or a fixture id in every codebase --
    matching those would make the scanner noise, and a noisy scanner gets
    switched off."""
    digest = b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    # A hash, named as one.
    assert "hex-secret-assignment" not in signatures(b'sha256 = "' + digest + b'"')
    # Bare, with no assignment at all.
    assert "hex-secret-assignment" not in signatures(digest)
    # Assigned to a secret-shaped name, but not hex.
    assert "hex-secret-assignment" not in signatures(
        b'SECRET = "fake-token-not-a-real-secret"'
    )
    # Too short to be one of this project's `openssl rand -hex 32` tokens.
    assert "hex-secret-assignment" not in signatures(b'token = "deadbeef"')
    # The convention this repo uses for fixtures, so the fixtures stay quiet.
    assert "hex-secret-assignment" not in signatures(b'secret = "deadbeef" * 8')

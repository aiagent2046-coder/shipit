"""Tests for the secrets scanner. The masking test is the critical one:
a scanner that leaks the secrets it finds is worse than no scanner.
"""

import io
import zipfile

from app.scan.secrets import scan_secrets

# Deliberately fake but format-valid samples.
FAKE_AWS = "AKIA" + "A" * 16
FAKE_GHP = "ghp_" + "a" * 36
FAKE_STRIPE = "sk_live_" + "a" * 24
FAKE_ANTHROPIC = "sk-ant-api03-" + "a" * 24
FAKE_TG = "1234567890:" + "A" * 35
FAKE_JWT = "eyJ" + "a" * 20 + ".eyJ" + "b" * 20 + "." + "c" * 20


def make_zip(entries: dict[str, bytes]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    buf.seek(0)
    return buf


def test_detects_known_token_formats_with_file_and_line():
    src = f"const a = '{FAKE_AWS}'\nconst b = '{FAKE_GHP}'\n".encode()
    findings = scan_secrets(make_zip({"src/config.ts": src}))
    ids = {f.rule_id for f in findings}
    assert {"aws-access-key-id", "github-pat"} <= ids
    aws = next(f for f in findings if f.rule_id == "aws-access-key-id")
    assert aws.file == "src/config.ts" and aws.line == 1
    assert aws.severity == "critical"


def test_detects_stripe_anthropic_telegram_privatekey():
    src = "\n".join([
        f'STRIPE = "{FAKE_STRIPE}"',
        f'client = Anthropic(api_key="{FAKE_ANTHROPIC}")',
        f'BOT = "{FAKE_TG}"',
        "-----BEGIN RSA PRIVATE KEY-----",
    ]).encode()
    ids = {f.rule_id for f in scan_secrets(make_zip({"app.py": src}))}
    assert {
        "stripe-live-key", "anthropic-api-key",
        "telegram-bot-token", "private-key-block",
    } <= ids


def test_finding_never_contains_secret_value():
    src = f"key = '{FAKE_STRIPE}'\ntoken = '{FAKE_JWT}'".encode()
    findings = scan_secrets(make_zip({"a.py": src}))
    assert findings
    for f in findings:
        dumped = repr(f)
        assert FAKE_STRIPE not in dumped
        assert FAKE_JWT not in dumped
        assert "****" in f.masked


def test_jwt_flagged_with_lower_confidence():
    findings = scan_secrets(make_zip({"a.js": f"const t='{FAKE_JWT}'".encode()}))
    jwt = next(f for f in findings if f.rule_id == "jwt-in-code")
    assert jwt.severity == "high" and jwt.confidence < 0.9


def test_generic_assignment_heuristic():
    src = b'PASSWORD = "correct-horse-battery"\n'
    ids = {f.rule_id for f in scan_secrets(make_zip({"settings.py": src}))}
    assert "generic-assignment" in ids


def test_skips_node_modules_binaries_and_lockfiles():
    entries = {
        "node_modules/pkg/index.js": f"'{FAKE_AWS}'".encode(),
        "logo.png": b"\x89PNG\x00\x00" + FAKE_AWS.encode(),
        "package-lock.json.lock": f"'{FAKE_AWS}'".encode(),
        "src/ok.ts": b"export const x = 1;",
    }
    assert scan_secrets(make_zip(entries)) == []


def test_clean_project_yields_no_findings():
    entries = {
        "src/main.py": b"from fastapi import FastAPI\napp = FastAPI()\n",
        ".env.example": b"ANTHROPIC_API_KEY=\nDATABASE_URL=\n",
    }
    assert scan_secrets(make_zip(entries)) == []

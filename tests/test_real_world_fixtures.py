"""Regression fixtures from real, human-verified findings on public repos
(free audit + LLM scan test pass, July 2026 — see the 6-repo test batch).

Each fixture is a minimal SYNTHETIC reproduction of the bug shape, not a
copy of the original source — this avoids pulling third-party licensed
code into this repo while still exercising the exact pattern that
produced a true-positive finding when we ran the real thing.

Scope, honestly stated: these test `select_files` (the rubric keyword
pre-filter) and `verify_finding` (the anti-hallucination gate) against
real-world code shapes. They do NOT test whether a real LLM call would
report the finding again on any given run — that's inherently
non-deterministic and not something CI should depend on. What they DO
guard against: a future refactor of either function silently starting
to skip or reject a finding shape we've already confirmed matters.
"""

from __future__ import annotations

from pathlib import Path

from app.scan.llm_scan import select_files, verify_finding

FIXTURES = Path(__file__).parent / "fixtures"


def _read(name: str) -> str:
    return (FIXTURES / name).read_text()


# --- unauthenticated webhook callback ---
# Real finding: theaiautomators/insights-lm-public,
# supabase/functions/process-document-callback/index.ts — an edge
# function callback mutates a database row straight from the request
# body, no token or signature check anywhere in the handler.

WEBHOOK = _read("unauthenticated_webhook.ts")


def test_unauthenticated_webhook_selected_for_auth_and_security():
    files = [("supabase/functions/callback/index.ts", WEBHOOK)]
    assert select_files(files, "auth")
    assert select_files(files, "security")


def test_unauthenticated_webhook_finding_verifies():
    finding = {
        "file": "supabase/functions/callback/index.ts",
        "line_start": 14,
        "line_end": 21,
        "evidence": "await supabase.from('sources').update({ status, error }).eq('id', source_id)",
        "severity": "high",
        "confidence": 0.9,
        "title": "Unauthenticated callback endpoint allows arbitrary record mutation",
        "explanation": "No token or signature check runs before the mutation.",
    }
    assert verify_finding(finding, {"supabase/functions/callback/index.ts": WEBHOOK})


# --- JWT secret recomputed at class-definition time ---
# Real finding: kumarsonu676/python-fastapi-starter-api-project,
# app/core/config.py — the SECRET_KEY default is evaluated once when
# the class body runs (import time), not per-request, so every process
# restart silently issues a new secret and invalidates all live tokens.

JWT_CONFIG = _read("jwt_secret_recompute.py")


def test_jwt_secret_file_selected_for_auth():
    files = [("app/core/config.py", JWT_CONFIG)]
    assert select_files(files, "auth")


def test_jwt_secret_recompute_finding_verifies():
    finding = {
        "file": "app/core/config.py",
        "line_start": 11,
        "line_end": 11,
        "evidence": 'SECRET_KEY: str = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))',
        "severity": "high",
        "confidence": 0.85,
        "title": "JWT secret key generated at class definition time, rotates on every process restart",
        "explanation": "The default is evaluated once at import time, not per-request.",
    }
    assert verify_finding(finding, {"app/core/config.py": JWT_CONFIG})


# --- shell injection via subprocess shell=True ---
# Real finding: djodiwa/BUGBUDDY.AI, backend/api.py — a tool-version
# helper shells out with shell=True on a command string that includes
# user-controlled input.

SHELL_INJECTION = _read("shell_injection.py")


def test_shell_injection_file_selected_for_security():
    files = [("backend/tool_version.py", SHELL_INJECTION)]
    assert select_files(files, "security")


def test_shell_injection_finding_verifies():
    finding = {
        "file": "backend/tool_version.py",
        "line_start": 8,
        "line_end": 9,
        "evidence": "out = subprocess.check_output(cmd, shell=True, timeout=2)",
        "severity": "high",
        "confidence": 0.85,
        "title": "Shell injection via unsanitized input in tool version command",
        "explanation": "user_input is concatenated into a shell=True command string.",
    }
    assert verify_finding(finding, {"backend/tool_version.py": SHELL_INJECTION})

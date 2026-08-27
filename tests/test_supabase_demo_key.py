"""Supabase's local-development demo key is not a credential (#354).

WHAT HAPPENED. `mckaywrigley/chatbot-ui` scored 3.8, and one of the two
criticals holding it there was the JWT in
`supabase/migrations/20240108234540_setup.sql`:

    Supabase service_role key committed — full RLS bypass
    → Remove it, invalidate the session it belongs to

There is no session to invalidate. That token is the one `supabase start`
prints for every developer on earth, signed with a secret published in
Supabase's own documentation. The same audit's LLM said so, at medium --
"although this appears to be the well-known local-dev demo key" -- and the
two were never reconciled. The critical is what capped the score at 6.9,
standing beside a genuine critical (SSRF via a user-controlled tool URL) and
claiming equal weight.

Not one repository's bad luck: every Supabase project that commits its
scaffolding shipped that finding, and Supabase-backed projects are much of
what this product exists to audit.

WHY THE SIGNATURE AND NOT THE CLAIM. `iss` is unsigned data the holder
controls. A self-hosted deployment that kept the demo issuer while setting a
real secret would carry `iss: supabase-demo` on tokens that ARE live
credentials, and damping those is the expensive direction of this mistake --
strictly worse than the bug being fixed. A signature that verifies against a
published secret proves the opposite outright: anyone can mint the same
token, so it opens nothing.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import zipfile

import pytest

from app.report.html import render_report
from app.report.plain_language import PLAIN
from app.scan.pipeline import run_static_scan

# The token from that migration, reproduced byte for byte: HS256 over
# {"iss":"supabase-demo","role":"service_role","exp":1983812996} with the
# published demo secret. Confirmed against the repository on 2026-08-27 --
# 164 characters, and its signature verifies.
REAL_DEMO_SERVICE_ROLE = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImV4cCI6MTk4"
    "MzgxMjk5Nn0.EGIM96RAZx35lJzdJsyH-qQwv8Hdp7fsn3W0YpN81IU"
)

DEMO_SECRET = "super-secret-jwt-token-with-at-least-32-characters-long"
# Any 32+ character secret that is NOT the published one. A token signed with
# this is a real credential to whoever holds the project it belongs to.
PRIVATE_SECRET = "a-real-projects-own-jwt-secret-at-least-32-chars"


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _jwt(secret: str, **claims) -> str:
    head = _b64u(json.dumps({"alg": "HS256", "typ": "JWT"},
                            separators=(",", ":")).encode())
    payload = _b64u(json.dumps(claims, separators=(",", ":")).encode())
    sig = _b64u(hmac.new(secret.encode(), f"{head}.{payload}".encode(),
                         hashlib.sha256).digest())
    return f"{head}.{payload}.{sig}"


def _scan_migration(token: str) -> dict | None:
    """One token in a committed migration -- the exact context that escalates
    confidence to 0.9, and the one chatbot-ui's finding came from."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("supabase/migrations/0001_setup.sql",
                    f"select set_config('app.key', '{token}', false);\n")
    for finding in run_static_scan(io.BytesIO(buf.getvalue()))["findings"]:
        if finding.get("masked"):
            return finding
    return None


def test_the_real_token_from_chatbot_ui_is_informational():
    """The defect, in the exact bytes that produced it."""
    finding = _scan_migration(REAL_DEMO_SERVICE_ROLE)

    assert finding is not None, "the token stopped being detected at all"
    assert finding["severity"] == "low"
    assert finding["rule_id"] == "supabase-demo-key"
    assert "demo key" in finding["title"]
    assert "full RLS bypass" not in finding["title"]


def test_migration_context_does_not_escalate_it():
    """`_MIGRATION_MIN_CONFIDENCE` raises confidence to 0.9 because secrets in
    applied migrations are confirmed real leaks. Applying that to a token
    anyone can mint is how this reached 0.95 in the first place."""
    finding = _scan_migration(REAL_DEMO_SERVICE_ROLE)

    assert finding["confidence"] < 0.9
    assert "committed database migration" not in finding["title"]


def test_a_real_service_role_key_is_still_critical():
    """THE CONTROL, and the failure that would be worse than the bug.

    A genuine service_role token is a full Row Level Security bypass for
    somebody's live database. If this fix damped every service_role token in
    a migration, it would turn a real leak into a footnote.
    """
    finding = _scan_migration(
        _jwt(PRIVATE_SECRET, iss="supabase", role="service_role",
             exp=2000000000))

    assert finding["severity"] == "critical"
    assert finding["confidence"] >= 0.9
    assert finding["rule_id"] == "jwt-in-code"
    assert "full RLS bypass" in finding["title"]


def test_the_issuer_claim_alone_does_not_damp_anything():
    """`iss` is unsigned data the holder controls. Keying on it would let a
    live credential be hidden by one edited claim -- and would also damp a
    self-hosted deployment that kept the demo issuer with a real secret,
    whose tokens ARE credentials."""
    forged = _jwt(PRIVATE_SECRET, iss="supabase-demo", role="service_role",
                  exp=2000000000)

    finding = _scan_migration(forged)

    assert finding["severity"] == "critical", (
        "a real key wearing the demo issuer was damped; the check has moved "
        "from the signature to the claim")


def test_the_demo_anon_token_is_informational_too():
    """The anon side of the same local stack. It was already informational by
    its `role` claim; this pins that the demo branch, which now runs first,
    did not accidentally make it louder."""
    finding = _scan_migration(
        _jwt(DEMO_SECRET, iss="supabase-demo", role="anon", exp=1983812996))

    assert finding["severity"] == "low"
    assert finding["rule_id"] == "supabase-demo-key"


@pytest.mark.parametrize("token", [
    "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9",          # two parts
    "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.aaaa.bbbb",  # four
    "eyJhbGciOiJIUzI1NiJ9.@@@@@@@@@@.cccccccccc",         # undecodable
])
def test_a_malformed_token_does_not_crash_the_scan(token):
    """The signature check runs on every JWT the scanner sees, including
    whatever a repository happens to contain. Raising here would take the
    whole audit down with it."""
    run_static_scan(io.BytesIO(_zip(token)))


def _zip(token: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("src/config.ts", f'const t = "{token}"\n')
    return buf.getvalue()


# --- what the reader is told ------------------------------------------------

def test_the_advice_does_not_send_anybody_to_rotate_nothing():
    """The half that made the finding worse than a plain false positive. The
    old text said "invalidate the session it belongs to"; there is no session,
    and a reader who tries to follow it finds nothing to follow it with."""
    what, risk, fix = PLAIN["supabase-demo-key"]
    low = fix.lower()

    # On the INSTRUCTION, not on the word. The first version of this test
    # banned "rotate" outright and failed against "Nothing to rotate — there
    # is no account behind this token", which is the correct sentence. A test
    # that forbids a token rather than a claim rejects the right answer for
    # containing the wrong letters.
    assert "nothing to rotate" in low
    assert "rotate the" not in low
    assert "invalidate the" not in low
    # And it says what the reader should check INSTEAD, rather than only what
    # not to worry about -- the real key does look identical to this one.
    assert "environment variable" in fix


def test_the_report_says_what_the_token_actually_is():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("supabase/migrations/0001_setup.sql",
                    f"select '{REAL_DEMO_SERVICE_ROLE}';\n")
    scan = run_static_scan(io.BytesIO(buf.getvalue()))
    scan.setdefault("score", {"total": 9.0, "categories": {}, "basis": "static_only"})

    html = render_report(scan)

    assert "local-development demo key" in html
    assert "invalidate the session" not in html

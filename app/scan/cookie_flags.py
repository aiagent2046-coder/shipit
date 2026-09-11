"""A session cookie set without the attributes that keep it out of reach.

ONE CLAIM, TWO LANGUAGES. "This cookie carries identity and the code leaves it
readable by script, or sends it cross-site" is the same sentence in Python and in
TypeScript, so both halves sit under one rule id -- the same decision
`tls-verification-disabled` made, and for the same reason: Drydock audits Next.js
repositories in the main, and a Python-only cookie rule would mostly not fire.

WHAT IT READS. Cookie-setting calls whose cookie name is authentication-shaped (a
literal, or a module-level constant resolved one hop) and the HttpOnly/SameSite
options on that call; the two Django settings that decide the same thing for the
session cookie; the express-session/cookie-session configuration object; and
`document.cookie` writes. Which DEFAULT each API has decides whether an absent
option is reported -- `res.cookie` defaults HttpOnly to false, express-session
defaults it to true -- and the halves say so where they implement it.

WHAT IT DOES NOT CLAIM. That the cookie value is a live session token, that any
script on the page is attacker-controlled, or that another layer does not rewrite
the cookie on the way out. A missing `secure` attribute is deliberately NOT
reported: a developer's localhost is the ordinary reason for it and browsers
already treat localhost as a secure context. A missing SameSite is not reported
either, because every browser in use defaults to Lax -- only an explicit
SameSite=None removes that protection. `csrf`/`xsrf`/`state` cookie names are
excluded outright: the double-submit pattern requires the cookie to be readable by
script. Set-Cookie header strings, framework config files and cookies set through
a wrapper are not read.

NEVER EXECUTES THE UPLOADED CODE. The Python half builds an AST, the TS/JS half a
tree-sitter syntax tree; nothing here imports or runs any of it.
"""

from __future__ import annotations

import zipfile
from typing import BinaryIO

from app.scan.checks import CheckFinding
from app.scan.cookie_flags_js import js_evidence
from app.scan.cookie_flags_python import python_evidence
from app.scan.secrets import is_dependency_path, is_non_production_path
# The same file-type vocabulary the TLS rule reads, imported rather than copied:
# two lists of "what counts as TypeScript" would drift, and the audience is the
# same repositories.
from app.scan.tls_verification import _JS_FILE_SUFFIXES as _JS_SUFFIXES

RULE_ID = "insecure-session-cookie-attributes"
_MAX_FILE_BYTES = 400_000
_MAX_FILES = 400
_MAX_FINDINGS = 32


def scan_cookie_flags(fileobj: BinaryIO) -> list[CheckFinding]:
    findings: list[CheckFinding] = []
    seen = set()
    with zipfile.ZipFile(fileobj) as archive:
        infos = [
            info
            for info in archive.infolist()
            if not info.is_dir()
            and info.file_size <= _MAX_FILE_BYTES
            and (info.filename.endswith(".py") or info.filename.endswith(_JS_SUFFIXES))
            and not is_non_production_path(info.filename)
            and not is_dependency_path(info.filename)
        ]
        for info in infos[:_MAX_FILES]:
            if len(findings) >= _MAX_FINDINGS:
                break
            try:
                text = archive.read(info).decode("utf-8")
                evidence = (
                    python_evidence(text)
                    if info.filename.endswith(".py")
                    else js_evidence(text, tsx=info.filename.endswith((".tsx", ".jsx")))
                )
            except (UnicodeError, SyntaxError, ValueError, RecursionError):
                continue
            for line, what, kind in evidence:
                key = (info.filename, line, what, kind)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(_finding(info.filename, line, what, kind))
                if len(findings) >= _MAX_FINDINGS:
                    break
    return findings


def _finding(path: str, line: int, what: str, kind: str) -> CheckFinding:
    script = kind == "httponly"
    return CheckFinding(
        rule_id=RULE_ID,
        title=(
            "A session cookie can be read by scripts" if script
            else "A session cookie is sent on cross-site requests"
        ),
        severity="medium",
        confidence=0.8,
        category="Security",
        file=path,
        line=line,
        explanation=(
            f"Line {line} {what}. "
            + (
                "HttpOnly keeps the cookie out of `document.cookie`, so a script that "
                "reaches the page cannot read the session. Without it, any cross-site "
                "scripting flaw turns into session theft. "
                if script
                else "SameSite=None tells the browser to attach the cookie to requests "
                "coming from other sites, which is the protection most browsers apply by "
                "default and the reason a state-changing route stops needing a CSRF token "
                "check. "
            )
            + "Whether the value is a live session token, whether another layer rewrites "
            "the cookie, and whether the request is reachable cross-site have NOT been "
            "verified."
        ),
        fix_hint=(
            "Set httponly=True (Python) / httpOnly: true (TypeScript) on the session "
            "cookie, and keep the session token out of client-readable storage."
            if script
            else "Leave SameSite unset or set it to Lax/Strict. Use SameSite=None only "
            "when cross-site use is required, keep Secure on, and verify the request "
            "origin wherever the cookie authorizes a state change."
        ),
    )

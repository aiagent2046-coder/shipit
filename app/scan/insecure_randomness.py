"""A secret or token generated from a non-cryptographic random source.

``Math.random()`` and Python's ``random`` module are not cryptographically
secure: their state is predictable, so a token, password reset link, OTP or
nonce drawn from them can be guessed or replayed. This rule reads JS/TS and
Python as text (no native grammar) and reports a random draw whose result lands
in a name that announces it is a secret -- a token, secret, password, OTP,
reset, nonce, salt, credential, API key, confirmation or verification value.

It stays silent when the draw feeds anything else: an animation, a shuffle, a
random test value, a game. ``crypto.getRandomValues``, ``secrets.*`` and
``random.SystemRandom`` are the secure alternatives and are NOT sinks. Only the
dotted spelling is read -- a bare ``randint(...)`` bound by ``from random import
randint`` and an aliased ``import random as rnd`` are outside this rule's claim.
A helper that returns a draw (``def gen(): return random.randint(...)`` called as
``otp = gen()``) is cross-function taint this rule does not follow, and that is
the dominant residual rather than a hidden gap. The security word must sit on
the LEFT of an assignment to the draw, so ``random.choice(tokens)`` (picking
from a list named ``tokens``) is not reported. String literals and comments are
masked out before matching, so a mention in a docstring or comment is not a
decision. No uploaded code is executed.
"""

from __future__ import annotations

import re
import zipfile
from typing import BinaryIO

from app.scan.checks import CheckFinding
from app.scan.rule_coverage import RuleCoverage

RULE_ID = "insecure-randomness"
_FILE_SUFFIXES = (".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")
_MAX_FILE_BYTES = 400_000
_MAX_FILES = 400
_MAX_FINDINGS = 32

# A name that announces the drawn value is a secret. Substring, not word-boundary
# split, so resetToken / reset_token / password_reset all match. "passcode" and
# "recovery" are the synonyms the hunt produced that the first vocabulary missed.
_SECRET_WORDS = (
    "token", "secret", "password", "passwd", "passcode", "otp", "reset", "recovery", "nonce",
    "salt", "credential", "apikey", "api_key", "confirmation", "verification",
)

# security-name LEFT of an assignment to a non-cryptographic draw, on one line.
# Lazy so a name that IS the word (otp, salt, nonce) still matches, and
# case-insensitive so resetToken / API_KEY are recognised.
_ASSIGN = re.compile(
    r"(?P<name>\b\w*?(?:" + "|".join(_SECRET_WORDS) + r")\w*\b)"
    r"\s*(?::\s*[^=\n;]+)?=\s*"
    r"[^;\n]*?"
    r"\b(?:Math\.random|random\.(?:random|randint|randrange|choice|getrandbits|uniform|sample))\b",
    re.IGNORECASE,
)


def _masked_lines(text: str) -> list[str]:
    """The text with string literals and comments replaced by spaces.

    Positions are preserved (so a finding's line is still right), and a string
    or comment is never a place the assignment can match. Block comments may
    span lines.
    """
    lines = text.splitlines()
    out: list[str] = []
    in_block = False
    for line in lines:
        chars = list(line)
        i, n = 0, len(line)
        while i < n:
            if in_block:
                end = line.find("*/", i)
                if end == -1:
                    for j in range(i, n):
                        chars[j] = " "
                    i = n
                    break
                for j in range(i, end + 2):
                    chars[j] = " "
                i = end + 2
                in_block = False
                continue
            char = line[i]
            if char in ("'", '"', "`"):
                quote = char
                chars[i] = " "
                i += 1
                while i < n:
                    if line[i] == "\\":
                        chars[i] = " "
                        if i + 1 < n:
                            chars[i + 1] = " "
                            i += 2
                        else:
                            i += 1
                        continue
                    chars[i] = " "
                    if line[i] == quote:
                        i += 1
                        break
                    i += 1
                continue
            if char == "/" and i + 1 < n:
                if line[i + 1] == "/":
                    for j in range(i, n):
                        chars[j] = " "
                    break
                if line[i + 1] == "*":
                    chars[i] = " "
                    chars[i + 1] = " "
                    end = line.find("*/", i + 2)
                    if end == -1:
                        for j in range(i, n):
                            chars[j] = " "
                        in_block = True
                        i = n
                        break
                    for j in range(i, end + 2):
                        chars[j] = " "
                    i = end + 2
                    continue
            if char == "#":
                for j in range(i, n):
                    chars[j] = " "
                break
            i += 1
        out.append("".join(chars))
    return out


def scan_insecure_randomness(fileobj: BinaryIO, *, coverage: dict | None = None) -> list[CheckFinding]:
    findings: list[CheckFinding] = []
    with zipfile.ZipFile(fileobj) as archive:
        accounting = RuleCoverage(archive, extensions=_FILE_SUFFIXES,
                                  max_file_bytes=_MAX_FILE_BYTES, coverage=coverage)
        for info in accounting.files(findings, max_files=_MAX_FILES, max_findings=_MAX_FINDINGS):
            raw = archive.read(info)
            if b"Math.random" not in raw and b"random." not in raw:
                accounting.analyzed()
                continue
            try:
                text = raw.decode("utf-8")
            except UnicodeError:
                accounting.skip("decode_error")
                continue
            for line_no, line in enumerate(_masked_lines(text), start=1):
                for match in _ASSIGN.finditer(line):
                    if len(findings) >= _MAX_FINDINGS:
                        accounting.skip("finding_limit")
                        accounting.finish()
                        return findings
                    findings.append(_finding(info.filename, line_no, match.group("name")))
            accounting.analyzed()
        accounting.finish()
    return findings


def _finding(path: str, line: int, name: str) -> CheckFinding:
    return CheckFinding(
        rule_id=RULE_ID,
        title="A secret-looking value is generated from a non-cryptographic random source",
        severity="high",
        confidence=0.7,
        category="Security",
        file=path,
        line=line,
        explanation=(
            f"Line {line} draws a value into {name!r} from a non-cryptographic source "
            "(Math.random or Python's random module). That source is predictable, so a token, "
            "reset link, OTP or nonce built from it can be guessed or replayed -- the classic "
            "account-takeover vector. Whether the value is actually used as a secret, and whether "
            "anything else re-randomizes it, are NOT verified; the rule reads only that a "
            "secret-named value came from a predictable draw."
        ),
        fix_hint=(
            "Use a cryptographically secure source: crypto.getRandomValues in JS/TS, or Python's "
            "secrets module (secrets.token_hex / secrets.token_urlsafe). Never derive a token, "
            "password, reset link, OTP, nonce or salt from Math.random or the random module."
        ),
    )

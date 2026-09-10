"""TLS certificate verification switched off, in Python and in JS/TS.

WHY THIS EXISTS. Certificate verification is the one control that turns TLS from
"encrypted" into "encrypted with the party you meant". Switching it off is a
single line, it is nearly always added to make something work, and it survives into
production because nothing fails when it does -- the traffic still flows, it is just
no longer authenticated. Nothing in the static stage read for it: no rule in
app/scan matched `verify=False`, `ssl.CERT_NONE` or `rejectUnauthorized` at all.

WHAT IT REPORTS, AND WHAT IT DOES NOT CLAIM. Literal evidence that verification was
disabled: a call that passes `verify=False`, a context whose `check_hostname` or
`verify_mode` is set off, the `_create_unverified_context` helper, and on the
JS/TS side `rejectUnauthorized: false` and a `NODE_TLS_REJECT_UNAUTHORIZED` of 0.
That is a fact about the source. It is NOT a claim about intent or exposure: a
self-signed internal service, a test double and a debugging session all look the
same from here, which is why the finding says what the line does and lets the owner
say why. Silence is not a certificate that every connection in a repository is
verified either -- dynamic configuration, environment variables read at runtime and
shell/YAML surfaces are outside this rule.

TWO LANGUAGES, ONE CLAIM. app/scan/sql_injection.py shipped Python-only and its
sibling module later recorded why that was a mistake in a Next.js-dominated
product: a rule that reads only `.py` does not run on the typical customer's code.
The same argument applies here, and both halves carry literal evidence, so both are
in this module: an AST pass for `.py`, and a literal-pattern pass for `.js`/`.ts`
and their variants. The JS half does not need a parser because there is no
structural distinction to make -- the evidence IS the literal, unlike the SQL rule's
tagged-template versus interpolation.

NEVER EXECUTES THE UPLOADED CODE. `ast.parse` builds a tree over the bytes; the JS
half is a regular-expression read of text. Nothing is imported, run or fetched.
"""

from __future__ import annotations

import ast
import re
import zipfile
from dataclasses import dataclass
from typing import BinaryIO

from app.scan.checks import CheckFinding
from app.scan.secrets import is_non_production_path

RULE_ID = "tls-verification-disabled"

# Keyword names whose False value turns CERTIFICATE VERIFICATION off. The family is
# wide because every client spells it differently, and the hunt produced two
# spellings the first version missed (`ssl_validation=False`, and aiohttp's older
# `verify_ssl`). `verify=None` is NOT covered: for requests and httpx that means
# "use the default", which is verification ON, and reporting it would be an
# accusation with a fix that changes nothing.
#
# Deliberately NOT here: `use_ssl=False` (that disables TLS itself rather than the
# check on the certificate -- a different claim, and this rule states one claim) and
# `cafile=""` (an empty trust store makes the handshake FAIL; it does not accept
# every certificate).
_DISABLING_KEYWORDS = frozenset({
    "cert_verify", "ssl_validation", "ssl_verify", "tls_verify", "validate_certs",
    "verify", "verify_certs", "verify_ssl",
})

# The stdlib helper that exists to skip verification.
_UNVERIFIED_CONTEXTS = frozenset({"_create_unverified_context", "create_unverified_context"})

# Attributes that are set to a disabled state, and what "disabled" looks like for
# each. `check_hostname = False` and `verify_mode = ssl.CERT_NONE` are the two
# spellings a hand-built context uses.
_DISABLED_ATTRIBUTES = {
    # `session.verify = False` is how requests turns it off on a shared session.
    "verify": {"False"},
    "check_hostname": {"False"},
    "verify_mode": {"CERT_NONE"},
    "cert_reqs": {"CERT_NONE"},
}

# A client that takes `ssl=False` as an argument to skip verification.
_SSL_FALSE_CALLEES = frozenset({"TCPConnector"})

_JS_FILE_SUFFIXES = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")

# The literal evidence on the JS/TS side, each pattern paired with the claim it
# supports. Deliberately narrow: an identifier that merely mentions TLS is not a
# finding, and every pattern here is a value that switches verification off.
_JS_PATTERNS = (
    (re.compile(r"rejectUnauthorized\s*[:=]\s*false\b"), "rejectUnauthorized: false"),
    (re.compile(r"""NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*['"]?0['"]?"""),
     "NODE_TLS_REJECT_UNAUTHORIZED set to 0"),
)

# Mirrors the sibling scanners: bounded so a generated or vendored file cannot turn
# one archive into a parse storm.
_MAX_FILE_BYTES = 400_000
_MAX_FILES = 400
_MAX_FINDINGS = 32


@dataclass(frozen=True)
class _Evidence:
    """What was read, where, and the words the report uses for it."""
    line: int
    what: str


def _is_false(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and (node.value is False or node.value == 0)


def _attr_or_name(node: ast.AST) -> str:
    if isinstance(node, ast.Attribute):
        return node.attr
    return node.id if isinstance(node, ast.Name) else ""


def _target_attr(node: ast.AST) -> str:
    """The attribute an assignment writes to, looking through `self.ctx.` chains."""
    return node.attr if isinstance(node, ast.Attribute) else ""


def _python_evidence(tree: ast.AST) -> list[_Evidence]:
    found: list[_Evidence] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            callee = _attr_or_name(node.func)
            if callee in _UNVERIFIED_CONTEXTS:
                found.append(_Evidence(node.lineno, f"calls {callee}()"))
            for keyword in node.keywords:
                if keyword.arg in _DISABLING_KEYWORDS and _is_false(keyword.value):
                    found.append(_Evidence(node.lineno, f"passes {keyword.arg}=False"))
                if (keyword.arg == "ssl" and _is_false(keyword.value)
                        and callee in _SSL_FALSE_CALLEES):
                    found.append(_Evidence(node.lineno, f"passes ssl=False to {callee}()"))
            # `ssl.CERT_NONE` handed straight to a call argument.
            for arg in node.args:
                if isinstance(arg, ast.Attribute) and arg.attr == "CERT_NONE":
                    found.append(_Evidence(node.lineno, "uses ssl.CERT_NONE"))
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            if value is None:
                continue
            for target in targets:
                attr = _target_attr(target)
                if attr not in _DISABLED_ATTRIBUTES:
                    continue
                if isinstance(value, ast.Attribute) and value.attr in _DISABLED_ATTRIBUTES[attr]:
                    found.append(_Evidence(node.lineno, f"sets {attr} = {value.attr}"))
                elif "False" in _DISABLED_ATTRIBUTES[attr] and _is_false(value):
                    found.append(_Evidence(node.lineno, f"sets {attr} = False"))
    return found


def _js_line_context(line: str) -> tuple[list[tuple[int, int]], int]:
    """(quoted spans, index where a trailing comment starts) for one line.

    The rule reads text, so it has to know where CODE stops: `const DOC =
    "rejectUnauthorized: false"` is documentation, and a line that has been
    commented out is history. A naive left-to-right walk is enough -- it errs by
    treating an unterminated template as a span reaching the end of the line, which
    loses a finding rather than inventing one, and losing is the side this rule errs
    on everywhere else.
    """
    spans: list[tuple[int, int]] = []
    quote = ""
    start = 0
    index = 0
    while index < len(line):
        char = line[index]
        if quote:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                spans.append((start, index + 1))
                quote = ""
        elif char in "\"'`":
            quote = char
            start = index
        elif char == "/" and index + 1 < len(line) and line[index + 1] == "/":
            return spans, index
        index += 1
    if quote:
        spans.append((start, len(line)))
    return spans, len(line)


def _js_evidence(text: str) -> list[_Evidence]:
    found: list[_Evidence] = []
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith(("//", "*", "/*")):
            continue
        spans, comment_at = _js_line_context(line)
        for pattern, what in _JS_PATTERNS:
            match = pattern.search(line)
            if match is None:
                continue
            if match.start() >= comment_at:
                continue  # a trailing comment, not code
            if any(start <= match.start() < end for start, end in spans):
                continue  # inside a string literal: documentation, not a decision
            found.append(_Evidence(number, what))
            break
    return found


def scan_tls_verification(fileobj: BinaryIO) -> list[CheckFinding]:
    findings: list[CheckFinding] = []
    with zipfile.ZipFile(fileobj) as archive:
        infos = [info for info in archive.infolist()
                 if not info.is_dir() and info.file_size <= _MAX_FILE_BYTES
                 and (info.filename.endswith(".py") or info.filename.endswith(_JS_FILE_SUFFIXES))
                 and not is_non_production_path(info.filename)]
        for info in infos[:_MAX_FILES]:
            if len(findings) >= _MAX_FINDINGS:
                break
            try:
                text = archive.read(info).decode("utf-8")
            except (UnicodeError, ValueError):
                continue
            if info.filename.endswith(".py"):
                try:
                    evidence = _python_evidence(ast.parse(text))
                except (SyntaxError, ValueError, RecursionError):
                    # An unparseable file is one this rule could not read, which is
                    # not the same as a clean one; the coverage text says so.
                    continue
            else:
                evidence = _js_evidence(text)
            for item in evidence:
                if len(findings) >= _MAX_FINDINGS:
                    break
                findings.append(_finding(info.filename, item))
    return findings


def _finding(path: str, item: _Evidence) -> CheckFinding:
    return CheckFinding(
        rule_id=RULE_ID,
        title="TLS certificate verification is switched off",
        severity="high",
        # The source fact is certain -- the line says what it does and nothing here
        # is inferred. What is not known is whether it matters: an internal service,
        # a test double or a debugging session is why the line was written, and this
        # rule cannot read the reason.
        confidence=0.9,
        category="Security",
        file=path,
        line=item.line,
        explanation=(
            f"Line {item.line} {item.what}, so this connection accepts ANY certificate the "
            "other side presents. Encryption still happens; authentication does not, which "
            "means anything able to answer for that address -- a proxy, a spoofed DNS answer, "
            "a machine on the same network -- is accepted as the party the code meant to "
            "reach. Why verification was turned off has NOT been read: an internal service "
            "with a self-signed certificate and a debugging session look identical here."
        ),
        fix_hint=(
            "Turn verification back on and make the trust explicit instead: point the client "
            "at the certificate authority that signed your service's certificate (REQUESTS_CA_BUNDLE "
            "/ SSL_CERT_FILE / NODE_EXTRA_CA_CERTS, or an explicit cafile/CA argument). If the "
            "certificate is self-signed, sign it with an internal CA the client is told to trust "
            "rather than disabling the check that would have caught an impostor."
        ),
    )

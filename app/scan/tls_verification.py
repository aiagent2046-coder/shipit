"""Bounded, source-only TLS certificate/hostname verification configuration.

Python imports and local client/context aliases establish which API a setting
belongs to. JS/TS is parsed as syntax, and only runtime options for recognised
Node https/tls calls or process.env are read. Neither language executes target
source. Findings describe configuration; connections and exploitability remain
unverified. Dynamic helpers and configuration outside these files are unresolved.
"""

from __future__ import annotations

import zipfile
from typing import BinaryIO

from app.scan.checks import CheckFinding
from app.scan.rule_coverage import RuleCoverage
from app.scan.tls_verification_js import js_evidence
from app.scan.tls_verification_python import python_evidence

RULE_ID = "tls-verification-disabled"
_JS_FILE_SUFFIXES = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")
_MAX_FILE_BYTES = 400_000
_MAX_FILES = 400
_MAX_FINDINGS = 32


def scan_tls_verification(fileobj: BinaryIO, *, coverage: dict | None = None) -> list[CheckFinding]:
    findings = []
    seen = set()
    with zipfile.ZipFile(fileobj) as archive:
        accounting = RuleCoverage(archive, extensions=(".py", *_JS_FILE_SUFFIXES),
                                  max_file_bytes=_MAX_FILE_BYTES, coverage=coverage)
        for info in accounting.files(findings, max_files=_MAX_FILES, max_findings=_MAX_FINDINGS):
            incomplete: dict[str, str] = {}
            try:
                text = archive.read(info).decode("utf-8")
            except UnicodeError:
                accounting.skip("decode_error")
                continue
            try:
                evidence = (
                    python_evidence(text, incomplete_reason=incomplete)
                    if info.filename.endswith(".py")
                    else js_evidence(text, tsx=info.filename.endswith((".tsx", ".jsx")),
                                     incomplete_reason=incomplete)
                )
            except (SyntaxError, ValueError):
                accounting.skip("parse_error")
                continue
            except RecursionError:
                accounting.skip("ast_limit")
                continue
            for line, what, kind in evidence:
                key = (info.filename, line, what, kind)
                if key in seen:
                    continue
                if len(findings) >= _MAX_FINDINGS:
                    incomplete["reason"] = "finding_limit"
                    break
                seen.add(key)
                findings.append(_finding(info.filename, line, what, kind))
            if incomplete:
                accounting.skip(incomplete["reason"])
            else:
                accounting.analyzed()
        accounting.finish()
    return findings


def _finding(path, line, what, kind):
    hostname = kind == "hostname"
    return CheckFinding(
        rule_id=RULE_ID,
        title=(
            "TLS hostname verification is switched off" if hostname else "TLS certificate verification is switched off"
        ),
        severity="high",
        confidence=0.9,
        category="Security",
        file=path,
        line=line,
        explanation=(
            f"Line {line} {what}. "
            + (
                "This disables matching the certificate to the expected hostname. Certificate-chain "
                "validation may still be enabled; this setting does not make every certificate acceptable. "
                if hostname
                else "This configures a recognised TLS client or SSL context to skip certificate-chain "
                "validation. If used without another peer-identity control, it can accept an untrusted peer. "
            )
            + "The source configuration is visible; runtime connections, external controls and exposure "
            "have not been verified. Why verification was turned off has NOT been read."
        ),
        fix_hint=(
            "Restore check_hostname=True and pass the expected server hostname when opening TLS. "
            "A trusted certificate chain alone does not ensure the certificate belongs to the requested host."
            if hostname
            else "Enable certificate verification and configure the trusted CA explicitly, using the supported "
            "client CA/context option (or REQUESTS_CA_BUNDLE / SSL_CERT_FILE / NODE_EXTRA_CA_CERTS where "
            "the client supports it). Keep hostname verification enabled and test the actual connection."
        ),
    )

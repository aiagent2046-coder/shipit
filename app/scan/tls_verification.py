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
from app.scan.secrets import is_dependency_path, is_non_production_path
from app.scan.tls_verification_js import js_evidence
from app.scan.tls_verification_python import python_evidence

RULE_ID = "tls-verification-disabled"
_JS_FILE_SUFFIXES = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")
_MAX_FILE_BYTES = 400_000
_MAX_FILES = 400
_MAX_FINDINGS = 32


def scan_tls_verification(fileobj: BinaryIO) -> list[CheckFinding]:
    findings = []
    seen = set()
    with zipfile.ZipFile(fileobj) as archive:
        infos = [
            info
            for info in archive.infolist()
            if not info.is_dir()
            and info.file_size <= _MAX_FILE_BYTES
            and (info.filename.endswith(".py") or info.filename.endswith(_JS_FILE_SUFFIXES))
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

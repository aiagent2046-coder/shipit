"""Deterministic presence checks over the archive file listing.

Cheap signals that need no code analysis: a committed .env, absence of
tests, Dockerfile or CI. Each check yields at most one finding.
"""

from __future__ import annotations

import zipfile
from dataclasses import dataclass
from typing import BinaryIO


@dataclass(frozen=True)
class CheckFinding:
    rule_id: str
    title: str
    severity: str
    confidence: float
    category: str
    file: str = ""


def _strip_root(names: list[str]) -> list[str]:
    """Normalize single-root exports (Lovable/Bolt wrap in one folder)."""
    tops = {n.split("/", 1)[0] for n in names if n.strip("/")}
    if len(tops) == 1 and all("/" in n or n.endswith("/") for n in names):
        root = next(iter(tops)) + "/"
        return [n[len(root):] for n in names if n != root]
    return names


def run_checks(fileobj: BinaryIO) -> list[CheckFinding]:
    with zipfile.ZipFile(fileobj) as zf:
        names = _strip_root(zf.namelist())

    findings: list[CheckFinding] = []
    files = [n for n in names if not n.endswith("/")]

    committed_env = [
        n for n in files
        if n == ".env" or n.endswith("/.env")
        or (n.rsplit("/", 1)[-1].startswith(".env.")
            and not n.endswith(".env.example"))
    ]
    if committed_env:
        findings.append(CheckFinding(
            "env-file-committed", "Environment file committed to repository",
            severity="critical", confidence=0.9, category="Security",
            file=committed_env[0],
        ))

    has_tests = any(
        "test" in n.rsplit("/", 1)[-1].lower() and n.endswith((".py", ".ts", ".tsx", ".js"))
        for n in files
    )
    if not has_tests:
        findings.append(CheckFinding(
            "no-tests", "No test files found",
            severity="medium", confidence=0.8, category="Testing",
        ))

    if not any(n.rsplit("/", 1)[-1] == "Dockerfile" for n in files):
        findings.append(CheckFinding(
            "no-dockerfile", "No Dockerfile — app is not containerized",
            severity="low", confidence=0.9, category="Deploy",
        ))

    if not any(n.startswith(".github/workflows/") for n in files):
        findings.append(CheckFinding(
            "no-ci", "No CI workflow found",
            severity="low", confidence=0.9, category="Deploy",
        ))

    return findings

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


def find_committed_env_files(files: list[str]) -> list[str]:
    """The committed env files a repo should never track: `.env` itself
    and any `.env.<something>` except `.env.example`. Shared by run_checks
    (to fire env-file-committed) and the Fix Pack generator (to know which
    files to untrack), so both agree on exactly what counts."""
    return [
        n for n in files
        if n == ".env" or n.endswith("/.env")
        or (n.rsplit("/", 1)[-1].startswith(".env.")
            and not n.endswith(".env.example"))
    ]


def gitignore_covers_env(gitignore_body: str) -> bool:
    """Whether a .gitignore's text already ignores .env. Same predicate
    run_checks uses to decide gitignore-missing-secrets, exposed so the
    Fix Pack generator can avoid appending a pattern that's already there."""
    return any(
        line.strip() in (".env", ".env*", "*.env", ".env.*")
        for line in gitignore_body.splitlines()
    )


def run_checks(fileobj: BinaryIO) -> list[CheckFinding]:
    with zipfile.ZipFile(fileobj) as zf:
        raw_names = zf.namelist()
        names = _strip_root(raw_names)
        # Read the root .gitignore's bytes while the zip is open. After
        # root-stripping it is exactly ".gitignore"; the original entry is
        # either top-level or prefixed by the single wrapping folder.
        gitignore_body = ""
        gitignore_raw = next(
            (n for n in raw_names
             if n == ".gitignore" or n.endswith("/.gitignore")),
            None,
        )
        if gitignore_raw is not None:
            gitignore_body = zf.read(gitignore_raw).decode("utf-8", errors="ignore")

    findings: list[CheckFinding] = []
    files = [n for n in names if not n.endswith("/")]

    committed_env = find_committed_env_files(files)
    if committed_env:
        findings.append(CheckFinding(
            "env-file-committed", "Environment file committed to repository",
            severity="critical", confidence=0.9, category="Security",
            file=committed_env[0],
        ))

    # A .gitignore that doesn't cover .env is how the committed-env leak
    # above happens in the first place: without it, the next `git add`
    # sweeps secret-bearing files back in. Fire when there's no
    # .gitignore at all, or one that doesn't ignore .env.
    gitignore = next((n for n in files if n == ".gitignore"), None)
    covers_env = gitignore_covers_env(gitignore_body)
    if not covers_env:
        findings.append(CheckFinding(
            "gitignore-missing-secrets",
            "No .gitignore coverage for secret-bearing files"
            if gitignore is None
            else ".gitignore does not cover .env / secret files",
            severity="high", confidence=0.8, category="Security",
            file=gitignore or "",
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

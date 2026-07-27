#!/usr/bin/env python3
"""Fail when newly added Git lines contain strong secret signatures."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from collections.abc import Sequence


PATTERNS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    (
        "private-key-header",
        re.compile(
            rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
        ),
    ),
    (
        "aws-access-key",
        re.compile(rb"AKIA[0-9A-Z]{16}"),
    ),
    (
        "github-token",
        re.compile(rb"gh[pousr]_[A-Za-z0-9_]{36,}"),
    ),
    (
        "github-fine-grained-token",
        re.compile(rb"github_pat_[A-Za-z0-9_]{70,}"),
    ),
    (
        "openai-project-key",
        re.compile(rb"sk-(?:proj|svcacct)-[A-Za-z0-9_-]{32,}"),
    ),
    (
        # Direct Anthropic fallback provider (ANTHROPIC_API_KEY, sent as the
        # x-api-key header in app/llm/client.py). Format mirrors the project's
        # own audit scanner, app/scan/secrets.py.
        "anthropic-api-key",
        re.compile(rb"sk-ant-api03-[A-Za-z0-9_-]{20,}"),
    ),
    (
        # Primary LLM provider (AITUNNEL_API_KEY). The repo does not pin the
        # key format anywhere, so this matches AITunnel's documented public
        # "sk-aitunnel-" prefix; the prefix is specific enough to avoid false
        # positives on ordinary code.
        "aitunnel-api-key",
        re.compile(rb"sk-aitunnel-[A-Za-z0-9_-]{20,}"),
    ),
    (
        # Telegram bot token (TELEGRAM_BOT_TOKEN): "<8-10 digits>:<35 chars>".
        # Boundaries keep it off ordinary "number:string" code: the leading
        # look-behind rejects a longer digit run and the trailing look-ahead
        # pins the secret half to exactly 35 characters. Mirrors the length
        # bounds used in app/scan/secrets.py.
        "telegram-bot-token",
        re.compile(
            rb"(?<![0-9A-Za-z_-])[0-9]{8,10}:[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])"
        ),
    ),
    (
        # Connection string carrying an EMBEDDED password
        # (postgres://user:password@host, e.g. a Supabase pooler URL). Requires
        # a non-empty "user:password@" userinfo, so a passwordless URL
        # (postgres://user@host) or the bare DATABASE_URL variable name is not
        # flagged -- only a real leaked password is.
        "postgres-url-password",
        re.compile(rb"postgres(?:ql)?://[^:/?#@\s]+:[^@/?#\s]+@"),
    ),
)


# Files that BY DESIGN carry secret-format samples: the scanner itself (every
# pattern above literally spells out a secret prefix), its test suite (a
# positive fixture per pattern), and the log-redaction test suite (a fake secret
# of each shape, because a redaction test that carries no secret-shaped string
# proves nothing). Scanning them flags the scanner against its own definitions
# on every change that touches them, so they are excluded here -- the
# self-exclusion that secret scanners (gitleaks, detect-secrets) carry for their
# own rule/fixture files. Kept next to PATTERNS so a pattern author sees the
# allowlist in the same place they add a signature.
#
# Excluded WHOLE, not line-filtered: the entire purpose of these files is to
# enumerate secret formats, so there is no "real code" in them worth scanning
# for the same signatures. Detection is still tested --
# tests/test_scan_added_secrets.py exercises PATTERNS directly in-process (it
# imports this module and calls pattern.search on synthetic blobs), NOT by
# asking this script to git-diff-scan a file, so the exclusion does not weaken
# the tests.
EXCLUDED_PATHS: frozenset[str] = frozenset(
    {
        ".github/scripts/scan-added-secrets.py",
        "tests/test_scan_added_secrets.py",
        "tests/test_logging_config.py",
    }
)


def run_git(arguments: Sequence[str]) -> bytes:
    completed = subprocess.run(
        ["git", *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    if completed.returncode != 0:
        message = completed.stderr.decode(
            "utf-8",
            errors="replace",
        ).strip()

        raise RuntimeError(
            f"git {' '.join(arguments)} failed: {message}"
        )

    return completed.stdout


def changed_files(base: str, head: str) -> list[str]:
    output = run_git(
        [
            "diff",
            "--name-only",
            "-z",
            "--diff-filter=ACMR",
            base,
            head,
            "--",
        ]
    )

    return [
        os.fsdecode(raw_path)
        for raw_path in output.split(b"\0")
        if raw_path
    ]


def added_lines(base: str, head: str, path: str) -> bytes:
    output = run_git(
        [
            "diff",
            "--unified=0",
            "--no-color",
            "--no-ext-diff",
            base,
            head,
            "--",
            path,
        ]
    )

    collected: list[bytes] = []
    inside_hunk = False

    for line in output.splitlines():
        if line.startswith(b"diff --git "):
            inside_hunk = False
            continue

        if line.startswith(b"@@"):
            inside_hunk = True
            continue

        if inside_hunk and line.startswith(b"+"):
            collected.append(line[1:])

    return b"\n".join(collected)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("base")
    parser.add_argument("head")
    arguments = parser.parse_args()

    files = [
        path
        for path in changed_files(arguments.base, arguments.head)
        if path not in EXCLUDED_PATHS
    ]
    findings: set[tuple[str, str]] = set()

    for path in files:
        content = added_lines(
            arguments.base,
            arguments.head,
            path,
        )

        for signature_name, pattern in PATTERNS:
            if pattern.search(content):
                findings.add((path, signature_name))

    if findings:
        for path, signature_name in sorted(findings):
            print(
                "Potential secret signature added in "
                f"{path} ({signature_name})",
                file=sys.stderr,
            )

        return 1

    print(
        f"Scanned added lines in {len(files)} changed files; "
        "no strong secret signatures detected."
    )

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as error:
        print(error, file=sys.stderr)
        raise SystemExit(2) from error

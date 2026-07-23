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
)


def run_git(arguments: Sequence[str]) -> bytes:
    completed = subprocess.run(
        ["git", *arguments],
        capture_output=True,
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

    files = changed_files(arguments.base, arguments.head)
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

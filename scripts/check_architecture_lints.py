"""Strict zero-debt wide-directory and long-file architecture limits.

Enforces the two structural size limits of the deslop-please method across the
Python codebase (app/, scripts/, tests/) with zero exemptions:
- long-file: a Python file over 2000 lines;
- wide-directory: a directory holding more than 15 members (regular files plus
  subdirectories that hold at least one file).

tests/detectors/** and tests/fixtures/** are detector corpora -- deliberate data
trees that grow with every new detector -- so they are excluded from
wide-directory; long-file still applies to any Python file there.

Usage:
    python scripts/check_architecture_lints.py
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

MOST_MEMBERS = 15
MOST_LINES = 2000
SCOPE = ("app", "scripts", "tests")
WIDE_EXCLUDED_PREFIXES = ("tests/detectors", "tests/fixtures")
FORBIDDEN_ALLOW_FILE = ".architecture-lint-allow.json"


def _count_members(directory: Path) -> int:
    """Regular files plus subdirectories that hold at least one file below
    (ignoring __pycache__), counted without descending."""
    files = 0
    subdirs = 0
    for entry in sorted(directory.iterdir()):
        if entry.name == "__pycache__":
            continue
        if entry.is_file():
            files += 1
        elif entry.is_dir() and _holds_any_file(entry):
            subdirs += 1
    return files + subdirs


def _holds_any_file(directory: Path) -> bool:
    for path in directory.rglob("*"):
        if "__pycache__" in path.parts:
            continue
        if path.is_file():
            return True
    return False


def measure(root: Path) -> dict[str, dict[str, int]]:
    long_files: dict[str, int] = {}
    wide_directories: dict[str, int] = {}
    for scope in SCOPE:
        base = root / scope
        if not base.is_dir():
            continue
        for directory, subdirs, files in os.walk(base):
            subdirs[:] = sorted(d for d in subdirs if d != "__pycache__")
            rel_dir = Path(directory).relative_to(root).as_posix()
            if not any(rel_dir == prefix or rel_dir.startswith(prefix + "/")
                       for prefix in WIDE_EXCLUDED_PREFIXES):
                members = _count_members(Path(directory))
                if members > MOST_MEMBERS:
                    wide_directories[rel_dir] = members
            for name in sorted(files):
                if not name.endswith(".py"):
                    continue
                rel = Path(directory, name).relative_to(root).as_posix()
                with open(Path(directory, name), encoding="utf-8",
                          errors="replace") as handle:
                    lines = sum(1 for _ in handle)
                if lines > MOST_LINES:
                    long_files[rel] = lines
    return {"long_file": long_files, "wide_directory": wide_directories}


def check(current: dict[str, dict[str, int]],
          root: Path | None = None) -> list[str]:
    """Return one message per structural limit violation (zero-debt policy)."""
    problems: list[str] = []
    if root is not None and (root / FORBIDDEN_ALLOW_FILE).exists():
        problems.append(
            f"FORBIDDEN allow-file: {FORBIDDEN_ALLOW_FILE} exists -- "
            f"architecture size limits enforce strict zero debt; delete it")
    for lint in ("long_file", "wide_directory"):
        unit = f"lines > {MOST_LINES}" if lint == "long_file" else f"members > {MOST_MEMBERS}"
        for path in sorted(current[lint]):
            count = current[lint][path]
            noun = "lines" if lint == "long_file" else "members"
            problems.append(
                f"{lint.replace('_', '-')}: {path} ({count} {noun}; limit is "
                f"<= {MOST_LINES if lint == 'long_file' else MOST_MEMBERS}, "
                f"found {unit}) -- split or narrow without allow-list exemptions")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path,
                        default=Path(__file__).resolve().parents[1])
    args = parser.parse_args(argv)
    root = args.root.resolve()
    current = measure(root)
    problems = check(current, root=root)
    for problem in problems:
        print(problem)
    if problems:
        return 1
    print("architecture-lints KEPT (strict zero-debt)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

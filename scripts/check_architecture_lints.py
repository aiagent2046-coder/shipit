"""Wide-directory and long-file architecture limits with a ratchet allow list.

Ports the two counting lints of the deslop-please method (thresholds are the
method's, rationale in its source): long-file -- a Python file over 2000
lines; wide-directory -- a directory holding more than 15 members (regular
files plus subdirectories that hold at least one file). Scope is the Python
codebase (app/, scripts/, tests/). tests/detectors/** and tests/fixtures/**
are detector corpora -- deliberate data trees that grow with every new
detector -- so they are excluded from wide-directory; long-file still
applies to any Python file there.

Usage:
    python scripts/check_architecture_lints.py                 # fail on NEW debt
    python scripts/check_architecture_lints.py --update-allow  # rewrite the baseline

The allow list (.architecture-lint-allow.json at the repository root)
suppresses known debt by path; anything NEW fails the check. Stale entries
(a file that shrank below the limit, a directory that narrowed) also fail,
so the list cannot rot behind refactors. A suppressed path may still grow
without complaint -- the ratchet tracks where the debt is, not how big it
has become.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

MOST_MEMBERS = 15
MOST_LINES = 2000
SCOPE = ("app", "scripts", "tests")
WIDE_EXCLUDED_PREFIXES = ("tests/detectors", "tests/fixtures")
ALLOW_FILE = ".architecture-lint-allow.json"


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
                lines = sum(1 for _ in open(Path(directory, name), encoding="utf-8",
                                            errors="replace"))
                if lines > MOST_LINES:
                    long_files[rel] = lines
    return {"long_file": long_files, "wide_directory": wide_directories}


def check(current: dict[str, dict[str, int]],
          allowed: dict[str, dict[str, int]]) -> list[str]:
    """Return one message per problem: new debt, or a stale allow entry."""
    problems = []
    for lint in ("long_file", "wide_directory"):
        for path in sorted(current[lint]):
            if path not in allowed.get(lint, {}):
                problems.append(
                    f"NEW {lint.replace('_', '-')}: {path} "
                    f"({current[lint][path]} {'lines' if lint == 'long_file' else 'members'}) "
                    f"-- refit under the limit or record it with --update-allow")
        for path in sorted(allowed.get(lint, {})):
            if path not in current[lint]:
                problems.append(
                    f"STALE {lint.replace('_', '-')}: {path} is in the allow list "
                    f"but no longer over the limit -- remove it with --update-allow")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path,
                        default=Path(__file__).resolve().parents[1])
    parser.add_argument("--update-allow", action="store_true",
                        help="rewrite the allow list with the current measurements")
    args = parser.parse_args()
    root = args.root.resolve()
    current = measure(root)
    allow_path = root / ALLOW_FILE
    if args.update_allow:
        allow_path.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n",
                              encoding="utf-8")
        recorded = sum(len(v) for v in current.values())
        print(f"architecture-lints UPDATED ({recorded} allowed entries recorded)")
        return 0
    try:
        allowed = json.loads(allow_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        allowed = {"long_file": {}, "wide_directory": {}}
    problems = check(current, allowed)
    for problem in problems:
        print(problem)
    if problems:
        return 1
    recorded = sum(len(v) for v in allowed.values())
    print(f"architecture-lints KEPT ({recorded} allowed)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

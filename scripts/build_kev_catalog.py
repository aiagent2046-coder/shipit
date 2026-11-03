#!/usr/bin/env python3
"""Compile a complete, reproducible KEV snapshot from an inert official Git checkout."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

OFFICIAL_REPOSITORY = "https://github.com/cisagov/kev-data"
OFFICIAL_REMOTES = {
    OFFICIAL_REPOSITORY, OFFICIAL_REPOSITORY + ".git",
    "git@github.com:cisagov/kev-data.git", "ssh://git@github.com/cisagov/kev-data.git",
}
SOURCE_FILE = "known_exploited_vulnerabilities.json"
MAX_UPSTREAM_BYTES = 16 * 1024 * 1024


def _git(source: Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
         "-C", str(source), *args], check=True, capture_output=True,
        env={**os.environ, "GIT_NO_REPLACE_OBJECTS": "1"}, timeout=30,
    ).stdout


def build_snapshot(source: Path) -> bytes:
    from app.scan.kev_catalog import decode_catalog, encode_catalog, normalize_upstream

    if _git(source, "remote", "get-url", "origin").decode().strip() not in OFFICIAL_REMOTES:
        raise ValueError("origin must be the official CISA KEV repository")
    if _git(source, "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("source checkout must be clean, including untracked files")
    commit = _git(source, "rev-parse", "HEAD^{commit}").decode().strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("source HEAD must resolve to a complete Git commit SHA")
    committed_at = _git(source, "show", "-s", "--format=%cI", commit).decode().strip()
    row = _git(source, "ls-tree", commit, "--", SOURCE_FILE).decode().strip().split()
    if len(row) != 4 or row[0:2] != ["100644", "blob"] or row[3] != SOURCE_FILE:
        raise ValueError("KEV input must be a regular non-executable JSON Git blob")
    oid = row[2]
    if not 0 < int(_git(source, "cat-file", "-s", oid)) <= MAX_UPSTREAM_BYTES:
        raise ValueError("KEV upstream size limit")
    # A concurrent worktree edit cannot change bytes attributed to the pinned commit.
    raw = _git(source, "cat-file", "blob", oid)
    snapshot = encode_catalog(normalize_upstream(raw, commit, committed_at))
    decode_catalog(snapshot, hashlib.sha256(snapshot).hexdigest())
    if _git(source, "rev-parse", "HEAD^{commit}").decode().strip() != commit:
        raise ValueError("source HEAD changed during compilation")
    return snapshot


def _replace(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
        handle.write(raw)
        temporary = Path(handle.name)
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path, help="clean official cisagov/kev-data checkout")
    parser.add_argument("--output", type=Path, default=PROJECT_ROOT / "app/data/kev-catalog.json")
    parser.add_argument("--check", action="store_true", help="rebuild and compare both outputs; write nothing")
    args = parser.parse_args(argv)
    try:
        raw = build_snapshot(args.source.resolve())
        digest = hashlib.sha256(raw).hexdigest()
        receipt = args.output.with_suffix(args.output.suffix + ".sha256")
        outputs = {args.output: raw, receipt: (digest + "\n").encode("ascii")}
        if args.check:
            for path, expected in outputs.items():
                if not path.is_file() or path.read_bytes() != expected:
                    raise ValueError(f"generated output does not match pinned source: {path}")
        else:
            for path, expected in outputs.items():
                _replace(path, expected)
        value = json.loads(raw)
        print(json.dumps({"catalog_sha256": digest, "entries": len(value["entries"]), "source": value["source"]},
                         sort_keys=True))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"KEV compilation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

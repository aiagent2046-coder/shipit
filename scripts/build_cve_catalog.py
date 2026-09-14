#!/usr/bin/env python3
"""Compile pinned CVE and reviewed GHSA Git data as one inert offline snapshot.

The compiler does not execute anything in either source checkout, follow
advisory links, install packages, or train a classifier. A rebuild replaces the
whole snapshot so rejected, withdrawn, changed, and deleted records cannot
linger in an index.
"""

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
from typing import Iterator

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

OFFICIAL_REPOSITORY = "https://github.com/CVEProject/cvelistV5"
OFFICIAL_REMOTES = {
    OFFICIAL_REPOSITORY, OFFICIAL_REPOSITORY + ".git",
    "git@github.com:CVEProject/cvelistV5.git",
    "ssh://git@github.com/CVEProject/cvelistV5.git",
}
OFFICIAL_GHSA_REPOSITORY = "https://github.com/github/advisory-database"
OFFICIAL_GHSA_REMOTES = {
    OFFICIAL_GHSA_REPOSITORY, OFFICIAL_GHSA_REPOSITORY + ".git",
    "git@github.com:github/advisory-database.git",
    "ssh://git@github.com/github/advisory-database.git",
}


def _git(source: Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
         "-C", str(source), *args], check=True, capture_output=True,
        env={**os.environ, "GIT_NO_REPLACE_OBJECTS": "1"},
    ).stdout


def source_identity(source: Path, official_remotes: set[str] = OFFICIAL_REMOTES) -> tuple[str, str]:
    if _git(source, "remote", "get-url", "origin").decode().strip() not in official_remotes:
        raise ValueError("origin must be an official advisory repository")
    if _git(source, "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("source checkout must be clean, including untracked files")
    commit = _git(source, "rev-parse", "HEAD^{commit}").decode().strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("source HEAD must resolve to a complete Git commit SHA")
    # Commit time, rather than wall clock, makes repeated builds byte-identical.
    generated_at = _git(source, "show", "-s", "--format=%cI", commit).decode().strip()
    return commit, generated_at


def source_blobs(\n    source: Path, commit: str, tree_path: str = "cves"\n) -> list[tuple[str, str]]:
    blobs = []
    for entry in _git(source, "ls-tree", "-r", "-z", commit, "--", tree_path).split(b"\0"):
        if not entry:
            continue
        metadata, raw_path = entry.split(b"\t", 1)
        path = raw_path.decode("utf-8")
        if not path.endswith(".json"):
            continue
        mode, kind, oid = metadata.decode("ascii").split()
        if mode != "100644" or kind != "blob":
            raise ValueError(f"input must be a regular non-executable JSON blob: {path}")
        blobs.append((path, oid))
    if not blobs:
        raise ValueError(f"source commit contains no JSON records under {tree_path}")
    return sorted(blobs)


def read_records(source: Path, blobs: list[tuple[str, str]]) -> Iterator[dict]:
    # Reading objects by ID guarantees that file changes during a long build
    # cannot produce a snapshot falsely attributed to the pinned commit.
    process = subprocess.Popen(
        ["git", "-C", str(source), "cat-file", "--batch"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={**os.environ, "GIT_NO_REPLACE_OBJECTS": "1"},
    )
    try:
        assert process.stdin is not None and process.stdout is not None
        for path, oid in blobs:
            process.stdin.write((oid + "\n").encode("ascii"))
            process.stdin.flush()
            header = process.stdout.readline().decode("ascii").split()
            if len(header) != 3 or header[:2] != [oid, "blob"]:
                raise ValueError(f"could not read pinned CVE blob: {path}")
            raw = process.stdout.read(int(header[2]))
            if process.stdout.read(1) != b"\n":
                raise ValueError(f"truncated pinned CVE blob: {path}")
            try:
                record = json.loads(raw)
            except (ValueError, UnicodeError) as exc:
                raise ValueError(f"invalid JSON in {path}: {exc}") from exc
            if not isinstance(record, dict):
                raise ValueError(f"advisory record must be a JSON object: {path}")
            yield record
        process.stdin.close()
        if process.wait() != 0:
            raise ValueError("git cat-file failed while reading source records")
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate() if process.stdin and not process.stdin.closed else process.wait()
        if process.stdout:
            process.stdout.close()
        if process.stderr:
            process.stderr.close()


def encode_json(value: dict) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def build_snapshot(source: Path, ghsa_source: Path | None = None) -> tuple[bytes, bytes]:
    from app.scan.cve_catalog import build_catalog
    from app.scan.ghsa_catalog import merge_reviewed_ghsa

    commit, generated_at = source_identity(source)
    blobs = source_blobs(source, commit)
    # These two upstream change indexes are JSON, but are not CVE records.
    # Full snapshots must read records directly rather than replay delta logs.
    metadata = {"cves/delta.json", "cves/deltaLog.json"}
    record_blobs = [(path, oid) for path, oid in blobs if path not in metadata]
    if any(not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}\.json", Path(path).name) for path, _ in record_blobs):
        raise ValueError("unexpected JSON path in cves tree; review upstream layout before compiling")
    catalog = build_catalog(read_records(source, record_blobs),
                            source_commit=commit, generated_at=generated_at)
    ghsa_blobs: list[tuple[str, str]] = []
    if ghsa_source is not None:
        ghsa_commit, ghsa_generated_at = source_identity(ghsa_source, OFFICIAL_GHSA_REMOTES)
        ghsa_blobs = source_blobs(
            ghsa_source, ghsa_commit, "advisories/github-reviewed"
        )
        path_pattern = re.compile(
            r"advisories/github-reviewed/[0-9]{4}/[0-9]{2}/"
            r"(GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-"
            r"[23456789cfghjmpqrvwx]{4})/\1\.json"
        )
        if any(not path_pattern.fullmatch(path) for path, _ in ghsa_blobs):
            raise ValueError(
                "unexpected JSON path in github-reviewed tree; review upstream layout before compiling"
            )
        catalog = merge_reviewed_ghsa(
            catalog, read_records(ghsa_source, ghsa_blobs),
            source_commit=ghsa_commit, generated_at=ghsa_generated_at,
        )
        if _git(ghsa_source, "rev-parse", "HEAD").decode().strip() != ghsa_commit:
            raise ValueError("GHSA source HEAD changed during compilation")

    if _git(source, "rev-parse", "HEAD").decode().strip() != commit:
        raise ValueError("CVE source HEAD changed during compilation")
    data = encode_json(catalog)
    packages = catalog["packages"]
    summary = {
        "schema": 1, "kind": "knowledge_compilation", "classifier_trained": False,
        "customer_outcomes_added": 0, "source": catalog["source"],
        "sources": catalog.get("sources", {"cvelist": catalog["source"]}),
        "catalog_sha256": hashlib.sha256(data).hexdigest(),
        "stats": {
            **catalog["stats"],
            "source_json_files": len(blobs),
            "source_record_json_files": len(record_blobs),
            "skipped_source_metadata_files": len(blobs) - len(record_blobs),
            "ghsa_source_json_files": len(ghsa_blobs),
        },
        "coverage": {
            "ecosystems": ["npm", "PyPI"],
            "packages_by_ecosystem": {
                ecosystem: sum(key.startswith(ecosystem + ":") for key in packages)
                for ecosystem in ("npm", "PyPI")
            },
            "sources": sorted(catalog.get("sources", {"cvelist": catalog["source"]})),
            "scope": (
                "Explicit npm/PyPI identity; confirmed matches require supported "
                "CVE constraints or OSV event ranges"
            ),
            "unresolved_is_safe": False,
            "complete_vulnerability_database": False,
        },
    }
    return data, encode_json(summary)

def _replace(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as temp:
        temp.write(data)
        temporary = Path(temp.name)
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path, help="clean local official cvelistV5 Git checkout")
    parser.add_argument(
        "--ghsa-source", type=Path,
        help="clean local official github/advisory-database checkout; omit only for legacy CVE-only rebuilds",
    )
    parser.add_argument("--output", type=Path, default=PROJECT_ROOT / "app/data/cve-catalog.json")
    parser.add_argument("--summary", type=Path, default=PROJECT_ROOT / "app/data/cve-learning.json")
    parser.add_argument("--check", action="store_true", help="verify all outputs match a rebuild; write nothing")
    args = parser.parse_args(argv)
    try:
        catalog, summary = build_snapshot(
            args.source.resolve(),
            args.ghsa_source.resolve() if args.ghsa_source else None,
        )
        digest = hashlib.sha256(catalog).hexdigest()
        outputs = {args.output: catalog, args.summary: summary,
                   args.output.with_suffix(args.output.suffix + ".sha256"):
                       f"{digest}  {args.output.name}\n".encode("ascii")}
        if len(outputs) != 3:
            raise ValueError("catalog, summary, and digest paths must be distinct")
        for path, content in outputs.items():
            if args.check:
                if not path.exists() or path.read_bytes() != content:
                    raise ValueError(f"generated output does not match pinned source: {path}")
            else:
                _replace(path, content)
        print(summary.decode("utf-8").strip())
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"CVE compilation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

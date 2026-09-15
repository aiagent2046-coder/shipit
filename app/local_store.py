"""Private local state and explicit, pinned catalog updates for Drydock."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import urllib.request

from app.scan.cve_match import _sources

MAX_CATALOG_BYTES = 64 * 1024 * 1024
CATALOG_ROOT = Path(__file__).parent / "data"
UPSTREAM = "https://raw.githubusercontent.com/aiagent2046-coder/shipit"


def default_state_dir() -> Path:
    return Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state"))) / "drydock"


def connect(state_dir: Path) -> sqlite3.Connection:
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if state_dir.is_symlink():
        raise ValueError("state directory must not be a symlink")
    if state_dir.stat().st_mode & 0o077:
        raise ValueError("state directory must be private (mode 0700); choose a new directory")
    path = state_dir / "local.sqlite3"
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)
    db = sqlite3.connect(path, timeout=10)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS catalog (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            revision TEXT NOT NULL, digest TEXT NOT NULL, body BLOB NOT NULL
        );
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY, root TEXT NOT NULL, created_at TEXT NOT NULL,
            summary TEXT NOT NULL, identities TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS scans_project ON scans(root, id);
    """)
    return db


def decode_catalog(raw: bytes, checksum: str) -> tuple[dict, str]:
    if len(raw) > MAX_CATALOG_BYTES:
        raise ValueError("catalog exceeds size limit")
    digest = hashlib.sha256(raw).hexdigest()
    if not re.fullmatch(r"[0-9a-f]{64}", checksum) or digest != checksum:
        raise ValueError("catalog checksum mismatch")
    catalog = json.loads(raw)
    sources = _sources(catalog)
    if sources is None or not isinstance(catalog.get("packages"), dict):
        raise ValueError("invalid catalog schema or provenance")
    if any(not isinstance(rows, list) for rows in catalog["packages"].values()):
        raise ValueError("invalid catalog package index")
    return catalog, digest


def load_catalog(db: sqlite3.Connection) -> tuple[dict, dict]:
    row = db.execute("SELECT revision, digest, body FROM catalog WHERE id = 1").fetchone()
    if row:
        revision, checksum, raw = row
    else:
        revision = "bundled"
        with (CATALOG_ROOT / "cve-catalog.json").open("rb") as handle:
            raw = handle.read(MAX_CATALOG_BYTES + 1)
        checksum = (CATALOG_ROOT / "cve-catalog.json.sha256").read_text().split()[0]
    catalog, digest = decode_catalog(raw, checksum)
    return catalog, {"revision": revision, "sha256": digest, "sources": _sources(catalog)}


def _download(url: str, limit: int) -> bytes:
    # Only update() calls the network. No project path, package or source is sent.
    with urllib.request.urlopen(url, timeout=30) as response:
        raw = response.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("catalog download exceeds size limit")
    return raw


def update_catalog(db: sqlite3.Connection, revision: str) -> dict:
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("revision must be a full lowercase Shipit commit SHA")
    base = f"{UPSTREAM}/{revision}/app/data/cve-catalog.json"
    checksum_text = _download(base + ".sha256", 1024).decode("ascii")
    checksum = checksum_text.split()[0] if checksum_text.split() else ""
    raw = _download(base, MAX_CATALOG_BYTES)
    catalog, digest = decode_catalog(raw, checksum)
    # One transaction: an interrupted or invalid update leaves the old catalog.
    with db:
        db.execute("INSERT OR REPLACE INTO catalog VALUES (1, ?, ?, ?)", (revision, digest, raw))
    return {"revision": revision, "sha256": digest, "sources": _sources(catalog),
            "packages": len(catalog["packages"]),
            "trust": "explicit_commit_over_https_with_checksum; not_a_digital_signature"}

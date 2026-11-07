"""Locate the shipit (drydock) checkout and bootstrap it as a library."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ENV_ROOT = "SCOUT_SHIPIT_ROOT"
DEFAULT_ROOT = Path.home() / "shipit"


def shipit_root() -> Path:
    root = Path(os.environ.get(ENV_ROOT, DEFAULT_ROOT)).resolve()
    if not (root / "app" / "scan" / "cve_match.py").is_file():
        raise FileNotFoundError(
            f"shipit checkout not found at {root}; set {ENV_ROOT} to the repo root"
        )
    return root


def bootstrap() -> Path:
    """Put shipit on sys.path once; import order is handled here."""
    root = shipit_root()
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    return root


def engine_commit() -> str | None:
    """Short SHA of the shipit checkout, recorded in every report for traceability."""
    root = shipit_root()
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--short", "HEAD"],
            check=False, capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return out.stdout.strip() or None if out.returncode == 0 else None

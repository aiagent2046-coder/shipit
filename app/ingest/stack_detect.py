"""Stack detection over a validated archive's file listing.

MVP supports exactly two stacks (architecture doc, principle 4):
Next.js and FastAPI. Anything else is an honest `unsupported`.
"""

from __future__ import annotations

import json
import re
import zipfile
from enum import Enum
from typing import BinaryIO


class Stack(str, Enum):
    NEXTJS = "nextjs"
    VITE_REACT = "vite-react"   # what Lovable actually generates
    FASTAPI = "fastapi"
    UNSUPPORTED = "unsupported"


_FASTAPI_IMPORT = re.compile(r"^\s*(from\s+fastapi\s+import|import\s+fastapi)", re.MULTILINE)


def _root_prefix(names: list[str]) -> str:
    """Lovable/Bolt exports wrap everything in a single top folder."""
    tops = {n.split("/", 1)[0] for n in names if n.strip("/")}
    if len(tops) == 1 and any("/" in n for n in names):
        return next(iter(tops)) + "/"
    return ""


def detect_stack(fileobj: BinaryIO) -> Stack:
    """Detect stack from a ZIP that already passed validate_zip."""
    with zipfile.ZipFile(fileobj) as zf:
        names = zf.namelist()
        prefix = _root_prefix(names)

        # Next.js: package.json with next dependency, or next.config.*
        pkg_path = f"{prefix}package.json"
        pkg_deps: dict = {}
        if pkg_path in names:
            try:
                pkg = json.loads(zf.read(pkg_path))
                pkg_deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
                if "next" in pkg_deps:
                    return Stack.NEXTJS
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
        if any(
            n.startswith(f"{prefix}next.config.") for n in names
        ):
            return Stack.NEXTJS

        # Vite + React: the stack Lovable/Bolt exports actually use
        has_vite_config = any(n.startswith(f"{prefix}vite.config.") for n in names)
        if ("react" in pkg_deps) and ("vite" in pkg_deps or has_vite_config):
            return Stack.VITE_REACT

        # FastAPI: python deps manifest + a fastapi import in any .py
        has_py_manifest = any(
            n in names
            for n in (f"{prefix}pyproject.toml", f"{prefix}requirements.txt")
        )
        if has_py_manifest:
            for n in names:
                if not n.endswith(".py"):
                    continue
                try:
                    src = zf.read(n).decode("utf-8", errors="ignore")
                except KeyError:
                    continue
                if _FASTAPI_IMPORT.search(src):
                    return Stack.FASTAPI

    return Stack.UNSUPPORTED

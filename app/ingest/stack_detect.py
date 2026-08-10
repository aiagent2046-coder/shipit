"""Stack detection over a validated archive's file listing.

Recognises Next.js, Vite + React (what Lovable and Bolt generate), and
FastAPI, at the archive root or in a workspace member (`apps/web`,
`services/api`). Anything else is an honest `unsupported`.

Naming a monorepo's framework does not mean we can containerize it: every
Deploy Pack template builds from the root manifest, and app/deploypack/
refuses a workspace for that reason. The label and the capability are
separate questions, and this function answers only the first -- previously
it got the first one wrong in a way that happened to give the right answer
to the second, which is not the same as being correct.

`unsupported` is a label, not a refusal. The audit does not read this value
at all -- app/scan/ is entirely stack-agnostic -- so a repository built with
something else still gets every static rule and every LLM rubric. What the
stack decides is which of the *fix* products can run: the Deploy Pack needs a
Dockerfile template (app/deploypack/generate.py) and the Fix Pack's verified
build needs a known build profile (app/fixpack/verified_build.py). Both check
for themselves and degrade in their own module.
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


_FASTAPI_IMPORT = re.compile(r"^\s*(from\s+fastapi\s+import|import\s+fastapi)", re.M)


def _root_prefix(names: list[str]) -> str:
    """Lovable/Bolt exports wrap everything in a single top folder."""
    tops = {n.split("/", 1)[0] for n in names if n.strip("/")}
    if len(tops) == 1 and any("/" in n for n in names):
        return next(iter(tops)) + "/"
    return ""


# A workspace puts the application in a member directory -- apps/web,
# packages/site, services/api -- and the framework marker goes with it. Only
# the archive root used to be examined, so dubinc/dub came back `unsupported`:
# 4177 files of Next.js whose root package.json, being a turborepo manifest,
# mentions no framework at all. The audit read every one of those files while
# the report told the customer we did not recognise their stack.
#
# Two levels is where workspaces actually live (`apps/web/package.json`), and
# stopping there keeps this a search for an application rather than a scan of
# the repository.
_MAX_MEMBER_DEPTH = 2


def _dirs_containing(names: list[str], prefix: str, filename: str) -> list[str]:
    """Directories holding `filename`, root first, then shallowest.

    Order is the whole point: a repository with both a root app and a member
    app must still be judged by its root, exactly as before this existed.
    """
    found: set[str] = set()

    for name in names:
        if not name.startswith(prefix):
            continue
        head, _, tail = name[len(prefix):].rpartition("/")
        if tail != filename:
            continue
        depth = head.count("/") + 1 if head else 0
        if depth <= _MAX_MEMBER_DEPTH:
            found.add(f"{head}/" if head else "")

    return sorted(found, key=lambda d: (d.count("/"), d))


def _node_deps(zf: zipfile.ZipFile, path: str) -> dict:
    try:
        pkg = json.loads(zf.read(path))
    except (json.JSONDecodeError, UnicodeDecodeError, KeyError):
        return {}
    if not isinstance(pkg, dict):
        return {}
    return {**(pkg.get("dependencies") or {}),
            **(pkg.get("devDependencies") or {})}


def detect_stack(fileobj: BinaryIO) -> Stack:
    """Detect stack from a ZIP that already passed validate_zip."""
    with zipfile.ZipFile(fileobj) as zf:
        names = zf.namelist()
        prefix = _root_prefix(names)

        # Next.js: package.json with next dependency, or next.config.*.
        # Checked at the root first and then in workspace members, so a repo
        # with an app at its root is still judged by that app.
        # Directories are the OUTER loop and frameworks the inner one, so a
        # directory is judged completely before the next is looked at. The
        # other way round -- every directory scanned for Next.js, then every
        # directory for Vite -- lets a member's framework outrank the root's,
        # which would change the answer for repositories that have worked
        # since the beginning.
        for directory in _dirs_containing(names, prefix, "package.json"):
            deps = _node_deps(zf, f"{prefix}{directory}package.json")

            if "next" in deps or any(
                n.startswith(f"{prefix}{directory}next.config.")
                for n in names
            ):
                return Stack.NEXTJS

            # Vite + React: the stack Lovable/Bolt exports actually use
            has_vite_config = any(
                n.startswith(f"{prefix}{directory}vite.config.") for n in names
            )
            if ("react" in deps) and ("vite" in deps or has_vite_config):
                return Stack.VITE_REACT

        # FastAPI: python deps manifest + a fastapi import in any .py
        has_py_manifest = any(
            _dirs_containing(names, prefix, manifest)
            for manifest in ("pyproject.toml", "requirements.txt")
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

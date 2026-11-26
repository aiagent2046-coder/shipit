"""The browser engine bundle ships a reviewed module set with no network
runtime. This contract keeps the allowlist in browser/scripts/build.mjs in
sync with module moves: every listed path must exist, the runtime import
closure must be fully shipped, and provider clients plus the orchestration
pipeline must never enter the static scanner runtime.
"""
from __future__ import annotations

import ast
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILD_MJS = ROOT / "browser" / "scripts" / "build.mjs"
# Mirrors the excluded set in build.mjs: orchestration and LLM never ship.
EXCLUDED_SCAN_MODULES = {"pipeline.py", "llm_scan.py"}
RUNTIME_ENTRIES: tuple[str, ...] = ("app/scan/browser.py", "app/ingest/validators.py")
FORBIDDEN_PREFIXES = ("app/llm/",)
FORBIDDEN_PATHS = {"app/scan_pipeline.py", "app/scan/llm_scan.py", "app/scan/pipeline.py"}


def _shipped_paths() -> set[str]:
    """Reproduce the file selection in build.mjs: every app/scan/*.py module
    except the excluded orchestration files, plus the literal allowlist."""
    import re

    literals = set(re.findall(r"'(app/[^']+\.py)'", BUILD_MJS.read_text(encoding="utf-8")))
    scan_dir = ROOT / "app" / "scan"
    scan_modules = {
        f"app/scan/{name}"
        for name in os.listdir(scan_dir)
        if name.endswith(".py") and name not in EXCLUDED_SCAN_MODULES
    }
    return literals | scan_modules


def _module_to_path(module: str) -> str | None:
    rel = module.replace(".", "/")
    if (ROOT / f"{rel}.py").exists():
        return f"{rel}.py"
    if (ROOT / rel / "__init__.py").exists():
        return f"{rel}/__init__.py"
    return None


def _imports_of(path: str) -> set[str]:
    """Absolute application modules imported by one file, resolving both
    absolute and relative imports."""
    module = path[:-3].replace("/", ".")
    tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
    mods: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                mods.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                package = module.split(".")[:-1]
                if node.level > 1:
                    package = package[: -(node.level - 1)]
                target = ".".join(package)
                if node.module:
                    target = f"{target}.{node.module}" if target else node.module
                mods.add(target)
            elif node.module:
                mods.add(node.module)
    return mods


def _runtime_closure() -> set[str]:
    seen = set(RUNTIME_ENTRIES)
    queue = list(RUNTIME_ENTRIES)
    while queue:
        current = queue.pop()
        for module in _imports_of(current):
            if not module.startswith("app"):
                continue
            path = _module_to_path(module)
            if path and path not in seen:
                seen.add(path)
                queue.append(path)
    return seen


def test_every_engine_bundle_path_exists() -> None:
    missing = sorted(p for p in _shipped_paths() if not (ROOT / p).exists())
    assert not missing, (
        "build.mjs allowlist references files that no longer exist; "
        f"update the paths after the module move: {missing}"
    )


def test_runtime_import_closure_is_fully_shipped() -> None:
    shipped = _shipped_paths()
    unshipped = sorted(p for p in _runtime_closure() if p not in shipped)
    assert not unshipped, (
        "the browser runtime imports modules the engine bundle does not ship; "
        f"add the missing paths to build.mjs: {unshipped}"
    )


def test_provider_clients_and_orchestration_never_ship() -> None:
    shipped = _shipped_paths()
    forbidden = sorted(
        p for p in shipped
        if p in FORBIDDEN_PATHS or p.startswith(FORBIDDEN_PREFIXES)
    )
    assert not forbidden, (
        "provider clients, billing, or the orchestration pipeline must never "
        f"enter the static scanner runtime: {forbidden}"
    )

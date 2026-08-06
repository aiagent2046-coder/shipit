"""Build-verification profiles for supported Fix Pack stacks.

This module is intentionally additive. It detects the checks a repository
supports, but does not yet execute them or change the existing semantic gate.
"""

from __future__ import annotations

import io
import json
import re
import zipfile
from dataclasses import dataclass
from typing import Literal

from app.fixpack.generate import _repo_relative


StageName = Literal["compile", "typecheck", "build", "import", "tests"]
StageStatus = Literal[
    "pending",
    "passed",
    "failed",
    "skipped",
    "unavailable",
]

MAX_PROFILE_FILE_BYTES = 256 * 1024

_PY_DEPS_DIR = ".shipit_pydeps"
_NODE_IMAGE = "node:20-slim"
_PYTHON_IMAGE = "python:3.12-slim"


@dataclass(frozen=True)
class VerificationStep:
    """One command planned for a supported repository."""

    name: StageName
    command: str
    required: bool


@dataclass(frozen=True)
class VerificationProfile:
    """Detected framework and the checks available for it."""

    ecosystem: Literal["node", "python"]
    framework: Literal["nextjs", "vite", "fastapi"]
    image: str
    install_command: str
    steps: tuple[VerificationStep, ...]


@dataclass(frozen=True)
class VerificationStage:
    """Result of executing one verification step."""

    name: StageName
    status: StageStatus
    command: str | None = None
    exit_code: int | None = None
    duration_ms: int = 0
    detail: str | None = None


@dataclass(frozen=True)
class VerificationReport:
    """Original-versus-patched verification result.

    Execution and comparison are added in the next increment. Defining the
    stable data contract first prevents the existing SemanticCheckResult from
    growing into another collection of loosely related scalar fields.
    """

    profile: VerificationProfile
    original: tuple[VerificationStage, ...]
    patched: tuple[VerificationStage, ...]
    regression: bool
    deliverable: bool
    detail: str


def _normalised_entries(
    zip_bytes: bytes,
) -> tuple[dict[str, zipfile.ZipInfo], zipfile.ZipFile, io.BytesIO]:
    """Return repository-relative ZIP entries and keep backing objects alive."""

    buffer = io.BytesIO(zip_bytes)
    archive = zipfile.ZipFile(buffer)

    entries: dict[str, zipfile.ZipInfo] = {}

    for info in archive.infolist():
        if info.is_dir():
            continue

        relative = _repo_relative(info.filename)

        if not relative:
            continue

        entries.setdefault(relative, info)

    return entries, archive, buffer


def _read_small_text(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo | None,
) -> str | None:
    if info is None or info.file_size > MAX_PROFILE_FILE_BYTES:
        return None

    try:
        return archive.read(info).decode("utf-8", errors="ignore")
    except (KeyError, OSError):
        return None


def _real_test_script(value: object) -> bool:
    if not isinstance(value, str):
        return False

    script = value.strip()

    return bool(script) and "no test specified" not in script.lower()


def _node_profile(
    entries: dict[str, zipfile.ZipInfo],
    archive: zipfile.ZipFile,
) -> VerificationProfile | None:
    package_text = _read_small_text(archive, entries.get("package.json"))

    if package_text is None:
        return None

    try:
        package = json.loads(package_text)
    except (TypeError, ValueError):
        return None

    if not isinstance(package, dict):
        return None

    scripts = package.get("scripts")
    scripts = scripts if isinstance(scripts, dict) else {}

    dependencies: dict[str, object] = {}

    for key in ("dependencies", "devDependencies", "peerDependencies"):
        value = package.get(key)
        if isinstance(value, dict):
            dependencies.update(value)

    build_script = scripts.get("build")
    build_script = build_script if isinstance(build_script, str) else ""

    if "next" in dependencies or re.search(r"\bnext\s+build\b", build_script):
        framework: Literal["nextjs", "vite"] = "nextjs"
    elif "vite" in dependencies or re.search(r"\bvite\s+build\b", build_script):
        framework = "vite"
    else:
        return None

    if "package-lock.json" in entries:
        install_command = "npm ci --no-audit --no-fund"
    else:
        install_command = "npm install --no-audit --no-fund"

    steps: list[VerificationStep] = []

    typecheck_script = scripts.get("typecheck")

    if isinstance(typecheck_script, str) and typecheck_script.strip():
        steps.append(
            VerificationStep(
                name="typecheck",
                command="npm run typecheck",
                required=True,
            )
        )
    elif "tsconfig.json" in entries:
        steps.append(
            VerificationStep(
                name="typecheck",
                command="npx --no-install tsc --noEmit",
                required=True,
            )
        )

    # For an explicitly supported frontend framework, a production build is
    # mandatory even when package.json does not define a test suite.
    steps.append(
        VerificationStep(
            name="build",
            command="npm run build",
            required=True,
        )
    )

    if _real_test_script(scripts.get("test")):
        steps.append(
            VerificationStep(
                name="tests",
                command="npm test",
                required=False,
            )
        )

    return VerificationProfile(
        ecosystem="node",
        framework=framework,
        image=_NODE_IMAGE,
        install_command=install_command,
        steps=tuple(steps),
    )


def _looks_like_python_test(relative: str) -> bool:
    lower = relative.lower()

    if not lower.endswith(".py"):
        return False

    parts = lower.split("/")

    if any(part in {"test", "tests"} for part in parts[:-1]):
        return True

    filename = parts[-1]

    return filename.startswith("test_") or filename.endswith("_test.py")


def _python_module_from_path(path: str) -> str | None:
    if not path.endswith(".py"):
        return None

    module = path[:-3].replace("/", ".")
    parts = module.split(".")

    if not parts or not all(part.isidentifier() for part in parts):
        return None

    return module


_FASTAPI_INSTANCE_RE = re.compile(
    r"(?m)^\s*([A-Za-z_]\w*)\s*(?::[^=\n]+)?=\s*FastAPI\s*\("
)


def _detect_fastapi_entrypoint(
    entries: dict[str, zipfile.ZipInfo],
    archive: zipfile.ZipFile,
) -> tuple[str, str] | None:
    python_paths = [
        path
        for path in entries
        if path.endswith(".py")
        and not _looks_like_python_test(path)
        and not path.startswith(".")
    ]

    preferred = {
        "app/main.py": 0,
        "main.py": 1,
        "app.py": 2,
    }

    python_paths.sort(key=lambda path: (preferred.get(path, 100), path))

    for path in python_paths:
        module = _python_module_from_path(path)

        if module is None:
            continue

        text = _read_small_text(archive, entries[path])

        if text is None or "FastAPI" not in text:
            continue

        match = _FASTAPI_INSTANCE_RE.search(text)

        if match:
            return module, match.group(1)

    return None


def _fastapi_profile(
    entries: dict[str, zipfile.ZipInfo],
    archive: zipfile.ZipFile,
) -> VerificationProfile | None:
    dependency_texts: list[str] = []

    for path in (
        "requirements.txt",
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
    ):
        text = _read_small_text(archive, entries.get(path))

        if text is not None:
            dependency_texts.append(text)

    if not any("fastapi" in text.lower() for text in dependency_texts):
        return None

    install_parts = [
        (
            f"pip install --no-cache-dir "
            f"--target=/work/{_PY_DEPS_DIR} pytest"
        ),
        (
            "if [ -f /work/requirements.txt ]; then "
            f"pip install --no-cache-dir --target=/work/{_PY_DEPS_DIR} "
            "-r /work/requirements.txt; fi"
        ),
        (
            "if [ -f /work/pyproject.toml ] || "
            "[ -f /work/setup.py ]; then "
            f"pip install --no-cache-dir --target=/work/{_PY_DEPS_DIR} "
            "/work; fi"
        ),
    ]

    steps: list[VerificationStep] = [
        VerificationStep(
            name="compile",
            command=(
                f"PYTHONPATH=/work/{_PY_DEPS_DIR}:/work "
                "python -m compileall -q /work"
            ),
            required=True,
        )
    ]

    entrypoint = _detect_fastapi_entrypoint(entries, archive)

    if entrypoint is not None:
        module, variable = entrypoint

        steps.append(
            VerificationStep(
                name="import",
                command=(
                    f"PYTHONPATH=/work/{_PY_DEPS_DIR}:/work "
                    'python -c "'
                    f"from {module} import {variable} as _shipit_app; "
                    'assert _shipit_app is not None"'
                ),
                required=True,
            )
        )

    if any(_looks_like_python_test(path) for path in entries):
        steps.append(
            VerificationStep(
                name="tests",
                command=(
                    f"PYTHONPATH=/work/{_PY_DEPS_DIR}:/work "
                    "python -m pytest -q --no-header -p no:cacheprovider"
                ),
                required=False,
            )
        )

    return VerificationProfile(
        ecosystem="python",
        framework="fastapi",
        image=_PYTHON_IMAGE,
        install_command=" && ".join(install_parts),
        steps=tuple(steps),
    )


def detect_verification_profile(
    zip_bytes: bytes,
) -> VerificationProfile | None:
    """Detect a supported build-verification profile.

    Node is checked first because repositories can contain auxiliary Python
    files while their deployable application is Next.js or Vite.
    """

    entries, archive, buffer = _normalised_entries(zip_bytes)

    try:
        node = _node_profile(entries, archive)

        if node is not None:
            return node

        return _fastapi_profile(entries, archive)
    finally:
        archive.close()
        buffer.close()

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


StageName = Literal["install", "compile", "typecheck", "build", "import", "tests"]
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

# Workspace members, same depth and same reasoning as
# app/ingest/stack_detect.py: the framework lives in apps/web, not in the
# turborepo manifest at the root. dubinc/dub's root package.json declares no
# dependencies at all and `"build": "turbo build"`, so this file returned None
# for it and every Fix Pack fell back to the semantic check -- the weaker
# guarantee, on the product that is paid for.
_MAX_MEMBER_DEPTH = 2

# npm is not the only installer, and on a workspace it is not even a working
# one: pnpm and yarn write `"@dub/utils": "workspace:*"` into member manifests,
# a protocol npm does not understand, so `npm install` fails outright rather
# than merely being unreproducible. Detecting the manager is therefore not a
# nicety here -- without it, member detection alone would find the framework
# and then fail to install it.
_NPM, _PNPM, _YARN = "npm", "pnpm", "yarn"


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


def _member_manifests(entries: dict[str, zipfile.ZipInfo]) -> list[str]:
    """package.json paths worth reading, root first then shallowest.

    node_modules is excluded explicitly. A vendored dependency's manifest sits
    at exactly the depth a workspace member does, and picking one would build
    a profile for somebody else's package.
    """
    found: list[str] = []

    for path in entries:
        head, _, tail = path.rpartition("/")

        if tail != "package.json" or "node_modules/" in f"{path}/":
            continue

        depth = head.count("/") + 1 if head else 0

        if depth <= _MAX_MEMBER_DEPTH:
            found.append(path)

    return sorted(found, key=lambda p: (p.count("/"), p))


def _load_package(
    archive: zipfile.ZipFile,
    entries: dict[str, zipfile.ZipInfo],
    path: str,
) -> dict | None:
    text = _read_small_text(archive, entries.get(path))

    if text is None:
        return None

    try:
        package = json.loads(text)
    except (TypeError, ValueError):
        return None

    return package if isinstance(package, dict) else None


def _package_manager(root: dict | None, entries: dict[str, object]) -> str:
    """corepack's `packageManager` field first, then the lockfile.

    The declared field is the repository's own answer and beats inference: a
    repo can carry a stale lockfile from a previous manager, and dub declares
    `"packageManager": "pnpm@9.15.9"` outright.
    """
    declared = (root or {}).get("packageManager")

    if isinstance(declared, str):
        name = declared.split("@", 1)[0].strip().lower()
        if name in (_NPM, _PNPM, _YARN):
            return name

    if "pnpm-lock.yaml" in entries:
        return _PNPM
    if "yarn.lock" in entries:
        return _YARN

    return _NPM


def _node_install_command(
    manager: str,
    root: dict | None,
    entries: dict[str, object],
) -> str:
    """corepack enable is required for pnpm and yarn.

    node:20-slim ships corepack but leaves the shims uninstalled, so `pnpm`
    is not on PATH until it is enabled. Without this the install step fails
    with "pnpm: not found", which reads like a broken repository rather than
    a missing one-line setup.
    """
    if manager == _PNPM:
        return "corepack enable && pnpm install --frozen-lockfile"

    if manager == _YARN:
        declared = str((root or {}).get("packageManager") or "")
        berry = ".yarnrc.yml" in entries or bool(
            re.match(r"yarn@(?!1\.)", declared)
        )
        flag = "--immutable" if berry else "--frozen-lockfile"
        return f"corepack enable && yarn install {flag}"

    if "package-lock.json" in entries:
        return "npm ci --no-audit --no-fund"

    return "npm install --no-audit --no-fund"


def _script_command(manager: str, script: str, workspace: str | None) -> str:
    """How to run a package script, optionally scoped to a workspace member.

    The root+npm strings are exactly what this file emitted before workspaces
    existed -- including bare `npm test` rather than `npm run test`. Every
    repository that verifies today must keep running the identical commands;
    a rename here would be an untested change to every existing Fix Pack.
    """
    if workspace is None:
        if manager == _NPM:
            return "npm test" if script == "test" else f"npm run {script}"
        return f"{manager} run {script}"

    if manager == _PNPM:
        return f"pnpm --filter {workspace} run {script}"
    if manager == _YARN:
        return f"yarn workspace {workspace} run {script}"

    return f"npm run {script} --workspace {workspace}"


def _exec_command(manager: str, tool: str, workspace: str | None) -> str:
    """Run a binary from node_modules, in the right package's context.

    `npx --no-install tsc` is correct at a repository root and wrong in a
    workspace: pnpm and yarn install a member's devDependencies under that
    member, so typescript is in apps/web/node_modules/.bin and not on the
    root's PATH. Run from the root it fails with "tsc not found", which reads
    as a repository that cannot typecheck rather than a command aimed at the
    wrong directory. Scoping through the manager also puts tsc in the member
    directory, so it finds that package's tsconfig.json with no --project.
    """
    if workspace is None:
        return f"npx --no-install {tool}"

    if manager == _PNPM:
        return f"pnpm --filter {workspace} exec {tool}"
    if manager == _YARN:
        return f"yarn workspace {workspace} exec {tool}"

    return f"npm exec --workspace {workspace} -- {tool}"


def _node_framework(package: dict) -> Literal["nextjs", "vite"] | None:
    """Which supported framework this manifest describes, if any.

    Split out so the workspace search can ask the question of each candidate
    manifest without building a profile it may then discard.
    """
    dependencies: dict[str, object] = {}

    for key in ("dependencies", "devDependencies", "peerDependencies"):
        value = package.get(key)
        if isinstance(value, dict):
            dependencies.update(value)

    scripts = package.get("scripts")
    scripts = scripts if isinstance(scripts, dict) else {}
    build_script = scripts.get("build")
    build_script = build_script if isinstance(build_script, str) else ""

    if "next" in dependencies or re.search(r"\bnext\s+build\b", build_script):
        return "nextjs"
    if "vite" in dependencies or re.search(r"\bvite\s+build\b", build_script):
        return "vite"

    return None


def _node_profile(
    entries: dict[str, zipfile.ZipInfo],
    archive: zipfile.ZipFile,
) -> VerificationProfile | None:
    root_package = _load_package(archive, entries, "package.json")

    package: dict | None = None
    manifest_path = "package.json"

    # Root first, so a single-app repository is resolved exactly as before and
    # a repository with both is judged by its root.
    for candidate in _member_manifests(entries):
        loaded = _load_package(archive, entries, candidate)

        if loaded is None:
            continue

        if _node_framework(loaded) is not None:
            package, manifest_path = loaded, candidate
            break

    if package is None:
        return None

    framework = _node_framework(package)

    if framework is None:                       # pragma: no cover - guarded above
        return None

    scripts = package.get("scripts")
    scripts = scripts if isinstance(scripts, dict) else {}

    directory = manifest_path[: -len("package.json")]
    name = package.get("name")
    workspace = name if directory and isinstance(name, str) and name else None

    # A member with no usable `name` cannot be addressed by --filter or
    # --workspace, and guessing from the directory would silently verify the
    # wrong package. Falling back to the whole-repo commands is wrong too: on
    # a workspace they run the root's `turbo build`, which is not this app.
    if directory and workspace is None:
        return None

    manager = _package_manager(root_package, entries)

    install_command = _node_install_command(manager, root_package, entries)

    steps: list[VerificationStep] = []

    typecheck_script = scripts.get("typecheck")

    if isinstance(typecheck_script, str) and typecheck_script.strip():
        steps.append(
            VerificationStep(
                name="typecheck",
                command=_script_command(manager, "typecheck", workspace),
                required=True,
            )
        )
    elif f"{directory}tsconfig.json" in entries:
        steps.append(
            VerificationStep(
                name="typecheck",
                command=_exec_command(manager, "tsc --noEmit", workspace),
                required=True,
            )
        )

    # For an explicitly supported frontend framework, a production build is
    # mandatory even when package.json does not define a test suite.
    steps.append(
        VerificationStep(
            name="build",
            command=_script_command(manager, "build", workspace),
            required=True,
        )
    )

    if _real_test_script(scripts.get("test")):
        steps.append(
            VerificationStep(
                name="tests",
                command=_script_command(manager, "test", workspace),
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


def compare_verification_stages(
    profile: VerificationProfile,
    original: tuple[VerificationStage, ...],
    patched: tuple[VerificationStage, ...],
) -> VerificationReport:
    """Compare original and patched verification stages.

    Delivery is allowed only when every required patched stage passes and no
    optional check introduces a new failure. Existing optional test failures
    may remain, but they are reported explicitly and do not qualify as full
    regression verification.
    """

    expected_names = (
        "install",
        *(step.name for step in profile.steps),
    )

    original_names = tuple(
        stage.name
        for stage in original
    )
    patched_names = tuple(
        stage.name
        for stage in patched
    )

    if (
        original_names != expected_names
        or patched_names != expected_names
    ):
        return VerificationReport(
            profile=profile,
            original=original,
            patched=patched,
            regression=False,
            deliverable=False,
            detail="verification stage contract mismatch",
        )

    all_stages = (*original, *patched)

    if any(
        stage.status == "unavailable"
        for stage in all_stages
    ):
        return VerificationReport(
            profile=profile,
            original=original,
            patched=patched,
            regression=False,
            deliverable=False,
            detail="verification infrastructure unavailable",
        )

    if any(
        stage.status == "pending"
        for stage in all_stages
    ):
        return VerificationReport(
            profile=profile,
            original=original,
            patched=patched,
            regression=False,
            deliverable=False,
            detail="verification report is incomplete",
        )

    original_by_name = {
        stage.name: stage
        for stage in original
    }
    patched_by_name = {
        stage.name: stage
        for stage in patched
    }

    # Install is network-dependent and runs independently for original and
    # patched workspaces. A failed original install followed by a successful
    # patched install is not evidence that the patch improved the repository:
    # it may only reflect a transient registry/proxy result. Never establish a
    # deliverable baseline from that asymmetric pair.
    if (
        original_by_name["install"].status != "passed"
        and patched_by_name["install"].status == "passed"
    ):
        return VerificationReport(
            profile=profile,
            original=original,
            patched=patched,
            regression=False,
            deliverable=False,
            detail=(
                "original dependency install did not pass; "
                "verification baseline is invalid"
            ),
        )

    regression_names = [
        name
        for name in expected_names
        if (
            original_by_name[name].status == "passed"
            and patched_by_name[name].status != "passed"
        )
    ]

    if regression_names:
        return VerificationReport(
            profile=profile,
            original=original,
            patched=patched,
            regression=True,
            deliverable=False,
            detail=(
                "new verification regression: "
                + ", ".join(regression_names)
            ),
        )

    required_names = {
        "install",
        *(
            step.name
            for step in profile.steps
            if step.required
        ),
    }

    required_failures = [
        name
        for name in expected_names
        if (
            name in required_names
            and patched_by_name[name].status != "passed"
        )
    ]

    if required_failures:
        return VerificationReport(
            profile=profile,
            original=original,
            patched=patched,
            regression=False,
            deliverable=False,
            detail=(
                "patched required verification failed: "
                + ", ".join(required_failures)
            ),
        )

    optional_names = {
        step.name
        for step in profile.steps
        if not step.required
    }

    optional_incomplete = [
        name
        for name in expected_names
        if (
            name in optional_names
            and patched_by_name[name].status != "passed"
            and original_by_name[name].status != "failed"
        )
    ]

    if optional_incomplete:
        return VerificationReport(
            profile=profile,
            original=original,
            patched=patched,
            regression=False,
            deliverable=False,
            detail=(
                "optional verification could not be compared: "
                + ", ".join(optional_incomplete)
            ),
        )

    baseline_optional_failures = [
        name
        for name in expected_names
        if (
            name in optional_names
            and original_by_name[name].status == "failed"
            and patched_by_name[name].status == "failed"
        )
    ]

    improvements = [
        name
        for name in expected_names
        if (
            original_by_name[name].status == "failed"
            and patched_by_name[name].status == "passed"
        )
    ]

    details = ["required patched verification passed"]

    if baseline_optional_failures:
        details.append(
            "baseline optional failures remain: "
            + ", ".join(baseline_optional_failures)
        )

    if improvements:
        details.append(
            "improvements: "
            + ", ".join(improvements)
        )

    return VerificationReport(
        profile=profile,
        original=original,
        patched=patched,
        regression=False,
        deliverable=True,
        detail="; ".join(details),
    )


# --- Runner wire contract --------------------------------------------------

_MAX_WIRE_TEXT_BYTES = 16 * 1024

_VALID_STAGE_NAMES = {
    "install",
    "compile",
    "typecheck",
    "build",
    "import",
    "tests",
}

_VALID_STAGE_STATUSES = {
    "pending",
    "passed",
    "failed",
    "skipped",
    "unavailable",
}


def _wire_text(
    value: object,
    field: str,
    *,
    allow_none: bool = False,
) -> str | None:
    if value is None and allow_none:
        return None

    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")

    if not value.strip():
        raise ValueError(f"{field} must not be empty")

    if "\x00" in value:
        raise ValueError(f"{field} contains a null byte")

    if len(value.encode("utf-8")) > _MAX_WIRE_TEXT_BYTES:
        raise ValueError(f"{field} exceeds size limit")

    return value


def verification_profile_to_wire(
    profile: VerificationProfile,
) -> dict[str, object]:
    """Serialize a trusted detected profile for the sandbox runner."""

    return {
        "ecosystem": profile.ecosystem,
        "framework": profile.framework,
        "image": profile.image,
        "install_command": profile.install_command,
        "steps": [
            {
                "name": step.name,
                "command": step.command,
                "required": step.required,
            }
            for step in profile.steps
        ],
    }


def verification_profile_from_wire(
    value: object,
) -> VerificationProfile:
    """Rebuild and validate a profile received by the runner."""

    if not isinstance(value, dict):
        raise ValueError("profile must be an object")

    ecosystem = value.get("ecosystem")
    framework = value.get("framework")

    if ecosystem not in {"node", "python"}:
        raise ValueError("unsupported verification ecosystem")

    if framework not in {"nextjs", "vite", "fastapi"}:
        raise ValueError("unsupported verification framework")

    expected_ecosystem = (
        "python"
        if framework == "fastapi"
        else "node"
    )

    if ecosystem != expected_ecosystem:
        raise ValueError(
            "verification framework/ecosystem mismatch"
        )

    image = _wire_text(
        value.get("image"),
        "profile.image",
    )

    install_command = _wire_text(
        value.get("install_command"),
        "profile.install_command",
    )

    raw_steps = value.get("steps")

    if not isinstance(raw_steps, list):
        raise ValueError("profile.steps must be an array")

    if not 1 <= len(raw_steps) <= 8:
        raise ValueError(
            "profile.steps must contain 1 to 8 stages"
        )

    steps: list[VerificationStep] = []
    seen_names: set[str] = set()

    for index, raw_step in enumerate(raw_steps):
        if not isinstance(raw_step, dict):
            raise ValueError(
                f"profile.steps[{index}] must be an object"
            )

        name = raw_step.get("name")

        if (
            name not in _VALID_STAGE_NAMES
            or name == "install"
        ):
            raise ValueError(
                f"profile.steps[{index}].name is invalid"
            )

        if name in seen_names:
            raise ValueError(
                f"duplicate verification stage: {name}"
            )

        seen_names.add(name)

        command = _wire_text(
            raw_step.get("command"),
            f"profile.steps[{index}].command",
        )

        required = raw_step.get("required")

        if not isinstance(required, bool):
            raise ValueError(
                f"profile.steps[{index}].required "
                "must be boolean"
            )

        steps.append(
            VerificationStep(
                name=name,
                command=command,
                required=required,
            )
        )

    return VerificationProfile(
        ecosystem=ecosystem,
        framework=framework,
        image=image,
        install_command=install_command,
        steps=tuple(steps),
    )


def verification_stage_to_wire(
    stage: VerificationStage,
) -> dict[str, object]:
    return {
        "name": stage.name,
        "status": stage.status,
        "command": stage.command,
        "exit_code": stage.exit_code,
        "duration_ms": stage.duration_ms,
        "detail": stage.detail,
    }


def verification_stage_from_wire(
    value: object,
) -> VerificationStage:
    if not isinstance(value, dict):
        raise ValueError(
            "verification stage must be an object"
        )

    name = value.get("name")
    status = value.get("status")

    if name not in _VALID_STAGE_NAMES:
        raise ValueError(
            "verification stage name is invalid"
        )

    if status not in _VALID_STAGE_STATUSES:
        raise ValueError(
            "verification stage status is invalid"
        )

    command = value.get("command")

    if command is not None:
        command = _wire_text(
            command,
            "verification stage command",
        )

    exit_code = value.get("exit_code")

    if (
        exit_code is not None
        and (
            isinstance(exit_code, bool)
            or not isinstance(exit_code, int)
        )
    ):
        raise ValueError(
            "verification stage exit_code is invalid"
        )

    duration_ms = value.get("duration_ms", 0)

    if (
        isinstance(duration_ms, bool)
        or not isinstance(duration_ms, int)
        or duration_ms < 0
    ):
        raise ValueError(
            "verification stage duration_ms is invalid"
        )

    detail = value.get("detail")

    if detail is not None:
        detail = _wire_text(
            detail,
            "verification stage detail",
        )

    return VerificationStage(
        name=name,
        status=status,
        command=command,
        exit_code=exit_code,
        duration_ms=duration_ms,
        detail=detail,
    )

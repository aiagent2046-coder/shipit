#!/usr/bin/env python3
"""Build and atomically switch immutable ShipIt releases."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NoReturn, Sequence


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
METADATA_FILE = ".shipit-release.json"
BUILD_MARKER = ".shipit-building"


class ReleaseError(RuntimeError):
    """Expected release-management failure."""


def fail(message: str) -> NoReturn:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def run(
    command: Sequence[str | Path],
    *,
    cwd: Path | None = None,
) -> None:
    printable = [str(item) for item in command]

    completed = subprocess.run(
        printable,
        cwd=cwd,
        check=False,
    )

    if completed.returncode != 0:
        raise ReleaseError(
            f"command failed with exit code {completed.returncode}: "
            + " ".join(printable)
        )


def capture(
    command: Sequence[str | Path],
    *,
    cwd: Path | None = None,
) -> str:
    printable = [str(item) for item in command]

    completed = subprocess.run(
        printable,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()

        raise ReleaseError(
            f"command failed: {' '.join(printable)}"
            + (f": {detail}" if detail else "")
        )

    return completed.stdout.strip()


def normalize_sha(repo: Path, revision: str) -> str:
    sha = capture(
        [
            "git",
            "-C",
            repo,
            "rev-parse",
            "--verify",
            f"{revision}^{{commit}}",
        ]
    ).lower()

    if not SHA_RE.fullmatch(sha):
        raise ReleaseError(
            f"unexpected Git commit SHA: {sha!r}"
        )

    return sha


def release_path(root: Path, sha: str) -> Path:
    if not SHA_RE.fullmatch(sha):
        raise ReleaseError(
            f"invalid release SHA: {sha!r}"
        )

    return root / "releases" / sha



def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def build_migration_manifest(
    release: Path,
) -> list[dict[str, str]]:
    migrations_dir = release / "migrations"

    if not migrations_dir.is_dir():
        return []

    return [
        {
            "filename": migration.name,
            "checksum": file_sha256(migration),
        }
        for migration in sorted(
            migrations_dir.glob("[0-9]*.sql")
        )
    ]


def validate_migration_manifest(
    release: Path,
    metadata: dict[str, Any],
) -> None:
    manifest = metadata.get("migration_manifest")

    if not isinstance(manifest, list):
        raise ReleaseError(
            f"release metadata lacks migration manifest: {release}"
        )

    normalized: list[dict[str, str]] = []
    seen: set[str] = set()

    for item in manifest:
        if not isinstance(item, dict):
            raise ReleaseError(
                f"invalid migration manifest entry in {release}"
            )

        filename = item.get("filename")
        checksum = item.get("checksum")

        if not isinstance(filename, str):
            raise ReleaseError(
                f"invalid migration filename in {release}"
            )

        if (
            not isinstance(checksum, str)
            or not re.fullmatch(r"[0-9a-f]{64}", checksum)
        ):
            raise ReleaseError(
                f"invalid migration checksum for {filename}"
            )

        if filename in seen:
            raise ReleaseError(
                f"duplicate migration in manifest: {filename}"
            )

        seen.add(filename)

        normalized.append(
            {
                "filename": filename,
                "checksum": checksum,
            }
        )

    actual = build_migration_manifest(release)

    if normalized != actual:
        raise ReleaseError(
            f"migration manifest does not match release files: {release}"
        )

def read_metadata(path: Path) -> dict[str, Any]:
    metadata_path = path / METADATA_FILE

    try:
        value = json.loads(
            metadata_path.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as error:
        raise ReleaseError(
            f"invalid or missing release metadata: {metadata_path}"
        ) from error

    if not isinstance(value, dict):
        raise ReleaseError(
            f"release metadata is not an object: {metadata_path}"
        )

    return value


def validate_release(path: Path, expected_sha: str) -> None:
    if not path.is_dir():
        raise ReleaseError(
            f"release directory does not exist: {path}"
        )

    if (path / BUILD_MARKER).exists():
        raise ReleaseError(
            f"release build is incomplete: {path}"
        )

    metadata = read_metadata(path)

    if metadata.get("git_sha") != expected_sha:
        raise ReleaseError(
            f"release metadata SHA mismatch in {path}"
        )

    validate_migration_manifest(path, metadata)

    required_paths = (
        path / "app" / "main.py",
        path / "requirements.txt",
        path / ".venv" / "bin" / "python",
        path / "deploy" / "scripts"
        / "validate-production-env.py",
    )

    missing = [
        item
        for item in required_paths
        if not item.exists()
    ]

    if missing:
        raise ReleaseError(
            "incomplete release; missing: "
            + ", ".join(str(item) for item in missing)
        )


def write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    temporary = path.with_name(
        f".{path.name}.tmp-{os.getpid()}-{uuid.uuid4().hex}"
    )

    temporary.write_text(
        json.dumps(
            value,
            sort_keys=True,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    os.replace(temporary, path)


def write_release_env(path: Path, sha: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    temporary = path.with_name(
        f".{path.name}.tmp-{os.getpid()}-{uuid.uuid4().hex}"
    )

    fd = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(f"SHIPIT_RELEASE={sha}\n")
            stream.flush()
            os.fsync(stream.fileno())

        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def atomic_symlink(target: Path, link: Path) -> None:
    link.parent.mkdir(parents=True, exist_ok=True)

    temporary = link.with_name(
        f".{link.name}.tmp-{os.getpid()}-{uuid.uuid4().hex}"
    )

    temporary.unlink(missing_ok=True)
    os.symlink(str(target), temporary)
    os.replace(temporary, link)


def resolved_symlink(link: Path) -> Path | None:
    if not link.is_symlink():
        return None

    raw_target = Path(os.readlink(link))

    if raw_target.is_absolute():
        return raw_target.resolve(strict=False)

    return (link.parent / raw_target).resolve(strict=False)


def release_sha_from_target(
    root: Path,
    target: Path | None,
) -> str | None:
    if target is None:
        return None

    releases = (root / "releases").resolve(strict=False)
    resolved = target.resolve(strict=False)

    if resolved.parent != releases:
        raise ReleaseError(
            f"symlink target is outside release directory: {resolved}"
        )

    if not SHA_RE.fullmatch(resolved.name):
        raise ReleaseError(
            f"symlink target is not a release SHA: {resolved}"
        )

    validate_release(resolved, resolved.name)
    return resolved.name


def append_journal(
    root: Path,
    event: str,
    **fields: Any,
) -> None:
    journal = root / "deployments" / "journal.jsonl"
    journal.parent.mkdir(parents=True, exist_ok=True)

    record = {
        "timestamp": utc_now(),
        "event": event,
        **fields,
    }

    with journal.open("a", encoding="utf-8") as stream:
        stream.write(
            json.dumps(record, sort_keys=True) + "\n"
        )
        stream.flush()
        os.fsync(stream.fileno())


def export_commit(
    repo: Path,
    sha: str,
    destination: Path,
) -> None:
    archive = subprocess.Popen(
        [
            "git",
            "-C",
            str(repo),
            "archive",
            "--format=tar",
            sha,
        ],
        stdout=subprocess.PIPE,
    )

    assert archive.stdout is not None

    extract = subprocess.run(
        [
            "tar",
            "-x",
            "-C",
            str(destination),
        ],
        stdin=archive.stdout,
        check=False,
    )

    archive.stdout.close()
    archive_code = archive.wait()

    if archive_code != 0 or extract.returncode != 0:
        raise ReleaseError(
            "failed to export Git commit into release directory"
        )


def build_release(
    root: Path,
    repo: Path,
    revision: str,
    python: Path,
) -> str:
    repo = repo.resolve()
    root = root.resolve()
    sha = normalize_sha(repo, revision)

    releases = root / "releases"
    releases.mkdir(parents=True, exist_ok=True)

    final = release_path(root, sha)

    if final.exists() or final.is_symlink():
        try:
            validate_release(final, sha)
        except ReleaseError:
            protected_targets = {
                target.resolve(strict=False)
                for target in (
                    resolved_symlink(root / "current"),
                    resolved_symlink(root / "previous"),
                )
                if target is not None
            }

            resolved_final = final.resolve(strict=False)

            if resolved_final in protected_targets:
                raise ReleaseError(
                    "invalid release is referenced by an active "
                    f"symlink: {final}"
                )

            print(f"Removing incomplete release: {final}")

            if final.is_symlink():
                final.unlink()
            else:
                shutil.rmtree(final)
        else:
            print(f"Release already built: {final}")
            return sha

    final.mkdir(mode=0o755)

    marker = final / BUILD_MARKER

    try:
        marker.write_text(
            utc_now() + "\n",
            encoding="utf-8",
        )

        # Build directly at the permanent SHA path. Python venv console
        # scripts embed absolute interpreter paths and must never be moved.
        export_commit(repo, sha, final)

        requirements = final / "requirements.txt"

        if not requirements.is_file():
            raise ReleaseError(
                f"requirements file missing: {requirements}"
            )

        run(
            [
                python,
                "-m",
                "venv",
                final / ".venv",
            ]
        )

        release_python = final / ".venv" / "bin" / "python"

        run(
            [
                release_python,
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--require-hashes",
                "-r",
                requirements,
            ]
        )

        run(
            [
                release_python,
                "-m",
                "compileall",
                "-q",
                final / "app",
            ]
        )

        write_json_atomic(
            final / METADATA_FILE,
            {
                "git_sha": sha,
                "built_at": utc_now(),
                "source_repository": str(repo),
                "python": str(python),
                "migration_manifest": (
                    build_migration_manifest(final)
                ),
            },
        )

        marker.unlink()
        validate_release(final, sha)

    except BaseException:
        shutil.rmtree(final, ignore_errors=True)
        raise

    append_journal(
        root,
        "release_built",
        git_sha=sha,
        release_path=str(final),
    )

    print(f"Built release: {final}")
    return sha


def activate_release(
    root: Path,
    sha: str,
    release_env: Path,
) -> None:
    root = root.resolve()
    target = release_path(root, sha).resolve()
    validate_release(target, sha)

    current_link = root / "current"
    previous_link = root / "previous"

    current_target = resolved_symlink(current_link)
    current_sha = release_sha_from_target(root, current_target)

    if current_sha == sha:
        write_release_env(release_env, sha)
        print(f"Release already active: {sha}")
        return

    if current_target is not None:
        atomic_symlink(current_target, previous_link)

    atomic_symlink(target, current_link)
    write_release_env(release_env, sha)

    append_journal(
        root,
        "release_activated",
        git_sha=sha,
        previous_git_sha=current_sha,
    )

    print(f"Activated release: {sha}")

    if current_sha:
        print(f"Previous release: {current_sha}")


def rollback_release(
    root: Path,
    release_env: Path,
) -> str:
    root = root.resolve()

    current_link = root / "current"
    previous_link = root / "previous"

    current_target = resolved_symlink(current_link)
    previous_target = resolved_symlink(previous_link)

    current_sha = release_sha_from_target(root, current_target)
    previous_sha = release_sha_from_target(root, previous_target)

    if previous_target is None or previous_sha is None:
        raise ReleaseError(
            "no previous release is available"
        )

    atomic_symlink(previous_target, current_link)

    if current_target is not None and current_sha is not None:
        atomic_symlink(current_target, previous_link)

    write_release_env(release_env, previous_sha)

    append_journal(
        root,
        "release_rolled_back",
        git_sha=previous_sha,
        replaced_git_sha=current_sha,
    )

    print(f"Rolled back to release: {previous_sha}")
    return previous_sha


def status(root: Path) -> None:
    root = root.resolve()

    current = release_sha_from_target(
        root,
        resolved_symlink(root / "current"),
    )
    previous = release_sha_from_target(
        root,
        resolved_symlink(root / "previous"),
    )

    releases_dir = root / "releases"

    releases = []

    if releases_dir.is_dir():
        releases = sorted(
            (
                path.name
                for path in releases_dir.iterdir()
                if path.is_dir()
                and SHA_RE.fullmatch(path.name)
            ),
            reverse=True,
        )

    print(f"Current:  {current or 'none'}")
    print(f"Previous: {previous or 'none'}")
    print(f"Releases: {len(releases)}")

    for sha in releases:
        print(f"  {sha}")


def prune_releases(root: Path, keep: int) -> None:
    if keep < 2:
        raise ReleaseError(
            "--keep must be at least 2"
        )

    root = root.resolve()
    releases_dir = root / "releases"

    if not releases_dir.is_dir():
        print("No release directory.")
        return

    protected = {
        sha
        for sha in (
            release_sha_from_target(
                root,
                resolved_symlink(root / "current"),
            ),
            release_sha_from_target(
                root,
                resolved_symlink(root / "previous"),
            ),
        )
        if sha is not None
    }

    candidates = [
        path
        for path in releases_dir.iterdir()
        if path.is_dir()
        and SHA_RE.fullmatch(path.name)
    ]

    candidates.sort(
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )

    retained = {
        path.name
        for path in candidates[:keep]
    } | protected

    removed = 0

    for path in candidates:
        if path.name in retained:
            continue

        validate_release(path, path.name)
        shutil.rmtree(path)
        removed += 1

        append_journal(
            root,
            "release_pruned",
            git_sha=path.name,
        )

        print(f"Removed release: {path.name}")

    print(f"Pruned releases: {removed}")


def parse_args(
    argv: Sequence[str] | None = None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="ShipIt immutable release manager"
    )

    parser.add_argument(
        "--root",
        type=Path,
        default=Path("/srv/shipit"),
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    build = subparsers.add_parser("build")
    build.add_argument(
        "--repo",
        type=Path,
        required=True,
    )
    build.add_argument(
        "--revision",
        required=True,
    )
    build.add_argument(
        "--python",
        type=Path,
        required=True,
    )

    activate = subparsers.add_parser("activate")
    activate.add_argument("--sha", required=True)
    activate.add_argument(
        "--release-env",
        type=Path,
        default=Path("/opt/shipit/.release-env"),
    )

    rollback = subparsers.add_parser("rollback")
    rollback.add_argument(
        "--release-env",
        type=Path,
        default=Path("/opt/shipit/.release-env"),
    )

    subparsers.add_parser("status")

    prune = subparsers.add_parser("prune")
    prune.add_argument(
        "--keep",
        type=int,
        default=5,
    )

    return parser.parse_args(argv)


def main(
    argv: Sequence[str] | None = None,
) -> int:
    arguments = parse_args(argv)

    if arguments.command == "build":
        build_release(
            arguments.root,
            arguments.repo,
            arguments.revision,
            arguments.python,
        )
        return 0

    if arguments.command == "activate":
        activate_release(
            arguments.root,
            arguments.sha.lower(),
            arguments.release_env,
        )
        return 0

    if arguments.command == "rollback":
        rollback_release(
            arguments.root,
            arguments.release_env,
        )
        return 0

    if arguments.command == "status":
        status(arguments.root)
        return 0

    if arguments.command == "prune":
        prune_releases(
            arguments.root,
            arguments.keep,
        )
        return 0

    raise ReleaseError(
        f"unsupported command: {arguments.command}"
    )


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReleaseError as error:
        fail(str(error))

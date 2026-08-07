from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "deploy"
    / "scripts"
    / "release_manager.py"
)

SPEC = importlib.util.spec_from_file_location(
    "shipit_release_manager",
    MODULE_PATH,
)

assert SPEC is not None
assert SPEC.loader is not None

release_manager = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = release_manager
SPEC.loader.exec_module(release_manager)


def make_release(root: Path, sha: str) -> Path:
    release = root / "releases" / sha

    (release / "app").mkdir(parents=True)
    (release / ".venv" / "bin").mkdir(parents=True)
    (
        release
        / "deploy"
        / "scripts"
    ).mkdir(parents=True)

    (release / "app" / "main.py").write_text(
        "",
        encoding="utf-8",
    )
    (release / "requirements.txt").write_text(
        "",
        encoding="utf-8",
    )
    (release / ".venv" / "bin" / "python").write_text(
        "",
        encoding="utf-8",
    )
    (release / ".venv" / "bin" / "uvicorn").write_text(
        "",
        encoding="utf-8",
    )
    (
        release
        / "deploy"
        / "scripts"
        / "validate-production-env.py"
    ).write_text(
        "",
        encoding="utf-8",
    )
    (
        release
        / release_manager.METADATA_FILE
    ).write_text(
        json.dumps(
            {
                "git_sha": sha,
                "migration_manifest": [],
            }
        ),
        encoding="utf-8",
    )

    return release


def test_activate_and_rollback(tmp_path: Path) -> None:
    first_sha = "1" * 40
    second_sha = "2" * 40

    first = make_release(tmp_path, first_sha)
    second = make_release(tmp_path, second_sha)
    release_env = tmp_path / "release.env"

    release_manager.activate_release(
        tmp_path,
        first_sha,
        release_env,
    )

    assert (
        release_manager.resolved_symlink(
            tmp_path / "current"
        )
        == first.resolve()
    )
    assert release_env.read_text(
        encoding="utf-8"
    ) == f"SHIPIT_RELEASE={first_sha}\n"

    release_manager.activate_release(
        tmp_path,
        second_sha,
        release_env,
    )

    assert (
        release_manager.resolved_symlink(
            tmp_path / "current"
        )
        == second.resolve()
    )
    assert (
        release_manager.resolved_symlink(
            tmp_path / "previous"
        )
        == first.resolve()
    )

    rolled_back = release_manager.rollback_release(
        tmp_path,
        release_env,
    )

    assert rolled_back == first_sha
    assert (
        release_manager.resolved_symlink(
            tmp_path / "current"
        )
        == first.resolve()
    )
    assert (
        release_manager.resolved_symlink(
            tmp_path / "previous"
        )
        == second.resolve()
    )


def test_activate_rejects_incomplete_release(
    tmp_path: Path,
) -> None:
    sha = "3" * 40
    release = tmp_path / "releases" / sha
    release.mkdir(parents=True)

    with pytest.raises(
        release_manager.ReleaseError,
        match="metadata",
    ):
        release_manager.activate_release(
            tmp_path,
            sha,
            tmp_path / "release.env",
        )


def test_prune_preserves_current_and_previous(
    tmp_path: Path,
) -> None:
    shas = [
        str(number) * 40
        for number in range(1, 7)
    ]

    releases = [
        make_release(tmp_path, sha)
        for sha in shas
    ]

    for index, release in enumerate(releases):
        release.touch()
        release_manager.os.utime(
            release,
            (100 + index, 100 + index),
        )

    release_manager.activate_release(
        tmp_path,
        shas[0],
        tmp_path / "release.env",
    )
    release_manager.activate_release(
        tmp_path,
        shas[1],
        tmp_path / "release.env",
    )

    release_manager.prune_releases(
        tmp_path,
        keep=2,
    )

    assert (
        tmp_path / "releases" / shas[0]
    ).exists()
    assert (
        tmp_path / "releases" / shas[1]
    ).exists()

    remaining = {
        path.name
        for path in (tmp_path / "releases").iterdir()
        if path.is_dir()
    }

    assert shas[0] in remaining
    assert shas[1] in remaining
    assert len(remaining) <= 4



def test_migration_manifest_detects_file_drift(
    tmp_path: Path,
) -> None:
    sha = "a" * 40
    release = make_release(tmp_path, sha)
    migrations = release / "migrations"
    migrations.mkdir()

    migration = migrations / "0001_example.sql"
    migration.write_text(
        "SELECT 1;\n",
        encoding="utf-8",
    )

    metadata_path = (
        release / release_manager.METADATA_FILE
    )

    metadata = json.loads(
        metadata_path.read_text(encoding="utf-8")
    )
    metadata["migration_manifest"] = (
        release_manager.build_migration_manifest(release)
    )

    metadata_path.write_text(
        json.dumps(metadata),
        encoding="utf-8",
    )

    release_manager.validate_release(release, sha)

    migration.write_text(
        "SELECT 2;\n",
        encoding="utf-8",
    )

    with pytest.raises(
        release_manager.ReleaseError,
        match="manifest does not match",
    ):
        release_manager.validate_release(release, sha)



def test_build_creates_venv_at_permanent_release_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sha = "c" * 40
    repo = tmp_path / "repo"
    root = tmp_path / "root"

    repo.mkdir()

    captured_venv_paths: list[Path] = []

    monkeypatch.setattr(
        release_manager,
        "normalize_sha",
        lambda repository, revision: sha,
    )

    def fake_export_commit(
        repository: Path,
        revision: str,
        destination: Path,
    ) -> None:
        (destination / "app").mkdir(parents=True)
        (
            destination
            / "deploy"
            / "scripts"
        ).mkdir(parents=True)

        (destination / "app" / "main.py").write_text(
            "",
            encoding="utf-8",
        )
        (destination / "requirements.txt").write_text(
            "",
            encoding="utf-8",
        )
        (
            destination
            / "deploy"
            / "scripts"
            / "validate-production-env.py"
        ).write_text(
            "",
            encoding="utf-8",
        )

    def fake_run(
        command: list[object],
        *,
        cwd: Path | None = None,
    ) -> None:
        values = [str(item) for item in command]

        if "-m" in values and "venv" in values:
            venv = Path(values[-1])
            captured_venv_paths.append(venv)

            (venv / "bin").mkdir(parents=True)
            (venv / "bin" / "python").write_text(
                "",
                encoding="utf-8",
            )

    monkeypatch.setattr(
        release_manager,
        "export_commit",
        fake_export_commit,
    )
    monkeypatch.setattr(
        release_manager,
        "run",
        fake_run,
    )

    result = release_manager.build_release(
        root,
        repo,
        "HEAD",
        Path("/usr/bin/python3"),
    )

    expected_release = root / "releases" / sha

    assert result == sha
    assert captured_venv_paths == [
        expected_release / ".venv"
    ]
    assert ".staging-" not in str(captured_venv_paths[0])

    release_manager.validate_release(
        expected_release,
        sha,
    )


def make_git_repo(path: Path) -> str:
    """A throwaway repo with one commit. Returns its SHA."""
    import subprocess

    def git(*args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(path), *args],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    path.mkdir(parents=True, exist_ok=True)
    git("init", "-q")
    git("config", "user.email", "test@example.invalid")
    git("config", "user.name", "Test")
    (path / "file.txt").write_text("content", encoding="utf-8")
    git("add", "file.txt")
    git("commit", "-q", "-m", "initial")

    return git("rev-parse", "HEAD")


def test_describe_revision_labels_a_tagged_commit(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    sha = make_git_repo(repo)

    import subprocess

    subprocess.run(
        ["git", "-C", str(repo), "tag", "-a", "v2026.08.07-1", "-m", "release"],
        check=True,
        capture_output=True,
    )

    assert release_manager.describe_revision(repo, sha) == "v2026.08.07-1"


def test_describe_revision_falls_back_to_a_short_sha_when_untagged(
    tmp_path: Path,
) -> None:
    """The no-tags case must still produce a label, not None.

    Regression guard: `git describe --dirty <commit-ish>` is rejected by git
    outright ("option '--dirty' and commit-ishes cannot be used together"),
    which silently degraded every single release label to None.
    """
    repo = tmp_path / "repo"
    sha = make_git_repo(repo)

    described = release_manager.describe_revision(repo, sha)

    assert described is not None
    assert sha.startswith(described)


def test_describe_revision_returns_none_instead_of_raising(
    tmp_path: Path,
) -> None:
    """A build must never fail because `git describe` did."""
    not_a_repo = tmp_path / "empty"
    not_a_repo.mkdir()

    assert release_manager.describe_revision(not_a_repo, "a" * 40) is None

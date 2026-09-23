"""Offline regressions for the pinned VTEX experiment's executable source boundary."""

import importlib.util
from pathlib import Path
import subprocess

import pytest


GUARDS = (
    Path(__file__).resolve().parents[1]
    / "docs/experiments/dependency-expansion-2026-09-22/pypi/source_guards.py"
)
spec = importlib.util.spec_from_file_location("dependency_expansion_source_guards", GUARDS)
guards = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guards)


def git(source, *args):
    return subprocess.check_output(["git", "-C", str(source), *args], stderr=subprocess.PIPE).decode().strip()


@pytest.fixture
def source(tmp_path):
    repo = tmp_path / "source"
    repo.mkdir()
    git(repo, "init")
    for name, content in {
        ".gitignore": "ignored.py\n",
        "app/__init__.py": "raise RuntimeError('must not import during preparation')\n",
        "scripts/verify_dependency_remediation.py": "PINNED = True\n",
        "requirements.txt": "requests==2.31.0\n",
    }.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    git(repo, "add", ".")
    git(repo, "-c", "user.name=Offline test", "-c", "user.email=test@example.invalid", "commit", "-m", "pinned source")
    return repo, git(repo, "rev-parse", "HEAD")


def test_project_export_excludes_conftest_and_uses_committed_bytes(source, tmp_path):
    repo, revision = source
    (repo / "conftest.py").write_text("raise RuntimeError('unreviewed pytest hook')\n")
    (repo / "ignored.py").write_text("raise RuntimeError('ignored executable')\n")
    (repo / "requirements.txt").write_text("requests==0.0.0\n")

    snapshot = guards.export_tracked_snapshot(repo, tmp_path / "snapshot", revision)

    assert not (snapshot / "conftest.py").exists()
    assert not (snapshot / "ignored.py").exists()
    assert (snapshot / "requirements.txt").read_text() == "requests==2.31.0\n"
    assert (repo / "requirements.txt").read_text() == "requests==0.0.0\n"


@pytest.mark.parametrize("staged", [False, True])
def test_dirty_scanner_is_rejected_before_preparing_importable_snapshot(source, tmp_path, staged):
    repo, revision = source
    (repo / "app/__init__.py").write_text("raise RuntimeError('modified scanner must not execute')\n")
    if staged:
        git(repo, "add", "app/__init__.py")
    destination = tmp_path / "snapshot"

    with pytest.raises(ValueError, match="scanner_tracked_code_modified"):
        guards.prepare_scanner_snapshot(repo, destination, revision)

    assert not destination.exists()


def test_scanner_snapshot_excludes_untracked_and_ignored_import_inputs(source, tmp_path):
    repo, revision = source
    for name in ("app/shadow.py", "app/ignored.py", "scripts/shadow.pyc"):
        (repo / name).write_bytes(b"unreviewed code")

    snapshot = guards.prepare_scanner_snapshot(repo, tmp_path / "snapshot", revision)

    assert sorted(str(p.relative_to(snapshot)) for p in snapshot.rglob("*") if p.is_file()) == [
        "app/__init__.py", "scripts/verify_dependency_remediation.py",
    ]
    assert (snapshot / "scripts/verify_dependency_remediation.py").read_text() == "PINNED = True\n"


def test_snapshot_rejects_wrong_commit(source, tmp_path):
    repo, _ = source
    with pytest.raises(ValueError, match="source_commit_mismatch"):
        guards.export_tracked_snapshot(repo, tmp_path / "snapshot", "0" * 40)


def test_snapshot_does_not_follow_committed_symlinks(source, tmp_path):
    repo, _ = source
    (repo / "external").symlink_to(tmp_path / "outside")
    git(repo, "add", "external")
    git(repo, "-c", "user.name=Offline test", "-c", "user.email=test@example.invalid", "commit", "-m", "symlink")
    with pytest.raises(ValueError, match="unsupported_snapshot_entry: external"):
        guards.export_tracked_snapshot(repo, tmp_path / "snapshot", git(repo, "rev-parse", "HEAD"))
    assert not (tmp_path / "outside").exists()

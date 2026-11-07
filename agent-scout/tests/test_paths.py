"""Engine provenance: what the report records when git cannot answer.

`engine_commit` must degrade to `None` — never crash, never guess a SHA —
so the report can state `unknown` instead of fabricating provenance.
Covered here: git binary missing, git failing, timeout, empty output,
and the happy path. The report's `unknown` fallback lives in test_report.
"""
from __future__ import annotations

import subprocess

import pytest

from scout import paths


@pytest.fixture
def checkout(tmp_path, monkeypatch):
    """Minimal shipit checkout shape so shipit_root() resolves honestly."""
    root = tmp_path / "shipit"
    marker = root / "app" / "scan" / "cve_match.py"
    marker.parent.mkdir(parents=True)
    marker.write_text("# fake checkout marker")
    monkeypatch.setenv(paths.ENV_ROOT, str(root))
    return root


def completed(stdout="", returncode=0):
    return subprocess.CompletedProcess(["git"], returncode, stdout, "")


def test_engine_commit_reads_short_sha(checkout, monkeypatch):
    monkeypatch.setattr(paths.subprocess, "run",
                        lambda *a, **k: completed("abc1234\n"))
    assert paths.engine_commit() == "abc1234"


def test_engine_commit_without_git_binary_is_none(checkout, monkeypatch):
    def missing(*a, **k):
        raise FileNotFoundError("git not installed")
    monkeypatch.setattr(paths.subprocess, "run", missing)
    assert paths.engine_commit() is None


def test_engine_commit_timeout_is_none(checkout, monkeypatch):
    def slow(*a, **k):
        raise subprocess.TimeoutExpired(cmd="git", timeout=10)
    monkeypatch.setattr(paths.subprocess, "run", slow)
    assert paths.engine_commit() is None


def test_engine_commit_git_failure_is_none(checkout, monkeypatch):
    # rc != 0 must return None even when git printed something to stdout.
    monkeypatch.setattr(paths.subprocess, "run",
                        lambda *a, **k: completed("HEAD\n", returncode=128))
    assert paths.engine_commit() is None


def test_engine_commit_empty_output_is_none(checkout, monkeypatch):
    monkeypatch.setattr(paths.subprocess, "run", lambda *a, **k: completed("  \n"))
    assert paths.engine_commit() is None

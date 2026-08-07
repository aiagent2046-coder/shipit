"""Tests for deploy/scripts/tag-release.sh — the CalVer release tagger.

Every test runs against a throwaway git repository under tmp_path with its own
`origin` remote, so nothing here can create, move or push a tag in the real
repository. `--skip-fetch` is passed everywhere except the one test that
exercises fetching, because a fetch would reach the network.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "deploy"
    / "scripts"
    / "tag-release.sh"
)


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def commit(repo: Path, message: str) -> str:
    (repo / "file.txt").write_text(message, encoding="utf-8")
    git(repo, "add", "file.txt")
    git(repo, "commit", "-q", "-m", message)
    return git(repo, "rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A clone with a real `origin` remote, so origin/main resolves."""
    upstream = tmp_path / "upstream.git"
    upstream.mkdir()
    git(upstream, "init", "-q", "--bare", "--initial-branch=main")

    work = tmp_path / "work"
    work.mkdir()
    git(work, "init", "-q", "--initial-branch=main")
    git(work, "config", "user.email", "test@example.invalid")
    git(work, "config", "user.name", "Test")
    git(work, "remote", "add", "origin", str(upstream))

    commit(work, "initial")
    git(work, "push", "-q", "origin", "main")
    git(work, "fetch", "-q", "origin")

    return work


def run_script(
    repo: Path,
    *args: str,
    fake_date: str = "2026.08.07",
) -> subprocess.CompletedProcess[str]:
    """Run the tagger with `date` stubbed, so the expected tag name is stable
    regardless of when the suite runs."""
    stub_dir = repo.parent / "stub-bin"
    stub_dir.mkdir(exist_ok=True)
    stub = stub_dir / "date"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        f'if [[ "$*" == "-u +%Y.%m.%d" ]]; then echo "{fake_date}"; exit 0; fi\n'
        'exec /bin/date "$@"\n',
        encoding="utf-8",
    )
    stub.chmod(0o755)

    import os

    env = dict(os.environ)
    env["PATH"] = f"{stub_dir}:{env['PATH']}"

    return subprocess.run(
        ["bash", str(SCRIPT), "--skip-fetch", *args],
        cwd=repo,
        capture_output=True,
        text=True,
        env=env,
    )


def test_first_tag_of_the_day_is_counter_one(repo: Path) -> None:
    result = run_script(repo)

    assert result.returncode == 0, result.stderr
    assert "v2026.08.07-1" in result.stdout
    assert git(repo, "tag", "--list") == "v2026.08.07-1"


def test_tag_is_annotated_and_points_at_the_commit(repo: Path) -> None:
    run_script(repo)

    # An annotated tag is its own object; a lightweight one would be "commit".
    assert git(repo, "cat-file", "-t", "v2026.08.07-1") == "tag"
    assert git(repo, "rev-parse", "v2026.08.07-1^{commit}") == git(
        repo, "rev-parse", "HEAD"
    )


def test_counter_increments_within_the_same_day(repo: Path) -> None:
    run_script(repo)
    commit(repo, "second")
    git(repo, "push", "-q", "origin", "main")
    git(repo, "fetch", "-q", "origin")

    result = run_script(repo)

    assert result.returncode == 0, result.stderr
    assert "v2026.08.07-2" in result.stdout


def test_counter_is_numeric_not_lexical(repo: Path) -> None:
    """With -10 present, the next tag must be -11, not -10 again.

    A lexical max ranks "9" above "10", so it would compute 9 as the highest
    and hand out -10 a second time — the script would then abort on "tag
    already exists" at best, or reuse a release number at worst. Seeding only
    1..9 does NOT catch this: for single digits the lexical and numeric
    answers agree. Verified by mutation — swapping (( > )) for [[ > ]] fails
    this test only because -10 is in the seed set.
    """
    for index in range(1, 11):
        git(
            repo,
            "tag",
            "-a",
            f"v2026.08.07-{index}",
            "-m",
            "seed",
        )

    result = run_script(repo)

    assert result.returncode == 0, result.stderr
    assert "v2026.08.07-11" in result.stdout


def test_a_different_day_restarts_the_counter(repo: Path) -> None:
    run_script(repo, fake_date="2026.08.07")

    result = run_script(repo, fake_date="2026.08.08")

    assert result.returncode == 0, result.stderr
    assert "v2026.08.08-1" in result.stdout


def test_refuses_a_commit_not_merged_into_main(repo: Path) -> None:
    """The gate deploy-production.sh applies, applied to tagging as well: a
    release tag must never point at unreviewed work."""
    git(repo, "checkout", "-q", "-b", "feature")
    unmerged = commit(repo, "unreviewed work")

    result = run_script(repo, "--revision", unmerged)

    assert result.returncode == 1
    assert "not an ancestor" in result.stderr
    assert git(repo, "tag", "--list") == ""


def test_tags_an_explicit_revision(repo: Path) -> None:
    first = git(repo, "rev-parse", "HEAD")
    commit(repo, "second")
    git(repo, "push", "-q", "origin", "main")
    git(repo, "fetch", "-q", "origin")

    result = run_script(repo, "--revision", first)

    assert result.returncode == 0, result.stderr
    assert git(repo, "rev-parse", "v2026.08.07-1^{commit}") == first


def test_does_not_push_unless_asked(repo: Path) -> None:
    result = run_script(repo)

    assert result.returncode == 0, result.stderr
    assert "Local only" in result.stdout

    upstream = repo.parent / "upstream.git"
    assert git(upstream, "tag", "--list") == ""


def test_pushes_when_asked(repo: Path) -> None:
    result = run_script(repo, "--push")

    assert result.returncode == 0, result.stderr

    upstream = repo.parent / "upstream.git"
    assert git(upstream, "tag", "--list") == "v2026.08.07-1"


def test_rejects_an_unknown_argument(repo: Path) -> None:
    result = run_script(repo, "--wat")

    assert result.returncode == 2
    assert "unknown argument" in result.stderr
    assert git(repo, "tag", "--list") == ""


def test_rejects_an_unresolvable_revision(repo: Path) -> None:
    result = run_script(repo, "--revision", "no-such-ref")

    assert result.returncode != 0
    assert git(repo, "tag", "--list") == ""

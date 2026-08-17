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
    skip_fetch: bool = True,
    env_extra: dict[str, str] | None = None,
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
    env.update(env_extra or {})

    # `origin` is a local bare repository, so even the fetching tests touch
    # no network; --skip-fetch stays the default because most tests are
    # about the counter, not the fetch.
    fetch_args = ["--skip-fetch"] if skip_fetch else []
    return subprocess.run(
        ["bash", str(SCRIPT), *fetch_args, *args],
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
    # The ERR trap, on a failure OUTSIDE the fetch wrapper -- the fetch
    # path prints its own diagnosis, so only a non-fetch failure proves the
    # trap exists. Without it, this exact shape is the silent death again.
    assert "tag-release: FAILED" in result.stderr


# --- failure must be loud ----------------------------------------------------
#
# This script died in complete silence three times in two days, on the same
# cause each time. Its first action was `git fetch --quiet --prune --tags`;
# a stale local tag whose name matched a different remote tag object made
# the fetch fail; --quiet swallowed git's one line naming the problem
# (" ! [rejected] ... would clobber existing tag"); and set -e exited before
# the script printed anything of its own. Piped through `| tail`, the
# operator saw a command that ran, printed nothing, and appeared to succeed
# -- on the script that decides what production is called. The stale tag is
# not an anomaly either: it is what a second machine holds whenever two
# people (or one person and one agent) tag the same release.


def _push_remote_tag(tmp_path: Path, name: str, sha: str) -> None:
    """Tag `sha` as `name` from a SECOND clone, so the tag object (tagger,
    timestamp, message) differs from anything the work clone creates --
    the same-name-different-object shape that makes fetch refuse."""
    other = tmp_path / "other"
    if not other.exists():
        git(tmp_path / "upstream.git", "symbolic-ref", "HEAD",
            "refs/heads/main")
        subprocess.run(
            ["git", "clone", "-q", str(tmp_path / "upstream.git"),
             str(other)],
            check=True, capture_output=True,
        )
        git(other, "config", "user.email", "other@example.invalid")
        git(other, "config", "user.name", "Other")
    git(other, "tag", "-a", name, sha, "-m", f"Release {name} (from other)")
    git(other, "push", "-q", "origin", f"refs/tags/{name}")


def test_a_stale_same_commit_tag_is_replaced_loudly(
        repo: Path, tmp_path: Path) -> None:
    """The common case, three times over: both tags point at the same commit
    and differ only as objects. Losing the local copy loses nothing -- the
    remote's is canonical and is fetched back immediately -- but it must
    happen out loud, and the run must then finish its actual job."""
    sha = git(repo, "rev-parse", "HEAD")
    _push_remote_tag(tmp_path, "v2026.08.07-1", sha)
    git(repo, "tag", "-a", "v2026.08.07-1", sha, "-m", "Release (local)")

    proc = run_script(repo, skip_fetch=False)

    assert proc.returncode == 0, proc.stderr
    # "stale duplicate", with the space, and not the bare word: pytest names
    # tmp_path after the test, git echoes that path in its "From ..." line,
    # and this test's own name contains "stale" -- so the bare word passed
    # with the script's message deleted. The assertion was being satisfied by
    # the name of the test asserting it. Caught because an identically-shaped
    # debug twin named test_dbg failed where this passed.
    assert "stale duplicate" in proc.stderr, "the replacement was silent"
    assert "Replacing it with" in proc.stderr
    assert "Created tag: v2026.08.07-2" in proc.stdout
    # The local ref now IS the remote's object.
    local = git(repo, "rev-parse", "refs/tags/v2026.08.07-1")
    remote = git(tmp_path / "upstream.git",
                 "rev-parse", "refs/tags/v2026.08.07-1")
    assert local == remote


def test_a_clash_on_a_different_commit_refuses_and_touches_nothing(
        repo: Path, tmp_path: Path) -> None:
    """The dangerous case. Same name, different commits, is a disagreement
    about what was released -- the script must say so, name both commits,
    and resolve nothing on its own."""
    first = git(repo, "rev-parse", "HEAD")
    _push_remote_tag(tmp_path, "v2026.08.07-1", first)
    second = commit(repo, "further work")
    git(repo, "tag", "-a", "v2026.08.07-1", second, "-m", "Release (local)")

    proc = run_script(repo, skip_fetch=False)

    assert proc.returncode != 0
    assert first[:7] in proc.stderr and second[:7] in proc.stderr, (
        "the two disagreeing commits are not named")
    assert "disagreement" in proc.stderr
    assert "Created tag" not in proc.stdout, "it went on to tag anyway"
    assert git(repo, "rev-parse", "refs/tags/v2026.08.07-1") != "", (
        "the local tag was deleted in the case that forbids it")
    assert git(repo, "rev-parse",
               "refs/tags/v2026.08.07-1^{commit}") == second


def test_any_failure_names_the_step_on_stderr(repo: Path) -> None:
    """The general guarantee behind both cases above: under set -e a failed
    step must identify itself, or a piped run reads as success. A remote
    that does not exist fails the fetch for a reason the clobber parser
    does not recognise -- the fallback path."""
    proc = run_script(repo, skip_fetch=False,
                      env_extra={"SHIPIT_TAG_REMOTE": "no-such-remote"})

    assert proc.returncode != 0
    assert proc.stderr.strip() != "", "the failure was silent"
    assert "tag-release" in proc.stderr, (
        "stderr carries only git's message; the script never spoke")


def test_fetch_success_output_is_not_mistaken_for_failure(
        repo: Path, tmp_path: Path) -> None:
    """A fetch that BRINGS tags prints lines; that is news, not an error.
    The run must succeed and count the arrived tag into the counter."""
    sha = git(repo, "rev-parse", "HEAD")
    _push_remote_tag(tmp_path, "v2026.08.07-1", sha)

    proc = run_script(repo, skip_fetch=False)

    assert proc.returncode == 0, proc.stderr
    assert "Created tag: v2026.08.07-2" in proc.stdout

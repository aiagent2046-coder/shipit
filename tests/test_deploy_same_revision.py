"""deploy-production.sh must not report PASSED for a deployment that changed
nothing.

On 2026-08-11 nine commits sat on an unmerged branch. tag-release.sh tagged
origin/main, as it is supposed to, so v2026.08.11-2 was cut against the same
commit as v2026.08.11-1. The deploy ran green -- build, migration gate, health
gate, "Production deployment: PASSED" -- and production kept running the old
code. Every gate in the script was working; none of them is about this.

The script already printed "Target release" and "Current release" one after
the other. Two identical SHAs on adjacent lines were not enough, because the
word that gets read is PASSED. So the equality is now checked rather than
displayed.

Deliberately an error with an escape hatch, not a refusal. Redeploying the
running commit is legitimate -- a rebuilt host, a manual change on the box, a
build no longer trusted -- and --allow-same-revision distinguishes that from
the accident, which is the whole point.

Runs the real script against a real git repository, with python3 and systemctl
stubbed. The fixtures come from test_deploy_control_checkout, which already
builds a host whose `current` symlink points at a real release.
"""

from __future__ import annotations

from pathlib import Path

from tests.test_deploy_control_checkout import SCRIPT, calls, git, run_deploy

# `host` is a fixture, not a helper, so it arrives this way rather than by
# import: importing the name would shadow it in every signature below, which
# is a real ambiguity and not merely a lint complaint -- the module-level name
# and the injected argument would be different objects with the same spelling.
# The plain functions above have no such problem and are imported normally.
pytest_plugins = ["tests.test_deploy_control_checkout"]


def test_deploying_the_running_commit_fails_instead_of_passing(host: dict):
    """The regression, in the shape it actually happened: the tag resolves to
    the commit already deployed."""
    git(host["control"], "fetch", "-q", "origin", "main")
    result = run_deploy(host, "--revision", host["old_sha"])

    assert result.returncode == 1, result.stdout

    assert "already resolves to the running release" in result.stderr
    assert "PASSED" in result.stderr, (
        "the message must name the outcome it is preventing -- an operator "
        "who saw PASSED is the reader this is written for"
    )
    assert "not merged yet" in result.stderr, (
        "the overwhelmingly likely cause has to be in the message; without "
        "it the operator is told what is wrong and not what to do"
    )
    assert "--allow-same-revision" in result.stderr


def test_it_stops_before_building_anything(host: dict):
    """Not merely before the health check. A build writes a release directory
    and takes minutes; there is nothing to learn from doing that work to
    arrive back where we started."""
    git(host["control"], "fetch", "-q", "origin", "main")
    run_deploy(host, "--revision", host["old_sha"])

    assert "build" not in calls(host)
    assert "systemctl" not in calls(host)


def test_the_escape_hatch_deploys_the_running_commit(host: dict):
    """A rebuilt host, a manual change on the box, a build no longer trusted.
    The flag says so out loud, which is the difference being drawn."""
    git(host["control"], "fetch", "-q", "origin", "main")
    result = run_deploy(
        host, "--revision", host["old_sha"], "--allow-same-revision",
    )

    assert result.returncode == 0, result.stderr
    assert "redeploying the running commit, as requested" in result.stdout
    assert "build" in calls(host)


def test_a_genuinely_new_commit_is_untouched_by_the_guard(host: dict):
    """The guard must be invisible on every ordinary deployment. This is the
    same path test_deploy_control_checkout covers, asserted here against the
    one thing that could have broken it."""
    result = run_deploy(host, "--revision", "v2026.08.07-1")

    assert result.returncode == 0, result.stderr
    assert "already resolves" not in result.stderr
    assert "build" in calls(host)


def test_the_ci_path_cannot_pass_the_escape_hatch():
    """The SSH key on the host is pinned to a forced command that accepts
    exactly `deploy <tag>`. It therefore cannot pass --allow-same-revision,
    and a CI deployment of the already-running commit now fails.

    That is the intended reading, not an oversight: the CI path is precisely
    where nobody is watching the two SHA lines, and the deliberate case --
    rebuilding a host, distrusting a build -- is one someone is doing by hand
    on the box anyway. Pinned here so that widening the forced command is a
    decision rather than a side effect.
    """
    forced = (
        Path(__file__).resolve().parents[1]
        / "deploy" / "scripts" / "ci-deploy-command.sh"
    ).read_text(encoding="utf-8")

    assert 'exec "$DEPLOY" --revision "$TAG"' in forced
    assert "allow-same-revision" not in forced


def test_the_guard_is_not_defeated_by_a_missing_symlink():
    """A first deployment onto a fresh host has no `current` at all. The check
    has to be about equality, not about the string being empty -- comparing an
    unset CURRENT_SHA against a real SHA must simply not match, and `set -u`
    must not fire on the way past."""
    source = SCRIPT.read_text(encoding="utf-8")

    assert 'if [[ -n "$CURRENT_SHA" && "$CURRENT_SHA" == "$TARGET_SHA" ]]' in source

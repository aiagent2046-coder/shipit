"""deploy-production.sh's fetch and control-checkout synchronisation.

Two defects, both found the hard way while cutting the first CalVer release:

  * the fetch was branch-scoped (`git fetch --prune origin main`), and tag
    auto-following only applies to the refs being fetched -- so a release tag
    never arrived and deploying by tag died at `rev-parse`;

  * the control checkout was never moved to the revision being deployed. The
    deploy tooling is versioned with the application but runs from that
    long-lived working tree, so the build was performed by whatever builder
    happened to be checked out -- an OLD builder producing a NEW release. The
    first CalVer deployment passed every gate and still reported
    `version: null`, because the previous builder wrote the metadata.

Both are exercised against a real git repository with a real remote, running
the actual script with `python3`/`systemctl` stubbed. Nothing here reaches the
network or touches the real host.
"""

from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path

import pytest


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "deploy"
    / "scripts"
    / "deploy-production.sh"
)

SYNC_SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "deploy"
    / "scripts"
    / "sync-release-systemd-unit.sh"
)


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def write(path: Path, body: str, *, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
    if executable:
        path.chmod(0o755)


def make_release(release_root: Path, sha: str) -> None:
    release = release_root / "releases" / sha
    (release / ".venv" / "bin").mkdir(parents=True, exist_ok=True)
    write(
        release / ".venv" / "bin" / "python",
        "#!/usr/bin/env bash\nexit 0\n",
        executable=True,
    )
    write(release / "deploy" / "scripts" / "validate-production-env.py", "")
    write(
        release / "deploy" / "systemd" / "shipit-fixpack.service",
        "[Unit]\nDescription=t\n\n[Service]\nType=oneshot\nExecStart=/bin/true\n",
    )


def stub_bin(tmp: Path) -> Path:
    """Stubs for the external commands the script drives.

    `python3` records which release_manager subcommand it was asked to run and
    the builder version that was on disk at that moment -- that recording is
    what makes the control-checkout defect observable.
    """
    bin_dir = tmp / "stub-bin"
    bin_dir.mkdir(exist_ok=True)

    write(
        bin_dir / "python3",
        f"""
        #!/usr/bin/env bash
        for arg in "$@"; do
          case "$arg" in
            *release_manager.py)
              echo "BUILDER_VERSION=$(cat "$arg" 2>/dev/null)" \
                >> "{tmp}/calls.log"
              ;;
          esac
        done
        echo "python3 $*" >> "{tmp}/calls.log"
        exit 0
        """,
        executable=True,
    )

    for name in ("systemctl", "flock"):
        write(
            bin_dir / name,
            f"""
            #!/usr/bin/env bash
            echo "{name} $*" >> "{tmp}/calls.log"
            exit 0
            """,
            executable=True,
        )

    return bin_dir


@pytest.fixture
def host(tmp_path: Path) -> dict:
    """A control checkout cloned from a real bare remote, plus a release root.

    The control checkout is deliberately left one commit BEHIND the remote, so
    a deploy has to move it -- reproducing the production situation.
    """
    upstream = tmp_path / "upstream.git"
    upstream.mkdir()
    git(upstream, "init", "-q", "--bare", "--initial-branch=main")

    seed = tmp_path / "seed"
    seed.mkdir()
    git(seed, "init", "-q", "--initial-branch=main")
    git(seed, "config", "user.email", "t@t")
    git(seed, "config", "user.name", "t")
    git(seed, "remote", "add", "origin", str(upstream))

    scripts = seed / "deploy" / "scripts"
    write(scripts / "release_manager.py", "OLD_BUILDER")
    write(scripts / "check_release_migrations.py", "")
    write(scripts / "health_gate.py", "")
    write(seed / ".env", "X=1\n")
    (scripts / "sync-release-systemd-unit.sh").write_bytes(
        SYNC_SCRIPT.read_bytes()
    )
    (scripts / "sync-release-systemd-unit.sh").chmod(0o755)

    git(seed, "add", "-A")
    git(seed, "commit", "-qm", "old builder")
    old_sha = git(seed, "rev-parse", "HEAD")
    git(seed, "push", "-q", "origin", "main")

    # The control checkout on the "host", pinned at the old commit.
    control = tmp_path / "opt"
    subprocess.run(
        ["git", "clone", "-q", str(upstream), str(control)],
        check=True,
        capture_output=True,
    )
    git(control, "config", "user.email", "t@t")
    git(control, "config", "user.name", "t")

    # A newer commit lands upstream, carrying a NEW builder and a tag.
    write(scripts / "release_manager.py", "NEW_BUILDER")
    git(seed, "add", "-A")
    git(seed, "commit", "-qm", "new builder")
    new_sha = git(seed, "rev-parse", "HEAD")
    git(seed, "tag", "-a", "v2026.08.07-1", "-m", "release")
    git(seed, "push", "-q", "origin", "main")
    git(seed, "push", "-q", "origin", "refs/tags/v2026.08.07-1")

    srv = tmp_path / "srv"
    make_release(srv, old_sha)
    make_release(srv, new_sha)
    (srv / "current").symlink_to(srv / "releases" / old_sha)

    unit_dest = tmp_path / "etc" / "systemd" / "system" / "shipit-fixpack.service"
    write(unit_dest, "[Unit]\nDescription=old\n")

    return {
        "tmp": tmp_path,
        "control": control,
        "srv": srv,
        "old_sha": old_sha,
        "new_sha": new_sha,
        "env": {
            "SHIPIT_CONTROL_ROOT": str(control),
            "SHIPIT_RELEASE_ROOT": str(srv),
            "SHIPIT_ENV_FILE": str(control / ".env"),
            "SHIPIT_RELEASE_ENV": str(tmp_path / ".release-env"),
            "SHIPIT_SERVICE": "stub.service",
            "SHIPIT_FIXPACK_UNIT_DEST": str(unit_dest),
            "SHIPIT_DEPLOY_LOCK": str(tmp_path / "deploy.lock"),
        },
    }


def run_deploy(host: dict, *args: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env.update(host["env"])
    env["PATH"] = f"{stub_bin(host['tmp'])}:{env['PATH']}"

    # EUID cannot be faked from outside; the root guard is a precondition, not
    # the behaviour under test.
    source = SCRIPT.read_text(encoding="utf-8").replace(
        'if [[ "$EUID" -ne 0 ]]; then', "if false; then"
    )
    harness = host["tmp"] / "deploy-under-test.sh"
    write(harness, source, executable=True)

    return subprocess.run(
        ["bash", str(harness), *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )


def calls(host: dict) -> str:
    log = host["tmp"] / "calls.log"
    return log.read_text(encoding="utf-8") if log.exists() else ""


def test_fetch_brings_release_tags(host: dict) -> None:
    """Deploying by tag must work on a host that has never seen the tag.

    A branch-scoped fetch does not auto-follow tags, so without --tags this
    dies at `rev-parse` with "Needed a single revision".
    """
    assert git(host["control"], "tag", "--list") == ""

    result = run_deploy(host, "--revision", "v2026.08.07-1")

    assert result.returncode == 0, result.stderr
    assert git(host["control"], "tag", "--list") == "v2026.08.07-1"


def test_control_checkout_is_moved_to_the_deployed_revision(
    host: dict,
) -> None:
    result = run_deploy(host, "--revision", "v2026.08.07-1")

    assert result.returncode == 0, result.stderr
    assert git(host["control"], "rev-parse", "HEAD") == host["new_sha"]


def test_the_new_builder_performs_the_build(host: dict) -> None:
    """The defect this exists for: an OLD builder producing a NEW release.

    The control checkout starts on the old commit. If it is not synced first,
    the build runs release_manager.py as it was BEFORE the deploy -- which is
    how the first CalVer release shipped with `version: null`.
    """
    assert (
        host["control"] / "deploy" / "scripts" / "release_manager.py"
    ).read_text(encoding="utf-8") == "OLD_BUILDER"

    result = run_deploy(host, "--revision", "v2026.08.07-1")

    assert result.returncode == 0, result.stderr
    assert "BUILDER_VERSION=NEW_BUILDER" in calls(host)
    assert "BUILDER_VERSION=OLD_BUILDER" not in calls(host)


def test_sync_is_reported_to_the_operator(host: dict) -> None:
    result = run_deploy(host, "--revision", "v2026.08.07-1")

    assert result.returncode == 0, result.stderr
    assert "Syncing control checkout" in result.stdout


def test_no_sync_message_when_already_on_the_revision(host: dict) -> None:
    """Redeploying the current revision must be quiet about syncing."""
    run_deploy(host, "--revision", "v2026.08.07-1")
    (host["tmp"] / "calls.log").unlink(missing_ok=True)

    result = run_deploy(host, "--revision", "v2026.08.07-1")

    assert result.returncode == 0, result.stderr
    assert "Syncing control checkout" not in result.stdout


def test_uncommitted_changes_still_block_the_deploy(host: dict) -> None:
    """The sync must never be able to discard an operator's local edits: the
    preflight refuses a dirty tree before anything is checked out."""
    (host["control"] / "deploy" / "scripts" / "health_gate.py").write_text(
        "local edit", encoding="utf-8"
    )

    result = run_deploy(host, "--revision", "v2026.08.07-1")

    assert result.returncode != 0
    assert "uncommitted changes" in result.stderr
    # Still on the old commit: nothing was checked out over the edit.
    assert git(host["control"], "rev-parse", "HEAD") == host["old_sha"]
    assert (
        host["control"] / "deploy" / "scripts" / "health_gate.py"
    ).read_text(encoding="utf-8") == "local edit"


def test_a_commit_not_on_main_is_still_refused(host: dict) -> None:
    """The ancestor gate runs BEFORE the sync, so an unreviewed commit can
    never be checked out into the control tree."""
    control = host["control"]

    # Build the unreviewed commit inside the control checkout itself, on a
    # local branch. Pushing it to the remote instead does not work: the
    # script's fetch uses --prune, and a local branch created purely to carry
    # the object would be pruned away, leaving `rev-parse` unable to resolve
    # it -- the run would then fail for the wrong reason.
    current = git(control, "rev-parse", "HEAD")
    git(control, "checkout", "-q", "-b", "stray")
    write(control / "unreviewed.txt", "x")
    git(control, "add", "-A")
    git(control, "commit", "-qm", "unreviewed")
    stray_sha = git(control, "rev-parse", "HEAD")
    git(control, "checkout", "-q", "--detach", current)

    result = run_deploy(host, "--revision", stray_sha)

    assert result.returncode != 0
    assert "not contained in origin/main" in result.stderr
    assert git(control, "rev-parse", "HEAD") == host["old_sha"]

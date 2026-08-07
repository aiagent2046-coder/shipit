"""ci-deploy-command.sh — the forced command guarding the CI deploy key.

This is a security boundary, so the tests are adversarial rather than
illustrative: the happy path is one test, and the rest are attempts to make
the wrapper run something it should not.

The real deploy script is replaced by a recorder, so a test that DID break
through would be visible as a recorded invocation rather than as an actual
deployment.
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
    / "ci-deploy-command.sh"
)


@pytest.fixture
def sandbox(tmp_path: Path) -> dict:
    """A stand-in deploy script that records its argv instead of deploying."""
    recorder = tmp_path / "deploy-production.sh"
    recorder.write_text(
        textwrap.dedent(
            f"""
            #!/usr/bin/env bash
            printf '%s\\n' "$@" >> "{tmp_path}/invocations.log"
            echo "Production deployment: PASSED"
            """
        ).lstrip(),
        encoding="utf-8",
    )
    recorder.chmod(0o755)

    return {"tmp": tmp_path, "log": tmp_path / "invocations.log"}


def run(sandbox: dict, request: str | None) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["SHIPIT_DEPLOY_SCRIPT"] = str(sandbox["tmp"] / "deploy-production.sh")
    if request is None:
        env.pop("SSH_ORIGINAL_COMMAND", None)
    else:
        env["SSH_ORIGINAL_COMMAND"] = request

    return subprocess.run(
        ["bash", str(SCRIPT)],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


def invocations(sandbox: dict) -> list[str]:
    log = sandbox["log"]
    if not log.exists():
        return []
    return log.read_text(encoding="utf-8").split()


def test_a_valid_tag_is_deployed(sandbox: dict) -> None:
    result = run(sandbox, "deploy v2026.08.07-2")

    assert result.returncode == 0, result.stderr
    assert invocations(sandbox) == ["--revision", "v2026.08.07-2"]


def test_multi_digit_counter_is_accepted(sandbox: dict) -> None:
    result = run(sandbox, "deploy v2026.08.07-11")

    assert result.returncode == 0, result.stderr
    assert invocations(sandbox) == ["--revision", "v2026.08.07-11"]


@pytest.mark.parametrize(
    "request_line",
    [
        # No request at all: someone opened a session without a command.
        None,
        "",
        # An interactive shell.
        "bash",
        "/bin/sh",
        # Reading secrets is the whole reason this wrapper exists.
        "cat /opt/shipit/.env",
        # The right verb, but no tag.
        "deploy",
        "deploy ",
        # Command chaining, in every shape a shell would honour.
        "deploy v2026.08.07-2; cat /opt/shipit/.env",
        "deploy v2026.08.07-2 && cat /opt/shipit/.env",
        "deploy v2026.08.07-2 | tee /tmp/x",
        "deploy v2026.08.07-2 & id",
        # Substitution.
        "deploy $(cat /opt/shipit/.env)",
        "deploy `id`",
        "deploy ${IFS}x",
        # A second argument smuggled past the tag.
        "deploy v2026.08.07-2 --revision main",
        "deploy v2026.08.07-2 extra",
        # Newline-separated second command.
        "deploy v2026.08.07-2\ncat /opt/shipit/.env",
        # A different verb.
        "rollback v2026.08.07-1",
        "DEPLOY v2026.08.07-2",
        # Not a release tag: a SHA, a branch, a ref expression.
        "deploy 7acc211cd3888183c5eccd184718b73e44d407f3",
        "deploy main",
        "deploy origin/main",
        "deploy HEAD",
        "deploy v2026.08.07-2^{commit}",
        # Tag-shaped but wrong.
        "deploy v2026.8.7-2",
        "deploy v2026.08.07",
        "deploy v2026.08.07-",
        "deploy 2026.08.07-2",
        "deploy vv2026.08.07-2",
        "deploy v2026.08.07-2x",
        # Path traversal in tag position.
        "deploy ../../etc/passwd",
        "deploy /etc/passwd",
    ],
)
def test_everything_else_is_refused(
    sandbox: dict, request_line: str | None
) -> None:
    result = run(sandbox, request_line)

    assert result.returncode != 0, (
        f"accepted {request_line!r}, which must be refused"
    )
    assert invocations(sandbox) == [], (
        f"{request_line!r} reached the deploy script"
    )


def test_refusal_does_not_echo_the_request_back(sandbox: dict) -> None:
    """The caller is untrusted: a refusal must not help it probe the wrapper
    by reflecting what it sent."""
    result = run(sandbox, "cat /opt/shipit/.env")

    assert result.returncode != 0
    assert "/opt/shipit/.env" not in result.stderr
    assert "/opt/shipit/.env" not in result.stdout
    assert "refused" in result.stderr


def test_a_missing_deploy_script_fails_loudly(sandbox: dict) -> None:
    """Never silently succeed when the thing being guarded is absent."""
    (sandbox["tmp"] / "deploy-production.sh").unlink()

    result = run(sandbox, "deploy v2026.08.07-2")

    assert result.returncode != 0
    assert "deploy script missing" in result.stderr


def test_the_deploy_scripts_exit_code_is_propagated(sandbox: dict) -> None:
    """A failed deployment must fail the CI job, not report success."""
    (sandbox["tmp"] / "deploy-production.sh").write_text(
        "#!/usr/bin/env bash\necho boom >&2\nexit 3\n", encoding="utf-8"
    )
    (sandbox["tmp"] / "deploy-production.sh").chmod(0o755)

    result = run(sandbox, "deploy v2026.08.07-2")

    assert result.returncode == 3

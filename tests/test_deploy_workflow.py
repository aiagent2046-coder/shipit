"""The deploy-production workflow's own guards.

The workflow cannot be executed here, so two things are tested instead:

  * its declared shape — trigger, permissions, concurrency, environment —
    since those are the properties that decide whether a merge can ship code
    or whether two deploys can overlap;

  * the tag-validation logic, extracted from the workflow and run as real bash
    against the same inputs the forced command is tested with, so the two
    layers cannot silently disagree about what a release tag is.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest
import yaml


WORKFLOW = (
    Path(__file__).resolve().parents[1]
    / ".github"
    / "workflows"
    / "deploy-production.yml"
)


@pytest.fixture(scope="module")
def workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def triggers(workflow: dict) -> dict:
    # PyYAML parses the bare `on:` key as the boolean True.
    return workflow.get(True) or workflow.get("on") or {}


def test_deployment_is_manual_only(workflow: dict) -> None:
    """Merging must never ship code by itself.

    A push or tag trigger here would turn every merge into a production
    deployment, which is a different risk posture than the one agreed.
    """
    assert set(triggers(workflow)) == {"workflow_dispatch"}


def test_it_takes_a_tag_input(workflow: dict) -> None:
    inputs = triggers(workflow)["workflow_dispatch"]["inputs"]

    assert "tag" in inputs
    assert inputs["tag"]["required"] is True


def test_token_permissions_are_read_only(workflow: dict) -> None:
    assert workflow["permissions"] == {"contents": "read"}


def test_deployments_cannot_overlap_or_be_cancelled(workflow: dict) -> None:
    """A half-finished deployment must be allowed to finish or roll back.

    cancel-in-progress would kill it mid-symlink-switch, leaving the host in a
    state neither release owns.
    """
    concurrency = workflow["concurrency"]

    assert concurrency["group"] == "deploy-production"
    assert concurrency["cancel-in-progress"] is False


def test_it_runs_in_the_production_environment(workflow: dict) -> None:
    """The environment is what carries the secrets and, once configured, the
    required-reviewer gate."""
    assert workflow["jobs"]["deploy"]["environment"] == "Production"


def test_the_private_key_is_never_echoed(workflow: dict) -> None:
    """`echo "$KEY"` would put the key in the log under `set -x`."""
    body = WORKFLOW.read_text(encoding="utf-8")

    assert "printf '%s\\n' \"$DEPLOY_SSH_KEY\"" in body
    assert 'echo "$DEPLOY_SSH_KEY"' not in body


def test_host_keys_are_pinned(workflow: dict) -> None:
    """Accepting an unknown host key would let anything answering on that
    address collect a deploy attempt.

    Comment lines are stripped before matching: the workflow explains *why* it
    does not use StrictHostKeyChecking=no, and a naive substring search over
    the whole file matches that explanation and passes for the wrong reason.
    """
    body = WORKFLOW.read_text(encoding="utf-8")
    code = "\n".join(
        line for line in body.splitlines() if not line.lstrip().startswith("#")
    )

    assert "DEPLOY_KNOWN_HOSTS" in code
    assert "StrictHostKeyChecking=no" not in code
    assert "StrictHostKeyChecking accept-new" not in code
    assert "StrictHostKeyChecking=accept-new" not in code


def test_the_release_is_verified_after_deploying(workflow: dict) -> None:
    """A deploy that left the previous release running must not pass."""
    steps = [s["name"] for s in workflow["jobs"]["deploy"]["steps"]]

    assert "Verify the running release" in steps
    assert steps.index("Verify the running release") > steps.index("Deploy")


# --- the tag guard, extracted and executed -------------------------------


def extract_tag_pattern() -> str:
    """Pull the regex out of the workflow so the test cannot drift from it."""
    body = WORKFLOW.read_text(encoding="utf-8")
    match = re.search(r'if \[\[ ! "\$TAG" =~ (\^v.*?\$) \]\]', body)
    assert match, "tag validation regex not found in the workflow"
    return match.group(1)


def check_tag(candidate: str) -> int:
    """Run the workflow's own guard as bash, against one candidate."""
    script = f"""
    set -Eeuo pipefail
    TAG="$1"
    if [[ ! "$TAG" =~ {extract_tag_pattern()} ]]; then
      exit 1
    fi
    exit 0
    """
    return subprocess.run(
        ["bash", "-c", script, "_", candidate],
        capture_output=True,
        text=True,
    ).returncode


@pytest.mark.parametrize(
    "tag", ["v2026.08.07-1", "v2026.08.07-2", "v2026.08.07-11", "v2027.01.31-9"]
)
def test_release_tags_are_accepted(tag: str) -> None:
    assert check_tag(tag) == 0


@pytest.mark.parametrize(
    "candidate",
    [
        "",
        "main",
        "origin/main",
        "HEAD",
        "7acc211cd3888183c5eccd184718b73e44d407f3",
        "v2026.8.7-2",
        "v2026.08.07",
        "v2026.08.07-",
        "2026.08.07-2",
        "vv2026.08.07-2",
        "v2026.08.07-2x",
        "v2026.08.07-2; id",
        "v2026.08.07-2 extra",
        "../../etc/passwd",
    ],
)
def test_non_release_tags_are_rejected(candidate: str) -> None:
    assert check_tag(candidate) != 0, f"accepted {candidate!r}"


def test_the_two_layers_agree_on_what_a_tag_is() -> None:
    """The workflow and the host-side forced command must use the same shape.

    If they drift, either the workflow rejects something the host would accept
    (merely annoying) or it accepts something the host refuses, which surfaces
    as an opaque "refused" with no explanation.
    """
    forced_command = (
        Path(__file__).resolve().parents[1]
        / "deploy"
        / "scripts"
        / "ci-deploy-command.sh"
    ).read_text(encoding="utf-8")

    match = re.search(r"TAG_RE='(\^v.*?\$)'", forced_command)
    assert match, "TAG_RE not found in ci-deploy-command.sh"

    assert match.group(1) == extract_tag_pattern()

"""scripts/preflight.sh must stay the local mirror of production-ci.

A gate script that drifts from CI is worse than none: it prints "all gates
passed" while the gate CI added last month never runs, and the author trusts
it. So the tie is asserted here rather than remembered -- every command the
workflow runs that CAN run locally must appear in the script.
"""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "preflight.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "production-ci.yml"

# The literal commands production-ci.yml runs which need nothing a laptop
# lacks. Deliberately NOT the workflow's step names: names are prose and drift
# harmlessly, commands are what actually gates a merge.
#
# Excluded on purpose, with the reason, so a reader can tell "not mirrored"
# from "forgotten":
#   * shellcheck / shfmt      -- installed by the job via apt, absent locally
#   * systemd unit validation -- needs a production-like unit tree
#   * dev-lock containment    -- compares lockfiles the job regenerates
# Pairs, because the two files spell the same gate differently: the workflow
# calls the tool directly, the script goes through "$PY"/"$RUFF" so it works
# with or without the venv. Matching one literal against both files failed on
# its first run -- against the script, which is correct and simply does not
# contain the string "ruff check .".
LOCAL_GATES = (
    ("git diff --check", "git diff --check"),
    ("scan-added-secrets.py", "scan-added-secrets.py"),
    ("ruff check .", '"$RUFF" check .'),
    ("pytest -q", "-m pytest -q"),
)


@pytest.mark.parametrize("in_workflow,in_script", LOCAL_GATES)
def test_preflight_runs_every_locally_runnable_ci_gate(in_workflow, in_script):
    workflow = WORKFLOW.read_text(encoding="utf-8")
    assert in_workflow in workflow, (
        f"{in_workflow!r} is no longer in production-ci.yml. If CI dropped "
        "it, drop it from LOCAL_GATES too; if it moved, update both."
    )
    assert in_script in SCRIPT.read_text(encoding="utf-8"), (
        f"production-ci.yml runs {in_workflow!r} and scripts/preflight.sh "
        "does not. A local gate missing a CI gate reports a pass CI will not "
        "honour."
    )


def test_preflight_is_executable():
    """Documented as `scripts/preflight.sh`, so it has to run as one."""
    assert SCRIPT.stat().st_mode & 0o111, "chmod +x scripts/preflight.sh"


def test_preflight_compares_against_the_remote_base():
    """Its first real run compared against a local origin/main two merges
    stale, scanning a wider diff than CI would. Fetching the base is what
    makes a local pass mean the same thing as a remote one.

    The first version of this assertion looked for "git fetch" anywhere in the
    file and passed against a script with the fetch removed -- the string also
    occurs in the "base not found" hint. Match the call, not the words.
    """
    body = SCRIPT.read_text(encoding="utf-8")
    assert 'git fetch --quiet origin "${BASE#origin/}"' in body
    assert 'BASE:-origin/main' in body

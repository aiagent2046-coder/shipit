"""scripts/env_keys.py -- the shape of breakage nothing else could see.

On 2026-08-28 a hand edit to /opt/shipit/.env replaced the LLM_MODEL line with
a different variable. The validator passed, the service started, jobs finished
`succeeded`, and every paid audit came back static-only under a paid basis.

The validator has since learned to catch a duplicated key and a provider with
no model pinned -- both from that same edit -- but neither can catch a variable
that was there yesterday and is not there today: it sees one file at one moment
and has no memory. The only thing that knew was a week-old backup of every live
credential, and keeping one of those around is its own problem.

THE SAFETY PROPERTY, tested first and hardest: the snapshot holds names and
never values. That is what lets it live beside the env file indefinitely.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "scripts" / "env_keys.py"

SPEC = importlib.util.spec_from_file_location("shipit_env_keys", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
env_keys = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = env_keys
SPEC.loader.exec_module(env_keys)

# Distinctive enough that finding it anywhere in the snapshot is unambiguous.
SECRET = "hunter2-this-must-never-be-written-down"
ENV_TEXT = (
    "# a comment\n"
    "DATABASE_URL=postgresql://fake-user@localhost:5432/fake-db\n"
    f"SMTP_PASSWORD={SECRET}\n"
    "LLM_MODEL=claude-sonnet-4.6\n"
    "\n"
    "# COMMENTED_OUT=value\n"
)


def _env(tmp_path: Path, text: str = ENV_TEXT) -> Path:
    path = tmp_path / ".env"
    path.write_text(text, encoding="utf-8")
    return path


def _run(*argv: str) -> int:
    return env_keys.main(list(argv))


def test_the_snapshot_records_names_and_never_values(tmp_path):
    """THE reason this file may sit next to /opt/shipit/.env forever."""
    env = _env(tmp_path)

    assert _run("snapshot", "--env-file", str(env)) == 0

    written = env_keys.snapshot_path(env).read_text(encoding="utf-8")
    assert "SMTP_PASSWORD" in written
    assert SECRET not in written, "a value reached the snapshot"
    assert "postgresql://" not in written
    assert "claude-sonnet-4.6" not in written


def test_a_dropped_variable_is_reported_and_fails(tmp_path, capsys):
    """The incident, reproduced: LLM_MODEL was there and then was not."""
    env = _env(tmp_path)
    assert _run("snapshot", "--env-file", str(env)) == 0

    env.write_text(ENV_TEXT.replace("LLM_MODEL=claude-sonnet-4.6\n", ""),
                   encoding="utf-8")

    assert _run("diff", "--env-file", str(env)) == 1
    err = capsys.readouterr().err
    assert "MISSING: LLM_MODEL" in err


def test_an_added_variable_is_reported_but_passes(tmp_path, capsys):
    """Adding a variable is ordinary -- most edits add one. Failing on it
    would train the operator to ignore the output, which is how a check stops
    being a check."""
    env = _env(tmp_path)
    assert _run("snapshot", "--env-file", str(env)) == 0

    env.write_text(ENV_TEXT + "MCP_ENABLED=1\n", encoding="utf-8")

    assert _run("diff", "--env-file", str(env)) == 0
    assert "added:   MCP_ENABLED" in capsys.readouterr().out


def test_an_unchanged_file_passes_quietly(tmp_path, capsys):
    env = _env(tmp_path)
    assert _run("snapshot", "--env-file", str(env)) == 0

    assert _run("diff", "--env-file", str(env)) == 0
    assert "nothing lost" in capsys.readouterr().out


def test_a_replaced_variable_is_caught(tmp_path, capsys):
    """Exactly what the edit did: one line became a DIFFERENT variable, so the
    count is unchanged and only the names give it away."""
    env = _env(tmp_path)
    assert _run("snapshot", "--env-file", str(env)) == 0

    env.write_text(
        ENV_TEXT.replace("LLM_MODEL=claude-sonnet-4.6",
                         "FREE_TIER_LLM_MODEL=glm-5.3-flash"),
        encoding="utf-8")

    assert _run("diff", "--env-file", str(env)) == 1
    captured = capsys.readouterr()
    assert "MISSING: LLM_MODEL" in captured.err
    assert "added:   FREE_TIER_LLM_MODEL" in captured.out


def test_diff_without_a_snapshot_is_not_a_pass(tmp_path, capsys):
    """A comparison with nothing to compare against is not a clean bill of
    health, and exit 0 would let it read as one from a script."""
    env = _env(tmp_path)

    assert _run("diff", "--env-file", str(env)) != 0
    assert "run `snapshot` BEFORE editing" in capsys.readouterr().err


def test_a_commented_line_is_not_a_variable(tmp_path):
    """The parser is env_file's, which is the validator's, which is the one
    the service agrees with. A second set of rules here would report a
    phantom loss the first time somebody commented a line out."""
    env = _env(tmp_path)
    names = env_keys.key_names(env)

    assert "COMMENTED_OUT" not in names
    assert names == ["DATABASE_URL", "LLM_MODEL", "SMTP_PASSWORD"]


def test_the_snapshot_path_is_git_ignored():
    """Asked of git, not of me.

    The snapshot lands in /opt/shipit, which is a git checkout, and
    deploy-production.sh refuses to deploy with ANY untracked file present --
    a stray dub_after.json blocked three deploys on 2026-08-28. Without a
    .gitignore entry this tool would break releases instead of protecting
    them.

    This test exists because the comment in env_keys.py first asserted the
    suffix was already covered by a `.env*` rule. There is no such rule; there
    is `.env` and `.env.bak*`. git settles it in a way a reading does not.
    """
    name = ".env" + env_keys.SNAPSHOT_SUFFIX
    result = subprocess.run(
        ["git", "check-ignore", "-q", name],
        cwd=REPO_ROOT, capture_output=True,
    )
    assert result.returncode == 0, (
        f"{name} is not git-ignored: a snapshot written into the control "
        "checkout would block the next deploy")


def test_the_script_is_executable():
    """Its own docstring documents `scripts/env_keys.py snapshot`, and that
    is the form an operator will type at the moment they need it.

    Committed 644, it answers "Permission denied" -- documentation that does
    not work, discovered on the box rather than here. migration_manager.py,
    the closest thing to it (an operator-run tool with subcommands), is 755.
    """
    import os

    assert os.access(MODULE_PATH, os.X_OK), (
        "scripts/env_keys.py must be executable: its documented usage invokes "
        "it directly. `git update-index --chmod=+x scripts/env_keys.py`")

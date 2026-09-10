"""Artifacts the CLI writes, and who can read them.

An audit is somebody else's repository: its report names files and paths, and
its findings carry credential-shaped material in masked form. Writing that to
a file the whole machine can read is the one part of that exposure this side
can fix, so it is tested rather than assumed.
"""
from __future__ import annotations

import os
import stat

from app.audit_cli import _write_artifact


def mode_of(path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def test_a_fresh_artifact_is_owner_only(tmp_path):
    artifact = tmp_path / "audit.sarif"
    _write_artifact(artifact, "{}")
    assert artifact.read_text() == "{}"
    assert mode_of(artifact) == 0o600, (
        "the default umask would make an audit of someone else's repository "
        "readable by every account on the box")


def test_overwriting_an_artifact_tightens_an_existing_loose_mode(tmp_path):
    artifact = tmp_path / "audit.html"
    artifact.write_text("old")            # created by an earlier run, 0644
    os.chmod(artifact, 0o644)
    _write_artifact(artifact, "new")
    assert artifact.read_text() == "new"
    assert mode_of(artifact) == 0o600, (
        "the create-time mode does not apply to an existing file")

"""Artifacts the CLI writes, and who can read them.

An audit is somebody else's repository: its report names files and paths, and
its findings carry credential-shaped material in masked form. Writing that to
a file the whole machine can read is the one part of that exposure this side
can fix, so it is tested rather than assumed.
"""
from __future__ import annotations

import os
import stat
import io
import json
import zipfile

import pytest

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


@pytest.mark.parametrize("paths,root_option,expected", [
    (["aiagent2046-coder-shipit-952d392/src/config.py",
      "aiagent2046-coder-shipit-952d392/.env"], None, ["src/config.py", ".env"]),
    (["src/config.py", "src/other.py"], None, ["src/config.py", "src/other.py"]),
    (["export/src/config.py"], None, ["export/src/config.py"]),
    (["export/src/config.py"], "export", ["src/config.py"]),
    (["shipit-952d392/src/config.py", "README.md"], None,
     ["shipit-952d392/src/config.py", "README.md"]),
    (["shipit-952d392/src/config.py"], ".", ["shipit-952d392/src/config.py"]),
])
def test_cli_sarif_paths_use_archive_context(tmp_path, monkeypatch, capsys,
                                           paths, root_option, expected):
    """Exercise ZIP inspection, argument parsing and artifact rendering together.

    Only the scanner is substituted: its findings must pass through unchanged
    in JSON while SARIF locations map onto checkout paths.
    """
    from app import audit_cli

    archive = tmp_path / "source.zip"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as output:
        for path in paths:
            output.writestr(path, "# source\n")
    archive.write_bytes(buffer.getvalue())
    sarif_path = tmp_path / "out.sarif"
    findings = [{"rule_id": "generic-assignment", "file": path, "line": 1,
                 "title": "Hardcoded credential", "severity": "high"}
                for path in paths]
    monkeypatch.setattr(audit_cli, "run_scan", lambda *args, **kwargs: {
        "findings": findings, "score": {"scan_manifest": {"engine_version": "test"}},
        "llm": {},
    })
    argv = ["audit_cli", str(archive), "--sarif", str(sarif_path)]
    if root_option is not None:
        argv.extend(["--sarif-root", root_option])
    monkeypatch.setattr(audit_cli.sys, "argv", argv)
    assert audit_cli.main() == 0
    report = json.loads(capsys.readouterr().out)
    assert [finding["file"] for finding in report["findings"]] == paths
    document = json.loads(sarif_path.read_text())
    assert [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for r in document["runs"][0]["results"]] == expected
    assert mode_of(sarif_path) == 0o600


@pytest.mark.parametrize("arguments", [
    ["source.zip", "--sarif", "out.sarif", "--sarif-root"],
    ["source.zip", "--sarif-root", "export"],
    ["source.zip", "--sarif-root", "--sarif", "out.sarif"],
])
def test_cli_rejects_incomplete_sarif_root_options(monkeypatch, arguments):
    from app import audit_cli

    monkeypatch.setattr(audit_cli.sys, "argv", ["audit_cli", *arguments])
    assert audit_cli.main() == 2

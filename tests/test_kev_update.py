"""Pinned Git input and full-replacement updates preserve reproducible KEV context."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

from app.scan.kev_catalog import decode_catalog
from scripts import build_kev_catalog as builder


def upstream(ids=("CVE-2026-12345", "CVE-2026-12346")):
    return {"title": "CISA Catalog of Known Exploited Vulnerabilities", "catalogVersion": "2026.10.30",
            "dateReleased": "2026-10-30T12:00:00Z", "count": len(ids), "vulnerabilities": [
                {"cveID": cve, "vendorProject": "Fixture", "product": "Fixture product",
                 "vulnerabilityName": "Fixture only", "dateAdded": "2026-10-30",
                 "shortDescription": "An inert compiler test.", "requiredAction": "Apply vendor mitigations.",
                 "dueDate": "2026-11-13", "knownRansomwareCampaignUse": "Unknown", "notes": "",
                 "cwes": ["CWE-20"], "forensicTriage": "No"} for cve in ids]}


def git(path, *args):
    return subprocess.run(["git", "-C", str(path), *args], check=True, capture_output=True, text=True,
                          env={**os.environ, "GIT_AUTHOR_DATE": "2026-10-31T00:00:00Z",
                               "GIT_COMMITTER_DATE": "2026-10-31T00:00:00Z"}).stdout.strip()


def commit(path):
    git(path, "add", ".")
    git(path, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
        "commit", "--quiet", "-m", "Inert KEV fixture")


@pytest.fixture
def source(tmp_path):
    directory = tmp_path / "source"
    directory.mkdir()
    git(directory, "init", "--quiet")
    git(directory, "remote", "add", "origin", builder.OFFICIAL_REPOSITORY + ".git")
    (directory / builder.SOURCE_FILE).write_text(json.dumps(upstream()))
    commit(directory)
    return directory


def test_same_pinned_git_input_rebuilds_byte_identically_with_provenance(source, tmp_path):
    first = builder.build_snapshot(source)
    assert builder.build_snapshot(source) == first
    result = json.loads(first)
    assert result["source"]["commit"] == git(source, "rev-parse", "HEAD")
    assert result["source"]["source_committed_at"] == "2026-10-31T00:00:00Z"
    assert result["source"]["upstream_sha256"] == hashlib.sha256(
        (source / builder.SOURCE_FILE).read_bytes()).hexdigest()
    output = tmp_path / "out" / "kev-catalog.json"
    args = ["--source", str(source), "--output", str(output)]
    assert builder.main(args) == builder.main([*args, "--check"]) == 0
    receipt = output.with_suffix(".json.sha256")
    assert receipt.read_text() == hashlib.sha256(first).hexdigest() + "\n"
    assert decode_catalog(output.read_bytes(), receipt.read_text().strip())[0] == result
    assert builder.main(args) == 0
    assert output.read_bytes() == first


@pytest.mark.parametrize("corrupt_receipt", [False, True])
def test_check_detects_corruption_without_repairing_files(source, tmp_path, corrupt_receipt):
    output = tmp_path / "kev-catalog.json"
    args = ["--source", str(source), "--output", str(output)]
    assert builder.main(args) == 0
    changed = output.with_suffix(".json.sha256") if corrupt_receipt else output
    changed.write_bytes(b"corrupt\n")
    assert builder.main([*args, "--check"]) == 1
    assert changed.read_bytes() == b"corrupt\n"


def test_full_replacement_removes_deleted_upstream_cve(source):
    first = json.loads(builder.build_snapshot(source))
    assert len(first["entries"]) == 2
    (source / builder.SOURCE_FILE).write_text(json.dumps(upstream(("CVE-2026-12346",))))
    commit(source)
    second = json.loads(builder.build_snapshot(source))
    assert list(second["entries"]) == ["CVE-2026-12346"]
    assert second["source"]["commit"] != first["source"]["commit"]


def test_unknown_upstream_shape_does_not_replace_a_valid_catalog(source, tmp_path):
    output = tmp_path / "kev-catalog.json"
    args = ["--source", str(source), "--output", str(output)]
    assert builder.main(args) == 0
    old = output.read_bytes()
    value = upstream()
    value["newUnsupportedField"] = True
    (source / builder.SOURCE_FILE).write_text(json.dumps(value))
    commit(source)
    assert builder.main(args) == 1
    assert output.read_bytes() == old


def test_dirty_or_unofficial_source_cannot_be_attributed_to_cisa(source):
    (source / "untracked").write_text("not a pinned input")
    with pytest.raises(ValueError, match="clean"):
        builder.build_snapshot(source)
    (source / "untracked").unlink()
    git(source, "remote", "set-url", "origin", "https://example.invalid/kev-data.git")
    with pytest.raises(ValueError, match="official"):
        builder.build_snapshot(source)


@pytest.mark.parametrize("kind", ["executable", "symlink", "oversized"])
def test_non_data_blob_or_excessive_input_is_rejected(source, kind, monkeypatch):
    path = source / builder.SOURCE_FILE
    if kind == "executable":
        path.chmod(0o755)
        git(source, "update-index", "--chmod=+x", builder.SOURCE_FILE)
        commit(source)
    elif kind == "symlink":
        path.unlink()
        path.symlink_to("missing.json")
        commit(source)
    else:
        monkeypatch.setattr(builder, "MAX_UPSTREAM_BYTES", 1)
    with pytest.raises(ValueError, match="regular|size limit"):
        builder.build_snapshot(source)


def test_blob_read_ignores_concurrent_worktree_changes(source, monkeypatch):
    original = builder.build_snapshot(source)
    original_git = builder._git
    def mutate(path, *args):
        if args[:2] == ("cat-file", "blob"):
            (path / builder.SOURCE_FILE).write_text(json.dumps(upstream(("CVE-2026-99999",))))
        return original_git(path, *args)
    monkeypatch.setattr(builder, "_git", mutate)
    assert builder.build_snapshot(source) == original


def test_pinned_repository_snapshot_receipt_matches_committed_bytes():
    path = Path(__file__).resolve().parents[1] / "app/data/kev-catalog.json"
    catalog, digest = decode_catalog(path.read_bytes(), path.with_suffix(".json.sha256").read_text().strip())
    assert digest == hashlib.sha256(path.read_bytes()).hexdigest()
    assert catalog["source"]["repository"] == builder.OFFICIAL_REPOSITORY
    assert catalog["entries"]


@pytest.mark.parametrize("scenario, allowed", [
    ("open_bot_update", True), ("already_merged", True), ("closed_unmerged", False),
    ("human_commit", False), ("code_change", False), ("different_head", False),
    ("human_pr", False), ("two_open_prs", False),
])
def test_update_guard_preserves_human_changes_and_rejected_proposals(tmp_path, scenario, allowed):
    """Execute the actual workflow guard against real Git ancestry and PR metadata."""
    repository = tmp_path / "repo"
    repository.mkdir()
    git(repository, "init", "--quiet")
    (repository / "README.md").write_text("reviewed base\n")
    commit(repository)
    base = git(repository, "rev-parse", "HEAD")
    data = repository / "app/data"
    data.mkdir(parents=True)
    (data / "kev-catalog.json").write_text("snapshot\n")
    (data / "kev-catalog.json.sha256").write_text("receipt\n")
    if scenario == "code_change":
        (repository / "source.py").write_text("print('unexpected branch edit')\n")
    git(repository, "add", ".")
    git(repository, "-c", "user.name=github-actions[bot]",
        "-c", "user.email=41898282+github-actions[bot]@users.noreply.github.com",
        "commit", "--quiet", "-m", "Bot update")
    if scenario == "human_commit":
        (data / "kev-catalog.json").write_text("human reviewed change\n")
        commit(repository)
    head = git(repository, "rev-parse", "HEAD")
    if scenario != "already_merged":
        git(repository, "checkout", "--quiet", "--detach", base)
    pr = {"number": 1, "state": "OPEN", "mergedAt": None, "headRefOid": head,
          "author": {"login": "app/github-actions"}, "isCrossRepository": False, "baseRefName": "main"}
    if scenario in {"closed_unmerged", "already_merged"}:
        pr["state"] = "CLOSED" if scenario == "closed_unmerged" else "MERGED"
        pr["mergedAt"] = "2026-11-01T00:00:00Z" if scenario == "already_merged" else None
    if scenario == "different_head":
        pr["headRefOid"] = "a" * 40
    if scenario == "human_pr":
        pr["author"]["login"] = "maintainer"
    prs = [pr, {**pr, "number": 2}] if scenario == "two_open_prs" else [pr]
    (tmp_path / "kev-existing-prs.json").write_text(json.dumps(prs))
    path = Path(__file__).resolve().parents[1] / ".github/workflows/update-kev-catalog.yml"
    workflow = yaml.safe_load(path.read_text())
    step = next(step for step in workflow["jobs"]["compile-and-propose"]["steps"]
                if step.get("name") == "Maintain one reviewable KEV update PR")
    guard = step["run"].split('OLD_HEAD="$old_head" python - <<\'PY\'\n', 1)[1].split("\nPY\n", 1)[0]
    result = subprocess.run([sys.executable, "-c", guard], cwd=repository, capture_output=True, text=True,
                            env={**os.environ, "OLD_HEAD": head, "RUNNER_TEMP": str(tmp_path), "BASE_BRANCH": "main"})
    assert (result.returncode == 0) is allowed, result.stderr

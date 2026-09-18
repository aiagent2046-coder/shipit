"""Bun workspace ownership must remove only demonstrably false coverage gaps."""
import json

import pytest

from app import local_cli
from app.sca import bun_lock, lockfiles
from app.scan import cve_match
from tests.bun_fixtures import archive, bun, registry
from tests.test_cve_match import catalog


WORKSPACE = "packages/web/package.json"


def workspace_files(prefix=""):
    """A real nested manifest, rather than only the workspace entry in a lock."""
    workspace = {"name": "@project/web", "dependencies": {"widget": "^1.0.0"}}
    files = {
        "package.json": json.dumps({"name": "root", "workspaces": ["packages/*"]}),
        "bun.lock": bun({"widget": registry("widget", "1.0.0")}, {
            "": {"name": "root", "dependencies": {"@project/web": "workspace:*"}},
            "packages/web": workspace,
        }),
        WORKSPACE: json.dumps(workspace),
    }
    return {prefix + name: body for name, body in files.items()}


def coverage(files):
    return cve_match.match_archive(archive(files), catalog())["coverage"]


@pytest.mark.parametrize("prefix", ["", "project/"])
def test_real_workspace_is_checked_and_does_not_fail_the_local_execution_gate(prefix):
    raw = archive(workspace_files(prefix))
    snapshot = catalog()
    report = local_cli.inspect_project(
        raw, {}, snapshot, {"sources": {"cvelist": snapshot["source"]}})
    result = report["dependency_cve"]
    assert result["dependencies_checked"] == 1
    assert result["incomplete_manifests"] == {}
    assert result["manifest_gap_reason_counts"] == {}
    assert result["status"] == "checked"
    findings = [finding for finding in report["findings"]
                if finding["rule_id"] == "dependency-cve-match"]
    assert len(findings) == 1
    assert findings[0]["file"] == prefix + "bun.lock"
    assert local_cli.exit_status(report, "none") == 0


def test_same_named_unrelated_manifest_is_not_claimed_by_a_workspace():
    files = workspace_files()
    files["packages/unrelated/package.json"] = files[WORKSPACE]
    result = coverage(files)
    assert result["dependencies_checked"] == 1
    assert result["incomplete_manifests"] == {"packages/unrelated/package.json": "unresolved"}
    assert result["manifest_gap_reason_counts"] == {"missing_supported_lockfile": 1}


@pytest.mark.parametrize("body,status", [
    ("{broken", "malformed"),
    ('{"name":"@project/web","name":"@project/web"}', "malformed"),
    ('{"name":"@project/other"}', "unresolved"),
    ('[]', "malformed"),
    ('{"name":"@project/web","dependencies":[]}', "malformed"),
    ('{"name":"@project/web","dependencies":{"widget":null}}', "malformed"),
])
def test_invalid_or_different_workspace_metadata_keeps_a_specific_gap(body, status):
    files = workspace_files()
    files[WORKSPACE] = body
    result = coverage(files)
    assert result["status"] == "partial"
    assert result["dependencies_checked"] == 1
    assert result["incomplete_manifests"] == {WORKSPACE: status}
    assert "missing_supported_lockfile" not in result["manifest_gap_reason_counts"]


def test_oversized_workspace_metadata_keeps_its_metadata_limit_reason(monkeypatch):
    monkeypatch.setattr(lockfiles, "MAX_LOCKFILE_BYTES", 2_000)
    monkeypatch.setattr(cve_match, "MAX_MANIFEST_METADATA_BYTES", 2_000)
    files = workspace_files()
    files[WORKSPACE] += " " * 2_001
    result = coverage(files)
    assert result["dependencies_checked"] == 1
    assert result["incomplete_manifests"] == {WORKSPACE: "oversized"}
    assert result["manifest_gap_reason_counts"] == {"manifest_metadata_size_limit": 1}


@pytest.mark.parametrize("failure", ["malformed", "unsupported", "unresolved", "parser_limit"])
def test_partial_root_lock_cannot_claim_workspace_coverage(failure, monkeypatch):
    files = workspace_files()
    if failure == "malformed":
        files["bun.lock"] = "{broken"
    elif failure == "unsupported":
        files["bun.lock"] = files["bun.lock"].replace('"lockfileVersion": 1', '"lockfileVersion": 2')
    elif failure == "unresolved":
        data = json.loads(files["bun.lock"])
        data["workspaces"]["packages/web"]["dependencies"]["missing"] = "^1"
        files["bun.lock"] = json.dumps(data)
    else:
        monkeypatch.setattr(bun_lock, "MAX_REFERENCE_CHECKS", 0)
    result = coverage(files)
    assert result["status"] == "partial"
    assert result["incomplete_manifests"] == {"bun.lock": failure, WORKSPACE: "unresolved"}
    assert result["manifest_gap_reason_counts"]["missing_supported_lockfile"] == 1


@pytest.mark.parametrize("limit", ["count", "size"])
def test_unselected_bun_lock_cannot_claim_workspace_coverage(limit, monkeypatch):
    files = workspace_files()
    if limit == "count":
        monkeypatch.setattr(lockfiles, "MAX_LOCKFILES", 0)
        reason = "truncated"
    else:
        monkeypatch.setattr(lockfiles, "MAX_LOCKFILE_BYTES", len(files["bun.lock"].encode()) - 1)
        reason = "oversized"
    result = coverage(files)
    assert result["dependencies_checked"] == 0
    assert result["incomplete_manifests"] == {"bun.lock": reason, WORKSPACE: "unresolved"}
    assert result["manifest_gap_reason_counts"]["missing_supported_lockfile"] == 1


def test_excluded_lock_cannot_claim_an_unrelated_production_workspace():
    files = workspace_files()
    files["docs/bun.lock"] = files.pop("bun.lock")
    result = coverage(files)
    assert result["dependencies_checked"] == 0
    assert result["excluded_manifests"] == {"docs/bun.lock": "non_production_documentation"}
    assert result["incomplete_manifests"] == {"package.json": "unresolved", WORKSPACE: "unresolved"}


@pytest.mark.parametrize("boundary,reason", [
    ("packages/bun.lock", "malformed"),
    ("packages/bun.lockb", "unsupported"),
    ("packages/yarn.lock", "unsupported"),
    ("packages/web/bun.lock", "malformed"),
])
def test_independent_lock_boundary_stays_incomplete(boundary, reason):
    files = workspace_files()
    files[boundary] = "{broken"
    snapshot = catalog()
    report = local_cli.inspect_project(
        archive(files), {}, snapshot, {"sources": {"cvelist": snapshot["source"]}})
    result = report["dependency_cve"]
    assert result["dependencies_checked"] == 1
    assert result["incomplete_manifests"][boundary] == reason
    if boundary.startswith("packages/") and not boundary.startswith("packages/web/"):
        assert result["incomplete_manifests"][WORKSPACE] == "unresolved"
        assert result["manifest_gap_reason_counts"]["missing_supported_lockfile"] == 1
    assert local_cli.exit_status(report, "none") == 2


@pytest.mark.parametrize("independent", [False, True])
def test_deep_workspace_paths_preserve_manifest_ownership(independent):
    relative = '/'.join(['a'] * 4_000)
    workspace = {"name": "@project/web", "dependencies": {"widget": "^1"}}
    manifest = relative + '/package.json'
    files = {
        "bun.lock": bun({"widget": registry("widget", "1.0.0")}, {
            "": {}, relative: workspace,
        }),
        manifest: json.dumps(workspace),
        # A sibling directory sharing a string prefix is not an ancestor.
        relative + 'b/yarn.lock': '',
    }
    if independent:
        files['/'.join(['a'] * 2_000) + '/yarn.lock'] = ''
    result = coverage(files)
    assert result["dependencies_checked"] == 1
    assert (manifest in result["incomplete_manifests"]) is independent
    assert result["manifest_gap_reason_counts"].get("missing_supported_lockfile", 0) == int(independent)

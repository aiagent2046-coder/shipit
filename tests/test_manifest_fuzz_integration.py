"""Malformed manifest coverage survives the real CLI/report boundary."""
import io
import json
import socket
import subprocess
import zipfile

import pytest

from app import local_cli, local_store
from app.sca import lockfiles
from app.scan import cve_match


def test_malformed_lockfile_cannot_report_success_with_retained_positive(tmp_path, capsys):
    project = tmp_path / "project"
    project.mkdir()
    (project / "poetry.lock").write_text('[[package]\n')
    (project / "requirements.txt").write_text('langflow==1.0.12\n')
    status = local_cli.main(["--state-dir", str(tmp_path / "state"), "scan", str(project), "--json"])
    report = json.loads(capsys.readouterr().out)
    assert status == 2
    assert report["checks_not_run"] == []
    assert report["dependency_cve"]["incomplete_manifests"] == {"poetry.lock": "malformed"}
    assert report["dependency_cve"]["status"] == "partial"
    assert any(f.get("claim_evidence", {}).get("cve_id") == "CVE-2024-7297"
               and f["file"] == "requirements.txt" for f in report["findings"])


@pytest.mark.parametrize("metadata,reason", [
    ('{"padding":"' + 'x' * 128 + '"}', "oversized"),
    ('{"dependencies":{"langflow":"1"},"dependencies":{}}', "malformed"),
    (b'{"name":"\xff"}', "malformed"),
    ('{"dependencies":[]}', "malformed"),
    ('{"devDependencies":null,"dependencies":{"lodash":"4.17.23"}}', "malformed"),
])
def test_bad_neighbor_metadata_keeps_locked_cve_and_cli_reports_partial(
        tmp_path, monkeypatch, capsys, metadata, reason):
    # Small test budgets exercise the same metadata gate without allocating
    # megabytes. The standalone requirements file is an independent positive.
    monkeypatch.setattr(lockfiles, "MAX_LOCKFILE_BYTES", 128)
    monkeypatch.setattr(cve_match, "MAX_MANIFEST_METADATA_BYTES", 128)
    project = tmp_path / "project"
    project.mkdir()
    (project / "package.json").write_bytes(metadata.encode() if isinstance(metadata, str) else metadata)
    (project / "package-lock.json").write_text(
        '{"packages":{"node_modules/lodash":{"version":"4.17.23"}}}')
    (project / "requirements.txt").write_text('langflow==1.0.12\n')
    (project / "canary.py").write_text('raise RuntimeError("project must never execute")\n')

    def forbidden(*args, **kwargs):
        pytest.fail("Manifest scanning must remain offline and must not execute project code")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(local_store.urllib.request, "urlopen", forbidden)
    status = local_cli.main(["--state-dir", str(tmp_path / "state"), "scan", str(project), "--json"])
    output = capsys.readouterr()
    assert status == 2
    report = json.loads(output.out)
    assert not output.err
    assert report["checks_not_run"] == []
    assert report["can_continue"] is False
    assert report["runtime_verified"] is False
    coverage = report["dependency_cve"]
    assert coverage["status"] == "partial"
    assert coverage["incomplete_manifests"] == {"package.json": reason}
    assert coverage["dependencies_checked"] == 2
    assert coverage["status_counts"]["affected"] >= 2
    found = {(f["claim_evidence"].get("cve_id"), f["file"]) for f in report["findings"]
             if f["rule_id"] == "dependency-cve-match"}
    assert {("CVE-2026-2950", "package-lock.json"),
            ("CVE-2024-7297", "requirements.txt")} <= found
    reason_key = "manifest_metadata_size_limit" if reason == "oversized" else "malformed_lockfile"
    assert coverage["manifest_gap_reason_counts"] == {reason_key: 1}


def test_standalone_oversized_package_metadata_keeps_independent_assessment(monkeypatch):
    monkeypatch.setattr(cve_match, "MAX_MANIFEST_METADATA_BYTES", 64)
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("other/package.json", " " * 65)
        z.writestr("requirements.txt", "widget==1.2.3\n")
    catalog = {
        "schema_version": 1,
        "source": {"repository": "https://github.com/CVEProject/cvelistV5",
                   "commit": "a" * 40, "generated_at": "2026-09-17T00:00:00Z"},
        "packages": {"PyPI:widget": [{"id": "CVE-2026-12345", "default_status": "unaffected",
                                     "versions": [{"version": "1.2.3", "status": "affected"}]}]},
    }
    result = cve_match.match_archive(archive.getvalue(), catalog)
    assert result["coverage"]["status"] == "partial"
    assert result["coverage"]["incomplete_manifests"] == {"other/package.json": "oversized"}
    assert result["coverage"]["manifest_gap_reason_counts"] == {"manifest_metadata_size_limit": 1}
    assert len(result["findings"]) == 1
    assert result["findings"][0]["file"] == "requirements.txt"


@pytest.mark.parametrize("field", ["dependencies", "devDependencies", "optionalDependencies"])
def test_bad_metadata_field_preserves_directness_from_valid_fields(field):
    fields = {"dependencies", "devDependencies", "optionalDependencies"}
    metadata = {key: {"widget": "1.2.3"} for key in fields - {field}}
    metadata[field] = []
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("package.json", json.dumps(metadata))
        z.writestr("package-lock.json", json.dumps({"packages": {
            "node_modules/widget": {"version": "1.2.3"},
        }}))
    inventory = lockfiles.collect_dependency_inventory(archive.getvalue())
    assert inventory.incomplete_manifests == {"package.json": "malformed"}
    assert len(inventory.dependencies) == 1
    assert inventory.dependencies[0].name == "widget"
    assert inventory.dependencies[0].direct is True


@pytest.mark.parametrize("damaged_path", ["package.json", "package-lock.json"])
@pytest.mark.parametrize("damage", ["crc", "encrypted", "deflate"])
def test_unreadable_member_keeps_readable_lock_assessments(damaged_path, damage):
    files = {
        "package.json": '{"dependencies":{"widget":"1.2.3"}}',
        "package-lock.json": '{"packages":{"node_modules/widget":{"version":"1.2.3"}}}',
        "z/requirements.txt": "sentinel==1.2.3\n",
    }
    archive = io.BytesIO()
    compression = zipfile.ZIP_DEFLATED if damage == "deflate" else zipfile.ZIP_STORED
    with zipfile.ZipFile(archive, "w", compression=compression) as z:
        # Write the damaged member first to make its local/central header unambiguous.
        for path in [damaged_path, *[p for p in files if p != damaged_path]]:
            z.writestr(path, files[path])
    data = bytearray(archive.getvalue())
    payload_offset = 30 + len(damaged_path)
    if damage == "crc":
        data[payload_offset] ^= 1
    elif damage == "encrypted":
        data[6] |= 1
        data[data.index(b"PK\x01\x02") + 8] |= 1
    else:
        data[payload_offset] |= 6  # Reserved DEFLATE block type.
    catalog = {
        "schema_version": 1,
        "source": {"repository": "https://github.com/CVEProject/cvelistV5",
                   "commit": "a" * 40, "generated_at": "2026-09-17T00:00:00Z"},
        "packages": {key: [{"id": f"CVE-2026-{12345 + index}", "default_status": "unaffected",
                            "versions": [{"version": "1.2.3", "status": "affected"}]}]
                     for index, key in enumerate(["npm:widget", "PyPI:sentinel"])},
    }
    baseline = cve_match.match_archive(archive.getvalue(), catalog)
    assert baseline["coverage"]["status_counts"]["affected"] == 2
    result = cve_match.match_archive(bytes(data), catalog)
    coverage = result["coverage"]
    assert coverage["status"] == "partial"
    assert coverage["incomplete_manifests"] == {damaged_path: "malformed"}
    expected_files = {"z/requirements.txt"}
    if damaged_path == "package.json":
        expected_files.add("package-lock.json")
    assert coverage["status_counts"]["affected"] == len(expected_files)
    assert {finding["file"] for finding in result["findings"]} == expected_files

"""Local product regressions: real scanner, no network, persistent change history."""
import hashlib
import io
import json
import os
import socket
import subprocess
import sys
import zipfile

import pytest

from app import local_cli as cli, local_store as store


@pytest.fixture
def state(tmp_path):
    path = tmp_path / "state"
    db = store.connect(path)
    yield path, db
    db.close()


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "main.py").write_text("import random\nreset_token = random.getrandbits(128)\n")
    (root / "requirements.txt").write_text("langflow==1.0.12\n")
    (root / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "node_modules/lodash": {"version": "4.17.23"}}}))
    return root


def test_offline_folder_scan_uses_real_static_and_dependency_engine(project, state, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("local scan must not start a network connection or execute project code")
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(store.urllib.request, "urlopen", forbidden)
    key, report = cli.poll_project(state[1], project, state[0])
    assert key
    assert any(f["rule_id"] == "insecure-randomness" for f in report["findings"])
    ids = {f.get("claim_evidence", {}).get("cve_id") for f in report["findings"]}
    assert {"CVE-2026-2950", "CVE-2024-7297"} <= ids
    assert report["dependency_cve"]["dependencies_checked"] == 2
    assert report["runtime_verified"] is False
    assert report["changes"]["baseline"]
    assert report["catalog"]["sources"]["github-reviewed"]
    assert cli.exit_status(report, "high") == 1
    assert cli.exit_status(report, "none") == 0


def test_watcher_detects_content_changes_with_same_mtime_and_size(project, state):
    key, first = cli.poll_project(state[1], project, state[0])
    assert cli.poll_project(state[1], project, state[0], key)[1] is None
    file = project / "requirements.txt"
    info = file.stat()
    file.write_text("langflow==1.0.13\n")
    os.utime(file, ns=(info.st_atime_ns, info.st_mtime_ns))
    next_key, second = cli.poll_project(state[1], project, state[0], key)
    assert next_key != key
    assert second["changes"]["no_longer_reported"]
    assert not second["changes"]["baseline"]
    assert "not proof of a fix" in second["changes"]["note"]
    assert state[1].execute("SELECT count(*) FROM scans").fetchone()[0] == 2


def test_exclusions_never_follow_links_and_keep_ignored_config(project, state, tmp_path):
    external = tmp_path / "outside"
    external.mkdir()
    (external / "private.txt").write_text("external contents")
    (project / "linked").symlink_to(external, target_is_directory=True)
    (project / "linked.txt").symlink_to(external / "private.txt")
    (project / "node_modules").mkdir()
    (project / "node_modules/skip.js").write_text("skip")
    (project / ".env").write_text("LOCAL_ONLY=value")
    (project / ".gitignore").write_text(".env\n")
    raw, scope = cli.snapshot(project, state[0])
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        assert ".env" in archive.namelist()
        assert not any(name.startswith(("linked", "node_modules/")) for name in archive.namelist())
    assert scope["excluded"]["symlinks"] == 2
    assert scope["excluded"]["directories"] == 1


def test_budget_failure_does_not_replace_scan_history(project, state, monkeypatch):
    cli.poll_project(state[1], project, state[0])
    monkeypatch.setattr(cli, "MAX_BYTES", 2)
    with pytest.raises(ValueError, match="budget"):
        cli.poll_project(state[1], project, state[0])
    assert state[1].execute("SELECT count(*) FROM scans").fetchone()[0] == 1


def test_state_inside_project_is_excluded_and_file_is_private(project):
    path = project / "scan-state"
    with store.connect(path) as db:
        key, _ = cli.poll_project(db, project, path)
        assert cli.poll_project(db, project, path, key)[1] is None
        assert (path / "local.sqlite3").stat().st_mode & 0o777 == 0o600


def test_update_is_atomic_and_catalog_change_triggers_rescan(project, state, monkeypatch):
    key, _ = cli.poll_project(state[1], project, state[0])
    catalog, _ = store.load_catalog(state[1])
    # New advisories can change even an untouched project's verdict.
    catalog["packages"].pop("PyPI:langflow")
    raw = json.dumps(catalog).encode()
    digest = hashlib.sha256(raw).hexdigest()
    requested = []

    def download(url, limit):
        requested.append(url)
        return (digest + "  cve-catalog.json\n").encode() if url.endswith(".sha256") else raw

    monkeypatch.setattr(store, "_download", download)
    result = store.update_catalog(state[1], "a" * 40)
    assert result["sha256"] == digest
    assert all("/" + "a" * 40 + "/app/data/" in url for url in requested)
    new_key, report = cli.poll_project(state[1], project, state[0], key)
    assert new_key != key
    assert not report["changes"]["same_engine_and_catalog"]
    monkeypatch.setattr(store, "_download", lambda url, limit: b"broken")
    with pytest.raises(ValueError):
        store.update_catalog(state[1], "b" * 40)
    assert store.load_catalog(state[1])[1]["sha256"] == digest


def test_ghsa_only_findings_keep_distinct_history_identities():
    base = {"rule_id": "dependency-cve-match", "file": "uv.lock", "line": 1}
    assert cli._identity({**base, "claim_evidence": {"advisory_id": "GHSA-aaaa-bbbb-cccc"}}) != cli._identity(
        {**base, "claim_evidence": {"advisory_id": "GHSA-dddd-eeee-ffff"}})


def test_cli_json_and_history(project, state, capsys):
    assert cli.main(["--state-dir", str(state[0]), "scan", str(project), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["mode"] == "local_offline"
    assert cli.main(["--state-dir", str(state[0]), "history", str(project)]) == 0
    history = json.loads(capsys.readouterr().out)
    assert len(history) == 1
    assert "identities" not in history[0]


@pytest.mark.parametrize("revision", ["main", "../main", "a" * 39])
def test_update_rejects_mutable_or_invalid_ref_before_network(state, revision, monkeypatch):
    monkeypatch.setattr(store, "_download", lambda *args: pytest.fail("network must not run"))
    with pytest.raises(ValueError, match="commit SHA"):
        store.update_catalog(state[1], revision)


def test_scan_partial_failure_has_nonzero_exit():
    report = {"checks_not_run": [{"check": "example"}], "can_continue": False, "findings": []}
    assert cli.exit_status(report, "none") == 2


def test_cli_import_does_not_load_server_or_llm():
    result = subprocess.run([sys.executable, "-c",
                             "import sys; import app.local_cli; "
                             "assert 'app.main' not in sys.modules; "
                             "assert 'app.llm.client' not in sys.modules; "
                             "assert 'app.db' not in sys.modules"], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_unavailable_rules_and_parse_skips_are_not_success():
    report = {"checks_not_run": [], "can_continue": False, "findings": [],
              "rule_coverage": {"sql": {"skip_reasons": {"parse_error": 1}}}}
    assert cli.exit_status(report, "none") == 2


def test_state_does_not_change_permissions_of_existing_public_directory(tmp_path):
    path = tmp_path / "shared"
    path.mkdir(mode=0o755)
    with pytest.raises(ValueError, match="private"):
        store.connect(path)
    assert path.stat().st_mode & 0o777 == 0o755


def test_broken_catalog_is_not_silently_replaced_by_bundled_data(state):
    with state[1]:
        state[1].execute("INSERT INTO catalog VALUES (1, ?, ?, ?)", ("a" * 40, "0" * 64, b"broken"))
    with pytest.raises(ValueError, match="checksum"):
        store.load_catalog(state[1])

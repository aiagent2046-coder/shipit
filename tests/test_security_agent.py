"""The coordinator cannot turn source observations or missing coverage into proof."""
from copy import deepcopy
import hashlib
import io
import json
import socket
import subprocess
import zipfile

import pytest

from app import local_cli
from app.llm.client import LLMClient
from app.report.evidence import claim_evidence_rows, manifest_rows
from app.report.html import render_report
from app.scan import security_agent, sql_injection
from app.scan.browser import ScanSession, scan_archive
from app.scan.pattern_catalog import catalog_manifest
from app.scan.pipeline import BASIS_PREVIEW, run_scan
from app.scan.static import run_static_scan
from tests.test_browser_cve import CATALOG


SQL = ('def load(cursor, user_id):\n'
       '    query = "SELECT id FROM users WHERE id = " + user_id\n'
       '    cursor.execute(query)\n')
PARAMETERIZED = ('def load(cursor, user_id):\n'
                 '    cursor.execute("SELECT id FROM users WHERE id = %s", (user_id,))\n')


def archive(files):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w", zipfile.ZIP_DEFLATED) as zipped:
        for name, source in files.items():
            zipped.writestr(name, source)
    return data.getvalue()


def report(files):
    return scan_archive(archive(files))["report"]


def sql_findings(result):
    return [f for f in result["findings"] if f["rule_id"] == "sql-injection-string-built-query"]


def test_sql_candidate_is_classified_without_driver_or_runtime_proof():
    result = report({"src/query.py": SQL})
    agent = result["security_agent"]
    assert agent["status"] == "completed"
    assert len(sql_findings(result)) == len(agent["observations"]) == 1
    decision = agent["observations"][0]
    assert decision["weaknesses"] == ["CWE-89"]
    assert decision["pattern_id"] == "python-sql-string-assembly"
    assert decision["state"] == "needs_evidence"
    assert decision["next_action"] == "manual_review"
    assert decision["recipe"]["automatic_apply"] is False
    assert set(decision["missing_evidence"]) == {
        "attacker_control", "psycopg3_cursor_provenance", "sql_value_position",
        "intended_value_type", "runtime_behavior_contract",
    }
    trace = decision["evidence"]["sql_observation"]
    assert (trace["assembly_line"], trace["sink_line"], trace["sink_method"]) == (2, 3, "execute")
    assert trace["source_sha256"] == hashlib.sha256(SQL.encode()).hexdigest()
    assert trace["flow_status"] == "possible_local_flow"
    assert "SELECT" not in json.dumps(trace)
    assert sql_findings(result)[0]["verification_status"] == "unverified"


def test_importing_psycopg_does_not_establish_cursor_provenance():
    result = report({"src/query.py": "import psycopg\n" + SQL})
    assert "psycopg3_cursor_provenance" in result["security_agent"]["observations"][0]["missing_evidence"]
    assert result["security_agent"]["automatic_patch"] is False


def test_parameterized_query_and_javascript_do_not_select_the_psycopg_card():
    result = report({"src/query.py": PARAMETERIZED,
                     "src/query.ts": 'db.query("SELECT id FROM users WHERE id = " + userId);'})
    assert len(sql_findings(result)) == 1  # The JS signal remains in the ordinary report.
    assert result["security_agent"]["observations"] == []
    assert result["security_agent"]["runtime_verified"] is False


def test_other_cards_keep_their_specific_missing_evidence():
    result = report({"src/load.py": "import pickle\nvalue = pickle.loads(payload)\n"})
    decision = next(row for row in result["security_agent"]["observations"]
                    if row["pattern_id"] == "python-unsafe-deserialization")
    assert decision["weaknesses"] == ["CWE-502"]
    assert "source_pattern" not in decision["missing_evidence"]
    assert "input_trust_boundary" in decision["missing_evidence"]
    assert decision["recipe"] == {"id": None, "status": "not_available", "automatic_apply": False}


@pytest.mark.parametrize("broken", [b"\xff", "def broken(:", "#" + "x" * 400_001])
def test_incomplete_source_keeps_independent_observation_and_blocks_completion(broken):
    result = report({"src/query.py": SQL, "src/broken.py": broken})
    agent = result["security_agent"]
    assert agent["status"] == "partial"
    assert agent["stop_reason"] == "coverage_incomplete"
    assert len(agent["observations"]) == 1
    assert next(row for row in agent["plan"] if row["check"] == "sql_injection")["status"] == "partial"


def test_no_coverage_is_never_inferred_from_an_empty_finding_list():
    result = security_agent.review_static_observations(
        {"findings": [], "checks_run": ["sql_injection"], "rule_coverage": {}},
        archive_sha256="a" * 64, engine_version="test",
    )
    assert result["status"] == "unavailable"
    assert all(row["status"] == "unavailable" for row in result["plan"])


def test_a_coordinator_failure_cannot_discard_the_scanner_findings(monkeypatch):
    def invalid_catalog():
        raise ValueError("private failure text must not reach reports")
    monkeypatch.setattr(security_agent, "catalog_manifest", invalid_catalog)
    scan = scan_archive(archive({"src/query.py": SQL}))
    result = scan["report"]
    assert len(sql_findings(result)) == 1
    assert result["security_agent"]["status"] == "unavailable"
    assert result["security_agent"]["stop_reason"] == "agent_error: ValueError"
    assert "private failure text" not in json.dumps(result)
    assert "security_agent_unavailable" in result["limitations"]
    invocation = scan["sarif"]["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is False
    assert invocation["toolExecutionNotifications"][0]["descriptor"]["id"] == "security-agent-unavailable"
    assert local_cli.exit_status(result, "none") == 2


def test_candidate_budget_and_input_order_cannot_hide_omitted_review(monkeypatch):
    raw = archive({"src/z.py": SQL, "src/a.py": SQL})
    static = run_static_scan(io.BytesIO(raw))
    monkeypatch.setattr(security_agent, "MAX_CANDIDATES", 1)
    options = {"archive_sha256": hashlib.sha256(raw).hexdigest(), "engine_version": "test"}
    first = security_agent.review_static_observations(static, **options)
    static["findings"].reverse()
    second = security_agent.review_static_observations(static, **options)
    assert first == second
    assert first["status"] == "partial"
    assert first["stop_reason"] == "candidate_budget_exhausted"
    assert first["budget"] == {"max_candidates": 1, "candidates_found": 2, "processed": 1, "candidates_omitted": 1}
    assert first["observations"][0]["file"] == "src/a.py"
    assert len(sql_findings(static)) == 2


def test_continuation_preserves_sql_trace_and_recomputes_agent(monkeypatch):
    raw = archive({"src/first.py": "value = 1\n", "src/tail.py": SQL})
    monkeypatch.setattr(sql_injection, "_MAX_FILES", 1)
    session = ScanSession(raw)
    initial = session.result()
    assert initial["report"]["security_agent"]["status"] == "partial"
    assert initial["report"]["security_agent"]["observations"] == []
    continued = session.continue_scan()
    assert continued["report"]["security_agent"]["status"] == "completed"
    assert len(continued["report"]["security_agent"]["observations"]) == 1
    assert sql_findings(continued["report"])[0]["claim_evidence"]["sql_observation"]["assembly_line"] == 2
    assert session.continue_scan() == continued
    monkeypatch.setattr(sql_injection, "_MAX_FILES", 400)
    assert scan_archive(raw)["report"]["security_agent"] == continued["report"]["security_agent"]


@pytest.mark.parametrize("field,value", [
    ("sink_line", 999), ("source_sha256", "invented"), ("assembly_kind", []),
    ("sink_method", {}), ("driver_status", "verified"), ("input_control_status", "verified"),
])
def test_inconsistent_or_upgraded_evidence_is_not_promoted(field, value):
    finding = sql_findings(report({"src/query.py": SQL}))[0]
    finding["claim_evidence"]["sql_observation"][field] = value
    assert security_agent.sql_observation(finding) is None
    finding["source"] = "llm"
    assert security_agent.sql_observation(finding) is None


def test_agent_and_source_trace_survive_offline_surfaces_and_exports(tmp_path, monkeypatch):
    marker = tmp_path / "executed"
    raw = archive({"src/query.py": SQL,
                   "src/canary.py": f'from pathlib import Path\nPath({str(marker)!r}).write_text("executed")\n'})
    attempts = []

    def forbidden(*args, **kwargs):
        attempts.append(True)
        raise AssertionError("No connections or submitted processes are permitted")
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    browser = scan_archive(raw, CATALOG)
    local = local_cli.inspect_project(raw, {}, CATALOG, {"sources": CATALOG["sources"]})
    online = run_scan(raw, LLMClient(providers=[]), depth=BASIS_PREVIEW)
    manifest = online["score"]["scan_manifest"]
    assert browser["report"]["security_agent"] == local["security_agent"] == manifest["security_agent"]
    assert sql_findings(browser["report"]) == sql_findings(local) == sql_findings(online)
    assert manifest["model_calls"] == 0
    assert not attempts and not marker.exists()
    agent = browser["report"]["security_agent"]
    invocation = browser["sarif"]["runs"][0]["invocations"][0]
    assert invocation["properties"]["securityAgent"] == agent
    finding = sql_findings(local)[0]
    sarif_sql = next(row for row in browser["sarif"]["runs"][0]["results"]
                     if row["ruleId"] == finding["rule_id"])
    assert sarif_sql["properties"]["sqlObservation"] == finding["claim_evidence"]["sql_observation"]
    assert "Possible local flow" in dict(claim_evidence_rows(finding))["SQL source trace"]
    assert "not project safety" in dict(manifest_rows(online["score"]))["Pattern review"]
    assert "SQL source trace" in render_report(online)
    assert json.loads(json.dumps(agent)) == agent


def test_catalog_and_history_are_available_without_network_or_extra_state(tmp_path, capsys, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Reading pattern cards must not open state or a connection")
    with monkeypatch.context() as patched:
        patched.setattr(local_cli, "connect", forbidden)
        patched.setattr(socket.socket, "connect", forbidden)
        assert local_cli.main(["patterns", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == catalog_manifest()
    project = tmp_path / "project"
    project.mkdir()
    (project / "query.py").write_text(SQL)
    command = ["--state-dir", str(tmp_path / "state"), "scan", str(project), "--json"]
    assert local_cli.main(command) == 0
    first = json.loads(capsys.readouterr().out)
    assert local_cli.main(command) == 0
    second = json.loads(capsys.readouterr().out)
    assert first["security_agent"] == second["security_agent"]
    assert second["changes"]["new"] == second["changes"]["no_longer_reported"] == []
    assert local_cli.main(["--state-dir", str(tmp_path / "state"), "history", str(project)]) == 0
    history = json.loads(capsys.readouterr().out)
    assert history[0]["pattern_review"]["catalog"] == first["security_agent"]["catalog"]
    assert history[0]["pattern_review"]["observations"] == 1
    assert history[0]["pattern_review"]["status"] == "completed"


def test_saved_legacy_or_upgraded_records_do_not_claim_a_review():
    current = report({"src/query.py": SQL})["security_agent"]
    assert security_agent.agent_record(None) is None
    for field, value in (("version", 99), ("runtime_verified", True), ("automatic_patch", True), ("status", [])):
        invalid = deepcopy(current)
        invalid[field] = value
        assert security_agent.agent_record(invalid) is None

"""The agent must acquire bounded source facts without claiming runtime proof."""
from copy import deepcopy
import hashlib
import io
import json
import socket
import subprocess

import pytest

from app import local_cli
from app.llm.client import LLMClient
from app.scan import security_agent, sql_injection
from app.scan.browser import ScanSession, scan_archive
from app.scan.pipeline import BASIS_PREVIEW, run_scan
from app.scan.static import run_static_scan
from tests.test_security_agent import archive, sql_findings


HTTP_SQL = '''from fastapi import FastAPI
import psycopg
app = FastAPI()
@app.get("/users")
def load(name: str):
    conn = psycopg.connect("PRIVATE_DSN")
    cur = conn.cursor()
    cur.execute(f"SELECT id FROM users WHERE name = '{name}'")
'''
SOURCE_FACTS = {"request_input_source", "local_input_flow", "sql_value_position", "value_constraints"}
RUNTIME_GAPS = {"caller_authorization", "route_reachability", "intended_value_type", "runtime_behavior_contract"}


def acquired(source=HTTP_SQL, *, files=None):
    result = scan_archive(archive({"src/query.py": source, **(files or {})}))
    observation, = [row for row in result["report"]["security_agent"]["observations"]
                    if row["pattern_id"] == "python-sql-string-assembly"]
    return result, observation, observation["acquisition"]


def fact_ids(acquisition):
    return {fact["id"] for fact in acquisition["facts"]}


def actions(acquisition):
    return [attempt["action"] for attempt in acquisition["attempts"]]


def test_agent_acquires_dependent_source_facts_and_preserves_runtime_gates():
    result, observation, acquisition = acquired()
    assert acquisition["version"] == 1
    assert acquisition["status"] == "completed"
    assert fact_ids(acquisition) == SOURCE_FACTS
    assert actions(acquisition) == [
        "locate_source", "trace_request_input", "inspect_sql_slots", "collect_value_constraints",
    ]
    assert len(actions(acquisition)) == len(set(actions(acquisition)))
    assert acquisition["source"]["file"] == "src/query.py"
    assert acquisition["source"]["source_sha256"] == hashlib.sha256(HTTP_SQL.encode()).hexdigest()
    assert acquisition["source"]["sink_span"]
    assert observation["state"] == "source_evidence_collected"
    assert observation["next_action"] == "review_runtime_contract"
    assert set(observation["missing_evidence"]) == RUNTIME_GAPS
    assert observation["recipe"]["automatic_apply"] is False
    agent = result["report"]["security_agent"]
    assert agent["runtime_verified"] is agent["automatic_patch"] is False
    finding, = sql_findings(result["report"])
    assert finding["verification_status"] == "unverified"
    # Facts carry locations and bounded categories, never customer's SQL or DSN.
    encoded = json.dumps(acquisition)
    assert "PRIVATE_DSN" not in encoded
    assert "SELECT id FROM users" not in encoded


def test_result_of_request_tracing_changes_the_next_available_action():
    _, _, http = acquired()
    _, observation, ordinary = acquired(HTTP_SQL.replace('@app.get("/users")\n', ''))
    assert "collect_value_constraints" in actions(http)
    assert "collect_value_constraints" not in actions(ordinary)
    assert not {"request_input_source", "local_input_flow"} & fact_ids(ordinary)
    assert {"request_input_source", "local_input_flow"} <= set(observation["missing_evidence"])
    assert observation["state"] == "needs_evidence"
    assert observation["next_action"] == "manual_review"


def test_unknown_driver_does_not_schedule_psycopg_sql_slot_analysis():
    source = HTTP_SQL.replace('psycopg.connect("PRIVATE_DSN")',
                              'psycopg.connect("PRIVATE_DSN", cursor_factory=CustomCursor)')
    result, observation, acquisition = acquired(source)
    assert "inspect_sql_slots" not in actions(acquisition)
    assert "collect_value_constraints" in actions(acquisition)
    assert {"request_input_source", "local_input_flow"} <= fact_ids(acquisition)
    assert {"psycopg3_cursor_provenance", "sql_value_position"} <= set(observation["missing_evidence"])
    assert len(sql_findings(result["report"])) == 1


@pytest.mark.parametrize("source", [
    HTTP_SQL.replace('app = FastAPI()', 'FastAPI = CustomFactory\napp = FastAPI()'),
    HTTP_SQL.replace('@app.get("/users")', 'app = CustomApp()\n@app.get("/users")'),
    HTTP_SQL.replace('from fastapi import FastAPI', 'from fastapi import Depends, FastAPI')
    .replace('def load(name: str):', 'def load(name: str = Depends(provide_name)):'),
    HTTP_SQL.replace('    cur.execute(', '    name = unknown_wrapper(name)\n    cur.execute('),
    HTTP_SQL.replace('    cur.execute(', '    name = other_value\n    cur.execute('),
], ids=["factory-shadow", "app-rebinding", "dependency-input", "unknown-wrapper", "input-rebinding"])
def test_unsupported_or_overwritten_input_cannot_establish_http_flow(source):
    result, observation, acquisition = acquired(source)
    assert "local_input_flow" not in fact_ids(acquisition)
    assert "local_input_flow" in observation["missing_evidence"]
    assert "collect_value_constraints" not in actions(acquisition)
    assert observation["state"] == "needs_evidence"
    assert RUNTIME_GAPS <= set(observation["missing_evidence"])
    assert len(sql_findings(result["report"])) == 1


def test_identifier_interpolation_does_not_satisfy_value_parameterization():
    source = HTTP_SQL.replace("SELECT id FROM users WHERE name = '{name}'", "SELECT id FROM {name}")
    result, observation, acquisition = acquired(source)
    assert "inspect_sql_slots" in actions(acquisition)
    assert "sql_value_position" not in fact_ids(acquisition)
    assert "sql_value_position" in observation["missing_evidence"]
    assert observation["state"] == "needs_evidence"
    assert len(sql_findings(result["report"])) == 1


def test_duplicate_sinks_on_one_line_cannot_share_source_proof():
    source = HTTP_SQL.replace(
        '    cur.execute(f"SELECT id FROM users WHERE name = \'{name}\'")',
        '    cur.execute(f"SELECT id FROM users WHERE name = \'{name}\'"); '
        'cur.execute(f"SELECT id FROM users WHERE name = \'{other}\'")',
    )
    result = scan_archive(archive({"src/query.py": source}))["report"]
    assert sql_findings(result)
    for observation in result["security_agent"]["observations"]:
        if observation["pattern_id"] != "python-sql-string-assembly":
            continue
        acquisition = observation["acquisition"]
        assert acquisition["status"] != "completed"
        assert not fact_ids(acquisition)
        assert actions(acquisition) == ["locate_source"]
        assert observation["state"] == "needs_evidence"


def test_snapshot_and_acquired_facts_are_stable_across_repeated_runs_and_exports():
    raw = archive({"src/query.py": HTTP_SQL})
    first = scan_archive(raw)
    second = scan_archive(raw)
    agent = first["report"]["security_agent"]
    assert second["report"]["security_agent"] == agent
    assert first["sarif"]["runs"][0]["invocations"][0]["properties"]["securityAgent"] == agent
    assert json.loads(json.dumps(agent)) == agent


def test_continuation_acquires_source_for_the_newly_discovered_sink(monkeypatch):
    raw = archive({"src/first.py": 'value = 1\n', "src/query.py": HTTP_SQL})
    monkeypatch.setattr(sql_injection, "_MAX_FILES", 1)
    session = ScanSession(raw)
    assert session.result()["report"]["security_agent"]["observations"] == []
    resumed = session.continue_scan()
    observation, = resumed["report"]["security_agent"]["observations"]
    assert fact_ids(observation["acquisition"]) == SOURCE_FACTS
    assert session.continue_scan() == resumed
    monkeypatch.setattr(sql_injection, "_MAX_FILES", 400)
    complete = scan_archive(raw)
    assert resumed["report"]["security_agent"] == complete["report"]["security_agent"]


def test_browser_cli_and_online_preview_acquire_facts_without_execution_or_network(tmp_path, monkeypatch):
    marker = tmp_path / "project_was_executed"
    raw = archive({"src/query.py": HTTP_SQL, "src/canary.py":
                   f'from pathlib import Path\nPath({str(marker)!r}).touch()\n'})
    attempts = []

    def forbidden(*args, **kwargs):
        attempts.append(True)
        raise AssertionError("Evidence acquisition cannot execute project code or make connections")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(LLMClient, "complete", forbidden)
    browser = scan_archive(raw)
    local = local_cli.inspect_project(raw, {}, {}, {"sources": {}})
    online = run_scan(raw, LLMClient(providers=[]), depth=BASIS_PREVIEW)
    agent = browser["report"]["security_agent"]
    assert local["security_agent"] == online["score"]["scan_manifest"]["security_agent"] == agent
    assert fact_ids(agent["observations"][0]["acquisition"]) == SOURCE_FACTS
    assert online["score"]["scan_manifest"]["model_calls"] == 0
    assert not attempts and not marker.exists()


def test_forged_file_digest_cannot_attach_facts_from_another_snapshot():
    from app.scan.source_snapshot import SourceSnapshot

    raw = archive({"src/query.py": HTTP_SQL})
    static = deepcopy(run_static_scan(io.BytesIO(raw)))
    finding, = sql_findings(static)
    finding["claim_evidence"]["sql_observation"]["source_sha256"] = "0" * 64
    digest = hashlib.sha256(raw).hexdigest()
    snapshot = SourceSnapshot.from_archive(io.BytesIO(raw), archive_sha256=digest)
    agent = security_agent.review_static_observations(
        static, archive_sha256=digest, engine_version="test", source_snapshot=snapshot,
    )
    observation, = agent["observations"]
    assert not fact_ids(observation["acquisition"])
    assert observation["acquisition"]["status"] != "completed"
    assert observation["state"] == "needs_evidence"
    assert SOURCE_FACTS - {"value_constraints"} <= set(observation["missing_evidence"])
    assert len(sql_findings(static)) == 1


@pytest.mark.parametrize("limit", ["MAX_EVIDENCE_WORK", "MAX_EVIDENCE_ACTIONS", "MAX_CANDIDATE_STEPS"])
def test_exhausted_evidence_budget_preserves_findings_and_marks_partial(monkeypatch, limit):
    from app.scan import evidence_acquisition

    monkeypatch.setattr(evidence_acquisition, limit, 0)
    result, observation, acquisition = acquired()
    assert len(sql_findings(result["report"])) == 1
    assert acquisition["status"] == "partial"
    assert not fact_ids(acquisition)
    assert result["report"]["security_agent"]["status"] == "partial"
    assert observation["state"] == "needs_evidence"
    assert observation["recipe"]["automatic_apply"] is False
    notifications = result["sarif"]["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    assert any(row["descriptor"]["id"] == "security-agent-incomplete" for row in notifications)
    assert local_cli.exit_status(result["report"], "none") == 2


def test_partial_acquisition_keeps_established_facts_without_claiming_completion(monkeypatch):
    from app.scan import evidence_acquisition

    monkeypatch.setattr(evidence_acquisition, "MAX_CANDIDATE_STEPS", 2)
    result, observation, acquisition = acquired()
    assert actions(acquisition) == ["locate_source", "trace_request_input"]
    assert fact_ids(acquisition) == {"request_input_source", "local_input_flow"}
    assert acquisition["status"] == "partial"
    assert {"request_input_source", "local_input_flow"}.isdisjoint(observation["missing_evidence"])
    assert {"sql_value_position", *RUNTIME_GAPS} <= set(observation["missing_evidence"])
    assert result["report"]["security_agent"]["status"] == "partial"
    assert len(sql_findings(result["report"])) == 1


def test_action_budget_is_shared_between_candidates_in_one_scan(monkeypatch):
    from app.scan import evidence_acquisition

    monkeypatch.setattr(evidence_acquisition, "MAX_EVIDENCE_ACTIONS", 4)
    raw = archive({"src/a.py": HTTP_SQL, "src/z.py": HTTP_SQL})
    result = scan_archive(raw)["report"]
    observations = result["security_agent"]["observations"]
    assert len(observations) == len(sql_findings(result)) == 2
    executed = [attempt for row in observations for attempt in row["acquisition"]["attempts"]
                if attempt["result"] != "budget_exhausted"]
    assert len(executed) <= 4
    assert fact_ids(observations[0]["acquisition"]) == SOURCE_FACTS
    assert observations[1]["acquisition"]["status"] == "partial"
    assert not fact_ids(observations[1]["acquisition"])
    assert result["security_agent"]["status"] == "partial"


def test_failed_collector_preserves_findings_and_prior_facts_without_exception_text(monkeypatch):
    from app.scan import sql_slot_evidence

    def failed(*args, **kwargs):
        raise ValueError("private SQL text and password must not reach the report")

    monkeypatch.setattr(sql_slot_evidence, "classify_sql_slots", failed)
    result, observation, acquisition = acquired()
    assert acquisition["status"] == "partial"
    assert acquisition["stop_reason"] == "collector_error"
    assert fact_ids(acquisition) == {"request_input_source", "local_input_flow"}
    assert len(sql_findings(result["report"])) == 1
    assert "sql_value_position" in observation["missing_evidence"]
    assert result["report"]["security_agent"]["status"] == "partial"
    assert "private SQL text" not in json.dumps(result)

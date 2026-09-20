"""Body provenance must survive scanning and replay without becoming trust proof."""
from copy import deepcopy
import hashlib
import io
import json
import socket
import subprocess

import pytest

from app import local_cli
from app.llm.client import LLMClient
from app.report.evidence import security_agent_rows
from app.report.html import render_report
from app.scan import evidence_acquisition, security_agent, unsafe_deserialization
from app.scan.agent_chain import normalize_chain
from app.scan.browser import ScanSession, scan_archive
from app.scan.evidence_record import normalize_acquisition
from app.scan.pipeline import BASIS_PREVIEW, run_scan
from app.scan.source_snapshot import SourceSnapshot
from app.scan.static import run_static_scan
from tests.test_security_agent import archive


HTTP_PICKLE = '''from fastapi import FastAPI, Body
import pickle
app = FastAPI()
@app.post("/load")
def load(payload: bytes = Body(...)):
    data = payload
    return pickle.loads(data)
'''
SOURCE_FACTS = {"request_input_source", "local_input_flow"}
RUNTIME_GAPS = {"input_trust_boundary", "loader_runtime_contract"}
PATTERN = "python-unsafe-deserialization"


def deserialization_findings(report):
    return [finding for finding in report["findings"] if finding["rule_id"] == "unsafe-deserialization"]


def observations(report):
    return [row for row in report["security_agent"]["observations"] if row["pattern_id"] == PATTERN]


def acquired(source=HTTP_PICKLE, *, files=None):
    result = scan_archive(archive({"src/load.py": source, **(files or {})}))
    observation, = observations(result["report"])
    return result, observation, observation["acquisition"]


def fact_ids(acquisition):
    return {fact["id"] for fact in acquisition["facts"]}


def test_body_flow_completes_source_goal_but_keeps_trust_and_loader_gates():
    result, observation, acquisition = acquired()
    agent = result["report"]["security_agent"]
    finding, = deserialization_findings(result["report"])
    trace = finding["claim_evidence"]["deserialization_observation"]
    assert observation["pattern_revision"] == 3
    assert acquisition["version"] == 2
    assert acquisition["status"] == "completed"
    assert fact_ids(acquisition) == SOURCE_FACTS
    assert [step["action"] for step in acquisition["attempts"]] == ["locate_source", "trace_request_input"]
    assert acquisition["source"] == {
        "file": "src/load.py", "source_sha256": hashlib.sha256(HTTP_PICKLE.encode()).hexdigest(),
        "sink_span": trace["sink_span"],
    }
    assert acquisition["facts"][0]["sources"][0]["channel"] == "body"
    assert acquisition["facts"][1]["locations"][-1] == trace["sink_span"]
    assert observation["state"] == "source_evidence_collected"
    assert observation["next_action"] == "review_runtime_contract"
    assert set(observation["missing_evidence"]) == RUNTIME_GAPS
    assert observation["recipe"] == {"id": None, "status": "not_available", "automatic_apply": False}
    assert agent["runtime_verified"] is agent["automatic_patch"] is False
    assert finding["verification_status"] == "unverified"
    assert trace["input_control_status"] == "not_checked"
    chain = observation["agent_chain"]
    assert chain["scope"] == "source_evidence"
    assert chain["status"] == "waiting_for_evidence"
    assert [task["agent"] for task in chain["tasks"]] == ["detector", "researcher", "experimenter", "verifier"]
    assert [task["status"] for task in chain["tasks"]] == ["completed", "completed", "blocked", "blocked"]
    for previous, current in zip(chain["tasks"], chain["tasks"][1:]):
        assert current["depends_on"] == [previous["id"]]
        assert current["input_sha256"] == previous["output_sha256"]
    assert all(task["source"]["source_sha256"] == trace["source_sha256"] for task in chain["tasks"])
    assert normalize_chain(chain, observation, agent["source"], agent["catalog"]) == chain
    assert "synthetic_contract" not in observation


@pytest.mark.parametrize("source", [
    HTTP_PICKLE.replace("import pickle", "from pickle import loads as decode")
    .replace("pickle.loads(data)", "decode(data)"),
    HTTP_PICKLE.replace("from fastapi import FastAPI, Body", "import fastapi as api\nfrom typing import Annotated")
    .replace("FastAPI()", "api.FastAPI()")
    .replace("payload: bytes = Body(...)", "payload: Annotated[bytes, api.Body(...)]"),
], ids=["loader-import-alias", "annotated-body-module-alias"])
def test_supported_aliases_reach_the_exact_import_resolved_sink(source):
    result, observation, acquisition = acquired(source)
    assert len(deserialization_findings(result["report"])) == 1
    assert acquisition["status"] == "completed"
    assert set(observation["missing_evidence"]) == RUNTIME_GAPS


@pytest.mark.parametrize("source", [
    HTTP_PICKLE.replace(" = Body(...)", ""),
    HTTP_PICKLE.replace("data = payload", "data = unknown_wrapper(payload)"),
], ids=["no-explicit-body", "unresolved-wrapper"])
def test_unsupported_flow_preserves_detection_and_source_gaps(source):
    result, observation, acquisition = acquired(source)
    assert len(deserialization_findings(result["report"])) == 1
    assert acquisition["status"] == "unsupported"
    assert not fact_ids(acquisition)
    assert observation["state"] == "needs_evidence"
    assert observation["next_action"] == "manual_review"
    assert set(observation["missing_evidence"]) == SOURCE_FACTS | RUNTIME_GAPS
    assert observation["agent_chain"]["tasks"][1]["status"] == "blocked"


@pytest.mark.parametrize("path", ["src/fastapi.py", "src/pickle/__init__.py"])
def test_repository_local_library_cannot_establish_http_to_pickle_provenance(path):
    result, observation, acquisition = acquired(files={path: "pass\n"})
    assert len(deserialization_findings(result["report"])) == 1
    assert not fact_ids(acquisition)
    assert SOURCE_FACTS <= set(observation["missing_evidence"])
    assert acquisition["attempts"][-1]["detail"] == "framework_import_shadowed"


def test_same_line_sinks_keep_separate_source_proof_and_cached_acquisitions():
    source = HTTP_PICKLE.replace("    data = payload\n    return pickle.loads(data)",
                                 '    pickle.loads(payload); pickle.loads(b"internal")')
    result = scan_archive(archive({"src/load.py": source}))["report"]
    assert len(deserialization_findings(result)) == 2
    first, second = sorted(observations(result),
                           key=lambda row: row["evidence"]["deserialization_observation"]["sink_span"])
    assert first["line"] == second["line"]
    assert first["id"] != second["id"]
    assert fact_ids(first["acquisition"]) == SOURCE_FACTS
    assert not fact_ids(second["acquisition"])
    assert first["state"] == "source_evidence_collected"
    assert second["state"] == "needs_evidence"
    assert normalize_acquisition(first["acquisition"], second["evidence"]["deserialization_observation"]) is None


def test_original_utf8_and_line_endings_bind_all_proof_to_the_archive_bytes():
    source = ("# Исходный файл\n" + HTTP_PICKLE).replace("\n", "\r\n")
    _, observation, acquisition = acquired(source)
    digest = hashlib.sha256(source.encode()).hexdigest()
    assert digest != hashlib.sha256(source.replace("\r\n", "\n").encode()).hexdigest()
    assert acquisition["status"] == "completed"
    assert acquisition["source"]["source_sha256"] == digest
    assert observation["evidence"]["deserialization_observation"]["source_sha256"] == digest


def test_continuation_investigates_newly_discovered_deserialization_sink(monkeypatch):
    raw = archive({"src/first.py": "value = 1\n", "src/load.py": HTTP_PICKLE})
    monkeypatch.setattr(unsafe_deserialization, "_MAX_FILES", 1)
    session = ScanSession(raw)
    assert observations(session.result()["report"]) == []
    resumed = session.continue_scan()
    observation, = observations(resumed["report"])
    assert fact_ids(observation["acquisition"]) == SOURCE_FACTS
    assert session.continue_scan() == resumed
    monkeypatch.undo()
    assert resumed["report"]["security_agent"] == scan_archive(raw)["report"]["security_agent"]


def test_browser_cli_and_free_preview_acquire_facts_without_model_network_or_execution(tmp_path, monkeypatch):
    marker = tmp_path / "project_executed"
    raw = archive({"src/load.py": HTTP_PICKLE, "src/canary.py":
                   f'from pathlib import Path\nPath({str(marker)!r}).touch()\n'})
    calls = []

    def forbidden(*args, **kwargs):
        calls.append(True)
        raise AssertionError("Source evidence must not execute code, make connections or call a model")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(LLMClient, "complete", forbidden)
    browser = scan_archive(raw)
    cli = local_cli.inspect_project(raw, {}, {}, {"sources": {}})
    online = run_scan(raw, LLMClient(providers=[]), depth=BASIS_PREVIEW)
    runtime_enabled = run_static_scan(io.BytesIO(raw), synthetic_sql_executor=forbidden)
    agent = browser["report"]["security_agent"]
    assert cli["security_agent"] == online["score"]["scan_manifest"]["security_agent"] == agent
    assert runtime_enabled["security_agent"]["observations"] == agent["observations"]
    assert fact_ids(observations(browser["report"])[0]["acquisition"]) == SOURCE_FACTS
    assert online["score"]["scan_manifest"]["model_calls"] == 0
    assert not calls and not marker.exists()


@pytest.mark.parametrize("limit", ["MAX_EVIDENCE_WORK", "MAX_EVIDENCE_ACTIONS"])
def test_exhausted_budget_preserves_finding_and_reports_incomplete_investigation(monkeypatch, limit):
    monkeypatch.setattr(evidence_acquisition, limit, 0)
    result, observation, acquisition = acquired()
    assert len(deserialization_findings(result["report"])) == 1
    assert acquisition["status"] == "partial"
    assert acquisition["stop_reason"] == "budget_exhausted"
    assert not fact_ids(acquisition)
    assert set(observation["missing_evidence"]) == SOURCE_FACTS | RUNTIME_GAPS
    assert result["report"]["security_agent"]["status"] == "partial"
    assert local_cli.exit_status(result["report"], "none") == 2
    notifications = result["sarif"]["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    assert any(row["descriptor"]["id"] == "security-agent-incomplete" for row in notifications)


def test_action_budget_is_shared_across_deserialization_candidates(monkeypatch):
    monkeypatch.setattr(evidence_acquisition, "MAX_EVIDENCE_ACTIONS", 2)
    report = scan_archive(archive({"src/a.py": HTTP_PICKLE, "src/b.py": HTTP_PICKLE}))["report"]
    first, second = observations(report)
    assert len(deserialization_findings(report)) == 2
    assert first["acquisition"]["status"] == "completed"
    assert second["acquisition"]["status"] == "partial"
    assert not fact_ids(second["acquisition"])
    assert report["security_agent"]["status"] == "partial"


@pytest.mark.parametrize("snapshot_present", [False, True], ids=["snapshot-unavailable", "wrong-source-digest"])
def test_absent_or_mismatched_snapshot_cannot_supply_body_facts(snapshot_present):
    raw = archive({"src/load.py": HTTP_PICKLE})
    static = deepcopy(run_static_scan(io.BytesIO(raw)))
    digest = hashlib.sha256(raw).hexdigest()
    snapshot = None
    if snapshot_present:
        deserialization_findings(static)[0]["claim_evidence"]["deserialization_observation"]["source_sha256"] = "0" * 64
        snapshot = SourceSnapshot.from_archive(io.BytesIO(raw), archive_sha256=digest)
    try:
        agent = security_agent.review_static_observations(
            static, archive_sha256=digest, engine_version="test", source_snapshot=snapshot,
        )
    finally:
        if snapshot is not None:
            snapshot.close()
    observation, = agent["observations"]
    assert len(deserialization_findings(static)) == 1
    assert not fact_ids(observation["acquisition"])
    assert observation["acquisition"]["status"] == "unsupported"
    assert observation["state"] == "needs_evidence"
    assert set(observation["missing_evidence"]) == SOURCE_FACTS | RUNTIME_GAPS


def test_collector_exception_cannot_drop_the_static_finding_or_leak_private_text(monkeypatch):
    from app.scan import deserialization_input_evidence

    def failed(*args, **kwargs):
        raise ValueError("PRIVATE CUSTOMER PAYLOAD")

    monkeypatch.setattr(deserialization_input_evidence, "analyze_deserialization_input", failed)
    result, observation, acquisition = acquired()
    assert len(deserialization_findings(result["report"])) == 1
    assert acquisition["status"] == "partial"
    assert acquisition["stop_reason"] == "collector_error"
    assert not fact_ids(acquisition)
    assert observation["state"] == "needs_evidence"
    assert "PRIVATE CUSTOMER PAYLOAD" not in json.dumps(result)


def test_saved_source_proof_is_deterministic_and_survives_json_sarif_and_html():
    raw = archive({"src/load.py": HTTP_PICKLE})
    first, second = scan_archive(raw), scan_archive(raw)
    agent = first["report"]["security_agent"]
    assert second["report"]["security_agent"] == agent
    saved = json.loads(json.dumps(agent))
    assert security_agent.agent_record(saved) == agent
    assert first["sarif"]["runs"][0]["invocations"][0]["properties"]["securityAgent"] == agent
    rows = dict(security_agent_rows(saved))
    assert rows["Source investigation"].startswith("completed;")
    assert "body parameter payload" in rows["Source fact: request input source"]
    assert "input trust boundary" in rows["Missing evidence"]
    assert "loader runtime contract" in rows["Missing evidence"]
    assert "loader options" in rows["Next step"]
    before = deepcopy(saved)
    html = render_report({"score": {"scan_manifest": {"security_agent": saved}},
                          "findings": deserialization_findings(first["report"])})
    assert "body parameter payload" in html
    assert "loader runtime contract" in html
    assert "Source fact: request input source" in html
    assert "Model interpretation — unverified" not in html
    assert saved == before


@pytest.mark.parametrize("mutate", [
    lambda record: record["source"].update(source_sha256="0" * 64),
    lambda record: record["source"].update(sink_span=[7, 0, 7, 99]),
    lambda record: record["facts"][0]["sources"][0].update(channel="query"),
    lambda record: record["facts"].pop(),
    lambda record: record["facts"].append({"id": "input_trust_boundary", "method": "fastapi_ast_binding"}),
], ids=["wrong-source", "wrong-sink", "wrong-channel", "missing-flow", "invented-trust-proof"])
def test_saved_acquisition_tampering_cannot_render_established_body_proof(mutate):
    result, observation, acquisition = acquired()
    mutate(acquisition)
    trace = observation["evidence"]["deserialization_observation"]
    assert normalize_acquisition(acquisition, trace) is None
    rows = dict(security_agent_rows(result["report"]["security_agent"]))
    assert "Source fact: request input source" not in rows
    assert rows["Pattern review"].startswith("partial;")
    assert rows["Review state"].startswith("Needs evidence;")
    assert "request input source" in rows["Missing evidence"]
    assert "input trust boundary" in rows["Missing evidence"]


def test_cross_file_replay_and_removed_runtime_gaps_cannot_be_presented_as_complete():
    report = scan_archive(archive({"src/a.py": HTTP_PICKLE, "src/b.py": HTTP_PICKLE}))["report"]
    first, second = observations(report)
    assert normalize_acquisition(first["acquisition"], second["evidence"]["deserialization_observation"]) is None
    assert normalize_chain(first["agent_chain"], second, report["security_agent"]["source"],
                           report["security_agent"]["catalog"]) is None
    first["missing_evidence"] = []
    report["security_agent"]["observations"] = [first]
    rows = dict(security_agent_rows(report["security_agent"]))
    assert "Source fact: request input source" not in rows
    assert rows["Pattern review"].startswith("partial;")
    assert rows["Review state"].startswith("Needs evidence;")
    assert "input trust boundary" in rows["Missing evidence"]
    assert "loader runtime contract" in rows["Missing evidence"]


@pytest.mark.parametrize("evidence", [{}, None], ids=["empty-evidence", "missing-evidence"])
def test_deleting_entire_source_trace_revokes_saved_source_completion(evidence):
    result, observation, _ = acquired()
    observation["evidence"] = evidence
    normalized = security_agent.agent_record(result["report"]["security_agent"])
    assert normalized["status"] == "partial"
    assert normalized["stop_reason"] == "source_evidence_invalid"
    restored, = normalized["observations"]
    assert restored["state"] == "needs_evidence"
    assert restored["next_action"] == "manual_review"
    assert set(restored["missing_evidence"]) == SOURCE_FACTS | RUNTIME_GAPS
    assert "acquisition" not in restored
    assert "agent_chain" not in restored
    rows = dict(security_agent_rows(normalized))
    assert "Source fact: request input source" not in rows
    assert rows["Review state"].startswith("Needs evidence;")


def test_same_line_acquisition_transplant_does_not_promote_a_different_call():
    source = HTTP_PICKLE.replace("    data = payload\n    return pickle.loads(data)",
                                 '    pickle.loads(payload); pickle.loads(b"internal")')
    report = scan_archive(archive({"src/load.py": source}))["report"]
    first, second = sorted(observations(report),
                           key=lambda row: row["evidence"]["deserialization_observation"]["sink_span"])
    second.update(acquisition=deepcopy(first["acquisition"]), state="source_evidence_collected",
                  next_action="review_runtime_contract", missing_evidence=sorted(RUNTIME_GAPS))
    report["security_agent"]["observations"] = [second]
    normalized = security_agent.agent_record(report["security_agent"])
    assert normalized["status"] == "partial"
    restored, = normalized["observations"]
    assert restored["state"] == "needs_evidence"
    assert set(restored["missing_evidence"]) == SOURCE_FACTS | RUNTIME_GAPS
    assert "acquisition" not in restored


@pytest.mark.parametrize("mutate", [
    lambda agent: agent["source"].update(archive_sha256="0" * 64),
    lambda agent: agent["catalog"].update(sha256="0" * 64),
    lambda agent: agent["observations"][0].pop("agent_chain"),
], ids=["different-archive", "different-catalog", "deleted-chain"])
def test_saved_body_proof_requires_its_original_archive_catalog_and_chain(mutate):
    result, observation, acquisition = acquired()
    agent = result["report"]["security_agent"]
    mutate(agent)
    # An internally valid acquisition alone cannot bind the proof to this scan.
    assert normalize_acquisition(acquisition, observation["evidence"]["deserialization_observation"]) == acquisition
    normalized = security_agent.agent_record(agent)
    assert normalized["status"] == "partial"
    assert normalized["stop_reason"] == "source_evidence_invalid"
    restored, = normalized["observations"]
    assert restored["state"] == "needs_evidence"
    assert restored["next_action"] == "manual_review"
    assert set(restored["missing_evidence"]) == SOURCE_FACTS | RUNTIME_GAPS
    assert "acquisition" not in restored
    assert "agent_chain" not in restored
    rows = dict(security_agent_rows(normalized))
    assert "Source fact: request input source" not in rows
    assert rows["Review state"].startswith("Needs evidence;")

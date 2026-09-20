"""File provenance must survive the full scan without becoming a trust claim."""
from copy import deepcopy
import hashlib
import json
import socket
import subprocess

import pytest

from app import local_cli
from app.llm.client import LLMClient
from app.report.evidence import security_agent_rows
from app.scan import evidence_acquisition, security_agent
from app.scan.agent_chain import normalize_chain
from app.scan.browser import scan_archive
from app.scan.evidence_record import normalize_acquisition
from app.scan.pipeline import BASIS_PREVIEW, run_scan
from tests.test_security_agent import archive


FILE_LOADERS = '''import pickle

def read_primary(path):
    if use_other_format(path):
        return read_other_format(path)
    with open(path, "rb") as handle:
        return pickle.load(handle)

def read_secondary(path):
    with open(path, "rb") as handle:
        return pickle.load(handle)
'''
GAPS = {"request_input_source", "input_trust_boundary", "loader_runtime_contract"}
FACTS = {"file_input_source", "local_input_flow"}


def scan(files=None):
    return scan_archive(archive({"src/checkpoints.py": FILE_LOADERS, **(files or {})}))


def test_two_file_sinks_collect_distinct_bound_facts_and_keep_unknown_origin():
    result = scan()
    report, agent = result["report"], result["report"]["security_agent"]
    assert len(agent["observations"]) == 2
    assert agent["budget"]["evidence_actions"] == 4
    assert agent["budget"]["evidence_work"] > 0
    assert agent["runtime_verified"] is agent["automatic_patch"] is False
    findings = [f for f in report["findings"] if f["rule_id"] == "unsafe-deserialization"]
    assert len(findings) == 2
    assert all(f["severity"] == "high" and f["verification_status"] == "unverified" for f in findings)
    functions = set()
    for observation in agent["observations"]:
        trace = observation["evidence"]["deserialization_observation"]
        record = observation["acquisition"]
        assert trace["loader"] == "pickle.load"
        assert trace["input_control_status"] == "not_checked"
        assert trace["source_sha256"] == hashlib.sha256(FILE_LOADERS.encode()).hexdigest()
        assert record["status"] == "completed"
        assert {fact["id"] for fact in record["facts"]} == FACTS
        functions.add(record["facts"][0]["sources"][0]["function"])
        assert observation["state"] == "source_evidence_collected"
        assert set(observation["missing_evidence"]) == GAPS
        assert observation["recipe"]["automatic_apply"] is False
        chain = observation["agent_chain"]
        assert [task["status"] for task in chain["tasks"]] == ["completed", "completed", "blocked", "blocked"]
        assert normalize_chain(chain, observation, agent["source"], agent["catalog"]) == chain
        assert normalize_acquisition(record, trace) == record
    assert functions == {"read_primary", "read_secondary"}
    assert security_agent.agent_record(json.loads(json.dumps(agent))) == agent
    assert result["sarif"]["runs"][0]["invocations"][0]["properties"]["securityAgent"] == agent
    rows = dict(security_agent_rows(agent))
    assert "Source fact: file input source" in rows
    assert "input trust boundary" in rows["Missing evidence"]
    first, second = agent["observations"]
    assert normalize_acquisition(first["acquisition"], second["evidence"]["deserialization_observation"]) is None


@pytest.mark.parametrize("local_module", ["pickle.py", "builtins.py"])
def test_local_modules_preserve_findings_but_cannot_establish_library_semantics(local_module):
    report = scan({f"src/{local_module}": "pass\n"})["report"]
    for observation in report["security_agent"]["observations"]:
        assert observation["state"] == "needs_evidence"
        assert not observation["acquisition"]["facts"]
        assert set(observation["missing_evidence"]) == GAPS | {"local_input_flow"}


def test_unrelated_framework_module_does_not_block_a_file_binding():
    report = scan({"src/fastapi.py": "pass\n"})["report"]
    assert all(o["acquisition"]["status"] == "completed" for o in report["security_agent"]["observations"])


def test_file_scan_paths_never_execute_customer_code_or_call_network_or_model(tmp_path, monkeypatch):
    marker = tmp_path / "customer-code-ran"
    raw = archive({"src/checkpoints.py": FILE_LOADERS,
                   "src/canary.py": f'from pathlib import Path\nPath({str(marker)!r}).touch()\n'})
    forbidden_calls = []

    def forbidden(*args, **kwargs):
        forbidden_calls.append(True)
        raise AssertionError("File evidence must only inspect the source snapshot")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(LLMClient, "complete", forbidden)
    browser = scan_archive(raw)
    cli = local_cli.inspect_project(raw, {}, {}, {"sources": {}})
    online = run_scan(raw, LLMClient(providers=[]), depth=BASIS_PREVIEW)
    agent = browser["report"]["security_agent"]
    assert cli["security_agent"] == online["score"]["scan_manifest"]["security_agent"] == agent
    assert all(o["acquisition"]["status"] == "completed" for o in agent["observations"])
    assert online["score"]["scan_manifest"]["model_calls"] == 0
    assert not forbidden_calls and not marker.exists()


@pytest.mark.parametrize("limit", ["MAX_EVIDENCE_WORK", "MAX_EVIDENCE_ACTIONS"])
def test_shared_budget_exhaustion_cannot_claim_complete_file_evidence(monkeypatch, limit):
    monkeypatch.setattr(evidence_acquisition, limit, 0)
    report = scan()["report"]
    assert report["security_agent"]["status"] == "partial"
    assert local_cli.exit_status(report, "none") == 2
    for observation in report["security_agent"]["observations"]:
        assert observation["acquisition"]["stop_reason"] == "budget_exhausted"
        assert not observation["acquisition"]["facts"]
        assert observation["state"] == "needs_evidence"


def test_collector_failure_preserves_detection_without_exposing_exception_text(monkeypatch):
    from app.scan import deserialization_file_evidence

    def failed(*args, **kwargs):
        raise ValueError("PRIVATE CUSTOMER VALUE")

    monkeypatch.setattr(deserialization_file_evidence, "analyze_deserialization_file_input", failed)
    result = scan()
    for observation in result["report"]["security_agent"]["observations"]:
        assert observation["acquisition"]["stop_reason"] == "collector_error"
        assert observation["state"] == "needs_evidence"
        assert not observation["acquisition"]["facts"]
    assert "PRIVATE CUSTOMER VALUE" not in json.dumps(result)


@pytest.mark.parametrize("mutate", [
    lambda agent: agent["source"].update(archive_sha256="0" * 64),
    lambda agent: agent["observations"][0].pop("agent_chain"),
    lambda agent: agent["observations"][0].update(missing_evidence=[]),
    lambda agent: agent["observations"][0]["acquisition"]["facts"][0]["sources"][0].update(function="forged"),
])
def test_saved_file_proof_requires_consistent_receipts_and_unknown_boundaries(mutate):
    agent = deepcopy(scan()["report"]["security_agent"])
    agent["observations"] = agent["observations"][:1]
    mutate(agent)
    normalized = security_agent.agent_record(agent)
    assert normalized["status"] == "partial"
    observation, = normalized["observations"]
    assert observation["state"] == "needs_evidence"
    assert "acquisition" not in observation
    assert GAPS | {"local_input_flow"} == set(observation["missing_evidence"])
    assert "Source fact: file input source" not in dict(security_agent_rows(agent))

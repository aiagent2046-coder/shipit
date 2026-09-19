"""Exercise source-bound handoffs and independent verification without a model."""
from copy import deepcopy
import hashlib
import io
import json
import os

import pytest

from app.llm.client import LLMClient
from app.scan.agent_chain import normalize_chain, run_chain
from app.scan.pipeline import BASIS_PREVIEW, run_scan
from app.scan.security_agent import agent_record
from app.scan.static import run_static_scan
from app.scan.synthetic_record import unavailable_summary
from tests.test_agent_synthetic_runtime import passed_summary
from tests.test_evidence_acquisition import HTTP_SQL, RUNTIME_GAPS, SOURCE_FACTS
from tests.test_security_agent import archive, sql_findings


ROLES = ["detector", "researcher", "experimenter", "verifier"]


def investigate(executor=passed_summary, files=None):
    raw = archive(files or {"src/query.py": HTTP_SQL})
    return run_static_scan(io.BytesIO(raw), synthetic_sql_executor=executor)


def test_full_chain_transfers_bound_evidence_and_leaves_customer_proof_open(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("The deterministic chain must not call a language model")

    monkeypatch.setattr(LLMClient, "complete", forbidden)
    raw = archive({"src/query.py": HTTP_SQL})
    result = run_scan(raw, LLMClient(providers=[]), depth=BASIS_PREVIEW,
                      synthetic_sql_executor=passed_summary)
    manifest = result["score"]["scan_manifest"]
    agent = manifest["security_agent"]
    observation, = agent["observations"]
    chain = observation["agent_chain"]
    assert chain["status"] == "completed"
    assert [task["agent"] for task in chain["tasks"]] == ROLES
    assert all(task["status"] == "completed" for task in chain["tasks"])
    previous = None
    for task in chain["tasks"]:
        assert task["depends_on"] == ([previous["id"]] if previous else [])
        if previous:
            assert task["input_sha256"] == previous["output_sha256"]
        assert task["source"] == {
            **agent["source"], "archive_sha256": hashlib.sha256(raw).hexdigest(),
            "source_sha256": hashlib.sha256(HTTP_SQL.encode()).hexdigest(),
            "catalog_sha256": agent["catalog"]["sha256"], "observation_id": observation["id"],
        }
        assert task["attempts"] == task["max_attempts"] == 1
        previous = task
    assert normalize_chain(chain, observation, agent["source"], agent["catalog"]) == chain
    assert agent_record(agent) == agent
    assert {fact["id"] for fact in observation["acquisition"]["facts"]} == SOURCE_FACTS
    assert observation["state"] == "synthetic_recipe_verified"
    assert set(observation["missing_evidence"]) == RUNTIME_GAPS
    assert manifest["model_calls"] == 0
    assert agent["runtime_verified"] is agent["automatic_patch"] is False
    assert sql_findings(result)[0]["verification_status"] == "unverified"
    assert "_pending_contract" not in observation


def test_two_chains_share_one_experiment_without_sharing_task_identity():
    calls = []

    def execute():
        calls.append(True)
        return passed_summary()

    scan = investigate(execute, {"src/a.py": HTTP_SQL, "src/b.py": HTTP_SQL})
    agent = scan["security_agent"]
    first, second = agent["observations"]
    assert calls == [True]
    assert len(sql_findings(scan)) == 2
    assert first["synthetic_contract"]["reused"] is False
    assert second["synthetic_contract"]["reused"] is True
    assert {task["id"] for task in first["agent_chain"]["tasks"]}.isdisjoint(
        {task["id"] for task in second["agent_chain"]["tasks"]})
    for observation in (first, second):
        assert observation["agent_chain"]["status"] == "completed"
        assert all(task["source"]["observation_id"] == observation["id"]
                   for task in observation["agent_chain"]["tasks"])


@pytest.mark.parametrize("summary", [
    unavailable_summary("execution_timeout"),
    {**passed_summary(), "customer_project_verified": True},
])
def test_failed_or_forged_experiment_preserves_research_and_static_findings(summary):
    scan = investigate(lambda: deepcopy(summary))
    agent = scan["security_agent"]
    observation, = agent["observations"]
    assert len(sql_findings(scan)) == 1
    assert agent["status"] == "partial"
    assert observation["state"] == "source_evidence_collected"
    assert observation["agent_chain"]["status"] != "completed"
    assert {fact["id"] for fact in observation["acquisition"]["facts"]} == SOURCE_FACTS
    assert set(observation["missing_evidence"]) == RUNTIME_GAPS
    assert observation["synthetic_contract"]["status"] != "passed"
    assert "_pending_contract" not in observation


def test_research_failure_preserves_prior_facts_and_blocks_experiment(monkeypatch):
    from app.scan import sql_slot_evidence

    def fail(*args, **kwargs):
        raise ValueError("SECRET CUSTOMER SQL")

    monkeypatch.setattr(sql_slot_evidence, "classify_sql_slots", fail)
    calls = []
    scan = investigate(lambda: calls.append(True))
    agent = scan["security_agent"]
    observation, = agent["observations"]
    assert calls == []
    assert len(sql_findings(scan)) == 1
    assert agent["status"] == "partial"
    assert {fact["id"] for fact in observation["acquisition"]["facts"]} == {
        "request_input_source", "local_input_flow",
    }
    assert observation["agent_chain"]["status"] != "completed"
    assert "synthetic_contract" not in observation
    assert "SECRET CUSTOMER SQL" not in json.dumps(scan)


@pytest.mark.parametrize("source", [
    HTTP_SQL.replace("name: str", "name: int"),
    HTTP_SQL.replace('@app.get("/users")\n', ""),
    HTTP_SQL.replace('psycopg.connect("PRIVATE_DSN")', "unknown_connect()"),
])
def test_unsupported_source_blocks_experiment_with_explicit_terminal_receipt(source):
    calls = []
    scan = investigate(lambda: calls.append(True), {"src/query.py": source})
    observation, = scan["security_agent"]["observations"]
    assert calls == []
    assert observation["agent_chain"]["status"] == "waiting_for_evidence"
    assert [task["agent"] for task in observation["agent_chain"]["tasks"]] == ROLES
    assert observation["agent_chain"]["tasks"][2]["status"] == "blocked"
    assert "synthetic_contract" not in observation


@pytest.mark.parametrize("mutate", [
    lambda tasks: tasks[1]["source"].update(observation_id="0" * 64),
    lambda tasks: tasks[1].update(depends_on=[]),
    lambda tasks: tasks[2].update(input_sha256="0" * 64),
    lambda tasks: tasks[3].update(output_sha256="0" * 64),
    lambda tasks: tasks[0].update(attempts=True),
])
def test_saved_handoff_corruption_is_rejected(mutate):
    agent = investigate()["security_agent"]
    observation, = agent["observations"]
    mutate(observation["agent_chain"]["tasks"])
    assert normalize_chain(observation["agent_chain"], observation, agent["source"], agent["catalog"]) is None
    normalized = agent_record(agent)
    assert "agent_chain" not in normalized["observations"][0]
    assert normalized["status"] == "partial"


def test_cross_observation_chain_cannot_be_replayed_as_second_candidate_evidence():
    agent = investigate(files={"a.py": HTTP_SQL, "b.py": HTTP_SQL})["security_agent"]
    first, second = agent["observations"]
    assert normalize_chain(first["agent_chain"], second, agent["source"], agent["catalog"]) is None


def test_failed_worker_cannot_mutate_evidence_received_by_next_worker():
    agent = investigate()["security_agent"]
    seed = deepcopy(agent["observations"][0])
    seed.pop("agent_chain")
    original = deepcopy(seed)
    binding = {**agent["source"], "catalog_sha256": agent["catalog"]["sha256"],
               "source_sha256": seed["evidence"]["sql_observation"]["source_sha256"],
               "observation_id": seed["id"]}
    received = []

    def identity(value):
        return value, "completed", "accepted"

    def fail(value):
        value["acquisition"]["facts"].clear()
        value["missing_evidence"].clear()
        raise ValueError("PRIVATE FAILURE")

    def inspect(value):
        received.append(deepcopy(value))
        return identity(value)

    result = run_chain(seed, binding, {"detector": identity, "researcher": fail,
                                      "experimenter": identity, "verifier": inspect})
    assert seed == original == received[0]
    assert result["acquisition"] == original["acquisition"]
    assert result["agent_chain"]["status"] == "error"
    assert "PRIVATE FAILURE" not in json.dumps(result)


@pytest.mark.parametrize("mutation", [
    lambda value: value.update(id="0" * 64),
    lambda value: value["evidence"]["sql_observation"].update(source_sha256="0" * 64),
    lambda value: value["recipe"].update(automatic_apply=True),
    lambda value: value.update(state="synthetic_recipe_verified", next_action="review_project_runtime_contract"),
    lambda value: value.update(missing_evidence=[]),
    lambda value: value.update(file="other.py"),
])
def test_worker_cannot_replace_the_observation_or_authorize_a_patch(monkeypatch, mutation):
    from app.scan import security_agent

    def corrupt(observation, snapshot, budget):
        mutation(observation)
        return observation, "completed", "claimed_success"

    monkeypatch.setattr(security_agent, "_research_candidate", corrupt)
    calls = []
    scan = investigate(lambda: calls.append(True))
    agent = scan["security_agent"]
    observation, = agent["observations"]
    assert calls == []
    assert len(sql_findings(scan)) == 1
    assert agent["status"] == "partial"
    assert observation["agent_chain"]["status"] == "error"
    assert observation["agent_chain"]["tasks"][1]["status"] == "error"
    assert observation["id"] != "0" * 64
    assert observation["evidence"]["sql_observation"]["source_sha256"] == hashlib.sha256(HTTP_SQL.encode()).hexdigest()
    assert observation["recipe"]["automatic_apply"] is False
    assert "synthetic_contract" not in observation


def test_detector_failure_blocks_research_and_experiment_but_preserves_verification():
    agent = investigate()["security_agent"]
    seed = deepcopy(agent["observations"][0])
    seed.pop("agent_chain")
    binding = {**agent["source"], "catalog_sha256": agent["catalog"]["sha256"],
               "source_sha256": seed["evidence"]["sql_observation"]["source_sha256"],
               "observation_id": seed["id"]}
    calls = []

    def failed_detector(value):
        calls.append("detector")
        raise ValueError("invalid detection")

    def worker(role):
        def execute(value):
            calls.append(role)
            return value, "completed", "accepted"
        return execute

    result = run_chain(seed, binding, {"detector": failed_detector,
        "researcher": worker("researcher"), "experimenter": worker("experimenter"),
        "verifier": worker("verifier")})
    assert calls == ["detector", "verifier"]
    assert result["agent_chain"]["status"] == "error"
    assert [task["status"] for task in result["agent_chain"]["tasks"]] == [
        "error", "blocked", "blocked", "completed",
    ]
    assert {key: value for key, value in result.items() if key != "agent_chain"} == seed


@pytest.mark.skipif(not os.environ.get("SQL_CONTRACT_DATABASE_URL"),
                    reason="Dedicated PostgreSQL target is required")
def test_full_chain_runs_real_postgres_once_for_two_independent_candidates():
    from app.proof.sql_runtime_executor import SyntheticSqlExecutor

    scan = investigate(SyntheticSqlExecutor(), {"src/a.py": HTTP_SQL, "src/b.py": HTTP_SQL})
    agent = scan["security_agent"]
    assert len(sql_findings(scan)) == len(agent["observations"]) == 2
    assert agent["budget"]["synthetic_contract_runs"] == 1
    assert agent["budget"]["synthetic_contract_reuses"] == 1
    for observation in agent["observations"]:
        chain = observation["agent_chain"]
        assert chain["status"] == "completed"
        assert [task["agent"] for task in chain["tasks"]] == ROLES
        assert all(task["status"] == "completed" for task in chain["tasks"])
        assert normalize_chain(chain, observation, agent["source"], agent["catalog"]) == chain
        proof = observation["synthetic_contract"]["proof"]
        assert proof["executions"] == 27
        assert proof["before_row_ids"] == proof["mutation_row_ids"] == list(range(1, 10))
        assert proof["after_row_ids"] == [9]
        assert proof["rollback_completed"] is proof["temporary_table_absent"] is True
        assert set(observation["missing_evidence"]) == RUNTIME_GAPS
        assert observation["synthetic_contract"]["source"]["observation_id"] == observation["id"]
    assert agent["runtime_verified"] is agent["automatic_patch"] is False
    assert all(finding["verification_status"] == "unverified" for finding in sql_findings(scan))


@pytest.mark.parametrize("value", [None, [], {"sql_observation": None}, {"sql_observation": []}])
def test_malformed_saved_chain_evidence_cannot_crash_report_normalization(value):
    agent = investigate(None)["security_agent"]
    agent["observations"][0]["evidence"] = value
    normalized = agent_record(agent)
    assert normalized["status"] == "partial"
    assert normalized["stop_reason"] == "agent_chain_invalid"
    assert "agent_chain" not in normalized["observations"][0]

"""Exercise the planner/executor boundary, not just the standalone SQL harness."""
from copy import deepcopy
import hashlib
import io
import json
import os

import pytest

from app.llm.client import LLMClient
from app.scan.pipeline import BASIS_PREVIEW, run_scan
from app.scan.security_agent import agent_record
from app.scan.static import run_static_scan
from app.scan.synthetic_record import (CONTRACT_ID, FIXTURE_SHA256, SCHEMA_SHA256, SUMMARY_KEYS,
    normalize_synthetic_contract, normalize_synthetic_summary, unavailable_summary)
from tests.test_evidence_acquisition import HTTP_SQL, RUNTIME_GAPS
from tests.test_security_agent import archive, sql_findings


def passed_summary():
    return {**unavailable_summary("execution_unavailable"), "status": "passed", "reason": "synthetic_contract_passed",
            "synthetic_recipe_verified": True, "proof": {
                "fixture_sha256": FIXTURE_SHA256, "schema_sha256": SCHEMA_SHA256,
                "psycopg_version": "3.3.5", "postgresql_version": 170011,
                "executions": 27, "cases_per_stage": 9, "before_row_ids": list(range(1, 10)),
                "after_row_ids": [9], "mutation_row_ids": list(range(1, 10)),
                "rollback_completed": True, "temporary_table_absent": True}}


def investigate(executor, files=None):
    raw = archive(files or {"src/query.py": HTTP_SQL})
    return run_static_scan(io.BytesIO(raw), synthetic_sql_executor=executor)


def test_planner_runs_once_then_reuses_recipe_for_independently_bound_candidates():
    calls = []
    def execute():
        calls.append(True)
        return passed_summary()
    result = investigate(execute, {"src/a.py": HTTP_SQL, "src/b.py": HTTP_SQL})
    agent = result["security_agent"]
    assert calls == [True]
    assert agent["mode"] == "deterministic_evidence" and agent["status"] == "completed"
    assert agent["budget"]["synthetic_contract_runs"] == 1
    assert agent["budget"]["synthetic_contract_reuses"] == 1
    assert len(sql_findings(result)) == 2
    for index, item in enumerate(agent["observations"]):
        assert item["state"] == "synthetic_recipe_verified"
        assert item["next_action"] == "review_project_runtime_contract"
        assert set(item["missing_evidence"]) == RUNTIME_GAPS
        contract = item["synthetic_contract"]
        assert contract["contract_id"] == CONTRACT_ID and contract["reused"] is bool(index)
        assert contract["source"]["observation_id"] == item["id"]
        assert contract["source"]["source_sha256"] == hashlib.sha256(HTTP_SQL.encode()).hexdigest()
        assert normalize_synthetic_contract(contract, item, agent["source"], agent["catalog"]) == contract
        assert [step["action"] for step in item["steps"]][-3:] == [
            "select_synthetic_contract", "verify_synthetic_recipe", "replan_after_synthetic_contract"]
    assert agent_record(agent) == agent
    assert agent["runtime_verified"] is agent["automatic_patch"] is False
    assert all(finding["verification_status"] == "unverified" for finding in sql_findings(result))


@pytest.mark.parametrize("source", [
    HTTP_SQL.replace("name: str", "name: int"),
    HTTP_SQL.replace("cur.execute(", "cur.executemany("),
    HTTP_SQL.replace('@app.get("/users")\n', ''),
    HTTP_SQL.replace('psycopg.connect("PRIVATE_DSN")', 'unknown_connect()'),
    HTTP_SQL.replace("name = '{name}'", "name = '{name}' OR alias = '{name}'"),
    "x = 1\n",
])
def test_unsupported_or_missing_source_facts_never_start_the_executor(source):
    calls = []
    result = investigate(lambda: calls.append(True), {"src/query.py": source})
    assert calls == []
    assert result["security_agent"]["budget"]["synthetic_contract_runs"] == 0
    assert all("synthetic_contract" not in row for row in result["security_agent"]["observations"])


def test_default_scan_ignores_project_and_ambient_opt_in(monkeypatch, tmp_path):
    monkeypatch.setenv("SHIPIT_SQL_CONTRACT_AGENT_ENABLED", "1")
    monkeypatch.setenv("SQL_CONTRACT_DATABASE_URL", "not-a-target")
    canary = tmp_path / "executed"
    raw = archive({"src/query.py": HTTP_SQL,
                   "sitecustomize.py": f"open({str(canary)!r}, 'w').write('bad')\n",
                   ".env": "SHIPIT_SQL_CONTRACT_AGENT_ENABLED=1\n"})
    result = run_static_scan(io.BytesIO(raw))
    assert result["security_agent"]["mode"] == "deterministic_static"
    assert all("synthetic_contract" not in row for row in result["security_agent"]["observations"])
    assert not canary.exists()


@pytest.mark.parametrize("result", [
    unavailable_summary("execution_timeout"),
    {**unavailable_summary("execution_unavailable"), "status": "failed", "reason": "synthetic_contract_failed"},
    {**passed_summary(), "customer_project_verified": True},
])
def test_failure_unavailable_or_invalid_results_preserve_findings_and_do_not_retry(result):
    calls = []
    def execute():
        calls.append(True)
        return deepcopy(result)
    scan = investigate(execute, {"a.py": HTTP_SQL, "b.py": HTTP_SQL})
    assert calls == [True] and len(sql_findings(scan)) == 2
    agent = scan["security_agent"]
    assert agent["status"] == "partial" and agent["stop_reason"] == "synthetic_verification_incomplete"
    for item in agent["observations"]:
        assert item["state"] == "source_evidence_collected"
        assert item["synthetic_contract"]["status"] != "passed"
        assert set(item["missing_evidence"]) == RUNTIME_GAPS


def test_executor_exception_is_sanitized_without_discarding_source_facts():
    def fail():
        raise ValueError("SECRET DSN")
    result = investigate(fail)
    assert len(sql_findings(result)) == 1
    assert "SECRET DSN" not in json.dumps(result)
    assert result["security_agent"]["observations"][0]["acquisition"]["status"] == "completed"


@pytest.mark.parametrize("mutate", [
    lambda record: record.update(scope="customer_project"),
    lambda record: record.update(runtime_verified=True),
    lambda record: record.update(automatic_patch=True),
    lambda record: record.update(evidence_sha256="fake"),
    lambda record: record["proof"].update(executions=0),
    lambda record: record["proof"].update(after_row_ids=[1, 9]),
    lambda record: record["proof"].update(mutation_row_ids=[9]),
    lambda record: record["proof"].update(rollback_completed=False),
    lambda record: record["source"].update(observation_id="a" * 64),
    lambda record: record["source"].update(archive_sha256="a" * 64),
    lambda record: record["source"].update(catalog_sha256="a" * 64),
])
def test_saved_invalid_synthetic_records_are_removed_before_json_sarif_export(mutate):
    agent = investigate(passed_summary)["security_agent"]
    mutate(agent["observations"][0]["synthetic_contract"])
    normalized = agent_record(agent)
    item = normalized["observations"][0]
    assert "synthetic_contract" not in item and item["state"] == "source_evidence_collected"
    assert normalized["status"] == "partial" and normalized["stop_reason"] == "synthetic_evidence_invalid"


def test_summary_validation_rejects_bool_counts_unicode_versions_and_unknown_fields():
    for key, value in [("executions", True), ("postgresql_version", 1), ("psycopg_version", "3.٣.5"),
                       ("before_row_ids", [True, *range(2, 10)])]:
        summary = passed_summary()
        summary["proof"][key] = value
        assert normalize_synthetic_summary(summary) is None
    summary = passed_summary()
    summary["arbitrary_sql"] = "DROP TABLE anything"
    assert normalize_synthetic_summary(summary) is None
    assert set(passed_summary()) == SUMMARY_KEYS


def test_no_llm_pipeline_retains_synthetic_evidence_in_scan_manifest():
    result = run_scan(archive({"src/query.py": HTTP_SQL}), LLMClient(providers=[]), depth=BASIS_PREVIEW,
                      synthetic_sql_executor=passed_summary)
    manifest = result["score"]["scan_manifest"]
    assert manifest["model_calls"] == 0
    assert manifest["security_agent"]["observations"][0]["state"] == "synthetic_recipe_verified"
    assert len(sql_findings(result)) == 1


def test_native_command_does_not_certify_an_empty_selection(tmp_path, monkeypatch, capsys):
    from scripts import investigate_sql_runtime as command

    path = tmp_path / "input.zip"
    path.write_bytes(archive({"main.py": "print('never executed')\n"}))
    monkeypatch.setattr(command, "SyntheticSqlExecutor", lambda: lambda: pytest.fail("no eligible candidate"))
    assert command.main([str(path)]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["score"]["scan_manifest"]["model_calls"] == 0


def test_native_command_preserves_existing_output_before_any_execution(tmp_path, monkeypatch):
    from scripts import investigate_sql_runtime as command

    output = tmp_path / "report.json"
    output.write_text("earlier evidence")
    monkeypatch.setattr(command, "SyntheticSqlExecutor", lambda: pytest.fail("must not construct executor"))
    with pytest.raises(FileExistsError):
        command.main([str(tmp_path / "input.zip"), "--output", str(output)])
    assert output.read_text() == "earlier evidence"


@pytest.mark.skipif(not os.environ.get("SQL_CONTRACT_DATABASE_URL"), reason="Dedicated PostgreSQL target is required")
def test_agent_selects_and_runs_real_postgres_contract(tmp_path):
    from app.proof.sql_runtime_executor import SyntheticSqlExecutor

    canary = tmp_path / "project-executed"
    result = investigate(SyntheticSqlExecutor(), {"src/query.py": HTTP_SQL,
        "sitecustomize.py": f"open({str(canary)!r}, 'w').write('executed')\n"})
    item = result["security_agent"]["observations"][0]
    assert item["state"] == "synthetic_recipe_verified"
    assert item["synthetic_contract"]["proof"]["after_row_ids"] == [9]
    assert item["synthetic_contract"]["proof"]["mutation_row_ids"] == list(range(1, 10))
    assert set(item["missing_evidence"]) == RUNTIME_GAPS
    assert not canary.exists()

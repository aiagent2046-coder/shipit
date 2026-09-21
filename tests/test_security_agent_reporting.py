"""Saved HTML exposes bounded review decisions without inventing provenance."""
from copy import deepcopy
from html import escape
import json
from pathlib import Path
import socket

import pytest

from app.llm.client import LLMClient
from app.report.evidence import claim_evidence_rows, manifest_rows, security_agent_rows
from app.report.html import render_report
from app.scan import security_agent
from app.scan.pipeline import BASIS_PREVIEW, run_scan
from tests.test_security_agent import SQL, archive, sql_findings

CASES = json.loads((Path(__file__).parent / "fixtures/security-agent-reports.json").read_text())


def scan(files):
    return run_scan(archive(files), LLMClient(providers=[]), depth=BASIS_PREVIEW)


@pytest.fixture(scope="module")
def completed():
    return scan({"src/query.py": SQL})


def test_offline_report_exposes_review_and_static_provenance_in_main_and_baseline(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("The HTML report must remain offline")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    result = scan({"src/query.py": SQL})
    before = deepcopy(result)
    manifest = result["score"]["scan_manifest"]
    agent = manifest["security_agent"]
    rows = dict(manifest_rows(result["score"]))
    observation = agent["observations"][0]
    assert manifest["model_calls"] == 0
    assert rows["Pattern review"] == (
        "completed; 1 observations; bounded_review_completed. "
        "Completion describes bounded review, not project safety."
    )
    assert rows["Pattern catalog"] == f"{agent['catalog']['version']}; SHA-256: {agent['catalog']['sha256']}"
    assert rows["Pattern catalog cards"] == "3"
    assert agent["source"]["archive_sha256"] in rows["Pattern review source"]
    assert rows["Candidate review budget"] == "1 processed of 1 candidates; 0 omitted; limit: 128."
    assert "1 of 1 eligible files analyzed" in rows["Pattern check: SQL text assembled from Python values"]
    assert "python-sql-string-assembly, revision 3" in rows["Pattern observation 1"]
    assert "src/query.py:3" in rows["Pattern observation 1"]
    assert rows["Candidate weakness classes"] == "CWE-89 — candidate classes, not verified vulnerabilities."
    assert "Possible local flow" in rows["SQL source trace"]
    assert rows["SQL source SHA-256"] == observation["evidence"]["sql_observation"]["source_sha256"]
    for missing in observation["missing_evidence"]:
        assert missing.replace("_", " ") in rows["Missing evidence"]
    assert "Manual review: gather the missing evidence" in rows["Next step"]
    assert observation["recipe"]["id"] in rows["Repair guidance"]
    assert "manual guidance only" in rows["Repair guidance"]
    assert "No automatic patch was applied" in rows["Repair guidance"]
    assert "missing preconditions" in rows["Review steps"]

    finding_rows = dict(claim_evidence_rows(sql_findings(result)[0]))
    assert "Static observation — unverified" in finding_rows
    assert "Model interpretation — unverified" not in finding_rows
    html = render_report(result)
    for label in ("Candidate weakness classes", "Missing evidence", "Next step", "Repair guidance"):
        assert f'<dt>{label}</dt><dd translate="no">{escape(rows[label])}</dd>' in html
    assert "Model interpretation — unverified" not in html
    assert result == before

    baseline = deepcopy(result)
    baseline["score"]["free_baseline"] = {
        "version": 1, "origin": "included", "status": "completed",
        "score": result["score"], "findings": result["findings"],
    }
    html = render_report(baseline)
    assert html.count("<dt>Candidate weakness classes</dt>") == 2
    assert html.count("<dt>Missing evidence</dt>") == 2
    assert html.count("<dt>Repair guidance</dt>") == 2
    assert "Model interpretation — unverified" not in html


def test_partial_coverage_and_budget_keep_gaps_visible(monkeypatch):
    monkeypatch.setattr(security_agent, "MAX_CANDIDATES", 1)
    result = scan({"src/first.py": SQL, "src/last.py": SQL, "src/broken.py": "def broken(:"})
    rows = dict(manifest_rows(result["score"]))
    assert rows["Pattern review"].startswith("partial; 1 observations; candidate_budget_exhausted.")
    assert rows["Candidate review budget"] == "1 processed of 2 candidates; 1 omitted; limit: 1."
    check = rows["Pattern check: SQL text assembled from Python values"]
    assert "Partial check; coverage is incomplete" in check
    assert "2 of 3 eligible files analyzed" in check
    assert "syntax errors: 1" in check
    assert "CWE-89" in render_report(result)


def test_unavailable_review_preserves_the_static_observation_without_exception_text(monkeypatch):
    def failed():
        raise ValueError("private exception detail <script>must not be rendered</script>")

    monkeypatch.setattr(security_agent, "catalog_manifest", failed)
    result = scan({"src/query.py": SQL})
    rows = dict(manifest_rows(result["score"]))
    assert rows["Pattern review"].startswith("unavailable; 0 observations; agent_error: ValueError.")
    assert rows["Pattern catalog"] == "Unavailable; SHA-256: Unavailable"
    assert "does not establish safety" in rows["Pattern observations"]
    html = render_report(result)
    assert "Pattern review incomplete" in html
    assert "SQL source trace" in html
    assert "private exception detail" not in html


def test_non_sql_candidate_has_its_class_and_manual_review_without_a_recipe():
    result = scan({"src/load.py": "import pickle\nvalue = pickle.loads(payload)\n"})
    rows = dict(manifest_rows(result["score"]))
    assert rows["Candidate weakness classes"].startswith("CWE-502")
    assert "input trust boundary" in rows["Missing evidence"]
    assert "loader runtime contract" in rows["Missing evidence"]
    assert rows["Deserialization source trace"].startswith("Import-resolved pickle.loads()")
    assert rows["Review state"].startswith("Needs evidence;")
    assert "request input source" in rows["Missing evidence"]
    assert "local input flow" in rows["Missing evidence"]
    assert "Source fact: request input source" not in rows
    assert rows["Repair guidance"].startswith("No repair recipe available. Manual review is required")


@pytest.mark.parametrize("value", [None, {}, [], {"version": 2}])
def test_legacy_and_unsupported_records_are_absent_without_breaking_html(value):
    assert security_agent_rows(value) == []
    html = render_report({"score": {"scan_manifest": {"security_agent": value}}, "findings": []})
    assert "<dt>Pattern review</dt>" not in html
    assert "<dt>Candidate weakness classes</dt>" not in html


@pytest.mark.parametrize("field,value", [
    ("version", 2), ("version", True), ("runtime_verified", True), ("automatic_patch", True),
    ("status", []), ("plan", {}), ("observations", {}), ("budget", []),
])
def test_upgraded_or_malformed_records_do_not_render_a_review(completed, field, value):
    invalid = deepcopy(completed["score"]["scan_manifest"]["security_agent"])
    invalid[field] = value
    assert security_agent_rows(invalid) == []
    html = render_report({"score": {"scan_manifest": {"security_agent": invalid}}, "findings": []})
    assert "<dt>Pattern review</dt>" not in html


@pytest.mark.parametrize("mutate", [
    lambda row: row.update(state="verified"),
    lambda row: row.update(next_action="automatic_patch"),
    lambda row: row.update(line=True),
    lambda row: row.update(file=[]),
    lambda row: row.update(recipe=[]),
    lambda row: row["recipe"].update(automatic_apply=True),
    lambda row: row["recipe"].update(status="verified"),
])
@pytest.mark.parametrize("legacy", [False, True])
def test_malformed_nested_decisions_keep_summary_and_explicit_display_gap(completed, mutate, legacy):
    invalid = deepcopy(completed["score"]["scan_manifest"]["security_agent"])
    if legacy:
        invalid["observations"][0].pop("agent_chain", None)
    mutate(invalid["observations"][0])
    rows = dict(security_agent_rows(invalid))
    status = "completed" if legacy else "partial"
    assert rows["Pattern review"].startswith(f"{status}; 1 observations;")
    if not legacy:
        assert "agent_chain_invalid" in rows["Pattern review"]
    assert "Candidate weakness classes" not in rows
    assert "Repair guidance" not in rows
    assert rows["Observation display incomplete"] == (
        "1 records could not be displayed within the supported schema and limit."
    )


def test_saved_exception_message_is_not_echoed(completed):
    invalid = deepcopy(completed["score"]["scan_manifest"]["security_agent"])
    invalid["stop_reason"] = "agent_error: ValueError: private credentials"
    rows = dict(security_agent_rows(invalid))
    assert "Stop reason not recorded" in rows["Pattern review"]
    assert "private credentials" not in str(rows)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_shared_saved_records_keep_complete_review_in_html(case):
    score = case["score"]
    agent = score["scan_manifest"]["security_agent"]
    html = render_report({"score": score, "findings": [case["finding"]]})
    assert f"{agent['status']}; {len(agent['observations'])} observations" in html
    for observation in agent["observations"]:
        assert escape(observation["pattern_id"]) in html
        assert escape(f"{observation['file']}:{observation['line']}") in html
        for weakness in observation["weaknesses"]:
            assert weakness in html
        for missing in observation["missing_evidence"]:
            assert missing.replace("_", " ") in html
        assert observation["recipe"]["id"] in html
        assert "Manual review: gather the missing evidence" in html
    assert "Static observation — unverified" in html
    assert "Model interpretation — unverified" not in html


def test_archive_markup_is_escaped_in_observation_rows():
    filename = 'src/<img src=x onerror="alert(1)">.py'
    result = scan({filename: SQL})
    html = render_report(result)
    assert "<dt>Pattern observation 1</dt>" in html
    assert escape(filename) in html
    assert "<img src=x" not in html


@pytest.mark.parametrize("source,rule_id,label", [
    ("static", "sql-injection-string-built-query", "Static observation — unverified"),
    ("llm", "llm-security", "Model interpretation — unverified"),
    (None, "llm-security", "Model interpretation — unverified"),
    ("dependency", "dependency-cve-match", "Source observation — unverified"),
    (None, "old-rule", "Legacy observation — provenance not recorded"),
    ("unknown", "old-rule", "Legacy observation — provenance not recorded"),
])
def test_interpretation_label_uses_recorded_finding_provenance(source, rule_id, label):
    finding = {"source": source, "rule_id": rule_id,
               "claim_evidence": {"version": 1, "observation": "Recorded observation."}}
    rows = dict(claim_evidence_rows(finding))
    assert rows[label] == "Recorded observation."
    assert len([value for value in rows.values() if value == "Recorded observation."]) == 1
    assert rows["Consequence check"] == "No independent verification recorded."


@pytest.fixture(scope="module")
def synthetic_report():
    from tests.test_evidence_acquisition import HTTP_SQL

    result = scan({"src/query.py": HTTP_SQL})
    agent = result["score"]["scan_manifest"]["security_agent"]
    agent["mode"] = "deterministic_evidence"
    observation, = agent["observations"]
    observation.update(state="synthetic_recipe_verified", next_action="review_project_runtime_contract")
    observation["synthetic_contract"] = {
        "version": 1, "scope": "synthetic_recipe", "contract_id": "sql-value-parameterization-python-psycopg3",
        "contract_revision": 1, "status": "passed", "reason": "synthetic_contract_passed",
        "evidence_sha256": "d" * 64, "synthetic_recipe_verified": True, "runtime_verified": False,
        "customer_project_verified": False, "automatic_patch": False, "reused": False,
        "source": {"archive_sha256": agent["source"]["archive_sha256"],
                   "source_sha256": observation["evidence"]["sql_observation"]["source_sha256"],
                   "observation_id": observation["id"], "engine_version": agent["source"]["engine_version"],
                   "catalog_sha256": agent["catalog"]["sha256"]},
        "proof": {
            "fixture_sha256": "8c856f7ededaa7fc4bf8c8cbb56819a30eb3f9553209e222e13ad7e4926b9517",
            "schema_sha256": "9ca4174618e52ccbafebba9d1b5b6151f6ecdd1d5c67ba9f3b7f4706e2ff91a2",
            "psycopg_version": "3.3.5", "postgresql_version": 170011, "executions": 27, "cases_per_stage": 9,
            "before_row_ids": list(range(1, 10)), "after_row_ids": [9], "mutation_row_ids": list(range(1, 10)),
            "rollback_completed": True, "temporary_table_absent": True,
        },
    }
    return result


def test_saved_synthetic_evidence_keeps_project_gaps_in_html_and_sarif(synthetic_report):
    from app.report.sarif import build_sarif

    before = deepcopy(synthetic_report)
    agent = synthetic_report["score"]["scan_manifest"]["security_agent"]
    rows = dict(security_agent_rows(agent))
    assert "Saved synthetic evidence: passed" in rows["Synthetic recipe contract"]
    assert "9 / 1 / 9" in rows["Before / after / mutation"]
    assert "rollback" in rows["Fixture cleanup"]
    assert "customer project runtime behavior" in rows["Review state"]
    assert "Customer project runtime tests not run" in rows["Customer project verification"]
    assert "No automatic patch applied" in rows["Customer project verification"]
    assert "customer project runtime contract" in rows["Next step"]
    assert "runtime behavior contract" in rows["Missing evidence"]
    html = render_report(synthetic_report)
    assert "Saved synthetic evidence: passed" in html
    assert "Customer project runtime tests not run" in html
    sarif = build_sarif(synthetic_report["findings"], score=synthetic_report["score"],
                        engine_version=agent["source"]["engine_version"])
    saved = sarif["runs"][0]["invocations"][0]["properties"]["securityAgent"]
    assert saved["observations"][0]["synthetic_contract"]["scope"] == "synthetic_recipe"
    assert saved["runtime_verified"] is saved["automatic_patch"] is False
    assert synthetic_report == before


@pytest.mark.parametrize("field,value", [
    ("scope", "customer_project"), ("runtime_verified", True), ("customer_project_verified", True),
    ("automatic_patch", True), ("evidence_sha256", "d" * 64 + "\n"),
    ("proof.fixture_sha256", "b" * 64), ("proof.schema_sha256", "b" * 64),
    ("proof.before_row_ids", []), ("proof.after_row_ids", [1]), ("proof.mutation_row_ids", [9]),
    ("proof.executions", 26), ("proof.rollback_completed", False), ("proof.temporary_table_absent", False),
    ("source.archive_sha256", "b" * 64), ("source.source_sha256", "b" * 64),
    ("source.observation_id", "b" * 64), ("source.catalog_sha256", "b" * 64),
    ("source.engine_version", "another-engine"), ("reason", "private error text"),
])
def test_inconsistent_synthetic_evidence_cannot_promote_saved_html_or_sarif(synthetic_report, field, value):
    from app.report.sarif import build_sarif

    result = deepcopy(synthetic_report)
    agent = result["score"]["scan_manifest"]["security_agent"]
    target = agent["observations"][0]["synthetic_contract"]
    path = field.split(".")
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    html = render_report(result)
    assert "Saved synthetic evidence: passed" not in html
    assert "Review the customer project runtime contract" not in html
    sarif = build_sarif(result["findings"], score=result["score"], engine_version=agent["source"]["engine_version"])
    exported = sarif["runs"][0]["invocations"][0]["properties"]["securityAgent"]
    assert exported["status"] == "partial"
    assert exported["stop_reason"] == "synthetic_evidence_invalid"
    assert "synthetic_contract" not in exported["observations"][0]
    assert exported["observations"][0]["state"] == "source_evidence_collected"
    assert exported["runtime_verified"] is exported["automatic_patch"] is False


@pytest.mark.parametrize("status,reason", [
    ("failed", "synthetic_contract_failed"), ("unavailable", "execution_timeout"),
])
def test_unsuccessful_synthetic_attempt_does_not_hide_source_evidence(synthetic_report, status, reason):
    agent = deepcopy(synthetic_report["score"]["scan_manifest"]["security_agent"])
    observation = agent["observations"][0]
    observation.update(state="source_evidence_collected", next_action="review_runtime_contract")
    observation["synthetic_contract"].update(status=status, reason=reason, synthetic_recipe_verified=False, proof=None)
    rows = dict(security_agent_rows(agent))
    assert f"Saved synthetic evidence: {status}" in rows["Synthetic recipe contract"]
    assert "Before / after / mutation" not in rows
    assert "Supported source evidence collected" in rows["Review state"]
    assert "Customer project runtime tests not run" in rows["Customer project verification"]

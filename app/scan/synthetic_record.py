"""Bounded saved synthetic evidence; no native imports or execution authority.

These checks establish record consistency, not authenticity of uploaded JSON.
Only a fresh result from an explicitly supplied trusted executor is consumed by
the planner. Customer-project proof and automatic repair always remain false.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import re

from app.scan.evidence_record import normalize_acquisition

CONTRACT_ID = "sql-value-parameterization-python-psycopg3"
FIXTURE_SHA256 = "8c856f7ededaa7fc4bf8c8cbb56819a30eb3f9553209e222e13ad7e4926b9517"
SCHEMA_SHA256 = "9ca4174618e52ccbafebba9d1b5b6151f6ecdd1d5c67ba9f3b7f4706e2ff91a2"
PROJECT_GAPS = frozenset({"caller_authorization", "route_reachability", "intended_value_type",
                          "runtime_behavior_contract"})
UNAVAILABLE_REASONS = frozenset({"database_not_configured", "invalid_database_target", "ambient_libpq_options",
    "execution_unavailable", "execution_timeout", "output_limit", "invalid_contract_result",
    "unsupported_runtime", "budget_exhausted"})
SUMMARY_KEYS = frozenset({"version", "scope", "contract_id", "contract_revision", "status", "reason",
    "evidence_sha256", "synthetic_recipe_verified", "runtime_verified", "customer_project_verified",
    "automatic_patch", "proof"})


def _sha(value):
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None


def unavailable_summary(reason):
    reason = reason if reason in UNAVAILABLE_REASONS else "execution_unavailable"
    evidence = {"status": "unavailable", "reason": reason}
    return {"version": 1, "scope": "synthetic_recipe", "contract_id": CONTRACT_ID, "contract_revision": 1,
            **evidence, "evidence_sha256": hashlib.sha256(json.dumps(evidence, sort_keys=True,
                separators=(",", ":")).encode()).hexdigest(), "synthetic_recipe_verified": False,
            "runtime_verified": False, "customer_project_verified": False, "automatic_patch": False,
            "proof": None}


def normalize_synthetic_summary(value):
    if (not isinstance(value, dict) or set(value) != SUMMARY_KEYS
            or type(value["version"]) is not int or value["version"] != 1
            or type(value["contract_revision"]) is not int or value["contract_revision"] != 1
            or value["scope"] != "synthetic_recipe" or value["contract_id"] != CONTRACT_ID
            or not isinstance(value["status"], str) or value["status"] not in {"passed", "failed", "unavailable"}
            or any(value[key] is not False for key in (
                "runtime_verified", "customer_project_verified", "automatic_patch"))
            or value["synthetic_recipe_verified"] is not (value["status"] == "passed")
            or not _sha(value["evidence_sha256"]) or not isinstance(value["reason"], str)):
        return None
    status, reason, proof = value["status"], value["reason"], value["proof"]
    if status != "passed":
        if proof is not None or (reason not in UNAVAILABLE_REASONS if status == "unavailable"
                                else reason != "synthetic_contract_failed"):
            return None
        return deepcopy(value)
    if (reason != "synthetic_contract_passed" or not isinstance(proof, dict) or set(proof) != {
            "fixture_sha256", "schema_sha256", "psycopg_version", "postgresql_version", "executions",
            "cases_per_stage", "before_row_ids", "after_row_ids", "mutation_row_ids",
            "rollback_completed", "temporary_table_absent"}
            or proof["fixture_sha256"] != FIXTURE_SHA256 or proof["schema_sha256"] != SCHEMA_SHA256
            or not isinstance(proof["psycopg_version"], str) or len(proof["psycopg_version"]) > 64
            or re.fullmatch(r"3\.[0-9]+\.[0-9]+", proof["psycopg_version"]) is None
            or type(proof["postgresql_version"]) is not int or not 100000 <= proof["postgresql_version"] <= 2**31 - 1
            or type(proof["executions"]) is not int or proof["executions"] != 27
            or type(proof["cases_per_stage"]) is not int or proof["cases_per_stage"] != 9
            or proof["rollback_completed"] is not True or proof["temporary_table_absent"] is not True):
        return None
    for key, expected in (("before_row_ids", list(range(1, 10))), ("after_row_ids", [9]),
                          ("mutation_row_ids", list(range(1, 10)))):
        if (not isinstance(proof[key], list) or proof[key] != expected
                or any(type(item) is not int for item in proof[key])):
            return None
    return deepcopy(value)


def supports_synthetic_contract(observation):
    """Only an acquired Psycopg execute with one text value can select v1."""
    if not isinstance(observation, dict):
        return False
    recipe = observation.get("recipe")
    evidence = observation.get("evidence")
    if (observation.get("pattern_id") != "python-sql-string-assembly"
            or observation.get("rule_id") != "sql-injection-string-built-query"
            or type(observation.get("pattern_revision")) is not int
            or not 1 <= observation["pattern_revision"] <= 2**31 - 1
            or type(observation.get("line")) is not int or not 1 <= observation["line"] <= 2**31 - 1
            or not isinstance(observation.get("file"), str) or not observation["file"].lower().endswith(".py")
            or not isinstance(recipe, dict) or recipe.get("id") != CONTRACT_ID
            or recipe.get("status") != "manual_guidance" or recipe.get("automatic_apply") is not False
            or not isinstance(evidence, dict)):
        return False
    trace = evidence.get("sql_observation")
    if (not isinstance(trace, dict) or trace.get("driver_status") != "source_resolved"
            or trace.get("sink_method") != "execute" or trace.get("file") != observation.get("file")
            or trace.get("sink_line") != observation.get("line")):
        return False
    acquisition = normalize_acquisition(observation.get("acquisition"), trace)
    if acquisition is None or acquisition["status"] != "completed":
        return False
    facts = {fact["id"]: fact for fact in acquisition["facts"]}
    constraints = facts["value_constraints"]["constraints"]
    missing = observation.get("missing_evidence")
    return (len(facts["sql_value_position"]["slots"]) == 1 and bool(constraints)
            and all(item["slot"] == 0 and item["type"] == "str" for item in constraints)
            and isinstance(missing, list) and all(isinstance(item, str) for item in missing)
            and PROJECT_GAPS <= set(missing))


def normalize_synthetic_contract(value, observation, agent_source, catalog):
    if (not isinstance(value, dict) or set(value) != SUMMARY_KEYS | {"source", "reused"}
            or type(value["reused"]) is not bool or not supports_synthetic_contract(observation)
            or not isinstance(agent_source, dict) or not isinstance(catalog, dict)):
        return None
    summary = normalize_synthetic_summary({key: value[key] for key in SUMMARY_KEYS})
    if summary is None:
        return None
    trace = observation["evidence"]["sql_observation"]
    expected = {"archive_sha256": agent_source.get("archive_sha256"), "source_sha256": trace.get("source_sha256"),
                "observation_id": observation.get("id"), "engine_version": agent_source.get("engine_version"),
                "catalog_sha256": catalog.get("sha256")}
    if (value["source"] != expected or not isinstance(value["source"], dict)
            or any(not _sha(expected[key]) for key in (
                "archive_sha256", "source_sha256", "observation_id", "catalog_sha256"))
            or not isinstance(expected["engine_version"], str) or not 1 <= len(expected["engine_version"]) <= 128):
        return None
    state = (observation.get("state"), observation.get("next_action"))
    required_state = (("synthetic_recipe_verified", "review_project_runtime_contract") if summary["status"] == "passed"
                      else ("source_evidence_collected", "review_runtime_contract"))
    return deepcopy(value) if state == required_state else None


def synthetic_contract_rows(record):
    if not record:
        return []
    rows = [("Synthetic recipe contract", f"Saved synthetic evidence: {record['status']}; "
             f"{record['reason'].replace('_', ' ')}. Scope: synthetic recipe."),
            ("Synthetic evidence SHA-256", record["evidence_sha256"])]
    if proof := record["proof"]:
        rows.extend([
            ("Before / after / mutation", "9 / 1 / 9 rows in the attack control; 27 executions across 9 cases."),
            ("Fixture cleanup", "Transaction rollback and temporary table removal confirmed."),
            ("Synthetic runtime", f"PostgreSQL {proof['postgresql_version']}; Psycopg {proof['psycopg_version']}."),
        ])
    rows.extend([
        ("Synthetic execution", "Reused within this investigation." if record["reused"]
         else "One bounded attempt; no automatic retry."),
        ("Customer project verification", "Customer project runtime tests not run. No automatic patch applied."),
    ])
    return rows

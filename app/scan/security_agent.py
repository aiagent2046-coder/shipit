"""Bounded review and adaptive collection of source evidence for pattern cards.

The coordinator selects actions from missing facts and validates each result
before planning again. It never runs project code, calls a model or patches it.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import hashlib
import json
import re

from app.scan.agent_chain import normalize_chain, run_chain
from app.scan.evidence_record import normalize_acquisition, normalize_deserialization_observation
from app.scan.pattern_catalog import catalog_manifest
from app.scan.rule_coverage import normalize_rule_coverage
from app.scan.evidence_acquisition import EvidenceBudget, acquire_sql_evidence, acquire_deserialization_evidence
from app.scan.source_snapshot import SourceSnapshot
from app.scan.synthetic_record import (normalize_synthetic_contract, normalize_synthetic_summary,
                                      supports_synthetic_contract, unavailable_summary)

MAX_CANDIDATES = 128
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_ASSEMBLIES = frozenset({"concatenation", "percent_format", "f_string", "format_call", "join_call"})
_SINKS = frozenset({"execute", "executemany", "executescript", "raw", "execute_sql"})


def sql_observation(finding: dict) -> dict | None:
    """Accept only scanner-owned structural facts, never prose or model claims."""
    evidence = finding.get("claim_evidence")
    if (finding.get("source") != "static"
            or finding.get("rule_id") != "sql-injection-string-built-query"
            or not isinstance(evidence, dict) or type(evidence.get("version")) is not int
            or evidence["version"] != 1):
        return None
    value = evidence.get("sql_observation")
    if not isinstance(value, dict):
        return None
    if (type(value.get("version")) is not int or value["version"] not in (1, 2)
            or value.get("method") != "python_ast_local_flow"
            or value.get("file") != finding.get("file")
            or not isinstance(value.get("source_sha256"), str)
            or not _SHA256.fullmatch(value["source_sha256"])
            or not isinstance(value.get("assembly_kind"), str) or value["assembly_kind"] not in _ASSEMBLIES
            or not isinstance(value.get("sink_method"), str) or value["sink_method"] not in _SINKS
            or value.get("flow_status") != "possible_local_flow"
            or value.get("input_control_status") != "not_checked"):
        return None
    if (any(type(value.get(key)) is not int or not 1 <= value[key] <= 2**31 - 1
            for key in ("assembly_line", "sink_line"))
            or value["sink_line"] != finding.get("line")):
        return None
    status = value.get("driver_status")
    if value["version"] == 1:
        if status != "not_checked":
            return None
    elif status not in ("unknown", "source_resolved"):
        return None
    result = {key: value[key] for key in (
        "version", "method", "file", "source_sha256", "assembly_line", "assembly_kind",
        "sink_line", "sink_method", "flow_status", "driver_status", "input_control_status",
    )}
    if value["version"] == 2 and status == "source_resolved":
        proof = value.get("driver_provenance")
        if (not isinstance(proof, dict) or type(proof.get("version")) is not int or proof["version"] != 1
                or proof.get("driver") != "psycopg3" or proof.get("method") != "python_ast_straight_line"
                or value["sink_method"] not in {"execute", "executemany"}
                or any(type(proof.get(key)) is not int or not 1 <= proof[key] <= value["sink_line"]
                       for key in ("import_line", "connection_line", "cursor_line"))
                or not proof["import_line"] <= proof["connection_line"] <= proof["cursor_line"]):
            return None
        result["driver_provenance"] = {key: proof[key] for key in (
            "version", "driver", "method", "import_line", "connection_line", "cursor_line")}
    elif "driver_provenance" in value:
        return None
    return result


def sql_driver_rows(trace: dict) -> list[tuple[str, str]]:
    proof = trace.get("driver_provenance")
    if proof:
        return [("SQL driver source", f"Psycopg 3: import line {proof['import_line']} → "
                 f"connect() line {proof['connection_line']} → cursor() line {proof['cursor_line']}. "
                 "Static source provenance only; installed driver and runtime behavior are unverified.")]
    return [("SQL driver source", "Unknown; cursor provenance was not established."
             if trace["version"] == 2 else "Not checked in this historical report.")]


def deserialization_observation(finding: dict) -> dict | None:
    evidence = finding.get("claim_evidence")
    if (finding.get("source") != "static" or finding.get("rule_id") != "unsafe-deserialization"
            or not isinstance(evidence, dict) or type(evidence.get("version")) is not int
            or evidence["version"] != 1):
        return None
    trace = normalize_deserialization_observation(evidence.get("deserialization_observation"))
    if trace is None or trace["file"] != finding.get("file") or trace["sink_line"] != finding.get("line"):
        return None
    return trace


def _base(archive_sha256: str, engine_version: str) -> dict:
    return {
        "version": 1, "mode": "deterministic_static",
        "source": {"archive_sha256": archive_sha256, "engine_version": engine_version},
        "catalog": None, "status": "unavailable", "plan": [], "observations": [],
        "budget": {"max_candidates": MAX_CANDIDATES, "candidates_found": 0,
                   "processed": 0, "candidates_omitted": 0},
        "stop_reason": "agent_unavailable", "runtime_verified": False, "automatic_patch": False,
        "limitations": ["catalog_covers_selected_patterns", "static_observations_only",
                        "attacker_control_not_checked", "runtime_driver_identity_not_checked",
                        "runtime_tests_not_run", "automatic_patch_not_run"],
    }


def _review_candidate(card: dict, finding: dict, archive_sha256: str, ordinal: int) -> dict:
    trace = sql_observation(finding) if card["detection"]["check"] == "sql_injection" else None
    deserialization = (deserialization_observation(finding)
                       if card["detection"]["check"] == "unsafe_deserialization" else None)
    established = {"static_rule_observation", "source_pattern"}
    if trace is not None:
        established.add("sql_source_observation")
        if trace.get("driver_status") == "source_resolved":
            established.add("psycopg3_cursor_provenance")
    required = list(dict.fromkeys([
        *card["applicability"]["required_evidence"], *card["recipe"]["preconditions"],
    ]))
    missing = [item for item in required if item not in established]
    identity = [archive_sha256, card["id"], card["revision"], finding["rule_id"],
                finding["file"], finding["line"], ordinal]
    recipe = card["recipe"]
    return {
        "id": hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode()).hexdigest(),
        "pattern_id": card["id"], "pattern_revision": card["revision"], "title": card["title"],
        "weaknesses": [weakness["id"] for weakness in card["weaknesses"]],
        "rule_id": finding["rule_id"], "file": finding["file"], "line": finding["line"],
        "state": "needs_evidence",
        "evidence": ({"sql_observation": trace} if trace else
                     {"deserialization_observation": deserialization} if deserialization else {}),
        "missing_evidence": missing,
        "next_action": "manual_review",
        "recipe": {"id": recipe.get("id"), "status": recipe["status"], "automatic_apply": False},
        "steps": [
            {"action": "classify_observation", "result": "candidate_weakness_class"},
            {"action": "check_source_evidence", "result": (
                "sql_source_observation" if trace else "deserialization_source_observation"
                if deserialization else "static_rule_observation")},
            {"action": "assess_recipe", "result": (
                "missing_preconditions" if missing else "manual_guidance_only")},
        ],
    }


def _research_candidate(observation, snapshot, budget):
    deserialization = observation["evidence"].get("deserialization_observation")
    trace = deserialization or observation["evidence"]["sql_observation"]
    acquire = acquire_deserialization_evidence if deserialization else acquire_sql_evidence
    acquisition = acquire(trace, snapshot, budget)
    acquisition = normalize_acquisition(acquisition, trace)
    if acquisition is None:
        raise ValueError("Invalid acquired evidence")
    observation["acquisition"] = acquisition
    facts = {fact["id"] for fact in acquisition["facts"]}
    observation["missing_evidence"] = [item for item in observation["missing_evidence"] if item not in facts]
    completed = acquisition["status"] == "completed"
    if completed:
        observation.update(state="source_evidence_collected", next_action="review_runtime_contract")
    return observation, "completed" if completed else "blocked", (
        "source_evidence_collected" if completed else "source_evidence_incomplete")


def _experiment_candidate(observation, executor, session, binding):
    if not supports_synthetic_contract(observation):
        return observation, "blocked", "contract_prerequisites_missing"
    if executor is None:
        return observation, "blocked", "executor_not_supplied"
    observation["steps"].append({"action": "select_synthetic_contract", "result": "single_text_value_psycopg3"})
    cached = session["summary"] is not None
    if cached:
        session["reuses"] += 1
    else:
        session["runs"] += 1
        try:
            session["summary"] = normalize_synthetic_summary(executor())
            if session["summary"] is None:
                session["summary"] = unavailable_summary("invalid_contract_result")
        except Exception:
            session["summary"] = unavailable_summary("execution_unavailable")
    # The experimenter cannot promote a candidate. Only the verifier consumes
    # this pending message; it never escapes into a saved report.
    observation["_pending_contract"] = {**deepcopy(session["summary"]), "reused": cached,
                                        "source": deepcopy(binding)}
    return observation, "completed", "contract_reused" if cached else "contract_obtained"


def _verify_candidate(observation, source, catalog):
    contract = observation.pop("_pending_contract", None)
    if contract is None:
        return observation, "blocked", "synthetic_evidence_missing"
    summary = normalize_synthetic_summary({key: value for key, value in contract.items()
                                            if key not in {"source", "reused"}})
    if summary is None:
        raise ValueError("Invalid experiment message")
    passed = summary["status"] == "passed"
    if passed:
        observation.update(state="synthetic_recipe_verified", next_action="review_project_runtime_contract")
    if normalize_synthetic_contract(contract, observation, source, catalog) is None:
        raise ValueError("Invalid synthetic evidence binding")
    observation["synthetic_contract"] = contract
    observation["steps"].extend([
        {"action": "verify_synthetic_recipe", "result": summary["status"]},
        {"action": "replan_after_synthetic_contract", "result": observation["next_action"]},
    ])
    return observation, "completed" if passed else "blocked", (
        "synthetic_recipe_verified" if passed else "synthetic_verification_incomplete")


def _coordinate_candidate(card, finding, ordinal, result, snapshot, budget, executor, session):
    seed = _review_candidate(card, finding, result["source"]["archive_sha256"], ordinal)
    trace = seed["evidence"].get("sql_observation") or seed["evidence"].get("deserialization_observation")
    if trace is None:
        return seed
    binding = {**result["source"], "source_sha256": trace["source_sha256"],
               "observation_id": seed["id"], "catalog_sha256": result["catalog"]["sha256"]}

    def detect(observation):
        # Revalidate the scanner-owned hand-off, never a model-written claim.
        expected = deserialization_observation(finding) if "deserialization_observation" in seed["evidence"] else (
            sql_observation(finding))
        if expected != trace or observation["evidence"] != seed["evidence"]:
            raise ValueError("Invalid detector hand-off")
        return observation, "completed", ("static_deserialization_observation"
                                          if "deserialization_observation" in seed["evidence"]
                                          else "static_sql_observation")

    return run_chain(seed, binding, {
        "detector": detect,
        "researcher": lambda item: _research_candidate(item, snapshot, budget),
        "experimenter": lambda item: _experiment_candidate(item, executor, session, binding),
        "verifier": lambda item: _verify_candidate(item, result["source"], result["catalog"]),
    })


def review_static_observations(static: dict, *, archive_sha256: str, engine_version: str,
                              source_snapshot=None, synthetic_sql_executor=None) -> dict:
    """Re-plan supported source checks while retaining independent coverage gaps."""
    if not isinstance(archive_sha256, str) or not _SHA256.fullmatch(archive_sha256):
        raise ValueError("Invalid source snapshot identity")
    if source_snapshot is not None and source_snapshot.archive_sha256 != archive_sha256:
        raise ValueError("Source snapshot identity mismatch")
    manifest = catalog_manifest()
    cards = sorted(manifest["cards"], key=lambda card: card["id"])
    result = _base(archive_sha256, engine_version)
    result["catalog"] = {"version": manifest["catalog_version"],
                         "sha256": manifest["catalog_sha256"], "cards": len(cards)}
    coverage = normalize_rule_coverage(static.get("rule_coverage")) or {}
    failed = {row.get("check") for row in static.get("checks_not_run", []) if isinstance(row, dict)}
    ran = set(static.get("checks_run", []))
    candidates = []
    for card in cards:
        check = card["detection"]["check"]
        record = coverage.get(check)
        unavailable = check in failed or check not in ran or record is None
        status = ("unavailable" if unavailable else "partial" if record["partial"]
                  else "not_applicable" if not record["eligible_files"] else "analyzed")
        result["plan"].append({"pattern_id": card["id"], "title": card["title"],
                               "check": check, "status": status, "coverage": record})
        # Every v1 card has Python-only applicability. In particular the JS
        # SQL scanner shares a rule ID and must never select a Psycopg recipe.
        for finding in static.get("findings", []):
            if (not isinstance(finding, dict) or finding.get("source") != "static"
                    or finding.get("rule_id") not in card["detection"]["rule_ids"]
                    or not isinstance(finding.get("file"), str)
                    or not finding["file"].lower().endswith(".py")
                    or type(finding.get("line")) is not int or finding["line"] < 1):
                continue
            candidates.append((card, finding))
    candidates.sort(key=lambda row: (
        row[0]["id"], row[1]["file"], row[1]["line"], row[1]["rule_id"],
        json.dumps(sql_observation(row[1]) or deserialization_observation(row[1]), sort_keys=True),
    ))
    occurrences: Counter = Counter()
    evidence_budget = EvidenceBudget()
    session = {"summary": None, "runs": 0, "reuses": 0}
    for card, finding in candidates[:MAX_CANDIDATES]:
        key = (card["id"], finding["rule_id"], finding["file"], finding["line"])
        ordinal = occurrences[key]
        occurrences[key] += 1
        result["observations"].append(_coordinate_candidate(
            card, finding, ordinal, result, source_snapshot, evidence_budget, synthetic_sql_executor, session))
    omitted = max(0, len(candidates) - MAX_CANDIDATES)
    result["budget"].update(candidates_found=len(candidates), processed=len(result["observations"]),
                            candidates_omitted=omitted, evidence_actions=evidence_budget.actions,
                            max_evidence_actions=evidence_budget.max_actions,
                            evidence_work=evidence_budget.maximum - evidence_budget.remaining,
                            max_evidence_work=evidence_budget.maximum)
    statuses = {row["status"] for row in result["plan"]}
    if statuses == {"unavailable"}:
        result["status"], result["stop_reason"] = "unavailable", "checks_unavailable"
    elif omitted or statuses & {"unavailable", "partial"}:
        result["status"] = "partial"
        result["stop_reason"] = "candidate_budget_exhausted" if omitted else "coverage_incomplete"
    elif any(row.get("acquisition", {}).get("status") == "partial" for row in result["observations"]):
        result["status"], result["stop_reason"] = "partial", "evidence_collection_incomplete"
    else:
        result["status"], result["stop_reason"] = "completed", "bounded_review_completed"
    if any(row.get("agent_chain", {}).get("status") == "error" for row in result["observations"]):
        result.update(status="partial", stop_reason="agent_task_failed")
    if synthetic_sql_executor is not None:
        result["mode"] = "deterministic_evidence"
        result["budget"].update(synthetic_contract_runs=session["runs"], max_synthetic_contract_runs=1,
                                synthetic_contract_reuses=session["reuses"])
        if session["runs"]:
            result["limitations"] = [item for item in result["limitations"] if item != "runtime_tests_not_run"]
            result["limitations"].extend(["synthetic_recipe_scope_only", "customer_project_runtime_not_verified"])
        if (any(row.get("synthetic_contract", {}).get("status") in {"failed", "unavailable"}
                for row in result["observations"]) and result["status"] == "completed"):
            result.update(status="partial", stop_reason="synthetic_verification_incomplete")
    return result


def attach_security_agent(static: dict, *, archive_sha256: str, engine_version: str, source_archive=None,
                          synthetic_sql_executor=None) -> None:
    """An unavailable coordinator never discards successful scanner findings."""
    snapshot = None
    try:
        if source_archive is not None and any(sql_observation(row) or deserialization_observation(row)
                                              for row in static.get("findings", [])):
            snapshot = SourceSnapshot.from_archive(source_archive, archive_sha256=archive_sha256)
        result = review_static_observations(static, archive_sha256=archive_sha256,
                                            engine_version=engine_version, source_snapshot=snapshot,
                                            synthetic_sql_executor=synthetic_sql_executor)
    except Exception as exc:  # Same isolation boundary as the detector stage.
        result = _base(archive_sha256, engine_version)
        result["stop_reason"] = f"agent_error: {type(exc).__name__}"
    finally:
        if snapshot is not None:
            snapshot.close()
    from app.scan.js_sql_review import review_js_sql
    js_review = review_js_sql(static, source_archive, archive_sha256=archive_sha256,
                              engine_version=engine_version)
    if js_review is not None:
        result["js_sql_review"] = js_review
    static["security_agent"] = result
    limitations = [item for item in static.get("limitations", [])
                   if item not in {"security_agent_unavailable", "security_agent_incomplete"}]
    if result["status"] in {"unavailable", "partial"}:
        limitations.append("security_agent_unavailable" if result["status"] == "unavailable"
                           else "security_agent_incomplete")
    static["limitations"] = limitations


def agent_record(value: object) -> dict | None:
    """Copy only versioned scanner records; legacy reports remain readable."""
    if (not isinstance(value, dict) or type(value.get("version")) is not int or value["version"] != 1
            or value.get("mode") not in ("deterministic_static", "deterministic_evidence")
            or not isinstance(value.get("status"), str)
            or value["status"] not in {"completed", "partial", "unavailable"}
            or value.get("automatic_patch") is not False or value.get("runtime_verified") is not False
            or not isinstance(value.get("plan"), list) or not isinstance(value.get("observations"), list)
            or not isinstance(value.get("budget"), dict)):
        return None
    result = deepcopy(value)
    for observation in result["observations"]:
        if (not isinstance(observation, dict)
                or observation.get("pattern_id") != "python-unsafe-deserialization"):
            continue
        evidence = observation.get("evidence")
        if (isinstance(evidence, dict) and "deserialization_observation" not in evidence
                and "acquisition" not in observation and observation.get("state") == "needs_evidence"):
            continue
        if not isinstance(evidence, dict):
            evidence = {}
            observation["evidence"] = evidence
        trace = deserialization_observation({
            "source": "static", "rule_id": observation.get("rule_id"),
            "file": observation.get("file"), "line": observation.get("line"),
            "claim_evidence": {"version": 1, **evidence},
        })
        acquisition = normalize_acquisition(observation.get("acquisition"), trace)
        facts = {fact["id"] for fact in acquisition["facts"]} if acquisition else set()
        required = ["request_input_source", "local_input_flow", "input_trust_boundary", "loader_runtime_contract"]
        missing = [key for key in required if key not in facts]
        state = (("source_evidence_collected", "review_runtime_contract")
                 if acquisition and acquisition["status"] == "completed" else ("needs_evidence", "manual_review"))
        if (acquisition is None or observation.get("missing_evidence") != missing
                or normalize_chain(observation.get("agent_chain"), observation,
                                   result.get("source"), result.get("catalog")) is None
                or (observation.get("state"), observation.get("next_action")) != state):
            # A saved record cannot remove trust/runtime gaps or borrow another
            # call's proof. Retain the detector candidate and restore its gaps.
            observation.pop("acquisition", None)
            observation.pop("agent_chain", None)
            observation.update(state="needs_evidence", next_action="manual_review", missing_evidence=required)
            if trace is None:
                evidence.pop("deserialization_observation", None)
            result.update(status="partial", stop_reason="source_evidence_invalid")
    for observation in result["observations"]:
        if not isinstance(observation, dict):
            continue
        if "synthetic_contract" not in observation and observation.get("state") != "synthetic_recipe_verified":
            continue
        contract = normalize_synthetic_contract(observation.get("synthetic_contract"), observation,
                                                 result.get("source"), result.get("catalog"))
        if contract is not None:
            observation["synthetic_contract"] = contract
            continue
        observation.pop("synthetic_contract", None)
        if observation.get("state") == "synthetic_recipe_verified":
            observation.update(state="source_evidence_collected", next_action="review_runtime_contract")
        if isinstance(observation.get("steps"), list):
            observation["steps"] = [step for step in observation["steps"] if isinstance(step, dict)
                and step.get("action") not in ("select_synthetic_contract", "verify_synthetic_recipe",
                                               "replan_after_synthetic_contract")]
        result.update(status="partial", stop_reason="synthetic_evidence_invalid")
    for observation in result["observations"]:
        if not isinstance(observation, dict) or "agent_chain" not in observation:
            continue
        chain = normalize_chain(observation["agent_chain"], observation, result.get("source"), result.get("catalog"))
        if chain is None:
            observation.pop("agent_chain", None)
            if result.get("stop_reason") != "synthetic_evidence_invalid":
                result.update(status="partial", stop_reason="agent_chain_invalid")
        else:
            observation["agent_chain"] = chain
    if "js_sql_review" in result:
        from app.scan.js_sql_review import normalize_review
        review = normalize_review(result["js_sql_review"], result.get("source"))
        if review is None:
            result.pop("js_sql_review", None)
            result["js_sql_review_rejected"] = True
        else:
            result["js_sql_review"] = review
    from app.scan.client_runtime_chain import normalize_client_runtime_attachment
    normalize_client_runtime_attachment(result)
    return result

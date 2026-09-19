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

from app.scan.pattern_catalog import catalog_manifest
from app.scan.rule_coverage import normalize_rule_coverage
from app.scan.evidence_acquisition import EvidenceBudget, acquire_sql_evidence
from app.scan.source_snapshot import SourceSnapshot

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


def _review_candidate(card: dict, finding: dict, archive_sha256: str, ordinal: int,
                      source_snapshot=None, evidence_budget=None) -> dict:
    trace = sql_observation(finding) if card["detection"]["check"] == "sql_injection" else None
    established = {"static_rule_observation", "source_pattern"}
    if trace is not None:
        established.add("sql_source_observation")
        if trace.get("driver_status") == "source_resolved":
            established.add("psycopg3_cursor_provenance")
    acquisition = None
    if trace is not None:
        acquisition = acquire_sql_evidence(trace, source_snapshot, evidence_budget or EvidenceBudget())
        established.update(fact["id"] for fact in acquisition["facts"])
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
        "state": ("source_evidence_collected" if acquisition and acquisition["status"] == "completed"
                  else "needs_evidence"),
        "evidence": {"sql_observation": trace} if trace else {},
        **({"acquisition": acquisition} if acquisition is not None else {}),
        "missing_evidence": missing,
        "next_action": ("review_runtime_contract" if acquisition and acquisition["status"] == "completed"
                        else "manual_review"),
        "recipe": {"id": recipe.get("id"), "status": recipe["status"], "automatic_apply": False},
        "steps": [
            {"action": "classify_observation", "result": "candidate_weakness_class"},
            {"action": "check_source_evidence", "result": (
                "sql_source_observation" if trace else "static_rule_observation")},
            {"action": "assess_recipe", "result": (
                "missing_preconditions" if missing else "manual_guidance_only")},
        ],
    }


def review_static_observations(static: dict, *, archive_sha256: str, engine_version: str,
                              source_snapshot=None) -> dict:
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
        json.dumps(sql_observation(row[1]), sort_keys=True),
    ))
    occurrences: Counter = Counter()
    evidence_budget = EvidenceBudget()
    for card, finding in candidates[:MAX_CANDIDATES]:
        key = (card["id"], finding["rule_id"], finding["file"], finding["line"])
        ordinal = occurrences[key]
        occurrences[key] += 1
        result["observations"].append(_review_candidate(card, finding, archive_sha256, ordinal,
                                                      source_snapshot, evidence_budget))
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
    return result


def attach_security_agent(static: dict, *, archive_sha256: str, engine_version: str, source_archive=None) -> None:
    """An unavailable coordinator never discards successful scanner findings."""
    snapshot = None
    try:
        if source_archive is not None and any(sql_observation(row) for row in static.get("findings", [])):
            snapshot = SourceSnapshot.from_archive(source_archive, archive_sha256=archive_sha256)
        result = review_static_observations(static, archive_sha256=archive_sha256,
                                            engine_version=engine_version, source_snapshot=snapshot)
    except Exception as exc:  # Same isolation boundary as the detector stage.
        result = _base(archive_sha256, engine_version)
        result["stop_reason"] = f"agent_error: {type(exc).__name__}"
    finally:
        if snapshot is not None:
            snapshot.close()
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
            or value.get("mode") != "deterministic_static"
            or not isinstance(value.get("status"), str)
            or value["status"] not in {"completed", "partial", "unavailable"}
            or value.get("automatic_patch") is not False or value.get("runtime_verified") is not False
            or not isinstance(value.get("plan"), list) or not isinstance(value.get("observations"), list)
            or not isinstance(value.get("budget"), dict)):
        return None
    return deepcopy(value)

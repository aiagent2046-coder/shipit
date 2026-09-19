"""Validate saved source acquisition records without upgrading runtime claims.

Only bounded structural records are exported. SQL text, project values and
exception messages are never accepted as acquisition facts or diagnostics.
"""
from __future__ import annotations

from copy import deepcopy
import re

ACTIONS = ("locate_source", "trace_request_input", "inspect_sql_slots", "collect_value_constraints")
FACT_METHODS = {
    "request_input_source": "fastapi_ast_binding",
    "local_input_flow": "python_ast_straight_line",
    "sql_value_position": "postgresql_ast_slot_context",
    "value_constraints": "python_ast_constraints",
}
PRODUCES = {
    "locate_source": set(),
    "trace_request_input": {"request_input_source", "local_input_flow"},
    "inspect_sql_slots": {"sql_value_position"},
    "collect_value_constraints": {"value_constraints"},
}
STOP_REASONS = {
    "source_goal_reached", "no_further_action", "source_unavailable", "source_changed", "source_parse_error",
    "source_limit", "ambiguous_sink", "sink_not_found", "budget_exhausted", "collector_error",
}
REASONS = {
    "source_snapshot_matched", "source_unavailable", "source_changed", "source_limit", "source_parse_error",
    "sink_not_found", "ambiguous_sink", "request_flow_established", "request_flow_not_established",
    "sql_value_positions_established", "sql_slots_not_established", "value_constraints_recorded",
    "value_constraints_unknown", "collector_failed", "work_budget_exhausted", "step_budget_exhausted",
}
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")


def _integer(value: object, minimum: int = 0, maximum: int = 2**31 - 1) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _span(value: object) -> bool:
    return (isinstance(value, list) and len(value) == 4
            and all(_integer(item) for item in value) and value[0] > 0
            and (value[2] > value[0] or value[2] == value[0] and value[3] > value[1]))


def _keys(value: object, required: set[str], optional: set[str] = frozenset()) -> bool:
    return isinstance(value, dict) and required <= value.keys() <= required | optional


def _driver(trace: dict) -> bool:
    proof = trace.get("driver_provenance")
    return (trace.get("version") == 2 and trace.get("driver_status") == "source_resolved"
            and trace.get("sink_method") in ("execute", "executemany")
            and isinstance(proof, dict) and type(proof.get("version")) is int and proof["version"] == 1
            and proof.get("driver") == "psycopg3" and proof.get("method") == "python_ast_straight_line"
            and all(_integer(proof.get(key), 1, trace["sink_line"])
                    for key in ("import_line", "connection_line", "cursor_line"))
            and proof["import_line"] <= proof["connection_line"] <= proof["cursor_line"])


def normalize_acquisition(value: object, trace: object) -> dict | None:
    """Return a bounded copy only when facts, actions and source identities agree."""
    if (not isinstance(trace, dict) or trace.get("version") != 2
            or trace.get("method") != "python_ast_local_flow"
            or trace.get("input_control_status") != "not_checked"
            or trace.get("flow_status") != "possible_local_flow"
            or not _integer(trace.get("sink_line"), 1)
            or not _keys(value, {"version", "status", "stop_reason", "source", "facts", "attempts", "budget"})
            or type(value.get("version")) is not int or value["version"] != 1
            or value.get("status") not in ("completed", "partial", "unsupported")
            or not isinstance(value.get("stop_reason"), str) or value["stop_reason"] not in STOP_REASONS):
        return None
    if (trace.get("driver_status") == "source_resolved" and not _driver(trace)
            or trace.get("driver_status") == "unknown" and "driver_provenance" in trace
            or trace.get("driver_status") not in ("unknown", "source_resolved")
            or not _integer(trace.get("assembly_line"), 1)
            or trace.get("assembly_kind") not in (
                "concatenation", "percent_format", "f_string", "format_call", "join_call")
            or trace.get("sink_method") not in ("execute", "executemany", "executescript", "raw", "execute_sql")):
        return None
    source = value["source"]
    if (not _keys(source, {"file", "source_sha256"}, {"sink_span"})
            or not isinstance(source["file"], str) or not 0 < len(source["file"]) <= 4096
            or any(ord(char) < 32 for char in source["file"])
            or source["file"] != trace.get("file")
            or not isinstance(source["source_sha256"], str) or not _SHA256.fullmatch(source["source_sha256"])
            or source["source_sha256"] != trace.get("source_sha256")
            or "sink_span" in source and (not _span(source["sink_span"])
                                           or source["sink_span"][0] != trace["sink_line"])):
        return None
    facts, attempts, budget = value["facts"], value["attempts"], value["budget"]
    if (not isinstance(facts, list) or len(facts) > 4 or not isinstance(attempts, list) or len(attempts) > 4
            or not _keys(budget, {"max_steps", "steps", "work_units"})
            or not _integer(budget["max_steps"], 0, 4)
            or not _integer(budget["steps"], 0, budget["max_steps"])
            or budget["steps"] != len(attempts) or not _integer(budget["work_units"])):
        return None
    found = {}
    for fact in facts:
        if (not isinstance(fact, dict) or not isinstance(fact.get("id"), str)
                or fact["id"] not in FACT_METHODS or fact["id"] in found
                or fact.get("method") != FACT_METHODS[fact["id"]]):
            return None
        field = {"request_input_source": "sources", "local_input_flow": "locations",
                 "sql_value_position": "slots", "value_constraints": "constraints"}[fact["id"]]
        entries = fact.get(field)
        if (not _keys(fact, {"id", "method", field}) or not isinstance(entries, list)
                or not 1 <= len(entries) <= (128 if field in {"locations", "constraints"} else 64)):
            return None
        if field == "sources":
            for item in entries:
                if (not _keys(item, {"parameter", "channel", "span"})
                        or not isinstance(item["parameter"], str) or not _NAME.fullmatch(item["parameter"])
                        or item["channel"] not in ("query", "path") or not _span(item["span"])):
                    return None
        elif field == "locations":
            if not all(_span(item) for item in entries):
                return None
        elif field == "slots":
            if (not _driver(trace) or any(not _keys(item, {"index", "role"})
                    or not _integer(item["index"], 0, 63) or item["role"] != "value" for item in entries)
                    or [item["index"] for item in entries] != list(range(len(entries)))):
                return None
        else:
            for item in entries:
                if (not _keys(item, {"slot", "kind", "type", "span"})
                        or not _integer(item["slot"], 0, 63)
                        or item["kind"] not in ("declared_type", "int_conversion", "request_string")
                        or item["type"] not in ("str", "int", "float", "bool") or not _span(item["span"])
                        or item["kind"] == "int_conversion" and item["type"] != "int"
                        or item["kind"] == "request_string" and item["type"] != "str"):
                    return None
        found[fact["id"]] = fact
    if bool(found.get("request_input_source")) != bool(found.get("local_input_flow")):
        return None
    if "value_constraints" in found:
        if "local_input_flow" not in found:
            return None
        covered = {item["slot"] for item in found["value_constraints"]["constraints"]}
        slots = ({item["index"] for item in found["sql_value_position"]["slots"]}
                 if "sql_value_position" in found else set(range(len(covered))))
        if covered != slots:
            return None
    produced, previous = set(), -1
    for attempt in attempts:
        if (not _keys(attempt, {"action", "result", "reason", "produced"}, {"detail"})
                or attempt["action"] not in ACTIONS
                or "detail" in attempt and (not isinstance(attempt["detail"], str)
                                            or not _NAME.fullmatch(attempt["detail"]))
                or attempt["result"] not in ("established", "unknown", "unsupported", "error", "budget_exhausted")
                or not isinstance(attempt["reason"], str) or attempt["reason"] not in REASONS
                or not isinstance(attempt["produced"], list)
                or any(not isinstance(item, str) for item in attempt["produced"])):
            return None
        established_reasons = {"locate_source": "source_snapshot_matched",
                               "trace_request_input": "request_flow_established",
                               "inspect_sql_slots": "sql_value_positions_established",
                               "collect_value_constraints": "value_constraints_recorded"}
        if (attempt["result"] == "established"
                and attempt["reason"] != established_reasons[attempt["action"]]):
            return None
        if attempt["action"] == "locate_source" and attempt["result"] == "established" and "sink_span" not in source:
            return None
        order, emitted = ACTIONS.index(attempt["action"]), set(attempt["produced"])
        if (order <= previous or len(emitted) != len(attempt["produced"])
                or emitted != (PRODUCES[attempt["action"]] if attempt["result"] == "established" else set())
                or not emitted <= found.keys()):
            return None
        if order > 0 and (not attempts or attempts[0]["action"] != "locate_source"
                          or attempts[0]["result"] != "established"):
            return None
        produced.update(emitted)
        previous = order
    if produced != found.keys() or facts and "sink_span" not in source:
        return None
    complete = len(found) == 4
    if ((value["status"] == "completed") != complete
            or (value["stop_reason"] == "source_goal_reached") != complete):
        return None
    if (value["status"] == "partial") != (
            value["stop_reason"] in {"budget_exhausted", "collector_error", "source_limit"}):
        return None
    return deepcopy(value)


def acquisition_rows(value: object, trace: object) -> list[tuple[str, str]]:
    record = normalize_acquisition(value, trace)
    if record is None:
        return []
    rows = [("Source investigation", f"{record['status']}; {record['stop_reason'].replace('_', ' ')}. "
             "Source evidence only; runtime exploitability and repair behavior remain unverified.")]
    labels = {"locate_source": "Locate the source", "trace_request_input": "Trace request input",
              "inspect_sql_slots": "Check SQL value positions", "collect_value_constraints": "Check value constraints"}
    for step in record["attempts"]:
        rows.append((f"Investigation: {labels[step['action']]}",
                     f"{step['result'].replace('_', ' ')}; {step['reason'].replace('_', ' ')}"))
    for fact in record["facts"]:
        if fact["id"] == "request_input_source":
            detail = "; ".join(f"{item['channel']} parameter {item['parameter']} at line {item['span'][0]}"
                               for item in fact["sources"])
        elif fact["id"] == "local_input_flow":
            detail = "Local flow at lines " + ", ".join(str(item[0]) for item in fact["locations"])
        elif fact["id"] == "sql_value_position":
            detail = f"{len(fact['slots'])} substitution(s) in SQL value positions."
        else:
            detail = "; ".join(f"slot {item['slot'] + 1}: {item['kind'].replace('_', ' ')} "
                               f"{item['type']} at line {item['span'][0]}" for item in fact["constraints"])
        rows.append((f"Source fact: {fact['id'].replace('_', ' ')}", detail))
    budget = record["budget"]
    rows.append(("Investigation budget", f"{budget['steps']} of {budget['max_steps']} actions; "
                 f"{budget['work_units']} work units."))
    return rows

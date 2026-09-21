"""Saved evidence is source-bound, bounded and cannot promote a runtime claim."""
from copy import deepcopy

import pytest

from app.report.evidence import security_agent_rows
from app.scan.evidence_record import acquisition_rows, normalize_acquisition


@pytest.fixture
def trace():
    return {"version": 2, "method": "python_ast_local_flow", "file": "src/query.py",
            "source_sha256": "a" * 64, "assembly_line": 8, "assembly_kind": "f_string",
            "sink_line": 8, "sink_method": "execute", "flow_status": "possible_local_flow",
            "input_control_status": "not_checked", "driver_status": "source_resolved",
            "driver_provenance": {"version": 1, "driver": "psycopg3", "method": "python_ast_straight_line",
                                  "import_line": 1, "connection_line": 6, "cursor_line": 7}}


@pytest.fixture
def acquisition(trace):
    return {"version": 1, "status": "completed", "stop_reason": "source_goal_reached",
            "source": {"file": trace["file"], "source_sha256": trace["source_sha256"], "sink_span": [8, 4, 8, 42]},
            "facts": [
                {"id": "request_input_source", "method": "fastapi_ast_binding",
                 "sources": [{"parameter": "user_id", "channel": "query", "span": [5, 11, 5, 23]}]},
                {"id": "local_input_flow", "method": "python_ast_straight_line",
                 "locations": [[5, 11, 5, 23], [8, 28, 8, 35]]},
                {"id": "sql_value_position", "method": "postgresql_ast_slot_context",
                 "slots": [{"index": 0, "role": "value"}]},
                {"id": "value_constraints", "method": "python_ast_constraints",
                 "constraints": [{"slot": 0, "kind": "declared_type", "type": "str", "span": [5, 20, 5, 23]}]},
            ],
            "attempts": [
                {"action": "locate_source", "result": "established", "reason": "source_snapshot_matched",
                 "produced": []},
                {"action": "trace_request_input", "result": "established", "reason": "request_flow_established",
                 "produced": ["request_input_source", "local_input_flow"]},
                {"action": "inspect_sql_slots", "result": "established", "reason": "sql_value_positions_established",
                 "produced": ["sql_value_position"]},
                {"action": "collect_value_constraints", "result": "established", "reason": "value_constraints_recorded",
                 "produced": ["value_constraints"]},
            ], "budget": {"max_steps": 4, "steps": 4, "work_units": 100}}


def agent(trace, acquisition):
    return {"version": 1, "mode": "deterministic_static", "status": "completed",
            "runtime_verified": False, "automatic_patch": False, "plan": [], "budget": {},
            "observations": [{"file": trace["file"], "line": 8, "rule_id": "sql-injection-string-built-query",
                              "state": "source_evidence_collected", "next_action": "review_runtime_contract",
                              "recipe": {"automatic_apply": False, "status": "manual_guidance"},
                              "missing_evidence": ["runtime_reachability", "attacker_control",
                                                   "expected_query_contract"],
                              "evidence": {"sql_observation": trace}, "acquisition": acquisition}]}


def test_complete_source_investigation_exposes_actions_and_remaining_runtime_gap(trace, acquisition):
    before = deepcopy(acquisition)
    record = normalize_acquisition(acquisition, trace)
    assert record == acquisition and record is not acquisition
    rows = dict(security_agent_rows(agent(trace, acquisition)))
    assert "Supported source evidence collected" in rows["Review state"]
    assert "query parameter user_id at line 5" in rows["Source fact: request input source"]
    assert "established" in rows["Investigation: Trace request input"]
    assert rows["Next step"].startswith("Review the runtime contract")
    assert "attacker control" in rows["Missing evidence"]
    assert "runtime exploitability and repair behavior remain unverified" in rows["Source investigation"]
    assert acquisition == before


@pytest.mark.parametrize("parameter", ["имя", "变量", "é", "e\u0301", "_данные2", "℘", "ᢅ", "a·",
                                      "𐐀" * 128, "a" * 128])
def test_python_identifiers_survive_saved_source_evidence(trace, acquisition, parameter):
    acquisition["facts"][0]["sources"][0]["parameter"] = parameter
    assert normalize_acquisition(acquisition, trace) == acquisition
    rows = dict(security_agent_rows(agent(trace, acquisition)))
    assert f"query parameter {parameter} at line 5" in rows["Source fact: request input source"]
    assert rows["Next step"].startswith("Review the runtime contract")


@pytest.mark.parametrize("parameter", ["", "2name", "name\n", "name\r", "a\u200c", "a\u200d", "😀",
                                      "a" * 129, "𐐀" * 129, "\u0301name", "<script>"])
def test_invalid_or_oversized_identifiers_cannot_be_saved_facts(trace, acquisition, parameter):
    acquisition["facts"][0]["sources"][0]["parameter"] = parameter
    assert normalize_acquisition(acquisition, trace) is None
    assert acquisition_rows(acquisition, trace) == []


def test_unicode_parameter_support_does_not_expand_diagnostic_names(trace, acquisition):
    acquisition["attempts"][1]["detail"] = "имя"
    assert normalize_acquisition(acquisition, trace) is None


@pytest.mark.parametrize("mutate", [
    lambda v: v.update(version=True),
    lambda v: v.update(status="verified"),
    lambda v: v.update(stop_reason="collector_error: private SQL"),
    lambda v: v["source"].update(file="another.py"),
    lambda v: v["source"].update(source_sha256="b" * 64),
    lambda v: v["source"].update(sink_span=[9, 0, 9, 2]),
    lambda v: v["source"].update(sink_span=[8, 42, 8, 4]),
    lambda v: v["source"].update(sink_span=[True, 0, 8, 4]),
    lambda v: v["facts"][0].update(method="model_guess"),
    lambda v: v["facts"][0]["sources"][0].update(parameter="secret <script>"),
    lambda v: v["facts"][0]["sources"][0].update(channel="body"),
    lambda v: v["facts"][1].update(locations=[[8, 0, 8, 2]] * 129),
    lambda v: v["facts"][2]["slots"][0].update(role="identifier"),
    lambda v: v["facts"][2]["slots"][0].update(index=1),
    lambda v: v["facts"][3]["constraints"][0].update(slot=1),
    lambda v: v["facts"][3]["constraints"][0].update(kind="int_conversion", type="str"),
    lambda v: v["facts"][3]["constraints"][0].update(value="private project value"),
    lambda v: v["facts"].pop(),
    lambda v: v["attempts"][1].update(produced=[]),
    lambda v: v["attempts"][1].update(reason="request_flow_not_established"),
    lambda v: v["attempts"][1].update(result="unknown"),
    lambda v: v["attempts"].reverse(),
    lambda v: v["attempts"][0].update(detail="private exception: value"),
    lambda v: v["budget"].update(steps=3),
    lambda v: v["budget"].update(max_steps=100000),
    lambda v: v["budget"].update(work_units=True),
])
def test_forged_or_unbounded_records_never_establish_source_evidence(trace, acquisition, mutate):
    mutate(acquisition)
    assert normalize_acquisition(acquisition, trace) is None
    assert acquisition_rows(acquisition, trace) == []
    rows = dict(security_agent_rows(agent(trace, acquisition)))
    assert "Review state" not in rows
    assert "Observation display incomplete" in rows


@pytest.mark.parametrize("invalid", [
    {"driver_status": "unknown"}, {"driver_provenance": None}, {"sink_method": "raw"},
    {"driver_provenance": {"version": 1, "driver": "psycopg3", "method": "python_ast_straight_line",
                           "import_line": 1, "connection_line": 7, "cursor_line": 6}},
])
def test_sql_value_facts_require_consistent_driver_provenance(trace, acquisition, invalid):
    trace.update(invalid)
    assert normalize_acquisition(acquisition, trace) is None


def test_partial_type_evidence_survives_an_unknown_driver(trace, acquisition):
    trace["driver_status"] = "unknown"
    del trace["driver_provenance"]
    acquisition.update(status="unsupported", stop_reason="no_further_action")
    acquisition["facts"].pop(2)
    acquisition["attempts"][2].update(result="unknown", reason="sql_slots_not_established", produced=[])
    assert normalize_acquisition(acquisition, trace) == acquisition
    rows = dict(acquisition_rows(acquisition, trace))
    assert "Source fact: value constraints" in rows
    assert "Source fact: sql value position" not in rows


def test_historical_observation_never_invents_acquisition(trace, acquisition):
    old = agent(trace, acquisition)
    row = old["observations"][0]
    row.update(state="needs_evidence", next_action="manual_review")
    del row["acquisition"]
    rows = dict(security_agent_rows(old))
    assert "Source investigation" not in rows
    assert rows["Next step"].startswith("Manual review")


def test_malformed_optional_acquisition_keeps_static_signal_and_explicit_gap(trace, acquisition):
    old = agent(trace, acquisition)
    row = old["observations"][0]
    row.update(state="needs_evidence", next_action="manual_review", acquisition={"unsafe": "private SQL"})
    rows = dict(security_agent_rows(old))
    assert "SQL source trace" in rows
    assert "Source investigation unavailable" in rows
    assert "private SQL" not in str(rows)


def test_zero_step_budget_retains_explicit_incomplete_record(trace, acquisition):
    acquisition.update(status="partial", stop_reason="budget_exhausted", facts=[], attempts=[])
    acquisition["budget"].update(max_steps=0, steps=0, work_units=0)
    acquisition["source"].pop("sink_span")
    assert normalize_acquisition(acquisition, trace) == acquisition
    rows = dict(acquisition_rows(acquisition, trace))
    assert "0 of 0 actions" in rows["Investigation budget"]
    assert "partial; budget exhausted" in rows["Source investigation"]


def test_source_size_limit_remains_partial(trace, acquisition):
    acquisition.update(status="partial", stop_reason="source_limit", facts=[])
    acquisition["attempts"] = [{"action": "locate_source", "result": "budget_exhausted",
                                "reason": "source_limit", "produced": []}]
    acquisition["budget"].update(steps=1)
    acquisition["source"].pop("sink_span")
    assert normalize_acquisition(acquisition, trace) == acquisition


@pytest.mark.parametrize("field", ["state", "next_action"])
def test_non_string_saved_decision_is_not_rendered(trace, acquisition, field):
    saved = agent(trace, acquisition)
    saved["observations"][0][field] = []
    rows = dict(security_agent_rows(saved))
    assert "Observation display incomplete" in rows
    assert "Review state" not in rows


def test_incomplete_acquisition_has_a_recognized_aggregate_reason(trace, acquisition):
    saved = agent(trace, acquisition)
    saved.update(status="partial", stop_reason="evidence_collection_incomplete")
    rows = dict(security_agent_rows(saved))
    assert "partial; 1 observations; evidence_collection_incomplete" in rows["Pattern review"]

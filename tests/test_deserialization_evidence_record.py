"""Saved body-origin evidence cannot cross source, schema or runtime boundaries."""
from copy import deepcopy

import pytest

from app.scan.evidence_record import normalize_acquisition, normalize_deserialization_observation


@pytest.fixture
def trace():
    return {"version": 1, "method": "python_ast_import_resolved", "file": "app.py",
            "source_sha256": "a" * 64, "sink_line": 8, "sink_span": [8, 11, 8, 31],
            "sink_method": "loads", "loader": "pickle.loads", "input_control_status": "not_checked"}


@pytest.fixture
def record(trace):
    return {"version": 2, "status": "completed", "stop_reason": "source_goal_reached",
            "source": {key: deepcopy(trace[key]) for key in ("file", "source_sha256", "sink_span")},
            "facts": [
                {"id": "request_input_source", "method": "fastapi_ast_binding",
                 "sources": [{"parameter": "body", "channel": "body", "span": [7, 14, 7, 25]}]},
                {"id": "local_input_flow", "method": "python_ast_straight_line",
                 "locations": [[7, 14, 7, 25], [8, 24, 8, 28], [8, 11, 8, 31]]},
            ],
            "attempts": [
                {"action": "locate_source", "result": "established",
                 "reason": "source_snapshot_matched", "produced": []},
                {"action": "trace_request_input", "result": "established", "reason": "request_flow_established",
                 "produced": ["request_input_source", "local_input_flow"]},
            ], "budget": {"max_steps": 2, "steps": 2, "work_units": 100}}


def test_body_trace_and_saved_acquisition_replay_without_mutation(trace, record):
    original = deepcopy(record)
    normalized = normalize_acquisition(record, trace)
    assert normalized == original and normalized is not record
    assert normalize_deserialization_observation(trace) == trace
    normalized["facts"][0]["sources"][0]["parameter"] = "other"
    assert record == original


@pytest.mark.parametrize("update", [
    {"version": True}, {"version": 2}, {"method": "model_guess"}, {"loader": "yaml.load"},
    {"sink_method": "load"}, {"sink_line": True}, {"sink_span": [8, 12, 8, 12]},
    {"sink_span": [True, 11, 8, 31]}, {"sink_span": [7, 11, 8, 31]},
    {"input_control_status": "verified"}, {"driver_status": "source_resolved"},
    {"file": "app.py\n"}, {"source_sha256": "a" * 64 + "\n"}, {"source_sha256": None},
])
def test_unbounded_or_invented_trace_is_not_a_supported_deserialization_observation(trace, record, update):
    trace.update(update)
    assert normalize_deserialization_observation(trace) is None
    assert normalize_acquisition(record, trace) is None


@pytest.mark.parametrize("mutate", [
    lambda r: r.update(version=1),
    lambda r: r["source"].update(file="other.py"),
    lambda r: r["source"].update(source_sha256="b" * 64),
    lambda r: r["source"].update(sink_span=[8, 12, 8, 31]),
    lambda r: r["source"].pop("sink_span"),
    lambda r: r["facts"][0]["sources"][0].update(channel="query"),
    lambda r: r["facts"][0]["sources"].append(deepcopy(r["facts"][0]["sources"][0])),
    lambda r: r["facts"][1].update(locations=[[8, 0, 8, 1]] * 129),
    lambda r: r["facts"][1]["locations"].pop(),
    lambda r: r["facts"][1]["locations"].pop(0),
    lambda r: r["facts"][1]["locations"].insert(1, r["facts"][1]["locations"][0]),
    lambda r: r["facts"].append({"id": "sql_value_position", "method": "postgresql_ast_slot_context", "slots": []}),
    lambda r: r["facts"][0].update(secret="private body content"),
    lambda r: r["attempts"][0].update(result="unknown"),
    lambda r: r["attempts"][1].update(produced=["request_input_source"]),
    lambda r: r["attempts"][1].update(action="inspect_sql_slots"),
    lambda r: r["attempts"].reverse(),
    lambda r: r["budget"].update(max_steps=4),
    lambda r: r["budget"].update(steps=True),
])
def test_source_or_action_forgery_cannot_close_evidence(trace, record, mutate):
    mutate(record)
    assert normalize_acquisition(record, trace) is None


@pytest.mark.parametrize("reason", ["budget_exhausted", "source_limit", "collector_error"])
def test_interrupted_collection_retains_an_explicit_gap(trace, record, reason):
    record.update(status="partial", stop_reason=reason, facts=[], attempts=[])
    record["budget"].update(steps=0, work_units=0)
    assert normalize_acquisition(record, trace) == record


def test_locating_source_without_input_flow_never_completes_the_goal(trace, record):
    record.update(status="unsupported", stop_reason="no_further_action", facts=[])
    record["attempts"][1].update(result="unknown", reason="request_flow_not_established", produced=[])
    assert normalize_acquisition(record, trace) == record
    record.update(status="completed", stop_reason="source_goal_reached")
    assert normalize_acquisition(record, trace) is None

"""Saved file provenance cannot become HTTP, trust or cross-source evidence."""
import ast
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from app.scan.evidence_record import acquisition_rows, normalize_acquisition, normalize_deserialization_observation
from app.scan.source_snapshot import source_span


FILE_PICKLE = '''import pickle
def read_checkpoint(path):
    with open(path, "rb") as handle:
        return pickle.load(handle)
'''


def file_record():
    """A reviewable fixture derived from real AST spans, not invented positions."""
    tree = ast.parse(FILE_PICKLE)
    function = tree.body[1]
    context = function.body[0].items[0]
    sink = function.body[0].body[0].value
    parameter = function.args.args[0]
    trace = {"version": 1, "method": "python_ast_import_resolved", "file": "checkpoints.py",
             "source_sha256": hashlib.sha256(FILE_PICKLE.encode()).hexdigest(),
             "sink_line": sink.lineno, "sink_span": source_span(sink), "sink_method": "load",
             "loader": "pickle.load", "input_control_status": "not_checked"}
    source = {"function": function.name, "parameter": parameter.arg, "handle": context.optional_vars.id,
              "mode": "rb", "function_span": source_span(function), "parameter_span": source_span(parameter),
              "open_span": source_span(context.context_expr), "handle_span": source_span(context.optional_vars)}
    record = {"version": 3, "status": "completed", "stop_reason": "source_goal_reached",
              "source": {key: deepcopy(trace[key]) for key in ("file", "source_sha256", "sink_span")},
              "facts": [
                  {"id": "file_input_source", "method": "python_ast_file_binding", "sources": [source]},
                  {"id": "local_input_flow", "method": "python_ast_file_flow",
                   "locations": [source_span(node) for node in
                                 (parameter, context.context_expr, context.optional_vars, sink.args[0], sink)]},
              ],
              "attempts": [
                  {"action": "locate_source", "result": "established",
                   "reason": "source_snapshot_matched", "produced": []},
                  {"action": "trace_file_input", "result": "established", "reason": "file_flow_established",
                   "produced": ["file_input_source", "local_input_flow"]},
              ], "budget": {"max_steps": 2, "steps": 2, "work_units": 100}}
    return trace, record


def test_file_record_replays_without_claiming_callers_input_control_or_format():
    trace, original = file_record()
    record = json.loads(json.dumps(original))
    normalized = normalize_acquisition(record, trace)
    assert normalized == original and normalized is not record
    assert normalize_deserialization_observation(trace) == trace
    rows = dict(acquisition_rows(record, trace))
    assert "Function read_checkpoint: parameter path" in rows["Source fact: file input source"]
    assert "Caller, path value and file trust are not established." in rows["Source fact: file input source"]
    assert "Source fact: request input source" not in rows
    assert all(key not in json.dumps(normalized) for key in
               ("input_trust_boundary", "runtime_verified", "attacker_control", "safetensors"))
    normalized["facts"][0]["sources"][0]["parameter"] = "different"
    assert record == original


@pytest.mark.parametrize("mutate", [
    lambda r: r.update(version=2),
    lambda r: r.update(version=True),
    lambda r: r["source"].update(file="other.py"),
    lambda r: r["source"].update(source_sha256="b" * 64),
    lambda r: r["source"].update(sink_span=[4, 15, 4, 33]),
    lambda r: r["source"].pop("sink_span"),
    lambda r: r["facts"][0]["sources"][0].update(channel="body"),
    lambda r: r["facts"][0]["sources"][0].update(mode="wb"),
    lambda r: r["facts"][0]["sources"][0].update(function="read\ncheckpoint"),
    lambda r: r["facts"][0]["sources"][0].update(parameter="x" * 129),
    lambda r: r["facts"][0]["sources"][0].update(handle=[]),
    lambda r: r["facts"][0]["sources"][0].update(function_span=[2, 0, 3, 35]),
    lambda r: r["facts"][0]["sources"][0].update(parameter_span=[True, 20, 2, 24]),
    lambda r: r["facts"][0]["sources"][0].update(open_span=[4, 35, 4, 40]),
    lambda r: r["facts"][0]["sources"][0].update(handle_span=[2, 5, 2, 11]),
    lambda r: r["facts"][0]["sources"].append(deepcopy(r["facts"][0]["sources"][0])),
    lambda r: r["facts"][0].update(id="request_input_source", method="fastapi_ast_binding"),
    lambda r: r["facts"][1].update(method="python_ast_straight_line"),
    lambda r: r["facts"][1]["locations"].pop(0),
    lambda r: r["facts"][1]["locations"].pop(1),
    lambda r: r["facts"][1]["locations"].pop(2),
    lambda r: r["facts"][1]["locations"].pop(),
    lambda r: r["facts"][1]["locations"].insert(1, [1, 0, 1, 13]),
    lambda r: r["facts"][1]["locations"].insert(1, r["facts"][1]["locations"][0]),
    lambda r: r["facts"].append({"id": "input_trust_boundary", "method": "python_ast_file_binding"}),
    lambda r: r["attempts"][1].update(action="trace_request_input", reason="request_flow_established"),
    lambda r: r["attempts"][1].update(produced=["file_input_source"]),
    lambda r: r["attempts"][1].update(reason="request_flow_established"),
    lambda r: r["attempts"].reverse(),
    lambda r: r["budget"].update(max_steps=4),
])
def test_forged_source_flow_or_action_cannot_render_saved_file_proof(mutate):
    trace, record = file_record()
    mutate(record)
    assert normalize_acquisition(record, trace) is None
    assert acquisition_rows(record, trace) == []


@pytest.mark.parametrize("update", [
    {"sink_method": "loads"}, {"loader": "pickle.loads"},
    {"loader": "dill.load"}, {"loader": "custom.load"}, {"input_control_status": "verified"},
])
def test_file_observation_needs_matching_exact_loader_and_method(update):
    trace, record = file_record()
    trace.update(update)
    assert normalize_deserialization_observation(trace) is None
    assert normalize_acquisition(record, trace) is None


def test_valid_body_observation_cannot_borrow_file_acquisition():
    trace, record = file_record()
    trace.update(loader="pickle.loads", sink_method="loads")
    assert normalize_deserialization_observation(trace) == trace
    assert normalize_acquisition(record, trace) is None
    record["version"] = 2
    assert normalize_acquisition(record, trace) is None


@pytest.mark.parametrize("reason", ["budget_exhausted", "source_limit", "collector_error"])
def test_interrupted_file_investigation_retains_an_explicit_gap(reason):
    trace, record = file_record()
    record.update(status="partial", stop_reason=reason, facts=[], attempts=[])
    record["budget"].update(steps=0, work_units=0)
    assert normalize_acquisition(record, trace) == record


def test_unknown_file_origin_does_not_complete_a_source_goal():
    trace, record = file_record()
    record.update(status="unsupported", stop_reason="no_further_action", facts=[])
    record["attempts"][1].update(result="unknown", reason="file_flow_not_established", produced=[])
    assert normalize_acquisition(record, trace) == record
    record.update(status="completed", stop_reason="source_goal_reached")
    assert normalize_acquisition(record, trace) is None


SHARED_CORPUS = json.loads((Path(__file__).parent / "fixtures" / "deserialization-file-record.json").read_text())


@pytest.mark.parametrize("case", SHARED_CORPUS["cases"], ids=lambda case: case["name"])
def test_file_record_validation_matches_shared_browser_and_web_corpus(case):
    """All three report readers consume the same valid and tampered records."""
    record = deepcopy(SHARED_CORPUS["record"])
    for change in case["changes"]:
        parent = record
        for key in change["path"][:-1]:
            parent = parent[key]
        key = change["path"][-1]
        if change.get("delete"):
            del parent[key]
        else:
            parent[key] = deepcopy(change["value"])
    assert (normalize_acquisition(record, SHARED_CORPUS["trace"]) is not None) is case["valid"]

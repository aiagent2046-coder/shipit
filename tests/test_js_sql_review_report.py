"""Saved source facts must not become stronger display claims."""
from copy import deepcopy

import pytest

from app.report.js_sql_review import js_sql_review_rows
from app.scan.js_sql_review import _observation


SOURCE = {"archive_sha256": "a" * 64, "engine_version": "test"}


def record():
    analysis = {
        "version": 1, "file": '<img src=x onerror="alert(1)">.ts', "source_sha256": "b" * 64,
        "sink_line": 3, "sink_column": 1, "sink_method": "query", "verdict": "fixed_sql_fragments",
        "parameter_argument": "present", "fragments": [{"line": 2, "kind": "fixed_helper",
        "reason": "single_return_literal_args"}], "reason": "proven_fixed", "runtime_verified": False,
    }
    return {"version": 1, "source": SOURCE, "status": "completed", "coverage_partial": False,
            "budget": {"max_candidates": 32, "candidates_found": 1, "processed": 1, "omitted": 0},
            "runtime_verified": False, "automatic_patch": False, "model_calls": 0,
            "observations": [_observation(SOURCE, 0, analysis)]}


def test_fixed_source_facts_preserve_runtime_limits():
    saved = record()
    before = deepcopy(saved)
    rows = js_sql_review_rows(saved, SOURCE)
    text = " ".join(value for _, value in rows)
    assert "within bounded source analysis" in text
    assert "presence alone does not establish parameter binding" in text
    assert "original finding is retained" in text
    assert saved == before


@pytest.mark.parametrize("mutation", ["runtime", "source", "receipt", "fixed_unknown"])
def test_corrupt_saved_claim_does_not_render_as_fixed(mutation):
    saved = record()
    if mutation == "runtime":
        saved["runtime_verified"] = True
    elif mutation == "source":
        saved["source"] = {**SOURCE, "archive_sha256": "c" * 64}
    elif mutation == "receipt":
        saved["observations"][0]["tasks"][1]["output_sha256"] = "0" * 64
    else:
        saved["observations"][0]["analysis"]["fragments"][0].update(kind="unknown", reason="unresolved_expression")
    rows = js_sql_review_rows(saved, SOURCE)
    assert rows[0][0] == "JavaScript SQL source review unavailable"
    assert "fixed fragments" not in str(rows)

"""Ordinary scans refine JS SQL without removing findings or granting runtime proof."""
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path

import pytest

from app.scan.js_sql_review import normalize_review, review_js_sql
from app.scan.security_agent import agent_record
from app.scan.static import run_static_scan
from app.report.js_sql_review import js_sql_review_rows
from tests.test_security_agent import archive

FIXED = b"""export {};
function clause(index: number) { return `owner = $${index}`; }
db.query(`SELECT * FROM items WHERE ${clause(1)}`, [userId]);
"""
DYNAMIC = b"""export {};
db.query(`SELECT * FROM items WHERE id = ${userId}`, [userId]);
"""


def reviewed(raw=FIXED):
    bundle = archive({"src/query.ts": raw.decode()})
    result = run_static_scan(io.BytesIO(bundle))
    return result, bundle


def test_ordinary_scan_runs_source_workers_and_preserves_findings(monkeypatch):
    import app.scan.js_sql_review as module
    result, bundle = reviewed()
    record = result["security_agent"]["js_sql_review"]
    assert len(record["observations"]) == 1
    row = record["observations"][0]
    assert row["state"] == "fixed_sql_fragments"
    assert row["analysis"]["source_sha256"] == hashlib.sha256(FIXED).hexdigest()
    assert [task["agent"] for task in row["tasks"]] == ["detector", "researcher", "verifier"]
    assert all(task["status"] == "completed" for task in row["tasks"])
    assert agent_record(result["security_agent"]) == result["security_agent"]
    assert record["model_calls"] == 0
    assert record["runtime_verified"] is record["automatic_patch"] is False
    monkeypatch.setattr(module, "review_js_sql", lambda *a, **k: None)
    baseline = run_static_scan(io.BytesIO(bundle))
    assert result["findings"] == baseline["findings"]
    assert result["security_agent"]["runtime_verified"] is False


def test_parameter_argument_does_not_hide_dynamic_sql():
    result, _ = reviewed(DYNAMIC)
    row = result["security_agent"]["js_sql_review"]["observations"][0]
    assert row["state"] == "dynamic_sql_unresolved"
    assert row["analysis"]["parameter_argument"] == "present"
    assert result["findings"]


@pytest.mark.parametrize("edit", [
    lambda r: r.update(runtime_verified=True),
    lambda r: r.update(model_calls=True),
    lambda r: r["source"].update(archive_sha256="0" * 64),
    lambda r: r["observations"][0].update(state="safe"),
    lambda r: r["observations"][0]["analysis"].update(source_sha256="0" * 64),
    lambda r: r["observations"][0]["analysis"].update(sink_line=True),
    lambda r: r["observations"][0]["tasks"][1].update(input_sha256="0" * 64),
    lambda r: r["observations"][0]["tasks"][2].update(depends_on=[]),
    lambda r: r["budget"].update(processed=True),
    lambda r: r["observations"].append(None),
])
def test_saved_tampering_cannot_promote_review(edit):
    result, _ = reviewed()
    agent = result["security_agent"]
    altered = deepcopy(agent)
    edit(altered["js_sql_review"])
    assert normalize_review(altered["js_sql_review"], agent["source"]) is None
    saved = agent_record(altered)
    assert "js_sql_review" not in saved
    assert saved["js_sql_review_rejected"] is True
    assert saved["observations"] == agent["observations"]
    assert saved["runtime_verified"] is False


def test_source_binding_failure_and_native_failure_retain_findings(monkeypatch):
    result, bundle = reviewed()
    source = result["security_agent"]["source"]
    r = review_js_sql(result, io.BytesIO(bundle), archive_sha256="0" * 64,
                      engine_version=source["engine_version"])
    assert r["status"] == "partial"
    assert r["observations"][0]["state"] == "unavailable"
    import app.scan.js_sql_source as researcher

    def unavailable(*args):
        raise ImportError("native parser unavailable")
    monkeypatch.setattr(researcher, "analyze_source", unavailable)
    retry = run_static_scan(io.BytesIO(bundle))
    assert retry["findings"] == result["findings"]
    assert retry["security_agent"]["js_sql_review"]["observations"][0]["state"] == "unavailable"


def test_candidate_limit_and_coverage_gaps_stay_explicit():
    result, bundle = reviewed()
    sql = next(f for f in result["findings"] if f["rule_id"] == "sql-injection-string-built-query")
    result["findings"] = [deepcopy(sql) for _ in range(35)]
    source = result["security_agent"]["source"]
    result["rule_coverage"]["sql_injection_js"]["partial"] = True
    r = review_js_sql(result, io.BytesIO(bundle), **source)
    assert r["status"] == "partial"
    assert r["coverage_partial"] is True
    assert r["budget"] == {"max_candidates": 32, "candidates_found": 35, "processed": 32, "omitted": 3}
    assert len({row["id"] for row in r["observations"]}) == 32


def test_presentation_shows_refinement_and_limits():
    result, _ = reviewed()
    agent = result["security_agent"]
    rows = js_sql_review_rows(agent["js_sql_review"], agent["source"])
    text = json.dumps(rows)
    assert "fixed fragments" in text
    assert "presence alone" in text
    assert "original finding is retained" in text
    from app.report.evidence import security_agent_rows
    assert "JavaScript SQL source review" in json.dumps(security_agent_rows(agent))


@pytest.mark.parametrize("fixture", json.loads(
    (Path(__file__).parent / "fixtures/js-sql-review-records.json").read_text()
), ids=lambda fixture: fixture["name"])
def test_shared_ui_receipts_match_python_normalization(fixture):
    record = fixture["review"]
    assert normalize_review(record, record["source"]) == record

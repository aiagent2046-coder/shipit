"""Owner wording must retain the exact limits of replayed source evidence."""
from copy import deepcopy
from html import escape
import json
from pathlib import Path

import pytest

from app.report.html import render_report
from app.report.owner_report import build_owner_report, owner_report_context
from app.report.sarif import build_sarif

FIXTURES = Path(__file__).parent / "fixtures"
REPORTS = {case["name"]: case["report"] for case in json.loads(
    (FIXTURES / "deserialization-file-agent.json").read_text())}
CASES = json.loads((FIXTURES / "owner-report.json").read_text())


def case_input(case):
    report = REPORTS[case["fixture"]]
    value = deepcopy({"findings": report["findings"], "context": owner_report_context(report)})
    for change in case["changes"]:
        parent = value
        for key in change["path"][:-1]:
            parent = parent[key]
        if change["op"] == "delete":
            del parent[change["path"][-1]]
        else:
            parent[change["path"][-1]] = deepcopy(change["value"])
    return value


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_shared_owner_projection_preserves_binding_and_unknowns(case):
    """The same receipt-corruption corpus is replayed by Python and TypeScript."""
    value = case_input(case)
    original = deepcopy(value)
    assert build_owner_report(value["findings"], value["context"]) == case["expected"]
    assert value == original


def test_neighbor_facts_cannot_fill_a_missing_call_and_unrelated_findings_remain():
    report = deepcopy(REPORTS["completed"])
    report["security_agent"]["observations"] = report["security_agent"]["observations"][1:]
    report["findings"].insert(0, {"rule_id": "other-rule", "source": "static", "severity": "critical"})
    projection = build_owner_report(report["findings"], owner_report_context(report))
    first, second = projection["cards"]
    assert (first["finding_index"], second["finding_index"]) == (1, 2)
    assert not first["source_refs"] and second["source_refs"]
    assert len(first["unknown"]) == len(second["unknown"]) + 1
    assert "other observations remain below" in projection["summary"]["text"]
    assert report["findings"][0]["severity"] == "critical"


def test_duplicate_records_do_not_invent_extra_locations():
    report = deepcopy(REPORTS["completed"])
    report["findings"].append(deepcopy(report["findings"][0]))
    projection = build_owner_report(report["findings"], owner_report_context(report))
    assert len(projection["cards"]) == 3
    assert projection["summary"]["text"].startswith("2 file-loading locations")


def test_html_owner_view_preserves_score_exports_and_developer_evidence():
    report = deepcopy(REPORTS["completed"])
    context = owner_report_context(report)
    context["dependency_cve"] = {"status": "partial"}
    result = {"findings": report["findings"], "score": {"total": 4.0, "scan_manifest": context}}
    original = deepcopy(result)
    sarif_before = build_sarif(result["findings"], score=result["score"], engine_version=report["engine_version"])
    html = render_report(result, "Example project")
    projection = build_owner_report(result["findings"], context)
    assert result == original
    sarif_after = build_sarif(result["findings"], score=result["score"], engine_version=report["engine_version"])
    assert sarif_after == sarif_before
    assert html.count('<summary>Details for a developer</summary>') == 2
    assert html.index('aria-label="Report in brief"') < html.index('id="owner-finding-0"')
    assert 'href="#owner-finding-0"' in html
    for card in projection["cards"]:
        for item in (*card["known"], *card["unknown"], card["next_action"], card["done_when"]):
            assert escape(item) in html
        assert card["source_refs"][0]["sha256"] in html
    for card in projection["cards"]:
        finding = result["findings"][card["finding_index"]]
        assert escape(finding["title"]) in html
        assert escape(finding["explanation"]) in html
        assert escape(finding["fix_hint"]) in html
    assert 'Dependency checking is incomplete; see the recorded coverage gaps.' in html


def test_online_adapter_keeps_outer_source_mismatch_and_history_out_of_current_facts():
    report = deepcopy(REPORTS["completed"])
    manifest = owner_report_context(report)
    manifest["archive_sha256"] = "0" * 64
    result = {"findings": report["findings"], "score": {
        "scan_manifest": manifest,
        "free_baseline": {"version": 1, "origin": "included", "status": "completed",
                          "score": {"scan_manifest": owner_report_context(report)},
                          "findings": deepcopy(report["findings"])},
    }}
    projection = build_owner_report(result["findings"], owner_report_context(result))
    assert all(not card["source_refs"] for card in projection["cards"])
    html = render_report(result)
    assert html.count('<summary>Details for a developer</summary>') == 2
    assert "The code opens the file at the supplied path" not in html
    assert "not independent confirmation" in html


def test_legacy_report_without_trace_keeps_original_rendering():
    case = next(case for case in CASES if case["name"] == "legacy-no-trace")
    value = case_input(case)
    result = {"findings": value["findings"], "score": {"scan_manifest": value["context"]}}
    html = render_report(result)
    assert 'aria-label="Report in brief"' not in html
    assert '<summary>Details for a developer</summary>' not in html
    assert escape(result["findings"][0]["title"]) in html


@pytest.mark.parametrize(('facts', 'message'), [
    ({'limitations': ['dependency_coverage_incomplete'],
      'sca_skipped_reason': 'no_resolvable_lockfile',
      'sca_incomplete_lockfiles': {'requirements.txt': 'unresolved'}}, 'incomplete'),
    ({'dependency_cve': {'status': 'unavailable'}}, 'unavailable'),
    ({'limitations': ['dependency_database_unavailable']}, 'unavailable'),
    ({'dependency_cve': {'status': 'checked'}, 'sca_skipped_reason': 'no_client',
      'sca_dependencies': 19, 'limitations': ['dependency_snapshot_scope',
                                           'dependency_runtime_reachability_not_checked']}, None),
    ({'dependency_cve': {'status': 'not_applicable'}, 'sca_skipped_reason': 'no_client'}, None),
    ({'limitations': 'dependency_coverage_incomplete', 'sca_coverage_incomplete': 'true',
      'sca_skipped_reason': ['no_resolvable_lockfile'], 'dependency_cve': {'status': []}}, None),
])
def test_summary_and_roadmap_share_current_dependency_scope(facts, message):
    from app.report.owner_roadmap import build_owner_roadmap

    report = {'findings': deepcopy(REPORTS['completed']['findings']),
              'score': {'scan_manifest': facts, 'free_baseline': {
                  'score': {'scan_manifest': {'dependency_cve': {'status': 'partial'}}}}}}
    context = owner_report_context(report)
    before = deepcopy(report)
    summary = build_owner_report(report['findings'], context)['summary']
    messages = [note for note in summary['coverage_notes'] if note.startswith('Dependency checking')]
    assert messages == ([f'Dependency checking is {message}; see the recorded coverage gaps.'] if message else [])
    assert ('dependency-coverage' in [task['id'] for task in
                                     build_owner_roadmap(report['findings'], context)['tasks']]) == bool(message)
    assert report == before


def test_context_keeps_only_current_saved_scope_and_ignores_history():
    current = {'limitations': ['dependency_coverage_incomplete'],
               'sca_skipped_reason': 'no_resolvable_lockfile', 'sca_coverage_incomplete': True,
               'sca_incomplete_lockfiles': {'requirements.txt': 'unresolved'}, 'sca_dependencies': 0}
    report = {'limitations': ['dependency_check_not_run'], 'score': {
        'scan_manifest': current,
        'free_baseline': {'score': {'scan_manifest': {'dependency_cve': {'status': 'partial'}}}},
    }}
    assert owner_report_context(report) == current
    assert owner_report_context({'score': {'scan_manifest': {},
                                         'free_baseline': report['score']['free_baseline']}}) == {}

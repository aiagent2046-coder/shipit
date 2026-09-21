"""Next steps must preserve evidence limits and links to the current report."""
from copy import deepcopy
from html import escape
from html.parser import HTMLParser
import json
from pathlib import Path

import pytest

from app.report.html import render_report
from app.report.owner_report import build_owner_report, owner_report_context
from app.report.owner_roadmap import build_owner_roadmap
from app.report.sarif import build_sarif


FIXTURES = Path(__file__).parent / "fixtures"
CASES = json.loads((FIXTURES / "owner-roadmap.json").read_text())
REPORT = next(case["report"] for case in json.loads(
    (FIXTURES / "deserialization-file-agent.json").read_text()) if case["name"] == "completed")


class Anchors(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.ids = []
        self.links = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if values.get("id"):
            self.ids.append(values["id"])
        if tag == "a" and values.get("href", "").startswith("#roadmap-"):
            self.links.append(values["href"][1:])


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_shared_roadmap_contract_and_inputs_are_preserved(case):
    value = deepcopy(case["input"])
    before = deepcopy(value)
    assert build_owner_roadmap(value["findings"], value["context"]) == case["expected"]
    assert value == before


def test_file_work_is_deduplicated_but_every_location_is_retained():
    findings = deepcopy(REPORT["findings"][:2])
    findings.append(deepcopy(findings[0]))
    tasks = build_owner_roadmap(findings)["tasks"]
    assert [task["id"] for task in tasks] == ["file-loading-origin", "file-loading-decision"]
    assert all(task["finding_indices"] == [0, 1, 2] for task in tasks)
    assert tasks[0]["depends_on"] == []
    assert tasks[1]["depends_on"] == [tasks[0]["id"]]
    assert "If protection needs to change" in tasks[1]["action"]
    assert "compatible with existing files" in tasks[1]["action"]
    assert "does not certify a fix" in tasks[1]["done_when"]
    for task in tasks:
        assert not {"status", "due_date", "progress", "readiness", "percentage"}.intersection(task)


def test_broken_receipt_cannot_upgrade_a_trust_question_or_hide_an_observation():
    report = deepcopy(REPORT)
    context = owner_report_context(report)
    before = build_owner_roadmap(report["findings"], context)
    assert build_owner_report(report["findings"], context)["cards"][0]["source_refs"]
    context["archive_sha256"] = "0" * 64
    assert not build_owner_report(report["findings"], context)["cards"][0]["source_refs"]
    assert build_owner_roadmap(report["findings"], context) == before
    report["findings"][0]["claim_evidence"]["deserialization_observation"]["source_sha256"] = "invalid"
    tasks = build_owner_roadmap(report["findings"], context)["tasks"]
    assert next(task for task in tasks if task["id"] == "file-loading-origin")["finding_indices"] == [1]
    remaining = next(task for task in tasks if task["id"] == "remaining-observations")
    assert 0 in remaining["finding_indices"]
    assert "before deciding whether any action is warranted" in remaining["why"]


def test_partial_dependencies_do_not_imply_missing_versions_and_first_tasks_are_independent():
    context = {"dependency_cve": {"status": "partial", "status_counts": {"unknown": 1},
                                  "incomplete_manifests": {"go.mod": "unsupported"}}}
    tasks = build_owner_roadmap(REPORT["findings"], context)["tasks"]
    dependency = next(task for task in tasks if task["id"] == "dependency-coverage")
    assert "versions" not in dependency["action"]
    assert "unresolved manifests" not in dependency["action"]
    assert all(task["depends_on"] == [] for task in tasks if task["stage"] == "first")
    context["dependency_cve"]["incomplete_manifests"]["requirements.txt"] = "unresolved"
    dependency = next(task for task in build_owner_roadmap([], context)["tasks"]
                      if task["id"] == "dependency-coverage")
    assert "exact installed versions or matching lockfiles" in dependency["action"]
    assert dependency["needs"][1:] == ["Unresolved manifest: requirements.txt"]


def test_no_runtime_status_is_invented_from_inventory_or_missing_context():
    finding = {"rule_id": "no-dockerfile", "source": "static", "context": "deployment_inventory"}
    task = build_owner_roadmap([finding])["tasks"][0]
    assert task["stage"] == "when_needed"
    assert task["coverage_refs"] == []
    assert "behavior has not been verified" not in task["why"]
    assert "Docker is only one possible hosting option" in task["action"]
    assert build_owner_roadmap([])["tasks"] == []
    for unknown in (None, "false", 0):
        assert build_owner_roadmap([], {"runtime_verified": unknown})["tasks"] == []
    assert build_owner_roadmap([], {"runtime_verified": False})["tasks"][0]["coverage_refs"] == ["runtime_verified"]


def test_html_keeps_original_json_and_sarif_and_current_links_outside_history():
    context = owner_report_context(REPORT)
    context["dependency_cve"] = {"status": "partial"}
    result = {"findings": deepcopy(REPORT["findings"]), "score": {"scan_manifest": context,
              "free_baseline": {"version": 1, "origin": "included", "status": "completed",
                                "score": {"scan_manifest": context}, "findings": deepcopy(REPORT["findings"])}}}
    original = json.dumps(result, sort_keys=True)
    sarif = build_sarif(result["findings"], score=result["score"], engine_version=REPORT["engine_version"])
    rendered = render_report(result)
    anchors = Anchors(rendered)
    assert json.dumps(result, sort_keys=True) == original
    assert build_sarif(result["findings"], score=result["score"], engine_version=REPORT["engine_version"]) == sarif
    assert rendered.count('id="roadmap-task-file-loading-origin"') == 1
    assert rendered.count('id="roadmap-task-file-loading-decision"') == 1
    assert len(anchors.ids) == len(set(anchors.ids))
    assert set(anchors.links) <= set(anchors.ids)
    assert all(f"roadmap-finding-{index}" in anchors.ids for index in range(len(result["findings"])))
    assert "owner-finding-0" in anchors.ids and "owner-finding-1" in anchors.ids
    assert rendered.index('aria-label="Project roadmap"') < rendered.index('id="owner-finding-0"')
    assert "These tasks have not been carried out or verified" in rendered
    assert "After clarification" in rendered and "If needed" in rendered
    # Current references must not point to an included historical copy.
    assert rendered.index('id="roadmap-finding-0"') > rendered.index("Current scan observations")


def test_html_grouped_contextual_and_contradicted_rows_keep_all_original_links():
    base = {"severity": "high", "source": "static", "confidence": 0.8, "category": "Security", "line": 0}
    findings = [
        dict(base, rule_id="rls-table-anon-readable", title="Table a", file="schema.sql"),
        dict(base, rule_id="rls-table-anon-readable", title="Table b", file="schema.sql"),
        dict(base, rule_id="other", title="Example", file="tests/example.py"),
        dict(base, rule_id="llm-other", title="Model hypothesis", source="llm", file="app.py"),
        dict(base, rule_id="llm-contradicted", title="Contradicted model premise", source="llm", file="app.py",
             claim_evidence={"version": 1, "syntax_check": {"result": "contradicted", "claim": "Model premise.",
                                                           "detail": "Source counterevidence."}}),
    ]
    html = render_report({"findings": findings, "score": {}})
    anchors = Anchors(html)
    assert html.count("— and 1 more like it") == 2  # plain title plus retained technical title
    for index in range(len(findings)):
        assert anchors.ids.count(f"roadmap-finding-{index}") == 1
    assert set(anchors.links) <= set(anchors.ids)
    assert "In tests, examples and scaffolding" in html
    assert "Model hypothesis" in html
    assert "Contradicted syntax premises" in html
    assert html.index('id="roadmap-finding-4"') > html.index("Contradicted syntax premises")


def test_history_only_cannot_generate_tasks_and_empty_state_does_not_claim_readiness():
    score = {"free_baseline": {"version": 1, "origin": "included", "status": "completed",
                              "score": {}, "findings": deepcopy(REPORT["findings"])}}
    html = render_report({"findings": [], "score": score})
    assert "No next steps can be generated from the recorded findings and coverage" in html
    assert "This does not establish that the project is ready or safe" in html
    assert not Anchors(html).links


def test_html_escapes_dependency_paths_in_action_details():
    path = '<img src=x onerror="alert(1)">.json'
    context = {"dependency_cve": {"status": "partial", "incomplete_manifests": {path: "unresolved"}}}
    html = render_report({"findings": [], "score": {"scan_manifest": context}})
    assert path not in html
    assert escape(path) in html
    assert "href=\"#roadmap-coverage\"" in html


@pytest.mark.parametrize(('context', 'status', 'unresolved'), [
    ({'limitations': ['dependency_coverage_incomplete'], 'sca_skipped_reason': 'no_resolvable_lockfile',
      'sca_incomplete_lockfiles': {'requirements.txt': 'unresolved', 'go.mod': 'unsupported'}},
     'partial', ['requirements.txt']),
    ({'sca_skipped_reason': 'no_client', 'sca_dependencies': 3}, 'unavailable', []),
    ({'sca_skipped_reason': 'no_client', 'sca_dependencies': 1.0}, 'unavailable', []),
    ({'sca_skipped_reason': 'no_client', 'sca_dependencies': 9_007_199_254_740_991}, 'unavailable', []),
    ({'sca_skipped_reason': 'no_client', 'sca_dependencies': 9_007_199_254_740_992}, None, []),
    ({'sca_skipped_reason': 'no_client', 'sca_dependencies': 1.5}, None, []),
    ({'sca_skipped_reason': 'no_client', 'sca_dependencies': float('inf')}, None, []),
    ({'sca_skipped_reason': 'no_client', 'sca_dependencies': True}, None, []),
    ({'sca_skipped_reason': 'no_client', 'sca_dependencies': '3'}, None, []),
    ({'sca_skipped_reason': 'no_client'}, None, []),
    ({'sca_coverage_incomplete': True}, 'partial', []),
    ({'sca_skipped_reason': 'osv_unavailable:timeout'}, 'unavailable', []),
    ({'sca_skipped_reason': 'lockfile_unreadable:syntax'}, 'partial', []),
    ({'dependency_cve': {'status': 'partial', 'incomplete_manifests': {'go.mod': 'unsupported'}},
      'sca_incomplete_lockfiles': {'requirements.txt': 'unresolved'}}, 'partial', []),
    ({'dependency_cve': {'status': {}}, 'limitations': [{'dependency_coverage_incomplete': True}]}, None, []),
    ({'dependency_cve': {'status': 'partial', 'incomplete_manifests': ['requirements.txt']}}, 'partial', []),
    ({'dependency_cve': {'status': 'partial', 'incomplete_manifests': {
        'requirements.txt': ['unresolved'], '': 'unresolved', ' \t': 'unresolved'}}}, 'partial', []),
])
def test_dependency_scope_uses_explicit_facts_and_types(context, status, unresolved):
    from app.report.owner_report import dependency_coverage_gap

    before = deepcopy(context)
    expected = {'status': status, 'unresolved_manifests': unresolved} if status else None
    assert dependency_coverage_gap(context) == expected
    tasks = build_owner_roadmap([], context)['tasks']
    assert len(tasks) == int(status is not None)
    if tasks:
        assert tasks[0]['needs'][1:] == ['Unresolved manifest: ' + path for path in unresolved]
        assert ('exact installed versions' in tasks[0]['action']) == bool(unresolved)
    assert context == before


def test_known_review_directions_retain_every_original_reference_without_certifying_a_fix():
    case = next(case for case in CASES if case['name'] == 'five-review-directions')
    findings = deepcopy(case['input']['findings'])
    before = deepcopy(findings)
    tasks = build_owner_roadmap(findings)['tasks']
    assert len(tasks) == 5
    refs = [index for task in tasks for index in task['finding_indices']]
    assert sorted(refs) == list(range(len(findings)))
    assert len(refs) == len(set(refs))
    dependency = tasks[0]
    assert dependency['finding_indices'] == [0, 1, 2, 3]
    assert 'library, ecosystem, and installed version' in dependency['action']
    assert 'development dependencies, and unknown use' in dependency['action']
    assert 'before choosing an update' in dependency['action']
    assert all(task['kind'] == 'review' and not task['depends_on'] for task in tasks)
    assert 'synthetic fixtures do not require account-level rotation' in tasks[2]['action']
    assert 'Git tracking' in tasks[4]['needs'][1]
    assert findings == before


def test_html_specialized_review_directions_keep_escaped_links_and_immutable_exports():
    case = next(case for case in CASES if case['name'] == 'five-review-directions')
    findings = [{**finding, 'title': '<script>unsafe label</script>', 'severity': 'high',
                 'category': 'Security', 'confidence': 0.7, 'file': 'example.py', 'line': 1}
                for finding in deepcopy(case['input']['findings'])]
    report = {'findings': findings, 'score': {}}
    before = deepcopy(report)
    original_sarif = build_sarif(findings, score=report['score'], engine_version='test-engine')
    html = render_report(report)
    anchors = Anchors(html)
    assert '<script>unsafe label</script>' not in html
    assert '&lt;script&gt;unsafe label&lt;/script&gt;' in html
    assert set(anchors.links) <= set(anchors.ids)
    assert all(anchors.ids.count(f'roadmap-finding-{index}') == 1 for index in range(len(findings)))
    assert report == before
    assert build_sarif(findings, score=report['score'], engine_version='test-engine') == original_sarif

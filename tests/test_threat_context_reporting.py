"""Threat context explains priority without creating findings or trust claims."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from app.report.html import render_report
from app.report.project_checks import project_checks_record, project_checks_rows
from app.report.sarif import build_sarif
from app.report.threat_context import threat_context_record, threat_context_rows

FIXTURES = Path(__file__).parents[1] / 'web/src/lib/fixtures'
CASES = json.loads((FIXTURES / 'threat_context_cases.json').read_text())
PROJECT = json.loads((FIXTURES / 'project_checks_cases.json').read_text())[0]['value']


@pytest.mark.parametrize('case', CASES, ids=lambda case: case['name'])
def test_shared_python_web_threat_contract(case):
    original = deepcopy(case['value'])
    assert threat_context_rows(original) == [tuple(row) for row in case['rows']]
    assert original == case['value']


def test_invalid_context_preserves_source_and_binary_evidence():
    value = {**PROJECT, 'threat_context': {'status': 'completed', 'runtime_verified': True}}
    record = project_checks_record(value)
    assert record['source']['status'] == PROJECT['source']['status']
    assert record['binary_static']['status'] == PROJECT['binary_static']['status']
    assert record['threat_context']['status'] == 'unavailable'
    rows = project_checks_rows(value)
    assert rows[0][0] == 'Source'
    assert rows[3][0] == 'CISA KEV threat context'
    assert 'Unavailable' in rows[3][1]


def test_sarif_has_bounded_context_without_new_findings_or_changed_execution():
    threat = next(case['value'] for case in CASES if case['name'] == 'unknown_fields_not_exported')
    value = {**PROJECT, 'threat_context': threat}
    baseline = build_sarif([], engine_version='test', score={'scan_manifest': {'project_checks': PROJECT}})
    added = build_sarif([], engine_version='test', score={'scan_manifest': {'project_checks': value}})
    a, b = baseline['runs'][0], added['runs'][0]
    assert a['results'] == b['results'] == []
    assert a['invocations'][0]['executionSuccessful'] == b['invocations'][0]['executionSuccessful']
    exported = b['invocations'][0]['properties']['projectChecks']['threat_context']
    assert exported['matches'][0]['priority'] == 'expedited'
    assert exported['runtime_verified'] is False
    assert 'secret_extra' not in json.dumps(exported)
    assert 'severity' not in exported['matches'][0]


@pytest.mark.parametrize('status', ['partial', 'stale', 'unavailable'])
def test_incomplete_context_is_warning_not_scanner_failure(status):
    threat = deepcopy(CASES[0]['value'])
    threat['status'] = status
    if status == 'unavailable':
        threat.update(source=None, matched_cves=0, matches=[])
    value = {**PROJECT, 'threat_context': threat}
    sarif = build_sarif([], engine_version='test', score={'scan_manifest': {'project_checks': value}})
    invocation = sarif['runs'][0]['invocations'][0]
    assert invocation['executionSuccessful'] is True
    notice = next(item for item in invocation['toolExecutionNotifications']
                  if item['descriptor']['id'] == 'threat-context-incomplete')
    assert notice['level'] == 'warning'


def test_html_summary_is_visible_and_unsafe_labels_stay_text():
    value = {**PROJECT, 'threat_context': CASES[0]['value']}
    html = render_report({'score': {'scan_manifest': {'project_checks': value}}, 'findings': []})
    assert html.index('CISA KEV threat context') < html.index('Project evidence bindings')
    assert 'Project compromise is not established.' in html
    assert '&lt;svg onload=alert(1)&gt;' in html
    assert '<svg onload=alert(1)>' not in html
    assert '2026-11-23' not in html  # CISA's date is not presented as the user's deadline.


def test_legacy_report_keeps_prior_shape():
    assert 'threat_context' not in project_checks_record(PROJECT)
    assert not any(label.startswith('CISA') for label, _ in project_checks_rows(PROJECT))
    assert threat_context_record(None)['status'] == 'unavailable'

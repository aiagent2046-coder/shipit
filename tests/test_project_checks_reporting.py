"""Project evidence remains bounded, escaped and separate from findings."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from app.report.html import render_report
from app.report.project_checks import project_checks_record, project_checks_rows
from app.report.sarif import build_sarif

FIXTURES = Path(__file__).parents[1] / 'web/src/lib/fixtures/project_checks_cases.json'
CASES = json.loads(FIXTURES.read_text())


@pytest.mark.parametrize('case', CASES, ids=lambda case: case['name'])
def test_saved_evidence_rows_match_shared_contract(case):
    before = deepcopy(case['value'])
    assert project_checks_rows(case['value']) == [tuple(row) for row in case['rows']]
    assert case['value'] == before


def test_binary_facts_are_not_findings_or_authenticated_execution():
    value = CASES[0]['value']
    manifest = {'project_checks': value}
    sarif = build_sarif([], engine_version='test', score={'scan_manifest': manifest})
    run = sarif['runs'][0]
    assert run['results'] == []
    record = run['invocations'][0]['properties']['projectChecks']
    binary = record['binary_static']
    assert binary['runtime_verified'] is False
    assert binary['automatic_patch'] is False
    assert binary['provenance'] == 'operator_supplied'
    assert binary['artifacts'][0]['fact_counts'] == {'functions': 1, 'imports': 1}
    assert 'facts' not in binary['artifacts'][0]
    assert 'secret_extra' not in json.dumps(record)
    assert 'CVE-2099-1234' not in json.dumps(record)


def test_html_escapes_project_binding_and_explains_skipped_checks():
    value = CASES[0]['value']
    report = {'score': {'scan_manifest': {'project_checks': value}}, 'findings': []}
    html = render_report(report)
    assert 'aria-label="Project checks"' in html
    assert '&lt;img src=x onerror=alert(1)&gt;.elf' in html
    assert '<img src=x onerror=alert(1)>.elf' not in html
    assert 'hash consistency does not authenticate tool execution' in html
    assert 'not run: 1' in html
    assert 'CVE-2099-1234' not in html


def test_legacy_reports_do_not_gain_evidence():
    assert project_checks_record(None) is None
    sarif = build_sarif([], engine_version='test', score={'scan_manifest': {}})
    assert 'projectChecks' not in sarif['runs'][0]['invocations'][0]['properties']

"""Offline false-success controls; the production matcher supplies baseline evidence."""
from copy import deepcopy
import json
import os
import sys

import pytest

from scripts import verify_dependency_remediation as contract


@pytest.fixture(scope='module')
def catalog():
    return json.loads((contract.ROOT / 'app/data/cve-catalog.json').read_bytes())


def manifest_files(case, version, *, nested_old=False):
    if case.ecosystem == 'PyPI':
        return {'requirements.txt': f'sqlparse=={version}\nDjango==5.2.10\n'.encode()}
    packages = {
        '': {'name': 'trusted-contract', 'version': '1.0.0'},
        'node_modules/picomatch': {'version': version},
        'node_modules/@rollup/pluginutils': {'version': '4.1.2'},
    }
    if nested_old:
        packages['node_modules/other/node_modules/picomatch'] = {'version': case.before}
    return {'package-lock.json': json.dumps({
        'name': 'trusted-contract', 'version': '1.0.0', 'lockfileVersion': 3,
        'packages': packages,
    }).encode()}


def make_stage(case, name, catalog, *, nested_old=False):
    after = name == 'after'
    version = case.after if after else case.before
    files = manifest_files(case, version, nested_old=nested_old)
    consumer = {
        'package': case.package, 'installed_version': version,
        'consumer': case.consumer, 'consumer_version': case.consumer_version,
        'functional_passed': True, 'functional_checks': case.checks,
    }
    if case.ecosystem == 'PyPI':
        consumer['regression'] = {
            'id': 'python-snippet-backslash-escaping', 'passed': after,
            'outcome': 'literal_roundtrip' if after else 'SyntaxError',
        }
    return {
        'name': name, 'consumer': consumer, 'scan': contract.scan(files, case, catalog),
        'manifest_sha256': {name: contract.digest(raw) for name, raw in files.items()},
    }


@pytest.fixture(scope='module')
def cycles(catalog):
    return {key: [make_stage(case, name, catalog) for name in ('before', 'after', 'restore')]
            for key, case in contract.CASES.items()}


def target_row(case, stage):
    return next(row for row in stage['scan']['inventory']
                if row['ecosystem'] == case.ecosystem and row['package'] == case.package)


@pytest.mark.parametrize('key,expected', [('npm', 2), ('pypi', 5)])
def test_real_matcher_card_and_restored_mutation_pass(cycles, key, expected):
    case = contract.CASES[key]
    stages = cycles[key]
    assert [len(contract.target_findings(case, s['scan'])) for s in stages] == [expected, 0, expected]
    contract.verify_cycle(case, stages)
    # Other package uncertainty is preserved, never presented as application safety.
    if key == 'pypi':
        assert stages[1]['scan']['coverage']['status_counts']['unknown'] > 0


@pytest.mark.parametrize('key', ['npm', 'pypi'])
def test_new_lockfile_cannot_hide_stale_installed_version(cycles, key):
    case = contract.CASES[key]
    stage = deepcopy(cycles[key][1])
    stage['consumer']['installed_version'] = case.before
    with pytest.raises(contract.ContractError, match='installed_version_mismatch'):
        contract.verify_stage(case, stage)


def test_nested_vulnerable_npm_copy_blocks_success(catalog):
    case = contract.CASES['npm']
    stage = make_stage(case, 'after', catalog, nested_old=True)
    assert len(contract.target_findings(case, stage['scan'])) == 2
    with pytest.raises(contract.ContractError, match='resolved_version_mismatch'):
        contract.verify_stage(case, stage)


@pytest.mark.parametrize('fault,reason', [
    ('empty_inventory', 'resolved_version_mismatch'),
    ('empty_assessments', 'target_not_assessed'),
    ('incomplete_identity', 'target_not_assessed'),
    ('unknown', 'target_assessment_unknown'),
    ('not_in_catalog', 'target_assessment_unknown'),
    ('unresolved_ranges', 'target_ranges_unresolved'),
    ('empty_entry_assessments', 'target_ranges_unresolved'),
    ('still_affected', 'target_still_affected'),
])
def test_no_findings_is_not_positive_evidence(cycles, fault, reason):
    case = contract.CASES['npm']
    stage = deepcopy(cycles['npm'][1])
    report = stage['scan']
    row = target_row(case, stage)
    assert not report['findings']
    if fault == 'empty_inventory':
        report['inventory'] = []
    elif fault == 'empty_assessments':
        row['assessments'] = []
    elif fault == 'incomplete_identity':
        row['complete'] = False
    elif fault in {'unknown', 'not_in_catalog'}:
        row['assessments'][0]['status'] = fault
    elif fault == 'unresolved_ranges':
        report['target_entry_assessments'][0]['unresolved_ranges'] = 1
    elif fault == 'empty_entry_assessments':
        report['target_entry_assessments'] = []
    else:
        report['target_entry_assessments'][0]['status'] = 'affected'
    with pytest.raises(contract.ContractError, match=reason):
        contract.verify_stage(case, stage)


@pytest.mark.parametrize('key', [
    'incomplete_manifests', 'inventory_truncated', 'findings_truncated', 'evaluations_truncated',
])
def test_truncated_scan_cannot_verify_fixture(cycles, key):
    stage = deepcopy(cycles['npm'][1])
    stage['scan']['coverage'][key] = {'package-lock.json': 'unresolved'} if key == 'incomplete_manifests' else 1
    with pytest.raises(contract.ContractError, match='scan_incomplete'):
        contract.verify_stage(contract.CASES['npm'], stage)


def test_baseline_must_actually_recommend_chosen_candidate(cycles):
    case = contract.CASES['npm']
    stage = deepcopy(cycles['npm'][0])
    for finding in contract.target_findings(case, stage['scan']):
        card = finding['claim_evidence']['remediation']
        card['candidate_versions'] = []
        card['status'] = 'manual_review'
    with pytest.raises(contract.ContractError, match='candidate_not_in_card'):
        contract.verify_stage(case, stage)


@pytest.mark.parametrize('order', [[], [0, 1], [0, 2, 1], [0, 1, 1], [0, 1, 2, 2]])
def test_cycle_requires_exact_three_stages(cycles, order):
    with pytest.raises(contract.ContractError, match='missing_or_reordered_stage'):
        contract.verify_cycle(contract.CASES['npm'], [cycles['npm'][i] for i in order])


def test_restore_must_reinstall_old_version(cycles):
    stages = deepcopy(cycles['npm'])
    stages[2]['consumer']['installed_version'] = contract.CASES['npm'].after
    with pytest.raises(contract.ContractError, match='installed_version_mismatch'):
        contract.verify_cycle(contract.CASES['npm'], stages)


def test_restore_must_restore_exact_manifest(cycles):
    stages = deepcopy(cycles['npm'])
    stages[2]['manifest_sha256']['package-lock.json'] = 'different'
    with pytest.raises(contract.ContractError, match='restore_manifest_mismatch'):
        contract.verify_cycle(contract.CASES['npm'], stages)


def test_restore_cannot_drop_one_original_advisory(cycles):
    stages = deepcopy(cycles['npm'])
    stages[2]['scan']['findings'].pop()
    with pytest.raises(contract.ContractError, match='affected_findings_incomplete'):
        contract.verify_cycle(contract.CASES['npm'], stages)


@pytest.mark.parametrize('key', ['npm', 'pypi'])
def test_identically_incomplete_baseline_and_restore_cannot_pass(cycles, key):
    case = contract.CASES[key]
    stages = deepcopy(cycles[key])
    for stage in (stages[0], stages[2]):
        finding = contract.target_findings(case, stage['scan'])[0]
        stage['scan']['findings'].remove(finding)
    # Comparing before and restore alone would incorrectly accept this cycle.
    assert stages[0]['scan']['findings'] == stages[2]['scan']['findings']
    assert not contract.target_findings(case, stages[1]['scan'])
    with pytest.raises(contract.ContractError, match='affected_findings_incomplete'):
        contract.verify_cycle(case, stages)


def test_restore_findings_cannot_silently_change_other_evidence(cycles):
    stages = deepcopy(cycles['npm'])
    stages[2]['scan']['findings'][0]['severity'] = 'changed'
    with pytest.raises(contract.ContractError, match='restore_findings_mismatch'):
        contract.verify_cycle(contract.CASES['npm'], stages)


def test_unrelated_dependency_update_is_not_a_narrow_contract(cycles):
    stages = deepcopy(cycles['npm'])
    other = next(row for row in stages[1]['scan']['inventory'] if row['package'] != 'picomatch')
    other['version'] = '99.0.0'
    with pytest.raises(contract.ContractError, match='unrelated_dependency_changed'):
        contract.verify_cycle(contract.CASES['npm'], stages)


@pytest.mark.parametrize('stage_index,outcome,passed', [
    (0, 'TimeoutError', False), (2, 'ImportError', False),
    (1, 'SyntaxError', False), (0, 'literal_roundtrip', True),
])
def test_runtime_error_is_not_expected_security_regression(cycles, stage_index, outcome, passed):
    stage = deepcopy(cycles['pypi'][stage_index])
    stage['consumer']['regression'].update(outcome=outcome, passed=passed)
    with pytest.raises(contract.ContractError, match='escaping_regression_mismatch'):
        contract.verify_stage(contract.CASES['pypi'], stage)


@pytest.mark.parametrize('checks,passed', [(0, True), (8, True), (True, True), (9, False)])
def test_missing_or_failed_consumer_controls_cannot_pass(cycles, checks, passed):
    stage = deepcopy(cycles['npm'][1])
    stage['consumer'].update(functional_checks=checks, functional_passed=passed)
    with pytest.raises(contract.ContractError, match='consumer_checks_failed'):
        contract.verify_stage(contract.CASES['npm'], stage)


@pytest.mark.parametrize('install,status', [(False, 'failed'), (True, 'unavailable')])
def test_command_nonzero_exit_is_never_success(tmp_path, install, status):
    with pytest.raises(contract.ContractError) as exc:
        contract.command([sys.executable, '-c', 'raise SystemExit(3)'], tmp_path,
                         dict(os.environ), tmp_path / 'failed.log', install=install)
    assert exc.value.status == status
    assert exc.value.reason == 'command_failed:failed'


def test_command_timeout_is_unavailable_not_security_proof(tmp_path):
    with pytest.raises(contract.ContractError) as exc:
        contract.command([sys.executable, '-c', 'import time; time.sleep(30)'], tmp_path,
                         dict(os.environ), tmp_path / 'timeout.log', timeout=0.05)
    assert exc.value.status == 'unavailable'
    assert exc.value.reason == 'command_timeout:timeout'


def test_missing_package_manager_is_unavailable(tmp_path):
    with pytest.raises(contract.ContractError) as exc:
        contract.command([str(tmp_path / 'nonexistent-manager')], tmp_path,
                         dict(os.environ), tmp_path / 'missing.log')
    assert exc.value.status == 'unavailable'
    assert exc.value.reason == 'command_unavailable:missing'


@pytest.mark.parametrize('status,expected', [('passed', 0), ('failed', 1), ('unavailable', 2)])
def test_main_persists_failure_and_never_turns_unavailable_into_skip(monkeypatch, tmp_path, status, expected):
    result = {'contract_id': 'dependency-remediation-npm', 'status': status,
              'fixture_verified': status == 'passed', 'reason': 'test-observation'}
    monkeypatch.setattr(contract, 'run', lambda case, output: result)
    output = tmp_path / 'evidence'
    assert contract.main(['--case', 'npm', '--output-dir', str(output)]) == expected
    assert json.loads((output / 'result.json').read_text()) == result


def test_existing_evidence_is_rejected_before_any_execution(monkeypatch, tmp_path):
    marker = tmp_path / 'result.json'
    marker.write_text('prior evidence')

    def forbidden_run(*args):
        pytest.fail('Existing output must be rejected before installing or executing anything')

    monkeypatch.setattr(contract, 'run', forbidden_run)
    with pytest.raises(FileExistsError):
        contract.main(['--case', 'npm', '--output-dir', str(tmp_path)])
    assert marker.read_text() == 'prior evidence'

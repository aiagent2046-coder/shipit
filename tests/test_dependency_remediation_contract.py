"""Offline false-success controls; the production matcher supplies baseline evidence."""
from copy import deepcopy
import json
import os
import sys

import pytest

from scripts import verify_dependency_remediation as contract


@pytest.fixture(scope='module')
def catalog():
    return contract.read_catalog('historical-fixture')[2]


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
              'fixture_verified': status == 'passed', 'reason': 'test-observation',
              'catalog_scope': 'shipped', 'current_candidate_verified': status == 'passed'}

    def fake_run(case, output, *, catalog_scope):
        assert catalog_scope == 'shipped'
        return result

    monkeypatch.setattr(contract, 'run', fake_run)
    output = tmp_path / 'evidence'
    assert contract.main(['--case', 'npm', '--output-dir', str(output)]) == expected
    assert json.loads((output / 'result.json').read_text()) == result


def test_historical_catalog_requires_exact_reviewed_bytes(monkeypatch, tmp_path):
    _, raw, catalog = contract.read_catalog('historical-fixture')
    assert catalog['fixture_provenance']['shipit_revision'] == 'b1e0d50d235b0fb6963504e65e459be5b5e9295e'
    assert catalog['fixture_provenance']['source_sha256'] == (
        'df1d847b192c8d9de21331a0dd103a6ea3c971815c1b8ee4964f2bab96bf49df')
    (tmp_path / 'historical-catalog.json').write_bytes(raw + b' ')
    monkeypatch.setattr(contract, 'FIXTURES', tmp_path)
    with pytest.raises(contract.ContractError, match='historical_catalog_digest_mismatch'):
        contract.read_catalog('historical-fixture')


@pytest.mark.parametrize('scope', ['shipped', 'historical-fixture'])
def test_cli_scope_is_explicit_in_summary_and_report(monkeypatch, tmp_path, capsys, scope):
    result = {'version': 2, 'contract_id': 'dependency-remediation-npm', 'status': 'passed',
              'fixture_verified': True, 'catalog_scope': scope, 'current_candidate_verified': False}

    def fake_run(case, output, *, catalog_scope):
        assert catalog_scope == scope
        return result

    monkeypatch.setattr(contract, 'run', fake_run)
    output = tmp_path / 'evidence'
    assert contract.main(['--case', 'npm', '--catalog-scope', scope, '--output-dir', str(output)]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary['catalog_scope'] == scope
    assert summary['current_candidate_verified'] is False
    assert json.loads((output / 'result.json').read_text()) == result


@pytest.fixture(params=[
    ('npm', 'CVE-2026-112366', '4.0.7'), ('pypi', 'CVE-2026-112307', '0.6.0'),
])
def unknown_catalog(request, catalog):
    key, advisory_id, bound = request.param
    case = contract.CASES[key]
    # Exact matching fields compiled from CVE List 1c63dfb4e7f9626e401fa1c10d625cdb55037216.
    # Keep these regression inputs fixed if the shipped advisory snapshot changes.
    entry = {'id': advisory_id, 'url': 'https://www.cve.org/CVERecord?id=' + advisory_id,
             'default_status': 'unaffected', 'unsupported_applicability': True,
             'versions': [{'version': '0', 'lessThanOrEqual': bound,
                           'status': 'affected', 'versionType': 'semver'}]}
    regression = deepcopy(catalog)
    regression['packages'][case.ecosystem + ':' + case.package].append(entry)
    return case, advisory_id, regression


def test_unknown_applicability_cannot_become_historical_success(unknown_catalog):
    case, advisory_id, regression = unknown_catalog
    for name in ('before', 'after', 'restore'):
        stage = make_stage(case, name, regression)
        unknown = next(a for a in target_row(case, stage)['assessments'] if advisory_id in a['advisory_ids'])
        assert unknown['status'] == 'unknown'
        assert unknown['reported'] is False
        with pytest.raises(contract.ContractError, match='target_assessment_unknown'):
            contract.verify_stage(case, stage)


def test_historical_after_keeps_full_current_catalog_rejection(catalog, unknown_catalog, monkeypatch, tmp_path):
    case, _, shipped = unknown_catalog
    raw = json.dumps(shipped).encode()
    path = tmp_path / 'shipped.json'
    path.write_bytes(raw)

    def read_current(scope):
        assert scope == 'shipped'
        return path, raw, shipped

    monkeypatch.setattr(contract, 'read_catalog', read_current)
    stage = make_stage(case, 'after', catalog)
    contract.verify_stage(case, stage)
    result = contract.current_candidate_assessment(case, stage, manifest_files(case, case.after))
    assert result['candidate_verified'] is False
    assert result['status'] == 'blocked'
    assert result['reason'] == 'target_assessment_unknown'
    assert result['catalog_sha256'] == contract.digest(raw)
    assert result['stage']['scan']['coverage']['advisory_evaluations'] == (
        contract.scan(manifest_files(case, case.after), case, shipped)['coverage']['advisory_evaluations'])
    assert result['stage']['scan']['coverage']['unknown_reason_counts']['unsupported_applicability'] > 0


def test_current_candidate_diagnostic_rejects_baseline_stage(cycles):
    result = contract.current_candidate_assessment(contract.CASES['npm'], cycles['npm'][0], {})
    assert result['candidate_verified'] is False
    assert result['reason'] == 'current_candidate_stage_mismatch'


def mock_npm_commands(monkeypatch, catalog, *, on_restore=lambda: None, restore_valid=True):
    """Keep orchestration and matcher real, substituting only registry/process I/O."""
    case = contract.CASES['npm']

    def command(args, cwd, env, log, **kwargs):
        if args[-1] == '--version':
            return 'test-manager-version'
        if args[:2] == ['npm', 'install']:
            path = cwd / 'package-lock.json'
            lock = json.loads(path.read_bytes())
            lock['packages']['node_modules/picomatch']['version'] = case.after
            path.write_text(json.dumps(lock))
        if args[0] == 'node':
            installed = cwd / 'installed.js'
            installed.write_text('fixture')
            probe = make_stage(case, cwd.name, catalog)['consumer']
            probe['installed_path'] = str(installed)
            if cwd.name == 'restore':
                on_restore()
                probe['functional_passed'] = restore_valid
            return json.dumps(probe)
        return ''

    monkeypatch.setattr(contract, 'command', command)


@pytest.mark.parametrize('fault,expected_status,expected_current,reason', [
    (None, 'passed', True, None),
    ('restore', 'failed', False, 'consumer_checks_failed'),
    ('historical_changed', 'failed', False, 'catalog_changed_during_run'),
    ('current_changed', 'passed', False, 'current_catalog_changed_during_run'),
    ('current_unavailable', 'passed', False, 'current_catalog_unavailable'),
    ('evidence_write', 'unavailable', False, 'execution_unavailable'),
])
def test_current_success_requires_complete_cycle_and_stable_catalog(
        monkeypatch, tmp_path, catalog, fault, expected_status, expected_current, reason):
    raw = json.dumps(catalog).encode()
    paths = {scope: tmp_path / (scope + '.json') for scope in ('shipped', 'historical-fixture')}
    for path in paths.values():
        path.write_bytes(raw)

    current_reads = 0

    def read_catalog(scope):
        nonlocal current_reads
        if scope == 'shipped':
            current_reads += 1
            if current_reads == 2:
                if fault == 'current_changed':
                    paths[scope].write_bytes(raw + b' ')
                elif fault == 'current_unavailable':
                    paths[scope].unlink()
        current_raw = paths[scope].read_bytes()
        return paths[scope], current_raw, json.loads(current_raw)

    def on_restore():
        if fault == 'historical_changed':
            paths['historical-fixture'].write_bytes(raw + b' ')

    original_save = contract.save

    def save(path, value):
        original_save(path, value)
        if fault == 'evidence_write' and value.get('candidate_verified'):
            raise OSError('write failed')

    monkeypatch.setattr(contract, 'read_catalog', read_catalog)
    monkeypatch.setattr(contract, 'save', save)
    mock_npm_commands(monkeypatch, catalog, on_restore=on_restore, restore_valid=fault != 'restore')
    result = contract.run('npm', tmp_path, catalog_scope='historical-fixture')
    assert result['status'] == expected_status
    assert result['fixture_verified'] is (expected_status == 'passed')
    assert result['current_candidate_verified'] is expected_current
    if reason:
        evidence = result if expected_status != 'passed' else result['current_catalog']
        assert evidence['reason'] == reason
    if fault in {'restore', 'historical_changed'}:
        assert 'current_catalog' not in result
        assert not (tmp_path / 'current-catalog-evidence.json').exists()
        assert current_reads == 0
    else:
        assert json.loads((tmp_path / 'current-catalog-evidence.json').read_text()) == result['current_catalog']
        assert result['current_catalog']['candidate_verified'] is expected_current


def test_default_run_fails_closed_on_current_unknown(monkeypatch, tmp_path, unknown_catalog):
    case, _, catalog = unknown_catalog
    raw = json.dumps(catalog).encode()
    path = tmp_path / 'shipped.json'
    path.write_bytes(raw)

    def read_current(scope):
        assert scope == 'shipped'
        return path, raw, catalog

    monkeypatch.setattr(contract, 'read_catalog', read_current)
    if case.ecosystem == 'npm':
        mock_npm_commands(monkeypatch, catalog)
    else:
        def command(args, cwd, env, log, **kwargs):
            if args[-1] == '--version':
                return 'test-manager-version'
            if args[-1] == 'freeze':
                return manifest_files(case, case.before)['requirements.txt'].decode()
            if args[-1].endswith('consumer.py'):
                installed = cwd / 'installed.py'
                installed.write_text('fixture')
                return json.dumps({**make_stage(case, cwd.name, catalog)['consumer'],
                                   'installed_path': str(installed)})
            return ''

        monkeypatch.setattr(contract, 'command', command)
    result = contract.run('npm' if case.ecosystem == 'npm' else 'pypi', tmp_path)
    assert result['status'] == 'failed'
    assert result['reason'] == 'target_assessment_unknown'
    assert result['fixture_verified'] is False
    assert result['current_candidate_verified'] is False
    assert result['catalog_scope'] == 'shipped'


def test_shipped_scope_reads_full_catalog():
    path, raw, catalog = contract.read_catalog('shipped')
    assert path == contract.ROOT / 'app/data/cve-catalog.json'
    assert raw == path.read_bytes()
    assert catalog == json.loads(raw)
    assert 'fixture_provenance' not in catalog


def test_existing_evidence_is_rejected_before_any_execution(monkeypatch, tmp_path):
    marker = tmp_path / 'result.json'
    marker.write_text('prior evidence')

    def forbidden_run(*args):
        pytest.fail('Existing output must be rejected before installing or executing anything')

    monkeypatch.setattr(contract, 'run', forbidden_run)
    with pytest.raises(FileExistsError):
        contract.main(['--case', 'npm', '--output-dir', str(tmp_path)])
    assert marker.read_text() == 'prior evidence'


def test_network_and_runtime_environment_survives_without_package_config(monkeypatch, tmp_path):
    # These runtime/CA values are required by setup-python and managed proxies.
    for key in ('LD_LIBRARY_PATH', 'NODE_EXTRA_CA_CERTS', 'NPM_CONFIG_HTTPS_PROXY'):
        monkeypatch.setenv(key, 'required-host-setting')
    for key in ('NODE_OPTIONS', 'PYTHONPATH', 'NPM_TOKEN', 'PIP_EXTRA_INDEX_URL', 'GITHUB_TOKEN'):
        monkeypatch.setenv(key, 'must-not-propagate')
    env = contract.execution_env(tmp_path)
    assert all(env[key] == 'required-host-setting'
               for key in ('LD_LIBRARY_PATH', 'NODE_EXTRA_CA_CERTS', 'NPM_CONFIG_HTTPS_PROXY'))
    assert 'must-not-propagate' not in env.values()
    # npm refuses to load the same config path twice, including /dev/null.
    assert env['NPM_CONFIG_USERCONFIG'] != env['NPM_CONFIG_GLOBALCONFIG']

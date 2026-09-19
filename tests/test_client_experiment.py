"""Adversarial checks of constructed receipts; these tests do not run Cumora."""

import hashlib
import json
from pathlib import Path
from uuid import UUID

import pytest

from app.scan.client_runtime_record import ARCHIVE_SHA256, SCENARIO_ID, SCENARIO_SHA256
from scripts.cumora_experiment import compare
from tests.test_client_runtime_record import runtime_evidence


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def read_json(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rebind_plan(root):
    """Allow source-plan attacks to reach semantic checks, past handoff hashing."""
    receipt = read_json(root / 'researcher.json')
    receipt['output_sha256'] = sha(root / 'plan.json')
    write_json(root / 'researcher.json', receipt)


@pytest.fixture
def cycle(tmp_path):
    scenario = Path(compare.__file__).with_name('scenario.mjs').read_bytes()
    assert hashlib.sha256(scenario).hexdigest() == SCENARIO_SHA256
    bindings = {}
    for index, name in enumerate(('baseline', 'mutant', 'restored'), start=1):
        directory = tmp_path / name
        directory.mkdir()
        run_id = str(UUID(int=index))
        binding = dict(run_id=run_id, router_sha256=('b' if name == 'mutant' else 'a') * 64,
                       tree_sha256=('d' if name == 'mutant' else 'c') * 64)
        write_json(directory / 'source-manifest.json', {
            'server/src/api/router.ts': binding['router_sha256'],
            'server/src/auth.ts': 'e' * 64,
        })
        binding['tree_sha256'] = sha(directory / 'source-manifest.json')
        bindings[name] = binding
        evidence = runtime_evidence()
        evidence['run_id'] = run_id
        if name == 'mutant':
            evidence['status'] = 'failed'
            evidence['checks'] = evidence['checks'][:7]
            evidence['checks'][-1]['pass'] = False
            evidence['checks'][-1]['actual']['ids'] = [evidence['fixtures']['project_id']]
            evidence['error'] = dict(kind='Error', reason='check_failed:list_other', code=None)
        write_json(directory / 'scenario.json', evidence)
        write_json(directory / 'probe.json', {'status': 'passed'})
        write_json(directory / 'execution.json', dict(variant=name, run_id=run_id,
                   project='disposable-' + name, status='executed', readiness=True,
                   scenario_exit=1 if name == 'mutant' else 0, cleanup_exit=0))
        (directory / 'scenario.mjs').write_bytes(scenario)
        for filename, content in {
            'fixture-reset.log': '0', 'image-id.txt': 'sha256:' + str(index) * 64,
            'run-id.txt': run_id, 'observed-router-sha256.txt': binding['router_sha256'],
            'observed-tree-sha256.txt': binding['tree_sha256'],
            'archive.txt': 'archive_sha256=' + ARCHIVE_SHA256,
            'cleanup-exit.txt': '0', 'scenario-exit.txt': '1' if name == 'mutant' else '0',
        }.items():
            (directory / filename).write_text(content + '\n')
    output = dict(archive_sha256=ARCHIVE_SHA256, selected_scenario_id=SCENARIO_ID,
                  router_sha256=bindings['baseline']['router_sha256'])
    output_hash = hashlib.sha256((json.dumps(output, sort_keys=True, indent=2) + '\n').encode()).hexdigest()
    write_json(tmp_path / 'detector.json', dict(schema_version=1, role='detector', status='completed',
               llm_calls=0, input_sha256=ARCHIVE_SHA256, output=output, output_sha256=output_hash))
    plan = dict(
        schema_version=1, archive_sha256=ARCHIVE_SHA256, scenario_id=SCENARIO_ID,
        scenario_sha256=SCENARIO_SHA256, router_path='server/src/api/router.ts',
        mutation=dict(id='remove-project-list-tenant-predicate', before='WHERE company_id = $1',
                      after='WHERE $1::text IS NOT NULL', changed_files=['server/src/api/router.ts'],
                      scope='GET /projects only; one predicate substitution; parameter count unchanged'),
        llm_calls=0, fixture_setup='clear_projects_in_disposable_database', variants=bindings,
        detector_output_sha256=output_hash,
        restoration=dict(method='inverse_predicate_on_mutant_copy', from_variant='mutant',
                         changed_files=['server/src/api/router.ts'], exact_original_tree=True),
    )
    write_json(tmp_path / 'plan.json', plan)
    write_json(tmp_path / 'researcher.json', dict(schema_version=1, role='researcher', status='completed',
               llm_calls=0, input_sha256=sha(tmp_path / 'detector.json'),
               output_sha256=sha(tmp_path / 'plan.json'), output_artifact='plan.json'))
    return tmp_path


def test_three_variant_cycle_preserves_scope_and_observations(cycle):
    verdict = compare.compare(cycle)
    assert verdict['cycle_status'] == 'passed'
    assert verdict['controlled_restoration_verified'] is True
    assert verdict['llm_calls'] == 0
    assert verdict['verification'] == 'host_side_evidence_consistency'
    assert verdict['customer_project_verified'] is False
    assert verdict['vulnerability_remediation_verified'] is False
    assert verdict['automatic_patch'] is False
    assert {name: (value['status'], value['checks_observed'])
            for name, value in verdict['variants'].items()} == {
                'baseline': ('accepted', 12), 'mutant': ('rejected', 7), 'restored': ('accepted', 12),
            }
    assert verdict['variants']['mutant']['reason'] == 'tenant_leak'


@pytest.mark.parametrize('filename,value', [
    ('scenario-exit.txt', '124'), ('cleanup-exit.txt', '1'),
    ('probe.json', '{"status": "failed"}'),
])
def test_infrastructure_failure_is_unavailable_not_detected_leak(cycle, filename, value):
    (cycle / 'mutant' / filename).write_text(value)
    with pytest.raises(compare.Unavailable):
        compare.compare(cycle)


def test_unrelated_scenario_error_is_unavailable(cycle):
    path = cycle / 'mutant' / 'scenario.json'
    report = read_json(path)
    report['error']['reason'] = 'ECONNRESET'
    write_json(path, report)
    with pytest.raises(compare.Unavailable, match='without tenant-disclosure'):
        compare.compare(cycle)


@pytest.mark.parametrize('ids', [[], ['p-unrelated']])
def test_failed_boolean_without_actual_disclosure_is_rejected(cycle, ids):
    path = cycle / 'mutant' / 'scenario.json'
    report = read_json(path)
    report['checks'][-1]['actual']['ids'] = ids
    write_json(path, report)
    with pytest.raises(ValueError, match='disclosure missing'):
        compare.compare(cycle)


@pytest.mark.parametrize('filename', ['run-id.txt', 'observed-router-sha256.txt', 'scenario.mjs'])
def test_swapped_execution_binding_rejected(cycle, filename):
    path = cycle / 'mutant' / filename
    path.write_bytes((cycle / 'baseline' / filename).read_bytes() if filename != 'scenario.mjs'
                     else b'console.log("different scenario")')
    with pytest.raises(ValueError):
        compare.compare(cycle)


@pytest.mark.parametrize('filename', ['observed-tree-sha256.txt', 'source-manifest.json'])
def test_full_source_binding_rejected_even_when_router_hash_matches(cycle, filename):
    path = cycle / 'restored' / filename
    if filename == 'source-manifest.json':
        manifest = read_json(path)
        manifest['server/src/auth.ts'] = 'f' * 64
        write_json(path, manifest)
    else:
        path.write_text('f' * 64 + '\n')
    with pytest.raises(ValueError, match='Executed source tree mismatch'):
        compare.compare(cycle)


@pytest.mark.parametrize('field', ['router_sha256', 'tree_sha256'])
def test_restored_source_must_equal_baseline_even_with_rehashed_plan(cycle, field):
    path = cycle / 'plan.json'
    plan = read_json(path)
    plan['variants']['restored'][field] = plan['variants']['mutant'][field]
    write_json(path, plan)
    rebind_plan(cycle)
    with pytest.raises(ValueError, match='Restored source differs'):
        compare.compare(cycle)


@pytest.mark.parametrize('variant', ['baseline', 'restored'])
def test_positive_pass_flags_cannot_hide_changed_database(cycle, variant):
    path = cycle / variant / 'scenario.json'
    report = read_json(path)
    report['checks'][9]['actual']['rows'][0]['name'] = 'unauthorized write'
    write_json(path, report)
    with pytest.raises(ValueError):
        compare.compare(cycle)


@pytest.mark.parametrize('artifact', ['plan.json', 'detector.json', 'researcher.json',
                                     'baseline/scenario.json', 'mutant/scenario.json'])
def test_duplicate_json_keys_fail_closed(cycle, artifact):
    path = cycle / artifact
    text = path.read_text()
    path.write_text('{"schema_version": 1,' + text[1:])
    with pytest.raises(ValueError, match='Duplicate JSON key'):
        compare.compare(cycle)


def test_changed_handoff_rejected(cycle):
    path = cycle / 'detector.json'
    receipt = read_json(path)
    receipt['output']['router_sha256'] = 'f' * 64
    write_json(path, receipt)
    with pytest.raises(ValueError, match='Detector output binding'):
        compare.compare(cycle)


def test_experiment_scenario_matches_import_contract():
    script = Path(compare.__file__).with_name('scenario.mjs')
    contract = script.parent.parent / 'runtime_contracts' / 'cumora_project_tenant_isolation_v1.mjs'
    assert script.read_bytes() == contract.read_bytes()


@pytest.mark.parametrize('field,value', [('variant', 'baseline'), ('readiness', 1),
                                       ('scenario_exit', True), ('cleanup_exit', False),
                                       ('status', 'failed')])
def test_execution_receipt_cannot_misrepresent_process_outcome(cycle, field, value):
    path = cycle / 'mutant' / 'execution.json'
    receipt = read_json(path)
    receipt[field] = value
    write_json(path, receipt)
    with pytest.raises(ValueError):
        compare.compare(cycle)

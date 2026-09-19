"""Adversarial contract checks for untrusted client runtime receipts."""
from copy import deepcopy

import pytest

from app.scan.client_runtime_record import (
    ARCHIVE_SHA256, CHECK_IDS, SCENARIO_ID, SCENARIO_SHA256,
    normalize_client_runtime_record, validate_client_runtime_evidence,
)

RUN_ID = 'c92c6f5f-6759-4768-b768-2d42408bf3de'


def runtime_evidence():
    f = dict(company_a='control-company-a-1234', company_b='control-company-b-1234',
             project_id='p-1234-abcd', original_name='Original', updated_name='Updated',
             original_description='Disposable runtime scenario',
             updated_description='Updated through authenticated HTTP')
    original = dict(company_id=f['company_a'], name=f['original_name'],
                    description=f['original_description'], status='active', archived_at=None)
    updated = dict(original, name=f['updated_name'], description=f['updated_description'])
    actuals = [
        {'status': 401},
        {'status': 201, 'body': dict(id=f['project_id'], name=f['original_name'],
             description=f['original_description'], status='active', extra='discard me')},
        {'rows': [original]}, {'status': 200, 'ids': [f['project_id']]},
        {'status': 200, 'body': {'ok': True}}, {'rows': [updated]},
        {'status': 200, 'ids': []}, {'status': 403}, {'status': 404},
        {'rows': [deepcopy(updated)]}, {'status': 200, 'body': {'ok': True, 'status': 'archived'}},
        {'rows': [dict(updated, status='archived', archived_at='2026-09-19T14:38:00.000Z')]},
    ]
    return dict(schema_version=1, scenario_sha256=SCENARIO_SHA256, scenario_id=SCENARIO_ID,
        run_id=RUN_ID, archive_sha256=ARCHIVE_SHA256, scope='client_application_runtime',
        status='passed', started_at='2026-09-19T14:37:00.000Z', finished_at='2026-09-19T14:39:00.000Z',
        authentication='dedicated_database_seeded_sessions', vulnerabilityRemediationVerified=False,
        oauthVerified=False, wholeApplicationVerified=False, fixtures=f,
        checks=[dict(id=name, actual=actual, **{'pass': True}) for name, actual in zip(CHECK_IDS, actuals)])


def validate(evidence, **kwargs):
    return validate_client_runtime_evidence(evidence, archive_sha256=kwargs.get('archive_sha256', ARCHIVE_SHA256),
                                            run_id=kwargs.get('run_id', RUN_ID))


def test_valid_evidence_is_bounded_consistency_record_not_attestation():
    evidence = runtime_evidence()
    record = validate(evidence)
    assert record['state'] == 'reported_scenario_passed'
    assert record['trust'] == 'operator_supplied_consistency_only'
    assert record['checks'] == list(CHECK_IDS)
    for flag in ('runtime_verified', 'customer_project_verified', 'automatic_patch',
                 'automatic_apply', 'vulnerability_remediation_verified', 'oauth_verified'):
        assert record[flag] is False
    assert 'extra' not in record['evidence']['checks'][1]['actual']['body']
    assert normalize_client_runtime_record(record, archive_sha256=ARCHIVE_SHA256) == record
    evidence['fixtures']['company_a'] = 'changed-after-import'
    assert record['evidence']['fixtures']['company_a'] != 'changed-after-import'


@pytest.mark.parametrize('field,value', [
    ('archive_sha256', '0' * 64), ('scenario_sha256', '0' * 64),
    ('scenario_id', 'other'), ('run_id', 'a07d3b84-1c26-433b-b728-f1dc0e0c34ff'),
    ('schema_version', True), ('status', 'failed'), ('scope', 'synthetic_recipe'),
    ('authentication', 'oauth'), ('vulnerabilityRemediationVerified', True),
    ('oauthVerified', 0), ('wholeApplicationVerified', True),
    ('finished_at', '2026-09-19T14:39:00'), ('started_at', '2027-01-01T00:00:00Z'),
])
def test_identity_schema_and_claims_fail_closed(field, value):
    evidence = runtime_evidence()
    evidence[field] = value
    assert validate(evidence) is None


@pytest.mark.parametrize('external', [{'archive_sha256': '0' * 64}, {'run_id': 'invalid'},
                                     {'run_id': 'a07d3b84-1c26-433b-b728-f1dc0e0c34ff'}])
def test_external_binding_required(external):
    assert validate(runtime_evidence(), **external) is None


@pytest.mark.parametrize('index', range(12))
def test_claimed_pass_does_not_override_missing_actuals(index):
    evidence = runtime_evidence()
    evidence['checks'][index]['actual'] = {}
    assert validate(evidence) is None


@pytest.mark.parametrize('index,field,value', [
    (0, 'status', True), (4, 'body', {'ok': 1}),
    (6, 'ids', ['p-1234-abcd']), (7, 'status', 200), (8, 'status', 200),
    (10, 'body', {'ok': True, 'status': 'active'}),
])
def test_wrong_actuals_rejected(index, field, value):
    evidence = runtime_evidence()
    evidence['checks'][index]['actual'][field] = value
    assert validate(evidence) is None


@pytest.mark.parametrize('index', [2, 5, 9, 11])
def test_database_row_from_other_tenant_rejected(index):
    evidence = runtime_evidence()
    evidence['checks'][index]['actual']['rows'][0]['company_id'] = evidence['fixtures']['company_b']
    assert validate(evidence) is None


def test_denied_request_mutation_rejected():
    evidence = runtime_evidence()
    evidence['checks'][9]['actual']['rows'][0]['name'] = 'forged tenant write'
    assert validate(evidence) is None


@pytest.mark.parametrize('mutation', ['missing', 'duplicate', 'reordered', 'same_tenant', 'no_update'])
def test_coverage_and_fixture_integrity(mutation):
    evidence = runtime_evidence()
    if mutation == 'missing':
        evidence['checks'].pop()
    elif mutation == 'duplicate':
        evidence['checks'][3] = evidence['checks'][2]
    elif mutation == 'reordered':
        evidence['checks'].reverse()
    elif mutation == 'same_tenant':
        evidence['fixtures']['company_b'] = evidence['fixtures']['company_a']
    else:
        evidence['fixtures']['updated_name'] = evidence['fixtures']['original_name']
    assert validate(evidence) is None


@pytest.mark.parametrize('bad', [None, [], 'passed', True, float('nan'),
                                {'checks': None}, {'checks': [None]}])
def test_malformed_inputs_do_not_throw(bad):
    assert validate(bad) is None


@pytest.mark.parametrize('bad', [None, [], True, float('nan'), {'rows': [None]}])
def test_malformed_nested_inputs_do_not_throw(bad):
    evidence = runtime_evidence()
    evidence['checks'][11]['actual'] = bad
    assert validate(evidence) is None


def test_size_depth_cycles_and_unknown_fields_are_rejected():
    for bad in ('x' * 4097, float('inf'), [0] * 101):
        evidence = runtime_evidence()
        evidence['checks'][1]['actual']['body']['extra'] = bad
        assert validate(evidence) is None
    evidence = runtime_evidence()
    evidence['checks'][1]['actual']['body']['extra'] = evidence
    assert validate(evidence) is None
    evidence = runtime_evidence()
    evidence['command'] = 'run arbitrary project'
    assert validate(evidence) is None


@pytest.mark.parametrize('field,value', [('runtime_verified', True), ('evidence_sha256', '0' * 64),
                                       ('trust', 'authenticated'), ('checks', [])])
def test_saved_record_cannot_inflate_or_corrupt_claims(field, value):
    record = validate(runtime_evidence())
    record[field] = value
    assert normalize_client_runtime_record(record, archive_sha256=ARCHIVE_SHA256) is None


def test_saved_record_actuals_revalidated():
    record = validate(runtime_evidence())
    record['evidence']['checks'][9]['actual']['rows'][0]['name'] = 'mutated'
    assert normalize_client_runtime_record(record, archive_sha256=ARCHIVE_SHA256) is None

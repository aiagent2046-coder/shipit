"""Bounded, offline consistency checks for one pinned client runtime scenario.

Receipts are supplied by an operator, not authenticated execution attestations.
Passing this contract cannot establish whole-project or remediation verification.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import re
import uuid

ARCHIVE_SHA256 = 'dce64bacef7ffcc5f801d50447f035bd67ec14829a97a79401bb0d0a397e226d'
SCENARIO_SHA256 = '080d9eae864c8ca7e98cd0d3dd7b132b1b19b1fd12236357b4c81e356efaea20'
SCENARIO_ID = 'cumora-project-tenant-isolation-v1'
CHECK_IDS = ('unauthenticated', 'create', 'db_created', 'list_owner',
             'update_owner', 'db_updated', 'list_other', 'forged_tenant',
             'update_other', 'db_after_denials', 'archive_owner', 'db_archived')
_ROOT_KEYS = {'schema_version', 'scenario_sha256', 'scenario_id', 'run_id',
              'archive_sha256', 'scope', 'status', 'started_at', 'finished_at',
              'authentication', 'vulnerabilityRemediationVerified',
              'oauthVerified', 'wholeApplicationVerified', 'fixtures', 'checks'}
_FIXTURE_KEYS = {'company_a', 'company_b', 'project_id', 'original_name',
                 'updated_name', 'original_description', 'updated_description'}


def _require(condition: bool) -> None:
    if not condition:
        raise ValueError('Invalid runtime evidence')


def _bounded_json(value: object, depth: int = 0, budget: list[int] | None = None) -> None:
    # Walk before serialization: no arbitrary __str__, non-JSON values, cycles,
    # unbounded nesting, NaN, or huge trees. Integers are only small JSON numbers.
    if budget is None:
        budget = [0]
    budget[0] += 1
    _require(depth <= 12 and budget[0] <= 2000)
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        _require(abs(value) <= 2**53)
    elif type(value) is str:
        _require(len(value) <= 4096)
    elif type(value) is list:
        _require(len(value) <= 100)
        for item in value:
            _bounded_json(item, depth + 1, budget)
    elif type(value) is dict:
        _require(len(value) <= 100)
        for key, item in value.items():
            _require(type(key) is str and len(key) <= 100)
            _bounded_json(item, depth + 1, budget)
    else:
        raise ValueError('Non-JSON evidence value')


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(',', ':'), allow_nan=False).encode('ascii')


def _timestamp(value: object) -> datetime.datetime:
    _require(type(value) is str and len(value) <= 40)
    result = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
    _require(result.tzinfo is not None)
    return result


def validate_client_runtime_evidence(evidence: object, *, archive_sha256: str,
                                     run_id: str) -> dict | None:
    """Validate actual observations, bound to independently selected archive/run.

    No code is executed. Unknown scenarios and malformed receipts fail closed.
    The run identity comparison is consistency only, never authentication.
    """
    try:
        _bounded_json(evidence)
        _require(type(evidence) is dict and set(evidence) == _ROOT_KEYS)
        _require(len(_canonical(evidence)) <= 64 * 1024)
        _require(type(run_id) is str and str(uuid.UUID(run_id)) == run_id)
        _require(archive_sha256 == ARCHIVE_SHA256)
        r = evidence
        _require(r['run_id'] == run_id and r['archive_sha256'] == archive_sha256)
        _require(type(r['schema_version']) is int and r['schema_version'] == 1)
        _require(r['scenario_id'] == SCENARIO_ID and r['scenario_sha256'] == SCENARIO_SHA256)
        _require(r['scope'] == 'client_application_runtime' and r['status'] == 'passed')
        _require(r['authentication'] == 'dedicated_database_seeded_sessions')
        _require(_timestamp(r['started_at']) <= _timestamp(r['finished_at']))
        for key in ('vulnerabilityRemediationVerified', 'oauthVerified', 'wholeApplicationVerified'):
            _require(r[key] is False)
        f = r['fixtures']
        _require(type(f) is dict and set(f) == _FIXTURE_KEYS)
        _require(all(type(v) is str and 0 < len(v) <= 200 for v in f.values()))
        _require(f['company_a'] != f['company_b'] and f['original_name'] != f['updated_name'])
        _require(re.fullmatch(r'p-[a-f0-9-]+', f['project_id']) is not None)
        checks = r['checks']
        _require(type(checks) is list and len(checks) == len(CHECK_IDS))
        for item, expected in zip(checks, CHECK_IDS):
            _require(type(item) is dict and set(item) == {'id', 'pass', 'actual'})
            _require(item['id'] == expected and item['pass'] is True and type(item['actual']) is dict)
        c = {item['id']: item['actual'] for item in checks}
        codes = {'unauthenticated': 401, 'create': 201, 'list_owner': 200,
                 'update_owner': 200, 'list_other': 200, 'forged_tenant': 403,
                 'update_other': 404, 'archive_owner': 200}
        for name, code in codes.items():
            _require(type(c[name]['status']) is int and c[name]['status'] == code)
        original = dict(company_id=f['company_a'], name=f['original_name'],
                        description=f['original_description'], status='active', archived_at=None)
        updated = dict(original, name=f['updated_name'], description=f['updated_description'])
        expected_actuals = {
            'unauthenticated': {'status': 401},
            'create': {'status': 201, 'body': dict(id=f['project_id'], name=f['original_name'],
                        description=f['original_description'], status='active')},
            'db_created': {'rows': [original]},
            'list_owner': {'status': 200, 'ids': [f['project_id']]},
            'update_owner': {'status': 200, 'body': {'ok': True}},
            'db_updated': {'rows': [updated]},
            'list_other': {'status': 200, 'ids': []},
            'forged_tenant': {'status': 403},
            'update_other': {'status': 404},
            'db_after_denials': {'rows': [updated]},
            'archive_owner': {'status': 200, 'body': {'ok': True, 'status': 'archived'}},
        }
        rows = c['db_archived']['rows']
        _require(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict)
        archived_at = rows[0]['archived_at']
        _timestamp(archived_at)
        expected_actuals['db_archived'] = {'rows': [dict(updated, status='archived', archived_at=archived_at)]}
        for name, expected in expected_actuals.items():
            actual = c[name]
            _require(set(actual) == set(expected))
            if 'body' in expected:
                # Real API may return additional project metadata. Retain only
                # fields used by the pinned verifier; never serialize extra data.
                _require(type(actual['body']) is dict)
                actual = dict(actual, body={key: actual['body'][key] for key in expected['body']})
            # Canonical bytes avoid Python's True == 1 equality weakening receipts.
            _require(_canonical(actual) == _canonical(expected))
        clean = dict(r, fixtures=dict(f), checks=[
            {'id': name, 'pass': True, 'actual': expected_actuals[name]} for name in CHECK_IDS])
        digest = hashlib.sha256(_canonical(clean)).hexdigest()
        return {
            'schema_version': 1, 'record_id': 'client-runtime-' + digest[:24],
            'evidence_sha256': digest, 'archive_sha256': archive_sha256,
            'run_id': run_id, 'scenario_id': SCENARIO_ID, 'scenario_sha256': SCENARIO_SHA256,
            'source': 'operator_supplied', 'state': 'reported_scenario_passed',
            'scope': 'project_crud_and_cross_tenant_isolation',
            'trust': 'operator_supplied_consistency_only', 'checks': list(CHECK_IDS),
            'runtime_verified': False, 'customer_project_verified': False,
            'automatic_patch': False, 'automatic_apply': False,
            'vulnerability_remediation_verified': False, 'oauth_verified': False,
            'evidence': clean,
        }
    except (ValueError, TypeError, KeyError, IndexError, OverflowError, RecursionError, AttributeError):
        return None


def normalize_client_runtime_record(value: object, *, archive_sha256: str) -> dict | None:
    """Revalidate saved data without promoting self-reported proof to attestation."""
    if type(value) is not dict:
        return None
    record = validate_client_runtime_evidence(value.get('evidence'),
        archive_sha256=archive_sha256, run_id=value.get('run_id'))
    if record is None:
        return None
    # Discard a corrupted or inflated receipt rather than preserve its claims.
    try:
        _bounded_json(value)
        return record if _canonical(value) == _canonical(record) else None
    except (ValueError, TypeError, OverflowError, RecursionError):
        return None

"""Source provenance must narrow one prerequisite without upgrading the verdict."""
import ast
from copy import deepcopy
import io
import json

import pytest

from app.report.evidence import claim_evidence_rows, security_agent_rows
from app.scan.psycopg_provenance import cursor_provenance
from app.scan.security_agent import sql_observation
from app.scan.sql_injection import scan_sql_injection
from tests.test_security_agent import archive, report, sql_findings

CHAIN = 'import psycopg\nconn = psycopg.connect("PRIVATE_DSN")\ncur = conn.cursor()\n'
SINK = 'cur.execute(f"SELECT {user_id}")\n'


def trace(source, files=None):
    findings = scan_sql_injection(io.BytesIO(archive({"src/query.py": source, **(files or {})})))
    assert findings, "The legacy SQL observation must survive unknown provenance"
    return [f.claim_evidence["sql_observation"] for f in findings]


@pytest.mark.parametrize('source,locations', [
    (CHAIN + SINK, (1, 2, 3)),
    ('import psycopg as pg\nc = pg.connect(dsn)\ncur = c.cursor()\n' + SINK, (1, 2, 3)),
    ('from psycopg import connect as open_db\nc = open_db(dsn)\ncur = c.cursor()\n' + SINK, (1, 2, 3)),
    ('import psycopg\nopen_db = psycopg.connect\nc = open_db(dsn)\ncur = c.cursor()\n' + SINK, (1, 3, 4)),
    ('import psycopg\npg = psycopg\nc = pg.connect(dsn)\nd = c\ncur = d.cursor()\n' + SINK, (1, 3, 5)),
    (CHAIN + 'other = cur\nother.execute(f"SELECT {user_id}")\n', (1, 2, 3)),
    ('import psycopg\ndef load(user_id):\n    c = psycopg.connect(dsn)\n    cur = c.cursor()\n    ' + SINK,
     (1, 3, 4)),
    ('def load(user_id):\n    import psycopg as pg\n    c = pg.connect(dsn)\n    cur = c.cursor()\n    ' + SINK,
     (2, 3, 4)),
    ('import psycopg\nwith psycopg.connect(dsn) as c:\n    with c.cursor() as cur:\n        ' + SINK, (1, 2, 3)),
    ('import psycopg\npsycopg.connect(dsn).cursor().execute(f"SELECT {user_id}")\n', (1, 2, 2)),
    (CHAIN + SINK.replace('execute(', 'executemany('), (1, 2, 3)),
    (CHAIN + SINK + SINK, (1, 2, 3)),
])
def test_supported_chains_record_only_source_locations(source, locations):
    for value in trace(source):
        assert value['driver_status'] == 'source_resolved'
        assert value['driver_provenance'] == {
            'version': 1, 'driver': 'psycopg3', 'method': 'python_ast_straight_line',
            'import_line': locations[0], 'connection_line': locations[1], 'cursor_line': locations[2],
        }
        assert 'PRIVATE_DSN' not in json.dumps(value)


@pytest.mark.parametrize('source', [
    'import psycopg\n' + SINK,
    'import psycopg\ndef load(cur, user_id):\n    ' + SINK,
    'import psycopg\ndef load(psycopg):\n    c = psycopg.connect(dsn)\n    cur = c.cursor()\n    ' + SINK,
    'from .psycopg import connect\nc = connect(dsn)\ncur = c.cursor()\n' + SINK,
    'import psycopg2 as psycopg\nc = psycopg.connect(dsn)\ncur = c.cursor()\n' + SINK,
    CHAIN.replace('psycopg.connect("PRIVATE_DSN")', 'wrapper(dsn)') + SINK,
    CHAIN.replace('psycopg.connect("PRIVATE_DSN")', 'psycopg.connect(dsn, cursor_factory=Custom)') + SINK,
    CHAIN.replace('psycopg.connect("PRIVATE_DSN")', 'psycopg.connect(**options)') + SINK,
    CHAIN.replace('psycopg.connect("PRIVATE_DSN")', 'psycopg.connect(*options)') + SINK,
    CHAIN.replace('conn.cursor()', 'conn.cursor("named")') + SINK,
    CHAIN.replace('conn.cursor()', 'conn.cursor(**options)') + SINK,
    CHAIN.replace('conn.cursor()', 'wrapper(conn)') + SINK,
    CHAIN + 'cur = Custom()\n' + SINK,
    CHAIN + 'other = cur\nmutate(other)\n' + SINK,
    CHAIN + 'cur = wrapper(cur)\n' + SINK,
    CHAIN + 'mutate(conn)\n' + SINK,
    CHAIN + 'stored = [cur]\n' + SINK,
    CHAIN + 'cur.customize()\n' + SINK,
    CHAIN + 'del cur\n' + SINK,
    CHAIN + 'cur += other\n' + SINK,
    CHAIN + 'if flag:\n    cur = other\n' + SINK,
    CHAIN + 'if flag:\n    ' + SINK,
    CHAIN + 'for item in items:\n    ' + SINK,
    CHAIN + 'try:\n    ' + SINK + 'except Exception:\n    pass\n',
    CHAIN + 'with custom():\n    ' + SINK,
    CHAIN + 'conn.cursor_factory = Custom\n' + SINK,
    CHAIN + 'alias = conn\nalias.cursor = fake\n' + SINK,
    CHAIN + 'setattr(conn, name, custom)\n' + SINK,
    CHAIN + 'psycopg.connect = custom\n' + SINK,
    CHAIN + 'psycopg.__dict__[name] = custom\n' + SINK,
    CHAIN + 'def f(arg=mutate(cur)):\n    pass\n' + SINK,
    CHAIN + 'def f(*args: mutate(cur)):\n    pass\n' + SINK,
    CHAIN + 'def f(**kwargs: mutate(cur)):\n    pass\n' + SINK,
    CHAIN + 'cur.execute(f"SELECT {mutate(cur)}")\n',
    CHAIN + 'cur.execute(f"SELECT {user_id}"); unknown.execute(f"SELECT {user_id}")\n',
    CHAIN + 'cur.execute(f"SELECT {user_id}"); f = lambda: other.execute(f"SELECT {user_id}")\n',
    CHAIN + 'def later():\n    ' + SINK,
    'import psycopg\ndef later():\n    c = psycopg.connect(dsn)\n    cur = c.cursor()\n    ' + SINK
    + 'psycopg = custom\n',
    'import psycopg\ndef later():\n    c = psycopg.connect(dsn)\n    cur = c.cursor()\n    ' + SINK
    + 'mutate(psycopg)\n',
    'import psycopg\ndef later():\n    c = psycopg.connect(dsn)\n    cur = c.cursor()\n    ' + SINK
    + 'from other import *\n',
    CHAIN + SINK.replace('execute(', 'raw('),
])
def test_ambiguous_chains_keep_the_driver_prerequisite(source):
    for value in trace(source):
        assert value['driver_status'] == 'unknown'
        assert 'driver_provenance' not in value


@pytest.mark.parametrize('path', ['psycopg.py', 'Psycopg.py', 'psycopg.pyc',
                                  'src/psycopg/__init__.py', 'vendor/psycopg/api.py'])
def test_local_driver_module_is_not_mistaken_for_installed_library(path):
    assert trace(CHAIN + SINK, {path: ''})[0]['driver_status'] == 'unknown'


def test_budget_exhaustion_cannot_produce_partial_driver_proof():
    tree = ast.parse(CHAIN + SINK)
    assert cursor_provenance(tree, max_nodes=10) == {}


def test_one_prerequisite_is_removed_but_runtime_and_repair_remain_manual():
    result = report({'src/query.py': CHAIN + SINK})
    observation, = result['security_agent']['observations']
    assert set(observation['missing_evidence']) == {
        'attacker_control', 'sql_value_position', 'intended_value_type', 'runtime_behavior_contract',
    }
    assert observation['state'] == 'needs_evidence'
    assert observation['next_action'] == 'manual_review'
    assert observation['recipe']['automatic_apply'] is False
    assert result['security_agent']['runtime_verified'] is False
    finding, = sql_findings(result)
    assert finding['verification_status'] == 'unverified'
    for rows in (claim_evidence_rows(finding), security_agent_rows(result['security_agent'])):
        details = dict(rows)['SQL driver source']
        assert 'import line 1 → connect() line 2 → cursor() line 3' in details
        assert 'runtime behavior are unverified' in details


@pytest.mark.parametrize('change', [
    {'driver_status': 'runtime_verified'}, {'driver_provenance': None},
    {'driver_provenance': {'version': 1}}, {'version': 1},
    {'driver_provenance': {'version': True}},
])
def test_malformed_or_future_provenance_cannot_establish_a_precondition(change):
    finding, = sql_findings(report({'src/query.py': CHAIN + SINK}))
    finding = deepcopy(finding)
    finding['claim_evidence']['sql_observation'].update(change)
    assert sql_observation(finding) is None


@pytest.mark.parametrize('key,value', [('import_line', True), ('connection_line', 0),
                                     ('cursor_line', 999), ('import_line', 3), ('version', 2)])
def test_invalid_chain_locations_are_rejected(key, value):
    finding, = sql_findings(report({'src/query.py': CHAIN + SINK}))
    finding['claim_evidence']['sql_observation']['driver_provenance'][key] = value
    assert sql_observation(finding) is None


def test_historical_trace_stays_readable_without_acquiring_new_proof():
    finding, = sql_findings(report({'src/query.py': SINK}))
    value = finding['claim_evidence']['sql_observation']
    value.update(version=1, driver_status='not_checked')
    assert sql_observation(finding) == value
    assert dict(claim_evidence_rows(finding))['SQL driver source'] == 'Not checked in this historical report.'


def test_online_preview_and_browser_exports_share_the_driver_decision(monkeypatch):
    import socket
    import subprocess
    from app.llm.client import LLMClient
    from app.scan.browser import scan_archive
    from app.scan.pipeline import BASIS_PREVIEW, run_scan

    def forbidden(*args, **kwargs):
        raise AssertionError('Static provenance must not use a network, subprocess or model')

    monkeypatch.setattr(socket.socket, 'connect', forbidden)
    monkeypatch.setattr(socket, 'create_connection', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    monkeypatch.setattr(LLMClient, 'complete', forbidden)
    data = archive({'src/query.py': CHAIN + SINK})
    offline = scan_archive(data)
    online = run_scan(data, LLMClient(providers=[]), depth=BASIS_PREVIEW)
    assert online['score']['scan_manifest']['model_calls'] == 0
    assert online['score']['scan_manifest']['security_agent'] == offline['report']['security_agent']
    finding, = sql_findings(offline['report'])
    results = offline['sarif']['runs'][0]['results']
    sql_result, = [result for result in results if result['ruleId'] == finding['rule_id']]
    assert sql_result['properties']['sqlObservation'] == finding['claim_evidence']['sql_observation']
    assert sql_result['properties']['sqlObservation']['driver_status'] == 'source_resolved'


@pytest.mark.parametrize('escape', ['stored = [psycopg]\n', 'mutate([psycopg])\n',
                                  'def expose():\n    return psycopg\n'])
def test_deferred_import_proof_is_lost_when_the_module_escapes(escape):
    source = ('import psycopg\ndef load():\n    c = psycopg.connect(dsn)\n'
              '    cur = c.cursor()\n    ' + SINK + escape)
    assert trace(source)[0]['driver_status'] == 'unknown'

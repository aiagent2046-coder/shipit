"""Review regressions: source identity must survive real Python binding rules."""

import pytest

from tests.test_security_agent import report, sql_findings


CHAIN = 'import psycopg\nconn = psycopg.connect(dsn)\ncur = conn.cursor()\n'
SINK = 'cur.execute(f"SELECT {user_id}")\n'
DEFERRED = (
    'def load(user_id):\n'
    '    conn = psycopg.connect(dsn)\n'
    '    cur = conn.cursor()\n'
    '    cur.execute(f"SELECT {user_id}")\n'
)


def assert_driver_decision(source, *, resolved=False):
    """The public report must keep SQL findings and the remaining evidence gate."""
    result = report({'src/query.py': source})
    finding, = sql_findings(result)
    observation, = [row for row in result['security_agent']['observations']
                    if row['pattern_id'] == 'python-sql-string-assembly']
    trace = finding['claim_evidence']['sql_observation']
    assert observation['evidence']['sql_observation'] == trace
    assert trace['driver_status'] == ('source_resolved' if resolved else 'unknown')
    assert ('driver_provenance' in trace) is resolved
    assert ('psycopg3_cursor_provenance' not in observation['missing_evidence']) is resolved
    assert {'attacker_control', 'sql_value_position', 'intended_value_type',
            'runtime_behavior_contract'} <= set(observation['missing_evidence'])
    assert observation['state'] == 'needs_evidence'
    assert observation['next_action'] == 'manual_review'
    assert observation['recipe']['automatic_apply'] is False
    assert finding['verification_status'] == 'unverified'
    assert result['security_agent']['runtime_verified'] is False
    assert result['security_agent']['automatic_patch'] is False


@pytest.mark.parametrize('annotation', [
    'marker: (cur := CustomCursor())\n',
    'marker: (cur := CustomCursor()) = None\n',
    'cur: (cur := CustomCursor()) = conn.cursor()\n',
    'marker: mutate(cur)\n',
    'marker: mutate(conn) = None\n',
])
def test_module_annotations_evaluate_after_the_assignment(annotation):
    assert_driver_decision(CHAIN + annotation + SINK)


def test_unevaluated_function_annotation_cannot_create_cursor_proof():
    source = (
        'import psycopg\n'
        'def load(cur, user_id):\n'
        '    marker: (cur := psycopg.connect(dsn).cursor()).execute("SELECT 1")\n'
        '    cur.execute(f"SELECT {user_id}")\n'
    )
    assert_driver_decision(source)


@pytest.mark.parametrize('parameter', ['connection=conn', 'cursor=cur'])
@pytest.mark.parametrize('separator', ['', '*, '], ids=['positional', 'keyword-only'])
def test_default_arguments_escape_connection_and_cursor(parameter, separator):
    source = CHAIN + f'def holder({separator}{parameter}):\n    pass\nmutate(holder)\n' + SINK
    assert_driver_decision(source)


@pytest.mark.parametrize('separator', ['', '*, '], ids=['positional', 'keyword-only'])
@pytest.mark.parametrize('deferred', [False, True], ids=['straight-line', 'deferred-before-escape'])
def test_default_arguments_escape_driver_even_after_a_deferred_function(separator, deferred):
    source = 'import psycopg\n' + (DEFERRED if deferred else '')
    source += f'def holder({separator}driver=psycopg):\n    pass\nmutate(holder)\n'
    if not deferred:
        source += CHAIN.split('\n', 1)[1] + SINK
    assert_driver_decision(source)


def test_bound_setter_alias_can_change_the_connection_cursor_factory():
    source = (
        'import psycopg\n'
        'conn = psycopg.connect(dsn)\n'
        'change = conn.__setattr__\n'
        'change("cursor_factory", CustomCursor)\n'
        'cur = conn.cursor()\n'
    ) + SINK
    assert_driver_decision(source)


@pytest.mark.parametrize('deferred', [False, True], ids=['straight-line', 'deferred-before-setter'])
def test_bound_setter_alias_can_replace_the_driver_factory(deferred):
    source = 'import psycopg\n' + (DEFERRED if deferred else '')
    source += 'change = psycopg.__setattr__\nchange("connect", alternate_connect)\n'
    if not deferred:
        source += CHAIN.split('\n', 1)[1] + SINK
    assert_driver_decision(source)


REGISTRY = '''from builtins import setattr as replace
class AlternateCursor:
    def execute(self, query):
        return "alternate-driver"
class AlternateConnection:
    def cursor(self):
        return AlternateCursor()
def alternate_connect(dsn):
    return AlternateConnection()
class Registry:
    def __setitem__(self, key, module):
        replace(module, "connect", alternate_connect)
registry = Registry()
'''


@pytest.mark.parametrize('assignment', [
    'registry["driver"] = pg = psycopg\n',
    'pg = registry["driver"] = psycopg\n',
])
@pytest.mark.parametrize('deferred', [False, True], ids=['straight-line', 'deferred-before-store'])
def test_chained_driver_store_cannot_restore_an_escaped_alias(assignment, deferred):
    source = REGISTRY + 'import psycopg\n' + (DEFERRED if deferred else '') + assignment
    if not deferred:
        source += 'conn = pg.connect(dsn)\ncur = conn.cursor()\n' + SINK
    assert_driver_decision(source)


@pytest.mark.parametrize('assignment', [
    'registry["cursor"] = alias = cur\n',
    'alias = registry["cursor"] = cur\n',
])
def test_chained_cursor_store_cannot_restore_an_escaped_alias(assignment):
    assert_driver_decision(CHAIN + assignment + 'alias.execute(f"SELECT {user_id}")\n')


@pytest.mark.parametrize('pattern', [
    'psycopg',
    '[*psycopg]',
    '{"driver": value, **psycopg}',
], ids=['capture', 'star-capture', 'mapping-rest'])
def test_later_match_capture_shadows_the_module_for_the_whole_function(pattern):
    source = ('import psycopg\n' + DEFERRED
              + f'    match payload:\n        case {pattern}:\n            pass\n')
    assert_driver_decision(source)


@pytest.mark.parametrize('source', [
    CHAIN + 'marker: int\n' + SINK,
    CHAIN + 'marker: int = 1\n' + SINK,
    CHAIN + 'cur: object = conn.cursor()\n' + SINK,
    'import psycopg as pg\nopen_db = pg.connect\nconn = open_db(dsn)\n'
    'connection = conn\ncur = connection.cursor()\nother = cur\nother.execute(f"SELECT {user_id}")\n',
    'import psycopg\nwith psycopg.connect(dsn) as conn:\n'
    '    with conn.cursor() as cur:\n        ' + SINK,
])
def test_pure_annotations_and_simple_aliases_keep_supported_source_proof(source):
    assert_driver_decision(source, resolved=True)

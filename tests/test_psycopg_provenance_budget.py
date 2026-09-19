"""Bound evidence work without losing the independent SQL observation."""
import ast
from functools import partial
import io

from app.scan import sql_injection
from app.scan.psycopg_provenance import cursor_provenance
from tests.test_security_agent import archive


SOURCE = ('import psycopg\nconn = psycopg.connect(dsn)\ncur = conn.cursor()\n'
          'cur.execute(f"SELECT {user_id}")\n')


def test_many_aliases_and_opaque_calls_fit_a_bounded_evidence_pass():
    # This near-limit input shape took 35 seconds before review: every f() copied
    # and compared all 8,000 aliases. Exercise the supported near-limit shape
    # with a deterministic work budget instead of a machine-dependent timer.
    prefix, sink = SOURCE.rsplit('cur.execute', 1)
    source = prefix + ''.join(f'c{i} = cur\n' for i in range(8_000)) + 'f()\n' * 8_000
    source += 'cur.execute' + sink
    tree = ast.parse(source)
    assert len(source.encode()) < sql_injection._MAX_FILE_BYTES
    assert sum(1 for _ in ast.walk(tree)) < sql_injection._MAX_NODES
    evidence = cursor_provenance(tree, max_work=640_000)
    assert evidence[(16_004, 'execute')]['driver'] == 'psycopg3'
    assert evidence[(16_004, 'execute')]['cursor_line'] == 3


def test_work_exhaustion_returns_no_partial_driver_facts():
    first = ast.parse(SOURCE)
    assert cursor_provenance(first, max_work=0) == {}
    # An early sink cannot leave apparently complete proof when the rest of
    # the file could not be checked for deferred mutation or module escapes.
    extended = ast.parse(SOURCE + 'pass\n' * 1_000)
    assert cursor_provenance(extended, max_work=100) == {}


def test_exhausted_evidence_work_preserves_sql_finding_and_coverage(monkeypatch):
    monkeypatch.setattr(sql_injection, 'cursor_provenance', partial(cursor_provenance, max_work=0))
    coverage = {}
    finding, = sql_injection.scan_sql_injection(io.BytesIO(archive({'src/query.py': SOURCE})), coverage=coverage)
    trace = finding.claim_evidence['sql_observation']
    assert trace['driver_status'] == 'unknown'
    assert 'driver_provenance' not in trace
    assert trace['assembly_line'] == trace['sink_line'] == finding.line == 4
    assert coverage['analyzed_files'] == 1
    assert coverage['partial'] is False


def test_no_driver_work_is_needed_without_a_sql_candidate(monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError('Driver evidence is irrelevant without SQL observations')

    monkeypatch.setattr(sql_injection, 'cursor_provenance', unexpected)
    source = SOURCE.replace('f"SELECT {user_id}"', '"SELECT %s", (user_id,)')
    assert sql_injection.scan_sql_injection(io.BytesIO(archive({'src/query.py': source}))) == []

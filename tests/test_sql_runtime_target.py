"""The synthetic runner cannot silently use an ambient or hosted database."""
import json
import os

import pytest

from scripts import verify_sql_runtime_contract as runner

DSN = 'postgresql://postgres:synthetic@localhost:5432/drydock_sql_contract'


@pytest.fixture(autouse=True)
def clean_libpq_environment(monkeypatch):
    for name in os.environ:
        if name.startswith('PG'):
            monkeypatch.delenv(name)


@pytest.mark.parametrize('target', [
    'postgresql://postgres:synthetic@production.example/drydock_sql_contract',
    DSN.replace('drydock_sql_contract', 'production'),
    DSN + '?hostaddr=203.0.113.1', DSN + '?service=production',
    DSN + '?options=-csearch_path=public', DSN + '#fragment',
    DSN.replace('localhost', 'localhost,production.example'),
    DSN.replace('postgres:synthetic', 'postgres'),
    DSN.replace(':5432/', ':0/'),
    'host=localhost dbname=drydock_sql_contract',
])
def test_unsafe_or_ambiguous_target_never_connects(target, monkeypatch):
    attempts = []
    monkeypatch.setattr(runner.psycopg, 'connect', lambda **kwargs: attempts.append(kwargs))
    with pytest.raises(runner.TargetError):
        runner.connect_target(target)
    assert not attempts


@pytest.mark.parametrize('host,address', [('localhost', '127.0.0.1'), ('127.0.0.1', '127.0.0.1'), ('[::1]', '::1')])
def test_explicit_local_target_pins_the_tcp_address(host, address):
    options = runner.target_options(DSN.replace('localhost', host))
    assert options['host'] == options['hostaddr'] == address
    assert options['dbname'] == 'drydock_sql_contract'
    assert options['connect_timeout'] == 5


@pytest.mark.parametrize('name', ['PGSERVICE', 'PGHOSTADDR', 'PGOPTIONS', 'PGSERVICEFILE'])
def test_ambient_libpq_overrides_are_rejected(name, monkeypatch):
    monkeypatch.setenv(name, 'not-to-be-consumed')
    with pytest.raises(runner.TargetError, match='ambient_libpq_options'):
        runner.target_options(DSN)


def test_missing_dedicated_database_is_unavailable_even_with_ambient_database(monkeypatch, capsys):
    monkeypatch.delenv('SQL_CONTRACT_DATABASE_URL', raising=False)
    monkeypatch.setenv('DATABASE_URL', DSN)
    assert runner.main([]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result['status'] == 'unavailable'
    assert not result['synthetic_recipe_verified']


def test_connection_errors_cannot_leak_credentials_or_count_as_success(monkeypatch, capsys, tmp_path):
    def fail(dsn):
        raise runner.psycopg.OperationalError('SECRET connection information')

    monkeypatch.setattr(runner, 'connect_target', fail)
    output = tmp_path / 'evidence.json'
    assert runner.main(['--output', str(output)]) == 2
    assert 'SECRET' not in capsys.readouterr().out
    result = json.loads(output.read_text())
    assert result['status'] == 'unavailable' and result['runtime_verified'] is False


def test_existing_evidence_is_preserved_before_any_connection(monkeypatch, tmp_path):
    output = tmp_path / 'evidence.json'
    output.write_text('earlier evidence')
    attempts = []
    monkeypatch.setattr(runner, 'connect_target', lambda dsn: attempts.append(dsn))
    with pytest.raises(FileExistsError):
        runner.main(['--output', str(output)])
    assert not attempts and output.read_text() == 'earlier evidence'

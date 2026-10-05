import ast
import asyncio
from contextlib import asynccontextmanager
import io
import json
import sqlite3
import uuid
import zipfile

import httpx
import pytest

from scripts import evaluate_pilot_models as trial
from scripts.evaluate_audit_models import run


def source_archive():
    buffer = io.BytesIO()
    names = set().union(*(set(s['files']) for s in trial.SCOPES.values()))
    with zipfile.ZipFile(buffer, 'w') as archive:
        for name in names:
            archive.writestr(name, (trial.ROOT / name).read_text())
    return buffer.getvalue()


def test_paired_prompts_and_no_expectations_leak(tmp_path):
    report = trial.prepare(source_archive(), list(trial.SCOPES))
    assert len(report['cases']) == 6
    for original, seeded in zip(report['cases'][::2], report['cases'][1::2]):
        assert original['prompt_sha256'] != seeded['prompt_sha256']
        assert original['files'].keys() == seeded['files'].keys()
        assert sum(original['files'][p] != seeded['files'][p] for p in original['files']) == 1
        assert max(original['submitted_chars'], seeded['submitted_chars']) <= trial.LIMIT
    calls = []

    def respond(request):
        payload = json.loads(request.content)
        calls.append(payload)
        assert 'expected_mechanism' not in request.content.decode()
        assert '-seeded' not in request.content.decode()
        return httpx.Response(200, json={'model': payload['model'], 'choices': [
            {'finish_reason': 'stop', 'message': {'content': '[]'}}]})

    assert run(report, 'synthetic', tmp_path / 'out.json', 8192,
               httpx.MockTransport(respond), read_timeout=600) == 0
    assert len(calls) == 12
    for i in range(0, 12, 2):
        assert calls[i]['messages'] == calls[i + 1]['messages']


def test_sql_seed_changes_query_semantics_not_just_format():
    name = 'app/db.py'
    original = {name: (trial.ROOT / name).read_text()}
    seeded = trial.mutate(original, 'sql')
    db = sqlite3.connect(':memory:')
    db.row_factory = sqlite3.Row
    db.execute('CREATE TABLE audits (id TEXT, stack TEXT, status TEXT, file_count INTEGER, '
               'score_total REAL, score_json TEXT, findings_json TEXT, repo_url TEXT, '
               'created_at TEXT, access_token TEXT)')
    victim = 'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa'
    db.execute('INSERT INTO audits (id, access_token) VALUES (?, ?)', (victim, 'private-secret'))

    class Connection:
        async def execute(self, query, params):
            # SQLite adapter only changes placeholder spelling; execute the generated SQL.
            cursor = db.execute(query.replace('%s', '?'), tuple(str(v) for v in params))

            class Cursor:
                async def fetchone(self):
                    return cursor.fetchone()
            return Cursor()

    class Pool:
        @asynccontextmanager
        async def connection(self):
            yield Connection()

    async def get_pool():
        return Pool()

    for source, should_disclose in ((original[name], False), (seeded[name], True)):
        cls = next(n for n in ast.parse(source).body if isinstance(n, ast.ClassDef) and n.name == 'AuditRepository')
        node = next(n for n in cls.body if getattr(n, 'name', None) == 'get_authorized')
        module = ast.Module(body=[ast.ImportFrom(module='__future__', names=[
            ast.alias(name='annotations')], level=0), node], type_ignores=[])
        ast.fix_missing_locations(module)
        ns = {'get_pool': get_pool, 'uuid': uuid, '_row_to_audit': dict,
              'DatabaseNotConfigured': type('DatabaseNotConfigured', (Exception,), {})}
        exec(compile(module, '<pilot-sql>', 'exec'), ns)
        lookup = ns['get_authorized']
        assert asyncio.run(lookup(None, victim, 'private-secret'))['id'] == victim
        result = asyncio.run(lookup(None, victim, "' OR '1'='1' --"))
        assert (result is not None) is should_disclose
    db.close()
    assert (trial.ROOT / name).read_text() == original[name]
    with pytest.raises(ValueError):
        trial.mutate(seeded, 'sql')


def test_mimo_only_larger_budget_sends_exactly_selected_prompts(tmp_path, monkeypatch):
    archive = source_archive()
    monkeypatch.setattr(trial.subprocess, 'check_output', lambda *a, **kw: archive)
    monkeypatch.setenv('AITUNNEL_API_KEY', 'synthetic')
    selected = ['files-seeded', 'payments-control', 'payments-seeded']
    baseline = trial.prepare(archive, list(trial.SCOPES))
    calls = []

    def respond(request):
        payload = json.loads(request.content)
        calls.append(payload)
        assert payload['model'] == 'mimo-v2.6-pro'
        assert payload['max_tokens'] == 16384
        return httpx.Response(200, json={'model': payload['model'], 'choices': [
            {'finish_reason': 'stop', 'message': {'content': '[]'}}]})

    def mocked_run(report, key, output, max_tokens, **kwargs):
        return run(report, key, output, max_tokens, httpx.MockTransport(respond), **kwargs)

    monkeypatch.setattr(trial, 'run', mocked_run)
    output = tmp_path / 'mimo.json'
    flags = ['--models', 'mimo-v2.6-pro', '--cases', *selected, '--max-tokens', '16384']
    prepared = tmp_path / 'prepared.json'
    assert trial.main([*flags, '--output', str(prepared)]) == 0
    assert calls == []
    assert trial.main([*flags, '--output', str(output), '--run']) == 0
    saved = json.loads(output.read_text())
    assert len(calls) == 3
    assert saved['cases'] == [c for c in baseline['cases'] if c['id'] in selected]
    assert [p['messages'][1]['content'] for p in calls] == [c['prompt'] for c in saved['cases']]
    assert saved['models'] == ['mimo-v2.6-pro']
    assert saved['requested_max_tokens'] == 16384
    assert saved['state'] == 'completed_needs_review'
    assert trial.main([*flags, '--resume', str(output), '--output', str(tmp_path / 'resumed.json'), '--run']) == 0
    assert len(calls) == 3  # Saved attempts, including errors, must not be repeated.
    for changed in (['--max-tokens', '8192'], ['--models', 'claude-sonnet-4.6'],
                    ['--cases', 'payments-seeded']):
        with pytest.raises(SystemExit):
            trial.main([*flags, *changed, '--resume', str(output),
                        '--output', str(tmp_path / 'changed-settings.json'), '--run'])
    assert len(calls) == 3


@pytest.mark.parametrize('flags', [
    ['--max-tokens', '0'], ['--max-tokens', '16385'],
    ['--models', 'mimo-v2.6-pro', 'mimo-v2.6-pro'],
    ['--cases', 'files-seeded', 'files-seeded'],
    ['--scenario', 'sql', '--cases', 'payments-control'],
])
def test_invalid_pilot_selection_never_runs(tmp_path, monkeypatch, flags):
    archive = source_archive()
    monkeypatch.setattr(trial.subprocess, 'check_output', lambda *a, **kw: archive)

    def forbidden(*args, **kwargs):
        raise AssertionError('Provider must not run')

    monkeypatch.setattr(trial, 'run', forbidden)
    output = tmp_path / 'invalid.json'
    with pytest.raises(SystemExit):
        trial.main([*flags, '--output', str(output), '--run'])
    assert not output.exists()

"""Behavior checks for in-memory audit examples; never contact DB/provider."""
import __future__
import ast
import asyncio
import copy
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi import Depends, HTTPException
from starlette.requests import Request

from app import accounts
from scripts import evaluate_repository_models as trial
from scripts.evaluate_audit_models import run


def sources():
    return {name: (trial.ROOT / name).read_text() for name, _, _ in trial.AUTH_MUTATIONS}


def function(source, name, namespace):
    node = next(n for n in ast.parse(source).body if getattr(n, "name", None) == name)
    node.decorator_list = []
    module = ast.Module(body=[node], type_ignores=[])
    exec(compile(module, '<trial>', 'exec', flags=__future__.annotations.compiler_flag), namespace)
    return namespace[name]


def test_uuid_login_bypass_persists_through_cookie_only_in_mutant(monkeypatch):
    monkeypatch.setenv('API_KEY_PEPPER', 'synthetic-test-pepper')
    original = sources()
    mutated = trial.seed_auth_files(original)
    victim_id = 'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa'
    victim = {'id': victim_id, 'tier': 'pro'}
    for files, expected in ((original, None), (mutated, victim)):
        namespace = dict(vars(accounts))
        lookup = function(files['app/accounts.py'], 'account_for_key', namespace)
        resolve = function(files['app/accounts.py'], 'resolve_account', namespace)
        repo = SimpleNamespace(get_by_key_hash=AsyncMock(return_value=None),
                               get_by_id=AsyncMock(return_value=victim))
        assert asyncio.run(lookup(victim_id, repo)) == expected
        request = Request({'type': 'http', 'headers': [
            (b'cookie', f'{accounts.API_KEY_COOKIE}={victim_id}'.encode()),
            (accounts.CSRF_HEADER.encode(), b'1')]})
        assert asyncio.run(resolve(request, repo)) == expected
        if expected is None:
            repo.get_by_id.assert_not_called()
        else:
            repo.get_by_id.assert_called_with(victim_id)
    assert sources() == original  # preparation never writes application files
    with pytest.raises(ValueError, match='anchor'):
        trial.seed_auth_files(mutated)


def test_rotation_target_requires_owner_in_original_but_not_mutant():
    original = sources()
    mutated = trial.seed_auth_files(original)
    caller = {'id': '11111111-1111-4111-8111-111111111111', 'tier': 'pro'}
    victim_id = 'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa'
    for files, expected_target in ((original, caller['id']), (mutated, victim_id)):
        # Authenticate the caller normally: isolate IDOR from the other mutation.
        auth = SimpleNamespace(resolve_account=AsyncMock(return_value=caller))
        namespace = {'Depends': Depends, 'get_account_repo': lambda: None,
                     'accounts': auth, '_bind_account': lambda _: None,
                     '_json_object_body': AsyncMock(return_value={'account_id': victim_id}),
                     'HTTPException': HTTPException}
        rotate = function(files['app/routes/accounts.py'], 'rotate_account_key', namespace)
        repo = SimpleNamespace(rotate_key=AsyncMock(return_value={
            'api_key': 'synthetic-new-secret', 'key_prefix': 'synthetic', 'tier': 'pro'}))
        request = object()
        answer = asyncio.run(rotate(request, repo))
        auth.resolve_account.assert_awaited_once_with(request, repo)
        repo.rotate_key.assert_awaited_once_with(expected_target)
        assert answer['api_key'] == 'synthetic-new-secret'


def test_seed_metadata_is_not_sent_to_either_model(tmp_path):
    files = trial.seed_auth_files(sources())
    prompt = trial.llm_scan.build_prompt(list(files.items()), 'auth')
    report = {'system_prompt': trial.llm_scan.SYSTEM_PROMPT, 'models': list(trial.MODELS),
              'repeats': 1, 'results': [], 'expected_findings': ['DO_NOT_SEND_EXPECTATIONS'],
              'mutations': ['DO_NOT_SEND_MUTATIONS'],
              'cases': [{'id': 'auth', 'prompt': prompt, 'prompt_sha256': 'test', 'files': files}]}
    requests = []

    def respond(request):
        body = json.loads(request.content)
        requests.append(body)
        assert 'DO_NOT_SEND' not in request.content.decode()
        return httpx.Response(200, json={'model': body['model'], 'choices': [
            {'finish_reason': 'stop', 'message': {'content': '[]'}}]})

    assert run(copy.deepcopy(report), 'synthetic', tmp_path / 'out.json', 8192,
               httpx.MockTransport(respond), read_timeout=600) == 0
    assert len(requests) == 2
    assert requests[0]['messages'] == requests[1]['messages']

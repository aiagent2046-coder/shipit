import io
import zipfile
import copy

import pytest

from scripts import evaluate_repository_models as trial


def archive():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as z:
        z.writestr('app/routes.py', (
            'from fastapi import APIRouter\nimport subprocess\nrouter = APIRouter()\n'
            '@router.get("/exec")\ndef command(name: str):\n'
            '    subprocess.run(["bash", "-c", "echo " + name])\n'
        ))
    return buffer.getvalue()


def test_preparation_is_deterministic_and_matches_production_prompt():
    data = archive()
    a = trial.prepare_archive(data, 'a' * 40)
    b = trial.prepare_archive(data, 'a' * 40)
    assert a == b
    assert a['models'] == ['claude-sonnet-4.6', 'mimo-v2.6-pro']
    assert a['repeats'] == 2
    assert a['requested_max_tokens'] == trial.llm_scan.RUBRIC_MAX_TOKENS
    assert a['system_prompt'] == trial.llm_scan.SYSTEM_PROMPT
    assert a['results'] == []
    assert any(c['id'] == 'security' for c in a['cases'])
    for case in a['cases']:
        assert case['submitted_files']
        assert all(name in case['files'] for name in case['submitted_files'])


def test_resume_preserves_paid_failure_and_rejects_changed_snapshot():
    expected = trial.prepare_archive(archive(), 'a' * 40)
    old = copy.deepcopy(expected)
    case = old['cases'][0]
    old['results'] = [{'repeat': 1, 'case': case['id'], 'requested_model': old['models'][0],
                      'prompt_sha256': case['prompt_sha256'], 'cost_rub': 2.73,
                      'error': 'incomplete_or_invalid_answer'}]
    resumed = trial.resume_results(copy.deepcopy(expected), old)
    assert resumed['results'] == old['results']
    old['revision'] = 'b' * 40
    with pytest.raises(ValueError):
        trial.resume_results(expected, old)

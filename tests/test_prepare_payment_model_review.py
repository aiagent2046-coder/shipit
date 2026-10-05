"""Protect the comparison boundary and the offline-only preparation contract."""
from copy import deepcopy
import json
import stat

import pytest

from scripts import evaluate_luna_pilot as pilot
from scripts import prepare_payment_model_review as review


@pytest.fixture
def baseline():
    system = 'Saved system prompt.\nJSON only.\n'
    cases, results = [], []
    for case_id in pilot.CASE_IDS:
        files = {'app/payment.py': 'payment = await provider.get_payment(payment_id)\n'}
        if case_id == 'payments-seeded':
            files['app/payment.py'] = 'payment = obj\n'
        prompt = (pilot.build_prompt(list(files.items()), 'money')
                  + '\nScope: unshown guards and deployment are unknown.')
        sha = pilot.digest(system, prompt)
        cases.append({'id': case_id, 'files': files, 'prompt': prompt, 'prompt_sha256': sha})
        results.append({'case': case_id, 'repeat': 1, 'requested_model': pilot.BASELINE_MODEL,
                        'prompt_sha256': sha, 'answer': 'Invalid prose',
                        'usage': {'balance': 'PRIVATE-ACCOUNT-MARKER'}})
    return {'suite': 'bounded-paired-pilot', 'requested_max_tokens': 8192,
            'system_prompt': system, 'cases': cases, 'results': results, 'revision': 'saved-revision'}


def test_new_pair_preserves_sources_without_relabeling_historical_answers(baseline):
    before = deepcopy(baseline)
    report = review.prepare_review(baseline, 'a' * 64)
    assert baseline == before
    assert report['planned_requests'] == 4
    assert report['requests_made'] == 0
    assert report['results'] == []
    assert len(report['manual_reviews']) == 4
    assert {(r['case'], r['model']) for r in report['manual_reviews']} == {
        (c['id'], m) for c in report['cases'] for m in (pilot.MODEL, pilot.BASELINE_MODEL)
    }
    assert all(r['mechanism_recognition'] is None and not r['response_present']
               for r in report['manual_reviews'])
    assert 'PRIVATE-ACCOUNT-MARKER' not in json.dumps(report)
    assert 'Invalid prose' not in json.dumps(report)
    for case, saved in zip(report['cases'], baseline['cases'][-2:], strict=True):
        assert case['id'] == saved['id'].replace('payments-', 'payments-security-v1-')
        assert case['files'] == saved['files']
        assert case['system_prompt'] == baseline['system_prompt']
        assert case['prompt_sha256'] != saved['prompt_sha256']
        assert case['prompt_sha256'] == pilot.digest(case['system_prompt'], case['prompt'])
        assert case['comparison'] == 'new_prompt_no_historical_comparator'
        assert case['prompt'].split('\n\n', 1)[0] == 'Rubric: ' + review.RUBRIC
        assert case['prompt'].split('<repo_map>', 1)[1] == saved['prompt'].split('<repo_map>', 1)[1]
        assert case['review_expectation'] not in case['prompt']
        assert 'WITHOUT an attacker' not in case['prompt']
        assert '1\t' + saved['files']['app/payment.py'].strip() in case['prompt']
    report['cases'][0]['files'].clear()
    assert baseline == before


@pytest.mark.parametrize('damage', ['prompt', 'system_prompt', 'historical_hash', 'source_boundary'])
def test_changed_historical_inputs_are_rejected(baseline, damage):
    if damage == 'prompt':
        baseline['cases'][-1]['prompt'] += 'changed'
    elif damage == 'system_prompt':
        baseline['system_prompt'] += 'changed'
    elif damage == 'historical_hash':
        baseline['results'][-1]['prompt_sha256'] = 'wrong'
    else:
        case = baseline['cases'][-1]
        case['prompt'] = case['prompt'].replace('<repo_map>', '<not_a_source_map>')
        case['prompt_sha256'] = pilot.digest(baseline['system_prompt'], case['prompt'])
        baseline['results'][-1]['prompt_sha256'] = case['prompt_sha256']
    with pytest.raises(ValueError):
        review.prepare_review(baseline, 'a' * 64)


def test_cli_is_offline_private_and_cannot_overwrite_baseline(baseline, tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('Offline preparation attempted execution or credential access')

    monkeypatch.setattr(pilot.httpx, 'Client', forbidden)
    monkeypatch.setattr(pilot, 'read_values', forbidden)
    monkeypatch.setattr(pilot, 'run', forbidden)
    monkeypatch.setattr(pilot.os, 'getenv', forbidden)
    source = tmp_path / 'baseline.json'
    source.write_text(json.dumps(baseline))
    original = source.read_bytes()
    output = tmp_path / 'prepared.json'
    assert review.main(['--baseline', str(source), '--output', str(output)]) == 0
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert json.loads(output.read_text())['state'] == 'prepared_offline'
    for target in (source, output):
        existing = target.read_bytes()
        with pytest.raises(SystemExit):
            review.main(['--baseline', str(source), '--output', str(target)])
        assert target.read_bytes() == existing
    assert source.read_bytes() == original
    with pytest.raises(SystemExit):
        review.main(['--baseline', str(source), '--output', str(output), '--run'])

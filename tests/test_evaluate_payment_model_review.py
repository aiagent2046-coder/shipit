"""Offline checks for a four-attempt comparison with real billing boundaries."""
from decimal import Decimal
import json
import stat

import httpx
import pytest

from scripts import evaluate_luna_pilot as pilot
from scripts import evaluate_payment_model_review as review


@pytest.fixture
def baseline():
    system = 'Saved audit instructions. JSON only.\n'
    cases, results = [], []
    for case_id in pilot.CASE_IDS:
        source = ('payment = obj\n' if case_id == 'payments-seeded'
                  else 'payment = await provider.get_payment(payment_id)\n')
        files = {'app/payment.py': source}
        prompt = pilot.build_prompt(list(files.items()), 'money')
        sha = pilot.digest(system, prompt)
        cases.append({'id': case_id, 'files': files, 'prompt': prompt, 'prompt_sha256': sha})
        results.append({'case': case_id, 'requested_model': pilot.BASELINE_MODEL,
                        'repeat': 1, 'prompt_sha256': sha, 'answer': 'HISTORICAL-ANSWER',
                        'usage': {'balance': 'PRIVATE-ACCOUNT-MARKER'}})
    return {'suite': 'bounded-paired-pilot', 'requested_max_tokens': 8192,
            'system_prompt': system, 'revision': 'saved-revision',
            'cases': cases, 'results': results}


def prepared(baseline, budget=Decimal('160')):
    return review.prepare(baseline, 'a' * 64, budget_rub=budget)


def reply(model, **overrides):
    return {'model': model,
            'usage': {'cost_rub': '0.1', 'prompt_tokens': 20, 'completion_tokens': 5,
                      'completion_tokens_details': {'reasoning_tokens': 3}},
            'choices': [{'finish_reason': 'stop', 'message': {'content': '[]'}}],
            **overrides}


def read(path):
    return json.loads(path.read_text())


def test_four_calls_have_identical_messages_and_private_preflight_checkpoint(baseline, tmp_path):
    report = prepared(baseline)
    output = tmp_path / 'result.json'
    calls = []
    expected = [(case, model) for case in report['cases']
                for model in (pilot.MODEL, pilot.BASELINE_MODEL)]
    assert len(expected) == 4
    assert report['results'] == [] and report['state'] == 'prepared'
    assert 'HISTORICAL-ANSWER' not in json.dumps(report)
    assert 'PRIVATE-ACCOUNT-MARKER' not in json.dumps(report)

    def respond(request):
        current = read(output)
        case, model = expected[len(calls)]
        assert current['state'] == 'running'
        assert len(current['results']) == len(calls) + 1
        assert current['results'][-1]['status'] == 'in_flight'
        assert current['results'][-1]['cost_rub'] is None
        assert stat.S_IMODE(output.stat().st_mode) == 0o600
        assert request.url == httpx.URL(pilot.ENDPOINT)
        body = json.loads(request.content)
        parameters = ({'max_completion_tokens': 8192, 'reasoning_effort': 'medium'}
                      if model == pilot.MODEL else {'max_tokens': 8192, 'temperature': 0})
        assert body == {'model': model, 'stream': False, **parameters,
                        'messages': [{'role': 'system', 'content': case['system_prompt']},
                                     {'role': 'user', 'content': case['prompt']}]}
        assert case['review_expectation'] not in request.content.decode()
        assert request.headers['Authorization'] == 'Bearer test-key'
        calls.append(body)
        return httpx.Response(200, json=reply(model))

    assert review.run(report, 'test-key', output, transport=httpx.MockTransport(respond)) == 0
    saved = read(output)
    assert len(calls) == len(saved['results']) == 4
    assert saved['state'] == 'completed_needs_review'
    assert Decimal(saved['known_spend_rub']) == Decimal('0.4')
    assert saved['requests_made'] == 4
    for manual in saved['manual_reviews']:
        assert manual['response_present'] is True
        assert manual['strict_json_array'] is True and manual['quote_checks'] == []
        assert manual['mechanism_recognition'] is None
        assert manual['source_supported_findings'] is None
    for index in (0, 2):
        assert calls[index]['messages'] == calls[index + 1]['messages']
    for row, (case, model) in zip(saved['results'], expected, strict=True):
        assert row['case'] == case['id'] and row['requested_model'] == model
        assert row['raw_response'] == reply(model)
        assert row['usage']['completion_tokens_details']['reasoning_tokens'] == 3
        assert row['answer_characters'] == row['answer_utf8_bytes'] == 2
        assert row['finish_reason'] == 'stop' and row['refusal'] is None
        assert row['strict_json_array'] and row['quote_checks'] == []
    assert 'test-key' not in output.read_text()
    with pytest.raises(ValueError):
        review.run(saved, 'test-key', output, transport=httpx.MockTransport(respond))
    assert len(calls) == 4


@pytest.mark.parametrize('failure, state', [
    ('timeout', 'stopped_on_error'), ('http', 'stopped_on_error'),
    ('redirect', 'stopped_on_error'), ('unknown_cost', 'stopped_on_unknown_cost'),
    ('model', 'stopped_on_served_model_mismatch'),
])
def test_stop_after_sonnet_failure_preserves_unknown_charge_without_retry(
    baseline, tmp_path, failure, state,
):
    report = prepared(baseline)
    output = tmp_path / 'result.json'
    calls = []

    def respond(request):
        body = json.loads(request.content)
        calls.append(body)
        if len(calls) == 1:
            return httpx.Response(200, json=reply(body['model']))
        if failure == 'timeout':
            raise httpx.ReadTimeout('secret-key must not leak', request=request)
        if failure == 'http':
            return httpx.Response(429, text='secret-key in provider error')
        if failure == 'redirect':
            return httpx.Response(302, headers={'location': 'https://elsewhere.invalid'})
        if failure == 'unknown_cost':
            return httpx.Response(200, json=reply(body['model'], usage={'completion_tokens': 5}))
        return httpx.Response(200, json=reply(pilot.MODEL))

    assert review.run(report, 'secret-key', output, transport=httpx.MockTransport(respond)) == 1
    saved = read(output)
    assert len(calls) == len(saved['results']) == 2
    assert saved['state'] == state
    assert saved['manual_reviews'][0]['response_present'] is True
    assert saved['manual_reviews'][1]['response_present'] is (failure in {'unknown_cost', 'model'})
    assert saved['manual_reviews'][2]['response_present'] is False
    assert saved['results'][-1]['requested_model'] == pilot.BASELINE_MODEL
    if failure != 'model':
        assert saved['results'][-1]['cost_rub'] is None
        assert Decimal(saved['known_spend_rub']) == Decimal('0.1')
    if failure == 'unknown_cost':
        assert saved['results'][-1]['answer'] == '[]'
    assert 'secret-key' not in output.read_text()
    with pytest.raises(ValueError):
        review.run(saved, 'secret-key', output, transport=httpx.MockTransport(respond))
    assert len(calls) == 2


def test_invalid_but_billed_answers_do_not_skip_comparator_or_retry(baseline, tmp_path):
    report = prepared(baseline)
    output = tmp_path / 'result.json'
    calls = []
    answers = [('[', 'length', None), ('не JSON', 'stop', None),
               (None, 'stop', 'Cannot answer'), ('[]', 'stop', None)]

    def respond(request):
        model = json.loads(request.content)['model']
        answer, reason, refusal = answers[len(calls)]
        calls.append(model)
        return httpx.Response(200, json=reply(model, choices=[{
            'finish_reason': reason, 'message': {'content': answer, 'refusal': refusal},
        }]))

    assert review.run(report, 'key', output, transport=httpx.MockTransport(respond)) == 0
    saved = read(output)
    assert saved['state'] == 'completed_with_errors_needs_review'
    assert len(calls) == 4
    assert all(row['error'] == 'incomplete_or_invalid_answer' for row in saved['results'][:3])
    assert saved['results'][1]['answer_utf8_bytes'] == len('не JSON'.encode())
    assert saved['results'][2]['refusal'] == 'Cannot answer'
    assert Decimal(saved['known_spend_rub']) == Decimal('0.4')


def test_reservation_prices_both_models_and_rejects_oversized_context(baseline):
    case = prepared(baseline)['cases'][0]
    tokens = len((case['system_prompt'] + case['prompt']).encode()) + 1024
    assert review.reserve_rub(case, pilot.MODEL) == Decimal(tokens * 25 + 8192 * 100) / 1_000_000
    assert review.reserve_rub(case, pilot.BASELINE_MODEL) == Decimal(tokens * 750 + 8192 * 3300) / 1_000_000
    oversized = {**case, 'prompt': 'x' * 180_000}
    for model in (pilot.MODEL, pilot.BASELINE_MODEL):
        with pytest.raises(ValueError):
            review.reserve_rub(oversized, model)
    with pytest.raises(ValueError):
        review.payload(case, 'unapproved-model')


@pytest.mark.parametrize('budget', ['0', '-1', '160.01', 'NaN', 'Infinity'])
def test_invalid_admission_budget_rejected_before_any_request(baseline, budget):
    with pytest.raises(ValueError):
        prepared(baseline, Decimal(budget))


def test_sonnet_reservation_is_checked_before_the_second_call(baseline, tmp_path):
    report = prepared(baseline)
    output = tmp_path / 'result.json'
    calls = []

    def respond(request):
        calls.append(request)
        return httpx.Response(200, json=reply(pilot.MODEL, usage={'cost_rub': '159'}))

    assert review.run(report, 'key', output, transport=httpx.MockTransport(respond)) == 1
    saved = read(output)
    assert saved['state'] == 'stopped_before_budget'
    assert len(calls) == len(saved['results']) == 1
    assert Decimal(saved['known_spend_rub']) == Decimal('159')


def test_cli_default_is_offline_private_and_refuses_overwriting(baseline, tmp_path, monkeypatch):
    source = tmp_path / 'baseline.json'
    source.write_text(json.dumps(baseline))
    output = tmp_path / 'prepared.json'

    def forbidden(*args, **kwargs):
        pytest.fail('Prepare mode must not read credentials or create a provider client')

    monkeypatch.setattr(review, 'read_values', forbidden)
    monkeypatch.setattr(review.httpx, 'Client', forbidden)

    class NoProviderKeyRead(dict):
        def get(self, name, default=None):
            if name == 'AITUNNEL_API_KEY':
                forbidden()
            return super().get(name, default)

    monkeypatch.setattr(review.os, 'environ', NoProviderKeyRead(review.os.environ))
    args = ['--baseline', str(source), '--output', str(output), '--env', str(tmp_path / 'missing.env')]
    assert review.main(args) == 0
    assert read(output)['state'] == 'prepared'
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    original = output.read_bytes()
    with pytest.raises(SystemExit):
        review.main(args)
    assert output.read_bytes() == original


@pytest.mark.parametrize('damage', ['prompt', 'source', 'case_order', 'extra_case', 'budget'])
def test_changed_prepared_plan_cannot_make_billable_requests(baseline, tmp_path, damage):
    report = prepared(baseline)
    if damage == 'prompt':
        report['cases'][0]['prompt'] += '\nChanged after preparation'
    elif damage == 'source':
        report['cases'][0]['files']['app/payment.py'] = 'payment = different\n'
    elif damage == 'case_order':
        report['cases'].reverse()
    elif damage == 'extra_case':
        report['cases'].append(report['cases'][0])
    else:
        report['budget_rub'] = '161'

    def forbidden(request):
        pytest.fail('Invalid saved comparison plan reached the provider')

    with pytest.raises(ValueError):
        review.run(report, 'key', tmp_path / 'result.json', transport=httpx.MockTransport(forbidden))

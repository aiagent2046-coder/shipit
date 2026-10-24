"""Offline failure-path tests; no provider key or network required."""
from copy import deepcopy
from decimal import Decimal
import json
from pathlib import Path
import signal
import tempfile
import time
import unittest
from unittest.mock import patch, MagicMock

from scripts import evaluate_haiku_pilot as pilot


def baseline():
    system = 'Review the supplied source.'
    cases = [{'id': name, 'prompt': name, 'files': {'example.py': 'pass'},
              'prompt_sha256': pilot.digest(system, name)} for name in pilot.CASE_IDS]
    return {'suite': 'bounded-paired-pilot', 'system_prompt': system,
            'requested_max_tokens': 8192, 'cases': cases,
            'results': [{'case': c['id'], 'requested_model': pilot.BASELINE_MODEL,
                         'repeat': 1, 'prompt_sha256': c['prompt_sha256'], 'answer': '[]'}
                        for c in cases]}


def response(**changes):
    data = {'model': pilot.MODEL, 'usage': {'cost_rub': '0.25'},
            'choices': [{'finish_reason': 'stop', 'message': {'content': '[]'}}]}
    data.update(changes)
    return data


class PilotTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.output = Path(self.tmp.name) / 'result.json'
        self.report = pilot.prepare(baseline(), pilot.BASELINE_SHA256)

    def execute(self, data):
        calls = []
        def send(case, key):
            calls.append(case['id'])
            checkpoint = json.loads(self.output.read_text())
            self.assertEqual(checkpoint['results'][-1]['status'], 'in_flight')
            self.assertEqual(checkpoint['unknown_charges'], 1)
            if isinstance(data, Exception):
                raise data
            return deepcopy(data)
        result = pilot.run(self.report, 'secret-test-key', self.output, send=send)
        self.assertNotIn('secret-test-key', self.output.read_text())
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
        return result, calls

    def test_success_six_calls_and_exact_prompts(self):
        status, calls = self.execute(response())
        self.assertEqual(status, 0)
        self.assertEqual(calls, list(pilot.CASE_IDS))
        self.assertEqual(self.report['known_spend_rub'], '1.50')
        self.assertEqual(self.report['unknown_charges'], 0)
        for original, prepared in zip(baseline()['cases'], self.report['cases']):
            self.assertEqual(original['prompt'], prepared['prompt'])
            self.assertEqual(original['files'], prepared['files'])
        sent = pilot.payload(self.report['cases'][0])
        self.assertEqual(sent['model'], 'claude-haiku-5.5')
        self.assertEqual(sent['reasoning'], {'effort': 'medium'})
        self.assertNotIn('temperature', sent)
        self.assertNotIn('cache_control', sent)

    def test_unknown_cost_stops_without_retry(self):
        status, calls = self.execute(response(usage={}))
        self.assertEqual((status, len(calls)), (1, 1))
        self.assertEqual(self.report['unknown_charges'], 1)
        self.assertEqual(self.report['state'], 'stopped_on_unknown_cost')

    def test_timeout_preserves_unknown_charge_and_redacts_exception(self):
        _, calls = self.execute(TimeoutError('secret-test-key'))
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.report['unknown_charges'], 1)
        self.assertEqual(self.report['results'][0]['error'], 'TimeoutError')

    def test_mismatch_stops_but_records_charge(self):
        _, calls = self.execute(response(model='claude-sonnet-4.6'))
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.report['known_spend_rub'], '0.25')
        self.assertEqual(self.report['state'], 'stopped_on_served_model_mismatch')

    def test_truncation_and_invalid_answers_stop(self):
        for finish, answer, refusal in [('length', '[]', None), ('stop', '', None),
                                         ('stop', '{}', None), ('stop', '[1]', None),
                                         ('stop', '[]', 'refused')]:
            with self.subTest(finish=finish, answer=answer, refusal=refusal):
                self.report = pilot.prepare(baseline(), pilot.BASELINE_SHA256)
                data = response(choices=[{'finish_reason': finish,
                                          'message': {'content': answer, 'refusal': refusal}}])
                _, calls = self.execute(data)
                self.assertEqual(len(calls), 1)
                self.assertEqual(self.report['state'], 'stopped_on_invalid_answer')

    def test_fenced_json_is_separate_from_strict(self):
        assessment = pilot.assess('```json\n[]\n```', {})
        self.assertFalse(assessment['strict_json_array'])
        self.assertTrue(assessment['json_array_after_fence_removal'])

    def test_budget_stops_before_next_call(self):
        _, calls = self.execute(response(usage={'cost_rub': '19.99'}))
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.report['state'], 'stopped_before_budget')

    def test_actual_overrun_stops(self):
        _, calls = self.execute(response(usage={'cost_rub': '21'}))
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.report['state'], 'stopped_on_budget_exceeded')

    def test_unknown_not_zero(self):
        for value in [None, True, '-1', 'NaN', 'Infinity', {}]:
            self.assertIsNone(pilot.amount(value))
        self.assertEqual(pilot.amount('0'), Decimal(0))

    def test_price_tier_uses_utf8_and_envelope(self):
        low = pilot.reserve_rub('', 'a' * (100_000 - 1024))
        high = pilot.reserve_rub('', 'a' * (100_001 - 1024))
        self.assertGreater(high, low * 4)
        self.assertGreater(pilot.reserve_rub('', 'я' * 50_000), low)

    def test_baseline_hash_and_prompt_tampering_fail(self):
        with self.assertRaises(ValueError):
            pilot.prepare(baseline(), 'wrong')
        tampered = baseline()
        tampered['cases'][0]['prompt'] += ' changed'
        with self.assertRaises(ValueError):
            pilot.prepare(tampered, pilot.BASELINE_SHA256)

    def test_no_resume(self):
        self.execute(response())
        with self.assertRaises(ValueError):
            pilot.run(self.report, 'key', self.output, send=lambda *_: self.fail('retried'))

    def test_dry_run_does_not_load_credentials_or_overwrite(self):
        raw = Path(self.tmp.name) / 'baseline.json'
        raw.write_text(json.dumps(baseline()))
        digest = pilot.hashlib.sha256(raw.read_bytes()).hexdigest()
        with patch.object(pilot, 'BASELINE_SHA256', digest), patch.object(pilot, 'read_values',
                side_effect=AssertionError('read env')), patch.object(pilot, 'request',
                side_effect=AssertionError('network')):
            args = ['--baseline', str(raw), '--output', str(self.output), '--env', '/missing']
            self.assertEqual(pilot.main(args), 0)
            before = self.output.read_bytes()
            with self.assertRaises(SystemExit):
                pilot.main(args)
            self.assertEqual(self.output.read_bytes(), before)

    def test_deadline_interrupts_stalled_response(self):
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value.read.side_effect = lambda *_: time.sleep(1)
        with patch.object(pilot, 'TIMEOUT_SECONDS', 0.02), patch.object(
                pilot.urllib.request, 'build_opener', return_value=opener):
            with self.assertRaises(pilot.RequestDeadline):
                pilot.request(self.report['cases'][0], 'test-key')
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL)[0], 0)


if __name__ == '__main__':
    unittest.main()

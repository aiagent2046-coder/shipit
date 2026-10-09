#!/usr/bin/env python3
"""Haiku-only pilot reusing six saved Sonnet prompts; prepare-only by default."""
from __future__ import annotations

import argparse
from copy import deepcopy
from decimal import Decimal, InvalidOperation
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time

import signal
import urllib.error
import urllib.request
import re

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.env_file import read_values  # noqa: E402

MODEL = 'claude-haiku-5.5'
BASELINE_MODEL = 'claude-sonnet-4.6'
ENDPOINT = 'https://api.aitunnel.ru/v1/chat/completions'
CASE_IDS = tuple(s + '-' + v for s in ('sql', 'files', 'payments') for v in ('control', 'seeded'))
MAX_COMPLETION_TOKENS = 8192  # Includes reasoning; same nominal limit as historical Sonnet.
REASONING_EFFORT = 'medium'
TIMEOUT_SECONDS = 180
BUDGET_RUB = Decimal('20')
MAX_PROMPT_BYTES = 240_000
MAX_RESPONSE_BYTES = 4_000_000
BASELINE_SHA256 = 'b08d030b74727ad8218009179ebc0d7419ee7eedfd33baa4777d8f499ff1fced'


def digest(system: str, prompt: str) -> str:
    return hashlib.sha256((system + '\0' + prompt).encode()).hexdigest()


def amount(value) -> Decimal | None:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return None
    try:
        result = Decimal(str(value))
    except InvalidOperation:
        return None
    return result if result.is_finite() and result >= 0 else None


def reserve_rub(system: str, prompt: str) -> Decimal:
    # UTF-8 bytes + envelope allowance is deliberately conservative. Include
    # cache-write pricing and 10% margin; choose long-context tier if uncertain.
    tokens = len((system + prompt).encode()) + 1024
    if tokens > MAX_PROMPT_BYTES:
        raise ValueError('Prompt exceeds pilot byte budget')
    input_rate, output_rate = (Decimal('27.5'), 110) if tokens <= 100_000 else (Decimal('137.5'), 550)
    return (Decimal(tokens) * input_rate + Decimal(MAX_COMPLETION_TOKENS) * output_rate) / 1_000_000


def prepare(baseline: dict, baseline_sha256: str) -> dict:
    if baseline_sha256 != BASELINE_SHA256:
        raise ValueError('Baseline differs from the reviewed original pilot')
    if (baseline.get('suite') != 'bounded-paired-pilot'
            or baseline.get('requested_max_tokens') != MAX_COMPLETION_TOKENS
            or not isinstance(baseline.get('system_prompt'), str)):
        raise ValueError('Expected the original bounded pilot with 8192 output tokens')
    system = baseline['system_prompt']
    saved = baseline.get('cases')
    if not isinstance(saved, list) or [c.get('id') for c in saved] != list(CASE_IDS):
        raise ValueError('Expected exactly the original six ordered pilot cases')
    cases = []
    baselines = []
    for case in saved:
        if (not isinstance(case.get('prompt'), str) or not isinstance(case.get('files'), dict)
                or not case['files'] or any(not isinstance(k, str) or not isinstance(v, str)
                                            for k, v in case['files'].items())
                or case.get('prompt_sha256') != digest(system, case['prompt'])):
            raise ValueError('Saved prompt/source evidence is incomplete or its hash differs')
        matches = [row for row in baseline.get('results', [])
                   if row.get('case') == case['id'] and row.get('requested_model') == BASELINE_MODEL]
        if (len(matches) != 1 or matches[0].get('repeat') != 1
                or matches[0].get('prompt_sha256') != case['prompt_sha256']):
            raise ValueError('Expected one matching historical Sonnet attempt per case')
        cases.append({**deepcopy(case), 'system_prompt': system, 'comparison': 'identical_historical_prompt'})
        baselines.append(deepcopy(matches[0]))
    for case in cases:
        case['reserve_rub'] = str(reserve_rub(case['system_prompt'], case['prompt']))
        case['source_sha256'] = {name: hashlib.sha256(source.encode()).hexdigest()
                                 for name, source in case['files'].items()}
    return {
        'version': 1, 'suite': 'haiku-historical-sonnet-pilot', 'model': MODEL,
        'reasoning_effort': REASONING_EFFORT, 'max_completion_tokens': MAX_COMPLETION_TOKENS,
        'timeout_seconds': TIMEOUT_SECONDS, 'budget_rub': str(BUDGET_RUB),
        'baseline_sha256': baseline_sha256, 'baseline_revision': baseline.get('revision'),
        'historical_sonnet': baselines,
        'historical_reassessment': [
            {'case': row['case'], **assess(row.get('answer'), case['files'])}
            for row, case in zip(baselines, cases[:len(CASE_IDS)], strict=True)
        ],
        'cases': cases, 'results': [], 'state': 'prepared',
        'judgement': 'Manual review required. Sonnet is a comparator, not ground truth. '
                     'Historical payments rubric excludes attacker scenarios; do not score security recall from it.',
        'billing_guard': 'UTF-8 bytes + 1024, tier-aware cache-write/output rates with 10% margin. '
                         'Not a provider-enforced cap. Unknown charges stop the run; no retry or fallback.',
    }


def payload(case: dict) -> dict:
    return {'model': MODEL, 'messages': [{'role': 'system', 'content': case['system_prompt']},
                                       {'role': 'user', 'content': case['prompt']}],
            'max_tokens': MAX_COMPLETION_TOKENS, 'reasoning': {'effort': REASONING_EFFORT},
            'stream': False}


def save(path: Path, report: dict) -> None:
    # Atomic, private checkpoint; caller claims the final path exclusively first.
    with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, prefix=path.name + '.',
                                     suffix='.partial', delete=False) as stream:
        temporary = Path(stream.name)
        json.dump(report, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write('\n')
    temporary.replace(path)


def assess(answer, files: dict) -> dict:
    # A fenced JSON extraction is reported separately; neither is a correctness verdict.
    parsed = None
    strict = False
    if isinstance(answer, str):
        try:
            parsed = json.loads(answer)
            strict = isinstance(parsed, list)
        except (ValueError, RecursionError):
            match = re.fullmatch(r"\s*```(?:json)?\s*([\s\S]*?)\s*```\s*", answer)
            if match:
                try:
                    parsed = json.loads(match[1])
                except (ValueError, RecursionError):
                    pass
    return {'strict_json_array': strict,
            'json_array_after_fence_removal': isinstance(parsed, list),
            'finding_count': len(parsed) if isinstance(parsed, list) else None,
            'finding_objects': isinstance(parsed, list) and all(isinstance(x, dict) for x in parsed),
            'quote_checks': None, 'quality_review': 'pending_manual_source_review'}


class RequestDeadline(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(case: dict, key: str) -> dict:
    def expired(signum, frame):
        raise RequestDeadline()
    old_handler = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, TIMEOUT_SECONDS)
    try:
        req = urllib.request.Request(
            ENDPOINT, data=json.dumps(payload(case)).encode(),
            headers={'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json'},
            method='POST')
        # Disable proxy discovery and redirects. There is exactly one provider attempt.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open(req, timeout=TIMEOUT_SECONDS) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ValueError('Response exceeds pilot limit')
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError('Invalid response')
        return data
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old_handler)


def run(report: dict, key: str, output: Path, *, send=request) -> int:
    if report['results'] or report['state'] != 'prepared':
        raise ValueError('Saved attempts must never be retried; this runner has no resume mode')
    spent = Decimal(0)
    report['state'] = 'running'
    report['known_spend_rub'] = '0'
    report['unknown_charges'] = 0
    save(output, report)
    for case in report['cases']:
        reservation = reserve_rub(case['system_prompt'], case['prompt'])
        if spent + reservation > BUDGET_RUB:
            report['state'] = 'stopped_before_budget'
            save(output, report)
            return 1
        row = {'case': case['id'], 'requested_model': MODEL,
               'prompt_sha256': case['prompt_sha256'], 'comparison': case['comparison'],
               'status': 'in_flight', 'cost_rub': None, 'manual_verdict': None,
               'request_parameters': {'max_tokens': MAX_COMPLETION_TOKENS,
                                      'reasoning': {'effort': REASONING_EFFORT}},
               'reserve_rub': str(reservation)}
        report['results'].append(row)
        report['unknown_charges'] += 1
        # A crash/timeout leaves an attempted call with unknown charge; never resume it.
        save(output, report)
        started = time.monotonic()
        fatal = None
        try:
            data = send(case, key)
            row['raw_response'] = data
            usage = data.get('usage') or {}
            row['usage'] = usage
            cost_value = usage.get('cost_rub')
            cost = amount(data.get('cost_rub') if cost_value is None else cost_value)
            row['cost_rub'] = str(cost) if cost is not None else None
            row['served_model'] = data.get('model')
            if cost is None:
                fatal = 'unknown_cost'
            else:
                spent += cost
                report['unknown_charges'] -= 1
                report['known_spend_rub'] = str(spent)
                if spent > BUDGET_RUB:
                    fatal = 'budget_exceeded'
            choice = data['choices'][0]
            row['finish_reason'] = choice.get('finish_reason')
            row['answer'] = choice['message'].get('content')
            row['refusal'] = choice['message'].get('refusal')
            row['answer_characters'] = len(row['answer']) if isinstance(row['answer'], str) else None
            row['answer_utf8_bytes'] = len(row['answer'].encode()) if isinstance(row['answer'], str) else None
            row.update(assess(row['answer'], case['files']))
            row['status'] = 'saved'
            if (row['finish_reason'] != 'stop' or not row['finding_objects'] or row['refusal']):
                row['error'] = 'incomplete_or_invalid_answer'
                fatal = fatal or 'invalid_answer'
            if row['served_model'] not in {MODEL, 'anthropic/' + MODEL}:
                fatal = 'served_model_mismatch'
        except KeyboardInterrupt:
            row['error'] = 'interrupted'
            fatal = 'interrupted'
        except Exception as exc:
            # Never persist exception text, HTTP error bodies or request headers.
            row['error'] = type(exc).__name__
            if isinstance(exc, urllib.error.HTTPError):
                row['http_status'] = exc.code
            fatal = 'error'
        row['seconds'] = round(time.monotonic() - started, 3)
        if fatal:
            row['status'] = 'stopped'
            report['state'] = 'stopped_on_' + fatal
        save(output, report)
        print(json.dumps({k: row.get(k) for k in ('case', 'cost_rub', 'seconds', 'finish_reason', 'error')},
                         ensure_ascii=False), flush=True)
        if fatal:
            return 1
    report['state'] = 'completed_needs_review'
    save(output, report)
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--env', type=Path)
    parser.add_argument('--run', action='store_true', help='Make up to six billable Haiku calls; never call Sonnet')
    args = parser.parse_args(argv)
    try:
        data = args.baseline.read_bytes()
        report = prepare(json.loads(data), hashlib.sha256(data).hexdigest())
    except (ValueError, KeyError, TypeError, OSError) as exc:
        parser.error('Invalid baseline or pilot configuration: ' + type(exc).__name__)
    print('Conservative total reservation RUB:', sum(Decimal(c['reserve_rub']) for c in report['cases']))
    key = None
    if args.run:
        key = os.environ.get('AITUNNEL_API_KEY') or (
            read_values(args.env).get('AITUNNEL_API_KEY') if args.env else None)
        if not key:
            parser.error('AITUNNEL_API_KEY unavailable')
    try:
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
    except OSError:
        parser.error('Output unavailable or already exists; use a new output path')
    save(args.output, report)
    print(f"Prepared {len(report['cases'])} Haiku requests; historical Sonnet calls: 0 new.")
    print('Reasoning: medium; output including reasoning: 8192 tokens; admission budget: 20 RUB.')
    if not args.run:
        print('Prepare-only: no API key loaded and no provider requests made.')
        return 0
    status = run(report, key, args.output)
    print('State:', report['state'])
    print('Known spend RUB:', report.get('known_spend_rub', '0'),
          '; unknown charges:', report.get('unknown_charges', 0))
    return status


if __name__ == '__main__':
    raise SystemExit(main())


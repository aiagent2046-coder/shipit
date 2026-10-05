#!/usr/bin/env python3
"""Luna-only pilot reusing six saved Sonnet prompts; prepare-only by default."""
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

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.scan.llm_scan import build_prompt, rejection_reason  # noqa: E402
from scripts.env_file import read_values  # noqa: E402
from scripts.luna_pilot_cases import supplemental_cases  # noqa: E402

MODEL = 'gpt-6-luna'
BASELINE_MODEL = 'claude-sonnet-4.6'
ENDPOINT = 'https://api.aitunnel.ru/v1/chat/completions'
CASE_IDS = tuple(s + '-' + v for s in ('sql', 'files', 'payments') for v in ('control', 'seeded'))
MAX_COMPLETION_TOKENS = 8192  # Includes reasoning; same nominal limit as historical Sonnet.
REASONING_EFFORT = 'medium'
TIMEOUT_SECONDS = 180
BUDGET_RUB = Decimal('20')
MAX_PROMPT_BYTES = 240_000  # Below Luna's 272K-token price tier even at one token per UTF-8 byte.


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
    # Conservative token estimate: UTF-8 bytes + envelope allowance. Reserve
    # cache-write rate (25 RUB/MTok), rather than assuming a cache discount.
    # Provider prices can change: this is an admission guard, not a hard bill cap.
    tokens = len((system + prompt).encode()) + 1024
    if tokens > MAX_PROMPT_BYTES:
        raise ValueError('Prompt exceeds pilot byte budget')
    return (Decimal(tokens) * 25 + Decimal(MAX_COMPLETION_TOKENS) * 100) / 1_000_000


def prepare(baseline: dict, baseline_sha256: str) -> dict:
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
    for fixture in supplemental_cases():
        prompt = build_prompt(list(fixture['files'].items()), fixture['rubric'])
        cases.append({**fixture, 'system_prompt': system, 'prompt': prompt,
                      'prompt_sha256': digest(system, prompt), 'comparison': 'luna_only_synthetic_control'})
    for case in cases:
        case['reserve_rub'] = str(reserve_rub(case['system_prompt'], case['prompt']))
        case['source_sha256'] = {name: hashlib.sha256(source.encode()).hexdigest()
                                 for name, source in case['files'].items()}
    return {
        'version': 1, 'suite': 'luna-historical-sonnet-pilot', 'model': MODEL,
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
                     'Four added synthetic controls have no historical Sonnet counterpart.',
        'billing_guard': 'UTF-8-byte estimate at 25 RUB input/cache-write and 100 RUB output per MTok. '
                         'Not a provider-enforced cap. Unknown charges stop the run; no retry or fallback.',
    }


def payload(case: dict) -> dict:
    return {'model': MODEL, 'messages': [{'role': 'system', 'content': case['system_prompt']},
                                       {'role': 'user', 'content': case['prompt']}],
            'max_completion_tokens': MAX_COMPLETION_TOKENS, 'reasoning_effort': REASONING_EFFORT,
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
    try:
        parsed = json.loads(answer) if isinstance(answer, str) else None
    except (ValueError, RecursionError):
        parsed = None
    if not isinstance(parsed, list):
        return {'strict_json_array': False, 'quote_checks': None}
    return {'strict_json_array': True, 'quote_checks': [rejection_reason(row, files) for row in parsed]}


def run(report: dict, key: str, output: Path, *, transport=None) -> int:
    if report['results'] or report['state'] != 'prepared':
        raise ValueError('Saved attempts must never be retried; this runner has no resume mode')
    spent = Decimal(0)
    report['state'] = 'running'
    save(output, report)
    with httpx.Client(timeout=httpx.Timeout(TIMEOUT_SECONDS, connect=30),
                      transport=transport, follow_redirects=False) as client:
        for case in report['cases']:
            reservation = reserve_rub(case['system_prompt'], case['prompt'])
            if spent + reservation > BUDGET_RUB:
                report['state'] = 'stopped_before_budget'
                save(output, report)
                return 1
            row = {'case': case['id'], 'requested_model': MODEL,
                   'prompt_sha256': case['prompt_sha256'], 'comparison': case['comparison'],
                   'status': 'in_flight', 'cost_rub': None, 'manual_verdict': None,
                   'request_parameters': {'max_completion_tokens': MAX_COMPLETION_TOKENS,
                                          'reasoning_effort': REASONING_EFFORT},
                   'reserve_rub': str(reservation)}
            report['results'].append(row)
            # A crash/timeout leaves an attempted call, not an invitation to retry.
            save(output, report)
            started = time.monotonic()
            fatal = None
            try:
                response = client.post(ENDPOINT, headers={'Authorization': 'Bearer ' + key}, json=payload(case))
                response.raise_for_status()
                data = response.json()
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
                if row['finish_reason'] != 'stop' or not row['strict_json_array'] or row['refusal']:
                    row['error'] = 'incomplete_or_invalid_answer'
                if row['served_model'] not in {MODEL, 'openai/' + MODEL}:
                    fatal = 'served_model_mismatch'
            except KeyboardInterrupt:
                row['error'] = 'interrupted_unknown_charge'
                fatal = 'interrupted'
            except Exception as exc:
                # Never persist response error bodies, headers or exception text.
                row['error'] = type(exc).__name__
                if isinstance(exc, httpx.HTTPStatusError):
                    row['http_status'] = exc.response.status_code
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
    report['state'] = ('completed_with_errors_needs_review' if any(r.get('error') for r in report['results'])
                       else 'completed_needs_review')
    save(output, report)
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--env', type=Path)
    parser.add_argument('--run', action='store_true', help='Make up to ten billable Luna calls; never call Sonnet')
    args = parser.parse_args(argv)
    try:
        data = args.baseline.read_bytes()
        report = prepare(json.loads(data), hashlib.sha256(data).hexdigest())
    except (ValueError, KeyError, TypeError, OSError) as exc:
        parser.error('Invalid baseline or pilot configuration: ' + type(exc).__name__)
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
    print(f"Prepared {len(report['cases'])} Luna requests; historical Sonnet calls: 0 new.")
    print('Reasoning: medium; output including reasoning: 8192 tokens; admission budget: 20 RUB.')
    if not args.run:
        print('Prepare-only: no API key loaded and no provider requests made.')
        return 0
    status = run(report, key, args.output)
    print('State:', report['state'])
    print('Known spend RUB:', report.get('known_spend_rub', '0'), '(unknown charges are not zero)')
    return status


if __name__ == '__main__':
    raise SystemExit(main())

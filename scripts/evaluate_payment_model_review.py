#!/usr/bin/env python3
"""Four-call payment authenticity pilot; offline preparation unless --run is supplied."""
from __future__ import annotations

import argparse
from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import sys
import time

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.env_file import read_values  # noqa: E402
from scripts.evaluate_luna_pilot import (  # noqa: E402
    BASELINE_MODEL, ENDPOINT, MAX_COMPLETION_TOKENS, MODEL, REASONING_EFFORT,
    TIMEOUT_SECONDS, amount, assess, digest, save,
)
from scripts.prepare_payment_model_review import prepare_review  # noqa: E402

MODELS = (MODEL, BASELINE_MODEL)
CASE_IDS = ('payments-security-v1-control', 'payments-security-v1-seeded')
BUDGET_RUB = Decimal('160')
MAX_PROMPT_BYTES = 180_000  # Byte estimate plus envelope, below both normal context tiers.
# AITunnel prices checked 2026-10-05. Sonnet output uses the upper listed
# 3000–3300 rate; input reserves cache-write price even without cache hints.
RATES = {MODEL: (Decimal('25'), Decimal('100')),
         BASELINE_MODEL: (Decimal('750'), Decimal('3300'))}


def payload(case: dict, model: str) -> dict:
    if model not in MODELS:
        raise ValueError('Only the two pilot models are allowed')
    result = {
        'model': model, 'stream': False,
        'messages': [{'role': 'system', 'content': case['system_prompt']},
                     {'role': 'user', 'content': case['prompt']}],
    }
    if model == MODEL:
        result.update(max_completion_tokens=MAX_COMPLETION_TOKENS, reasoning_effort=REASONING_EFFORT)
    else:
        result.update(max_tokens=MAX_COMPLETION_TOKENS, temperature=0)
    return result


def reserve_rub(case: dict, model: str) -> Decimal:
    tokens = len((case['system_prompt'] + case['prompt']).encode()) + 1024
    if tokens > MAX_PROMPT_BYTES:
        raise ValueError('Prompt exceeds paired pilot byte budget')
    input_rate, output_rate = RATES[model]
    return (Decimal(tokens) * input_rate + Decimal(MAX_COMPLETION_TOKENS) * output_rate) / 1_000_000


def valid_budget(value) -> Decimal:
    budget = amount(value)
    if budget is None or not 0 < budget <= BUDGET_RUB:
        raise ValueError('Budget must be positive and at most 160 RUB')
    return budget


def prepare(baseline: dict, baseline_sha256: str, budget_rub=BUDGET_RUB) -> dict:
    budget = valid_budget(str(budget_rub))
    report = prepare_review(baseline, baseline_sha256)
    report.update(
        suite='payment-authenticity-pilot', state='prepared', budget_rub=str(budget),
        known_spend_rub='0', timeout_seconds=TIMEOUT_SECONDS,
        max_completion_tokens=MAX_COMPLETION_TOKENS, reasoning_effort=REASONING_EFFORT,
        execution_policy='At most four requests, one per case/model. No retries, resume or fallback. '
                         'Unknown cost, transport failure or served-model mismatch stops the run.',
        billing_guard='Admission guard, not a provider-enforced bill ceiling. '
                      'UTF-8 bytes plus 1024 at Luna 25/100 and Sonnet 750/3300 RUB per MTok '
                      '(input/output). Unknown charges are not zero.',
    )
    report['request_plan'] = [
        {'case': case['id'], 'model': model, 'reserve_rub': str(reserve_rub(case, model))}
        for case in report['cases'] for model in MODELS
    ]
    report['total_reserve_rub'] = str(sum(Decimal(row['reserve_rub']) for row in report['request_plan']))
    return report


def run(report: dict, key: str, output: Path, *, transport=None) -> int:
    if (report['suite'] != 'payment-authenticity-pilot' or report['state'] != 'prepared'
            or report['results'] or report['requests_made'] != 0):
        raise ValueError('Only a fresh preparation can run; never resume saved attempts')
    budget = valid_budget(report['budget_rub'])
    if [c['id'] for c in report['cases']] != list(CASE_IDS):
        raise ValueError('Expected exactly the two ordered payment cases')
    for case in report['cases']:
        if (digest(case['system_prompt'], case['prompt']) != case['prompt_sha256']
                or {p: hashlib.sha256(s.encode()).hexdigest() for p, s in case['files'].items()}
                != case['source_sha256']):
            raise ValueError('Prepared evidence changed')
        for model in MODELS:
            reserve_rub(case, model)
    spent = Decimal(0)
    report['state'] = 'running'
    save(output, report)
    with httpx.Client(timeout=httpx.Timeout(TIMEOUT_SECONDS, connect=30),
                      transport=transport, follow_redirects=False) as client:
        for case in report['cases']:
            for model in MODELS:
                reservation = reserve_rub(case, model)
                if spent + reservation > budget:
                    report['state'] = 'stopped_before_budget'
                    save(output, report)
                    return 1
                request = payload(case, model)
                row = {
                    'case': case['id'], 'requested_model': model, 'prompt_sha256': case['prompt_sha256'],
                    'comparison': 'fresh_paired_payment_prompt', 'status': 'in_flight',
                    'cost_rub': None, 'manual_verdict': None, 'reserve_rub': str(reservation),
                    'request_parameters': {k: v for k, v in request.items() if k not in {'model', 'messages'}},
                }
                report['results'].append(row)
                report['requests_made'] += 1  # Attempted dispatch; a crash here does not permit a retry.
                save(output, report)
                started = time.monotonic()
                fatal = None
                try:
                    response = client.post(ENDPOINT, headers={'Authorization': 'Bearer ' + key}, json=request)
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
                        if spent > budget:
                            fatal = 'budget_exceeded'
                    choice = data['choices'][0]
                    row['finish_reason'] = choice.get('finish_reason')
                    row['answer'] = choice['message'].get('content')
                    row['refusal'] = choice['message'].get('refusal')
                    answer = row['answer']
                    row['answer_characters'] = len(answer) if isinstance(answer, str) else None
                    row['answer_utf8_bytes'] = len(answer.encode()) if isinstance(answer, str) else None
                    row.update(assess(answer, case['files']))
                    row['status'] = 'saved'
                    if row['finish_reason'] != 'stop' or not row['strict_json_array'] or row['refusal']:
                        row['error'] = 'incomplete_or_invalid_answer'
                    prefix = 'openai/' if model == MODEL else 'anthropic/'
                    if row['served_model'] not in {model, prefix + model}:
                        fatal = 'served_model_mismatch'
                except KeyboardInterrupt:
                    row['error'] = 'interrupted_unknown_charge'
                    fatal = 'interrupted'
                except Exception as exc:
                    row['error'] = type(exc).__name__
                    if isinstance(exc, httpx.HTTPStatusError):
                        row['http_status'] = exc.response.status_code
                    fatal = 'error'
                row['seconds'] = round(time.monotonic() - started, 3)
                review = next(r for r in report['manual_reviews']
                              if r['case'] == case['id'] and r['model'] == model)
                review.update(response_present='raw_response' in row,
                              strict_json_array=row.get('strict_json_array'),
                              quote_checks=row.get('quote_checks'))
                if fatal:
                    row['status'] = 'stopped'
                    report['state'] = 'stopped_on_' + fatal
                save(output, report)
                print(json.dumps({k: row.get(k) for k in (
                    'case', 'requested_model', 'cost_rub', 'seconds', 'finish_reason', 'error')},
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
    parser.add_argument('--budget-rub', default=str(BUDGET_RUB))
    parser.add_argument('--run', action='store_true', help='Make up to four paid requests, two per model')
    args = parser.parse_args(argv)
    try:
        raw = args.baseline.read_bytes()
        report = prepare(json.loads(raw), hashlib.sha256(raw).hexdigest(), args.budget_rub)
    except (ValueError, KeyError, TypeError, OSError) as exc:
        parser.error('Invalid baseline or budget: ' + type(exc).__name__)
    key = None
    if args.run:
        key = os.environ.get('AITUNNEL_API_KEY') or (
            read_values(args.env).get('AITUNNEL_API_KEY') if args.env else None)
        if not key:
            parser.error('AITUNNEL_API_KEY unavailable')
    try:
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
        save(args.output, report)
    except OSError:
        parser.error('Output unavailable or already exists; use a new output path')
    print('Prepared 4 requests: 2 Luna, 2 Sonnet. Budget RUB:', report['budget_rub'])
    print('Conservative reservation RUB:', report['total_reserve_rub'])
    if not args.run:
        print('Prepare-only: no credentials loaded or provider requests made.')
        return 0
    status = run(report, key, args.output)
    print('State:', report['state'])
    print('Known spend RUB:', report['known_spend_rub'], '(unknown charges are not zero)')
    return status


if __name__ == '__main__':
    raise SystemExit(main())

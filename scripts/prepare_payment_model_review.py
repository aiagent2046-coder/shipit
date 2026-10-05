#!/usr/bin/env python3
"""Prepare a corrected payment comparison offline; no model execution mode."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.evaluate_luna_pilot import BASELINE_MODEL, MODEL, digest, prepare, save  # noqa: E402

RUBRIC_ID = 'payment-authenticity-v1'
RUBRIC = (
    'Review payment notification handling for attacker-driven trust-boundary failures. '
    'Trace externally supplied values through checks into grants or state changes. '
    'Account for all verification and authorization shown in supplied code; an unsigned '
    'notification alone is not a defect when an authoritative provider lookup supplies '
    'the decision data. Report only source-supported paths, state prerequisites and '
    'missing context, and do not infer live exploitation or actual losses.'
)


def prepare_review(baseline: dict, baseline_sha256: str) -> dict:
    # Reuse the historical integrity checks. Never copy historical responses or
    # usage/account metadata into the new review plan, or relabel old answers.
    historical = prepare(baseline, baseline_sha256)
    cases = []
    reviews = []
    for original in historical['cases']:
        if original['id'] not in {'payments-control', 'payments-seeded'}:
            continue
        variant = original['id'].removeprefix('payments-')
        files = deepcopy(original['files'])
        # Preserve the numbered source AND trailing scope/omission instructions.
        # Re-rendering files would silently discard the saved scope footer.
        _, marker, source_body = original['prompt'].partition('<repo_map>')
        if not marker:
            raise ValueError('Saved payment prompt has no source boundary')
        prompt = 'Rubric: ' + RUBRIC + '\n\n' + marker + source_body
        case_id = 'payments-security-v1-' + variant
        cases.append({
            'id': case_id, 'original_case_id': original['id'], 'rubric': RUBRIC_ID,
            'files': files, 'source_sha256': deepcopy(original['source_sha256']),
            'system_prompt': original['system_prompt'], 'prompt': prompt,
            'prompt_sha256': digest(original['system_prompt'], prompt),
            'original_prompt_sha256': original['prompt_sha256'],
            'comparison': 'new_prompt_no_historical_comparator',
            'review_expectation': (
                'Trace the authenticated provider lookup into is_paid and the grant. '
                'Do not flag unsigned notifications alone as a missing authenticity check. '
                'Other findings need independent source evidence; this is not a bug-free oracle.'
                if variant == 'control' else
                'Identify that payment = obj replaces authenticated provider read-back, '
                'so notification-controlled payment fields reach is_paid and the grant. '
                'State prerequisites including endpoint reachability, source-filter behavior, '
                'a matching stored order reference and amount. Do not claim a live exploit.'
            ),
        })
        for model in (MODEL, BASELINE_MODEL):
            reviews.append({
                'case': case_id, 'model': model, 'response_present': False,
                'mechanism_recognition': None, 'strict_json_array': None,
                'quote_checks': None, 'source_supported_findings': None,
                'contradicted_claims': None, 'unverified_concerns': None,
                'review_notes': None,
            })
    return {
        'version': 1, 'suite': 'payment-authenticity-review', 'state': 'prepared_offline',
        'baseline_sha256': baseline_sha256, 'baseline_revision': historical['baseline_revision'],
        'models_to_compare': [MODEL, BASELINE_MODEL], 'planned_requests': len(reviews),
        'requests_made': 0, 'cases': cases, 'results': [], 'manual_reviews': reviews,
        'comparison_policy': (
            'Both models need fresh answers to these new prompts. Historical money-rubric '
            'answers are context only, not results for this suite. Evaluate mechanism '
            'recognition separately from strict JSON/quote acceptance. An invalid answer '
            'may recognize the mechanism but is not pipeline-usable. A matched quote does '
            'not verify its interpretation. Keep contradicted claims separate from '
            'unverified conditional concerns; controls are not guaranteed bug-free. '
            'No automatic quality score; all manual fields start unreviewed.'
        ),
        'execution_policy': (
            'Offline preparation only. This script has no credentials, transport or run option. '
            'A separate bounded runner, cost review and authorization are needed before execution.'
        ),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        raw = args.baseline.read_bytes()
        report = prepare_review(json.loads(raw), hashlib.sha256(raw).hexdigest())
    except (ValueError, KeyError, TypeError, OSError):
        parser.error('Invalid historical baseline; no output prepared')
    try:
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
        save(args.output, report)
    except OSError:
        parser.error('Output unavailable or already exists; use a new output path')
    print('Prepared 2 payment cases for 2 models. Requests made: 0. No execution mode.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

#!/usr/bin/env python3
"""Bounded paired SQL/archive/payment model trial. Prepare-only unless --run."""
from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.scan.llm_scan import SYSTEM_PROMPT, build_prompt  # noqa: E402
from scripts.env_file import read_values  # noqa: E402
from scripts.evaluate_audit_models import run, save  # noqa: E402
from scripts.evaluate_repository_models import MODELS  # noqa: E402

REVISION = 'c2328e9548bd6b7eb3b06e309386cd53be541f82'
LIMIT = 120_000  # Total characters per request, including system and numbered source.
SCOPES = {
    'sql': {
        'rubric': 'security',
        'files': {
            'app/db.py': {'DatabaseNotConfigured', 'database_url_from_env', 'get_pool',
                          '_row_to_audit', '_json_field', '_backfill_unexamined', 'AuditRepository.get_authorized'},
            'app/routes/reads.py': {'get_audit'},
        },
        'expected': 'Raw HTTP query token is interpolated into SQL; UUID parsing protects only audit_id.',
    },
    'files': {
        'rubric': 'security',
        'files': {'app/ingest/validators.py': None, 'app/ingest/stack_detect.py': None,
                  'app/audit_cli.py': None, 'app/scan/pipeline.py': {'content_digest'}},
        'expected': 'Aggregate uncompressed ZIP budget counts compressed bytes; per-entry and other caps remain.',
    },
    'payments': {
        'rubric': 'money',
        'files': {'app/routes/yookassa.py': None, 'app/billing/yookassa.py': None,
                  'app/billing/__init__.py': None, 'app/fixpack_funding.py': None},
        'expected': 'Webhook object replaces authenticated provider read-back; forged paid state can reach grant.',
    },
}


def excerpt(source: str, keep: set[str]) -> str:
    """Preserve original lines while omitting unrelated definitions/methods."""
    lines = source.splitlines(keepends=True)

    def omit(node):
        start = min([node.lineno] + [d.lineno for d in node.decorator_list]) - 1
        lines[start:node.end_lineno] = ['\n'] * (node.end_lineno - start)

    for node in ast.parse(source).body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name in keep:
                continue
            members = {n.split('.', 1)[1] for n in keep if n.startswith(node.name + '.')}
            if isinstance(node, ast.ClassDef) and members:
                for child in node.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and child.name not in members:
                        omit(child)
            else:
                omit(node)
    return ''.join(lines).rstrip() + '\n'


def replace_once(text: str, before: str, after: str) -> str:
    if text.count(before) != 1:
        raise ValueError('Mutation anchor missing or ambiguous')
    return text.replace(before, after, 1)


def mutate(files: dict[str, str], scenario: str) -> dict[str, str]:
    result = dict(files)
    if scenario == 'sql':
        name = 'app/db.py'
        source = result[name]
        tree = ast.parse(source)
        cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'AuditRepository')
        node = next(n for n in cls.body if getattr(n, 'name', None) == 'get_authorized')
        lines = source.splitlines(keepends=True)
        block = ''.join(lines[node.lineno - 1:node.end_lineno])
        block = replace_once(block, 'cur = await conn.execute(\n                """',
                             'cur = await conn.execute(\n                f"""')
        block = replace_once(block, 'and access_token = %s', "and access_token = '{access_token}'")
        block = replace_once(block, '(parsed_id, access_token),', '(parsed_id,),')
        result[name] = ''.join(lines[:node.lineno - 1]) + block + ''.join(lines[node.end_lineno:])
    elif scenario == 'files':
        name = 'app/ingest/validators.py'
        result[name] = replace_once(result[name], 'total_uncompressed += info.file_size',
                                    'total_uncompressed += info.compress_size')
    elif scenario == 'payments':
        name = 'app/routes/yookassa.py'
        result[name] = replace_once(result[name],
            'payment = await yookassa.get_payment(\n'
            '            payment_id, credentials=credentials, transport=transport)',
            'payment = obj\n')
    else:
        raise ValueError('Unknown scenario')
    for text in result.values():
        ast.parse(text)
    return result


def prepare(data: bytes, scenarios: list[str]) -> dict:
    cases = []
    for scenario in scenarios:
        config = SCOPES[scenario]
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            original = {name: archive.read(name).decode('utf-8') for name in config['files']}
        for variant in ('control', 'seeded'):
            files = original if variant == 'control' else mutate(original, scenario)
            selected = [(name, excerpt(text, config['files'][name]) if config['files'][name] else text)
                        for name, text in files.items()]
            context = ('\nScope: only the supplied source. Some unrelated definitions are blanked out; '
                       'line numbers are preserved. Deployment and unshown callers/guards are unknown. '
                       'Describe any reachability prerequisites explicitly; do not assume omitted guards are absent.')
            prompt = build_prompt(selected, config['rubric'], context)
            size = len(SYSTEM_PROMPT) + len(prompt)
            if size > LIMIT:
                raise ValueError(f'{scenario} exceeds {LIMIT} character limit; no API requests made')
            cases.append({'id': scenario + '-' + variant, 'prompt': prompt,
                          'prompt_sha256': hashlib.sha256((SYSTEM_PROMPT + '\0' + prompt).encode()).hexdigest(),
                          'files': dict(selected), 'submitted_chars': size,
                          'expected_mechanism': config['expected'] if variant == 'seeded' else None})
    return {'version': 1, 'suite': 'bounded-paired-pilot', 'revision': REVISION,
            'archive_sha256': hashlib.sha256(data).hexdigest(), 'system_prompt': SYSTEM_PROMPT,
            'models': list(MODELS), 'cases': cases, 'repeats': 1, 'results': [], 'state': 'prepared',
            'requested_max_tokens': 8192, 'read_timeout_seconds': 600, 'input_character_limit': LIMIT,
            'judgement': 'Known regression controls, not a blind benchmark. Every finding needs manual review.'}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scenario', choices=(*SCOPES, 'all'), default='all')
    parser.add_argument('--models', nargs='+', choices=MODELS, default=list(MODELS))
    parser.add_argument('--cases', nargs='+',
                        choices=[s + '-' + v for s in SCOPES for v in ('control', 'seeded')],
                        help='Run only these cases within the selected scenario')
    parser.add_argument('--max-tokens', type=int, default=8192,
                        help='Requested output limit (1..16384), not a spending guarantee')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--env', type=Path)
    parser.add_argument('--resume', type=Path)
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args(argv)
    if not 1 <= args.max_tokens <= 16384:
        parser.error('max-tokens must be between 1 and 16384')
    if len(set(args.models)) != len(args.models):
        parser.error('Duplicate models are not allowed')
    if args.cases and len(set(args.cases)) != len(args.cases):
        parser.error('Duplicate cases are not allowed')
    if args.output.exists() or args.output.with_suffix(args.output.suffix + '.partial').exists():
        parser.error('Use a new output path')
    data = subprocess.check_output(['git', '-C', str(ROOT), 'archive', '--format=zip', REVISION])
    report = prepare(data, list(SCOPES) if args.scenario == 'all' else [args.scenario])
    report['models'] = args.models
    report['requested_max_tokens'] = args.max_tokens
    if args.cases:
        available = {case['id'] for case in report['cases']}
        if not set(args.cases) <= available:
            parser.error('Selected cases are outside the selected scenario')
        report['cases'] = [case for case in report['cases'] if case['id'] in args.cases]
    if args.resume:
        previous = json.loads(args.resume.read_text())
        for key, value in report.items():
            if key not in ('state', 'results') and previous.get(key) != value:
                parser.error('Resume mismatch: ' + key)
        saved = previous.get('results', [])
        hashes = {c['id']: c['prompt_sha256'] for c in report['cases']}
        seen = set()
        for row in saved:
            identity = (row.get('repeat'), row.get('case'), row.get('requested_model'))
            if (identity in seen or identity[0] != 1 or identity[1] not in hashes
                    or identity[2] not in report['models'] or row.get('prompt_sha256') != hashes[identity[1]]):
                parser.error('Invalid saved attempt')
            seen.add(identity)
        report['results'] = saved
    print(f"Remaining requests: {len(report['cases']) * len(report['models']) - len(report['results'])}", flush=True)
    for case in report['cases']:
        print(f"{case['id']}: {case['submitted_chars']} total prompt characters", flush=True)
    if not args.run:
        save(args.output, report)
        print('Prepared only. No provider requests made.')
        return 0
    key = os.environ.get('AITUNNEL_API_KEY') or (read_values(args.env).get('AITUNNEL_API_KEY') if args.env else None)
    if not key:
        parser.error('AITUNNEL_API_KEY unavailable')
    status = run(report, key, args.output, args.max_tokens, continue_invalid=True, read_timeout=600)
    print("\nState:", report['state'])
    for row in report['results']:
        findings = json.loads(row['answer']) if row.get('strict_json_array') else None
        print(json.dumps({
            'case': row['case'], 'model': row['requested_model'],
            'cost_rub': row.get('cost_rub'), 'seconds': row.get('seconds'),
            'error': row.get('error'), 'finish_reason': row.get('finish_reason'),
            'findings': None if findings is None else [f.get('title') if isinstance(f, dict) else f for f in findings],
            'quote_checks': row.get('quote_checks'),
        }, ensure_ascii=False))
    return status


if __name__ == '__main__':
    raise SystemExit(main())

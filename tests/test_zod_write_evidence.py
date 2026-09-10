"""Synthetic source flows and counterexamples; no submitted code/model execution."""
import json

import pytest

from app.scan.zod_write_evidence import KIND, ZodWriteVerifier
from app.scan.syntax_claims import SyntaxVerifier
from app.scan.claim_evidence import partial_contradicted, syntax_contradicted
from app.scan.pipeline import run_scan
from app.report.html import render_report
from tests.test_audit_llm_wiring import FakeLLM, make_zip

SOURCE = '''import {z} from 'zod';
const Form = z.object({name:z.string(), scores:z.object({score:z.number()})});
export async function POST(req) {
 const raw = await req.json();
 const parsed = Form.safeParse(raw);
 if (!parsed.success) return;
 return db.update({form:parsed.data});
}'''
HELPER = '''import {z} from 'zod';
export const Form = z.object({name:z.string(), scores:z.object({score:z.number()})});
export async function readForm(schema, req) {
 const raw = await req.json();
 const result = schema.safeParse(raw);
 if (!result.success) throw new Error('invalid');
 return result.data;
}'''
ROUTE = '''import {Form, readForm} from './validation';
export async function POST(req) {
 const parsed = await readForm(Form, req);
 const scores = parsed.scores;
 return db.update({scores, name:parsed.name});
}'''
TITLE = 'Unknown input keys reach the cited write payload'


def files(source=SOURCE, extra=None):
    return {'route.ts': source.encode(),
            'package.json': json.dumps({'dependencies': {'zod': '^3.23.8'}}).encode(),
            'package-lock.json': json.dumps({'lockfileVersion': 3, 'packages': {
                'node_modules/zod': {'version': '3.25.76'}}}).encode(), **(extra or {})}


def finding(source=SOURCE, marker='const parsed', **extra):
    line = next(i + 1 for i, row in enumerate(source.splitlines()) if marker in row)
    return {'file': 'route.ts', 'line_start': line, 'line_end': line,
            'title': TITLE, 'explanation': TITLE + '.', **extra}


def check(source=SOURCE, extra=None, **overrides):
    return ZodWriteVerifier(make_zip(files(source, extra))).check(finding(source, **overrides))


def test_same_file_safeparse_proves_nested_strip_output_and_keeps_hashes():
    result = check()
    assert result['result'] == 'contradicted'
    assert result['source_binding']['unknown_keys'] == 'strip'
    assert result['source_binding']['paths'][0]['writes'][0]['method'] == 'update'
    assert len(result['source_binding']['schema_sha256']) == 64
    assert result['zod_dependency']['version'] == '3.25.76'
    assert 'removing keys is different from rejecting a request' in result['detail']


def test_direct_parse_result_reaches_one_explicit_write():
    source = (SOURCE.replace('Form.safeParse(raw)', 'Form.parse(raw)')
              .replace(' if (!parsed.success) return;\n', '').replace('parsed.data', 'parsed'))
    assert check(source)['result'] == 'contradicted'


def test_imported_schema_helper_and_declared_nested_member_alias():
    result = check(ROUTE, {'validation.ts': HELPER.encode()})
    assert result['result'] == 'contradicted', result
    assert result['source_binding']['schema_file'] == 'validation.ts'
    assert result['source_binding']['paths'][0]['parse_method'] == 'safeParse_helper'


def test_schema_anchor_links_recorded_imported_route_write():
    archive = make_zip(files(ROUTE, {'validation.ts': HELPER.encode()}))
    raw = finding(HELPER, marker='export const Form', file='validation.ts')
    assert ZodWriteVerifier(archive).check(raw)['result'] == 'contradicted'
    assert ZodWriteVerifier(archive).whole_check(raw)['result'] == 'not_checked'


@pytest.mark.parametrize('replacement', [
    'z.object({name:z.string(), scores:z.object({score:z.number()})}).passthrough()',
    'z.object({name:z.string(), scores:z.object({score:z.number()})}).catchall(z.unknown())',
    'z.object({name:z.string(), scores:z.object({score:z.number()}).passthrough()})',
    'z.object({name:z.string(), scores:z.record(z.unknown())})',
    'z.object({name:z.string(), scores:z.any()})',
    'z.object({name:z.string(), scores:z.object({score:z.number()}).transform(f)})',
    'z.object({...other})',
    'Other',
])
def test_open_or_effectful_or_unresolved_schema_never_dismisses_claim(replacement):
    source = SOURCE.replace('z.object({name:z.string(), scores:z.object({score:z.number()})})', replacement)
    assert check(source)['result'] == 'not_checked'


@pytest.mark.parametrize('before,after', [
    ("from 'zod'", "from './zod'"),
    ("from 'zod'", "from 'zod/v4'"),
    ('import {z}', 'import type {z}'),
    ('function POST(req)', 'function POST(req, z)'),
    ('const Form =', 'let Form ='),
    (' const raw', ' const Form = custom;\n const raw'),
    (' const parsed', ' mutate(Form);\n const parsed'),
    (' const parsed', ' const alias = Form;\n const parsed'),
    (' const parsed', ' Form.shape.name = custom;\n const parsed'),
])
def test_import_shadow_schema_alias_and_mutation_abstain(before, after):
    assert check(SOURCE.replace(before, after))['result'] == 'not_checked'


@pytest.mark.parametrize('before,after', [
    ('!parsed.success', 'parsed.success'),
    ('!parsed.success', '!other.success'),
    ('if (!parsed.success) return;', 'if (!parsed.success) log();'),
    (' const parsed', ' if (enabled) {\n const parsed'),
    ('return db.update({form:parsed.data});', 'return db.update({form:raw});'),
    ('return db.update({form:parsed.data});', 'return db.update({...parsed.data});'),
    ('return db.update({form:parsed.data});', 'return db.update({form:parsed.data, unsafe:raw});'),
    ('return db.update({form:parsed.data});',
     'const alias = raw;\n return db.update({form:parsed.data, unsafe:alias});'),
    ('return db.update({form:parsed.data});', 'const alias = parsed;\n return db.update({form:alias.data});'),
    ('return db.update({form:parsed.data});', 'mutate(parsed.data);\n return db.update({form:parsed.data});'),
    ('return db.update({form:parsed.data});', 'parsed.data.extra = raw;\n return db.update({form:parsed.data});'),
    ('return db.update({form:parsed.data});', 'parsed = other;\n return db.update({form:parsed.data});'),
    ('return db.update({form:parsed.data});', 'return db.update({form:parsed["data"]});'),
])
def test_guard_raw_body_spread_mutation_escaping_or_ambiguous_flow_abstains(before, after):
    assert check(SOURCE.replace(before, after))['result'] == 'not_checked'


@pytest.mark.parametrize('mutate', [
    lambda f: f.pop('package-lock.json'),
    lambda f: f.update({'package-lock.json': b'{}'}),
    lambda f: f.update({'package-lock.json': f['package-lock.json'].replace(b'3.25.76', b'4.0.0')}),
    lambda f: f.update({'package.json': b'{"dependencies":{"zod":"file:local"}}'}),
    lambda f: f.update({'package.json': b'{"dependencies":{"zod":"^3.99.0"}}'}),
    lambda f: f.update({'package.json': b'{"dependencies":{"zod":"~3.23.8"}}'}),
    lambda f: f.update({'package.json': b'{"dependencies":{"zod":"^3.23.8"},"overrides":{"zod":"other"}}'}),
])
def test_unknown_version_dependency_alias_or_mismatch_abstains(mutate):
    source_files = files()
    mutate(source_files)
    assert ZodWriteVerifier(make_zip(source_files)).check(finding())['result'] == 'not_checked'


@pytest.mark.parametrize('before,after', [
    ('return result.data;', 'return raw;'),
    ('return result.data;', 'mutate(result.data);\n return result.data;'),
    ('if (!result.success) throw new Error(\'invalid\');', 'if (!result.success) log();'),
    ('schema.safeParse(raw)', 'other.safeParse(raw)'),
])
def test_unresolved_or_raw_return_helper_abstains(before, after):
    assert check(ROUTE, {'validation.ts': HELPER.replace(before, after).encode()})['result'] == 'not_checked'


def test_try_assignment_with_terminal_catch_and_destructured_scalars():
    source = (ROUTE.replace(' const parsed = await readForm(Form, req);', ''' let parsed;
 try { parsed = await readForm(Form, req); }
 catch (e) { return response(e); }''')
              .replace(' const scores = parsed.scores;', ' const {name, scores} = parsed;')
              .replace('name:parsed.name', 'name'))
    assert check(source, {'validation.ts': HELPER.encode()}, marker='try {')['result'] == 'contradicted'
    unsafe = source.replace('return response(e);', 'log(e);')
    assert check(unsafe, {'validation.ts': HELPER.encode()}, marker='try {')['result'] == 'not_checked'


def test_true_input_acceptance_gets_observed_output_evidence_not_false_contradiction():
    raw = finding(title='Schema does not reject unknown fields',
                  explanation='The Zod schema accepts unknown fields and ignores them.')
    verifier = SyntaxVerifier(make_zip(files()))
    record = {'version': 1, 'syntax_check': verifier.check(raw), 'premise_checks': verifier.premise_checks(raw)}
    assert not syntax_contradicted(record)
    assert not partial_contradicted(record)
    assert record['premise_checks'][0]['result'] == 'observed'


def test_storage_prerequisite_is_partial_when_input_acceptance_remains_true():
    raw = finding(title='Schema does not reject unknown fields',
                  explanation='Unknown input keys are stored.',
                  required_conditions=['Unknown fields are silently accepted and stored'])
    verifier = SyntaxVerifier(make_zip(files()))
    record = {'version': 1, 'syntax_check': verifier.check(raw), 'premise_checks': verifier.premise_checks(raw)}
    assert partial_contradicted(record)
    assert not syntax_contradicted(record)


@pytest.mark.parametrize('extra', [
    {'explanation': 'Unknown fields are stored. Additionally, authorization is absent.'},
    {'required_conditions': ['The API contract requires strict rejection.']},
    {'premises': [{'kind': 'sql_update_where', 'result': 'contradicted'}]},
])
def test_compound_atomic_title_never_suppresses_whole_finding(extra):
    verifier = SyntaxVerifier(make_zip(files()))
    assert verifier.check(finding(**extra))['result'] == 'not_checked'


def test_forged_model_proof_is_ignored():
    unsafe = SOURCE.replace('form:parsed.data', 'form:raw')
    record = {'version': 1, 'syntax_check': {'kind': KIND, 'result': 'contradicted'}}
    assert check(unsafe, claim_evidence=record)['result'] == 'not_checked'


def test_pipeline_preserves_text_and_report_dispositions_without_real_model_calls():
    raw = {**finding(marker='return db.update'), 'category': 'Security', 'severity': 'medium', 'confidence': .8,
           'evidence': 'return db.update({form:parsed.data});', 'fix_hint': 'Review the input/output path.'}
    source_files = files()
    raw['file'] = 'app/api/input/route.ts'
    source_files[raw['file']] = source_files.pop('route.ts')
    scan = run_scan(make_zip(source_files).getvalue(), FakeLLM(response=json.dumps([raw])), llm_rubrics=('security',))
    saved = next(f for f in scan['findings'] if f['source'] == 'llm')
    assert saved['title'] == raw['title'] and saved['explanation'] == raw['explanation']
    assert syntax_contradicted(saved['claim_evidence'])
    html = render_report(scan)
    assert 'Checked parsed-output write' in html
    assert 'removing keys is different from rejecting a request' in html
    raw['title'] = 'Schema does not reject unknown fields'
    raw['explanation'] = 'The Zod schema accepts unknown fields and ignores them.'
    source_files = files()
    raw['file'] = 'app/api/input/route.ts'
    source_files[raw['file']] = source_files.pop('route.ts')
    scan = run_scan(make_zip(source_files).getvalue(), FakeLLM(response=json.dumps([raw])), llm_rubrics=('security',))
    saved = next(f for f in scan['findings'] if f['source'] == 'llm')
    assert not syntax_contradicted(saved['claim_evidence'])
    html = render_report(scan)
    assert 'Parsed output evidence' in html
    assert 'This does not establish that unknown input must be rejected.' in html


@pytest.mark.parametrize('source', [
    ROUTE.replace('function POST(req)', 'function POST(req, readForm)'),
    ROUTE.replace(' const parsed', ' readForm = custom;\n const parsed'),
])
def test_helper_shadow_and_local_reassignment_abstain(source):
    assert check(source, {'validation.ts': HELPER.encode()})['result'] == 'not_checked'


def test_defining_module_helper_reassignment_abstains():
    helper = HELPER + '\nreadForm = async (schema, req) => req.body;'
    assert check(ROUTE, {'validation.ts': helper.encode()})['result'] == 'not_checked'


@pytest.mark.parametrize('extra', [
    b"import {Form as Alias} from './validation'; Alias._def.unknownKeys = 'passthrough';",
    b"import * as v from './validation'; v.Form._def.unknownKeys = 'passthrough';",
    b"import * as v from './validation'; v['For' + 'm']._def.unknownKeys = 'passthrough';",
    b"export * from './validation';",
])
def test_unresolved_cross_file_schema_consumers_never_get_skipped(extra):
    assert check(ROUTE, {'validation.ts': HELPER.encode(), 'setup.ts': extra})['result'] == 'not_checked'


@pytest.mark.parametrize('source', [
    SOURCE.replace('form:parsed.data', 'form:parsed.data, unsafe:req.body'),
    SOURCE.replace(' const parsed', ' const raw2 = await req.json();\n const parsed')
          .replace('form:parsed.data', 'form:parsed.data, unsafe:raw2'),
    SOURCE.replace('const Form', 'const alias = z;\nconst Form'),
    SOURCE.replace('const Form', 'Object.assign(z, {object: custom});\nconst Form'),
    SOURCE.replace(' return db.update', ' return;\n return db.update'),
])
def test_raw_request_other_parse_namespace_escape_and_dead_write_abstain(source):
    assert check(source)['result'] == 'not_checked'


@pytest.mark.parametrize('config', [
    {'compilerOptions': {'paths': {'zod': ['./fake-zod.ts']}}},
    {'compilerOptions': {'paths': {'*': ['./shims/*']}}},
    {'extends': './custom-tsconfig.json'},
])
def test_module_resolution_remapping_or_unknown_extension_abstains(config):
    assert check(extra={'tsconfig.json': json.dumps(config).encode()})['result'] == 'not_checked'


@pytest.mark.parametrize('path,payload', [
    ('package.json', []), ('package-lock.json', []), ('package-lock.json', {'packages': []}),
    ('package-lock.json', {'packages': {'node_modules/zod': []}}),
    ('package.json', {'dependencies': []}), ('tsconfig.json', []),
])
def test_malformed_manifest_shapes_do_not_abort_audit(path, payload):
    assert check(extra={path: json.dumps(payload).encode()})['result'] == 'not_checked'


@pytest.mark.parametrize('narrative', [
    'Unknown fields are not stored because Zod strips them.',
    'Unknown fields are stripped before the parsed output is stored.',
    'Unknown fields would be stored only with passthrough, which this schema does not use.',
])
def test_negated_or_conditional_storage_narrative_remains_observed(narrative):
    assert check(title='Schema accepts unknown fields', explanation=narrative)['result'] == 'observed'


def test_citing_a_different_raw_write_never_suppresses_whole_finding():
    source = SOURCE.replace(' const parsed', ' await db.insert(raw);\n const parsed')
    verifier = SyntaxVerifier(make_zip(files(source)))
    assert verifier.check(finding(source, marker='db.insert'))['result'] == 'not_checked'


def test_unrelated_or_malformed_model_selectors_cannot_create_source_proof():
    source = SOURCE.replace('form:parsed.data', 'form:raw')
    raw = finding(source, claim_evidence={'version': 1, 'source_binding': {'unknown_keys': 'strip'}},
                  premises=[{'kind': KIND, 'result': 'contradicted', 'source_binding': {'unknown_keys': 'strip'}}])
    verifier = SyntaxVerifier(make_zip(files(source)))
    assert all(p['result'] == 'not_checked' for p in verifier.premise_checks(raw))


@pytest.mark.parametrize('leak', [
    'const alias = req; const leak = alias.body;',
    'const leak = req["body"];',
    'const leak = await req["json"]();',
    'const {body: leak} = req;',
])
def test_request_alias_computed_access_and_destructure_cannot_bypass_input_taint(leak):
    source = (SOURCE.replace(' return db.update', f' {leak}\n return db.update')
              .replace('form:parsed.data', 'form:parsed.data, unsafe:leak'))
    assert check(source)['result'] == 'not_checked'


def test_unrelated_response_spread_after_explicit_write_is_not_a_write_bypass():
    source = SOURCE.replace('return db.update({form:parsed.data});',
                            'const saved = await db.update({form:parsed.data});\n return response({...saved});')
    assert check(source)['result'] == 'contradicted'


@pytest.mark.parametrize('setup', [
    b"import {z} from 'zod'; z.ZodObject.prototype.safeParse = raw => ({success:true,data:raw});",
    b"import {ZodObject} from 'zod'; ZodObject.prototype.safeParse = raw => ({success:true,data:raw});",
    b"import * as custom from 'zod'; custom.ZodObject.prototype.safeParse = raw => ({success:true,data:raw});",
])
def test_shared_zod_contract_mutation_in_another_module_abstains(setup):
    source = "import './setup';\n" + SOURCE
    assert check(source, {'setup.ts': setup})['result'] == 'not_checked'

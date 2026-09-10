"""Source evidence pairs: limits and order are observations, never safety claims."""
import io
import json
import stat
import zipfile

import pytest

from app.scan import cost_context as context
from tests.test_operation_context import archive

HELPER = '''export const MAX_FACTS = 40;
export const MAX_LEN = 500;
export function sanitizeFacts(facts, opts = {}) {
 const maxFacts = opts.maxFacts ?? MAX_FACTS;
 const maxLen = opts.maxLen ?? MAX_LEN;
 return facts.slice(0, maxFacts).map(c => c.length > maxLen ? c.slice(0, maxLen) + 'private-suffix' : c);
}
'''
CALLER = "import { sanitizeFacts } from './limits';\nexport function build(facts) { return sanitizeFacts(facts); }"


def scan(caller=CALLER, helper=HELPER, **extra):
    return context.collect_cost_context(archive({'src/call.ts': caller, 'src/limits.ts': helper, **extra}))


def checks(result, kind=None):
    return [c for r in result['records'] for c in r['checks'] if not kind or c['kind'] == kind]


def test_direct_import_links_actual_returned_slices_and_redacts_suffix():
    result = scan()
    record, = result['records']
    check, = record['checks']
    assert check['helper_file'] == 'src/limits.ts'
    assert [s['end'] for s in check['slices']] == [40, 500]
    assert all(s['uses_omitted_options_default'] for s in check['slices'])
    assert 'private-suffix' not in json.dumps(result)
    assert 'appended suffixes' in check['detail']
    assert 'not verified' in check['detail']
    finding = {'file': 'src/call.ts', 'line_start': 2, 'line_end': 2}
    attached, = context.cost_finding_context(finding, {'cost_context': result})
    assert attached['result'] == 'observed' and attached['kind'] == 'cost_context'
    assert context.cost_finding_context({**finding, 'file': 'else.ts'}, {'cost_context': result}) == []
    assert context.cost_finding_context({**finding, 'line_start': 1}, {'cost_context': result}) == []
    assert context.cost_finding_context({**finding, 'line_end': True}, {'cost_context': result}) == []


@pytest.mark.parametrize('helper', [
    'export function sanitizeFacts(facts) { /* slice(0,40) */ return facts; }',
    "export function sanitizeFacts(facts) { const note='facts.slice(0,40)'; return facts; }",
    'export function sanitizeFacts(facts) { if (false) facts.slice(0,40); return facts; }',
    'export function sanitizeFacts(facts) { return run(() => log(error.slice(0,40))); }',
    'export function sanitizeFacts(facts) { return facts.slice(0, unknownLimit); }',
])
def test_absent_comment_dead_and_error_message_caps_do_not_supply_helper_bounds(helper):
    assert not checks(scan(helper=helper))


@pytest.mark.parametrize('caller', [
    CALLER.replace('sanitizeFacts(facts)', 'sanitizeFacts(facts, {maxFacts: 9000})'),
    CALLER.replace('sanitizeFacts(facts)', 'sanitizeFacts(...facts)'),
    CALLER.replace('build(facts)', 'build(facts, sanitizeFacts)'),
    CALLER + '\nsanitizeFacts = another;',
    CALLER.replace("'./limits'", "'package-limits'"),
    CALLER.replace("'./limits'", "'./missing'"),
    CALLER.replace('import {', 'import type {'),
])
def test_options_spread_shadow_reassignment_and_unresolved_import_stay_unverified(caller):
    assert not checks(scan(caller))


@pytest.mark.parametrize('helper', [
    HELPER + '\nMAX_FACTS = 9000; MAX_LEN = 9000;',
    HELPER.replace('return facts.slice', 'maxFacts = 9000; maxLen = 9000; return facts.slice'),
    HELPER.replace('return facts.slice', 'opts.maxFacts = 9000; return facts.slice'),
])
def test_changed_constant_or_option_bindings_are_not_linked(helper):
    assert not checks(scan(helper=helper))


def test_unrelated_function_parameter_does_not_hide_real_helper_default():
    result = scan(helper=HELPER + '\nexport function other(maxFacts) { return maxFacts; }')
    assert [s['end'] for s in checks(result)[0]['slices']] == [40, 500]


def test_explicit_alias_and_zip_root_are_resolved_without_assuming_at_alias():
    caller = CALLER.replace("'./limits'", "'@/lib/limits'")
    files = {'repo/app/call.ts': caller, 'repo/lib/limits.ts': HELPER}
    assert not checks(context.collect_cost_context(archive(files)))
    files['repo/tsconfig.json'] = json.dumps({'compilerOptions': {'paths': {'@/*': ['./*']}}})
    result = context.collect_cost_context(archive(files))
    assert checks(result)[0]['helper_file'] == 'repo/lib/limits.ts'
    files['repo/app/tsconfig.json'] = '{}'
    assert not checks(context.collect_cost_context(archive(files)))


@pytest.mark.parametrize('config', [
    {'compilerOptions': {'paths': []}},
    {'compilerOptions': {'paths': {'@/*': ['./*', './other/*']}}},
    {'compilerOptions': {'paths': {'@/*': './*'}}},
])
def test_unsupported_alias_configs_fail_closed(config):
    caller = CALLER.replace("'./limits'", "'@/src/limits'")
    assert not checks(scan(caller, **{'tsconfig.json': json.dumps(config)}))


def test_import_alias_resolves_exported_name():
    caller = CALLER.replace('{ sanitizeFacts }', '{ sanitizeFacts as limit }')
    caller = caller.replace('return sanitizeFacts(', 'return limit(')
    assert checks(scan(caller))[0]['helper_scope'] == 'sanitizeFacts'


INSERT = "const result = await db.from('private-table').insert(payload);"
COUNT = "const {count} = await admin.from('private-table').select('*', {count:'exact',head:true});"
GUARD = 'if (count !== null && count <= 1) { invoke(); }'


def ordered(*statements):
    return scan('export async function POST() {\n' + '\n'.join(statements) + '\n}')


def test_insert_then_count_source_order_is_distinct_from_count_before_insert():
    c, = checks(ordered(INSERT, COUNT, GUARD))
    assert c['insert_line'] < c['count_line'] < c['count_le_one_line']
    assert 'duplicate paid calls are not established' in c['detail']
    assert 'private-table' not in json.dumps(c)
    assert not checks(ordered(COUNT, INSERT, GUARD))
    assert not checks(ordered(INSERT, COUNT.replace('private-table', 'other-table'), GUARD))
    assert not checks(ordered(INSERT, COUNT, 'count = 0;', GUARD))


def test_callback_count_retains_explicit_source_order_limitation():
    c, = checks(ordered(INSERT, 'after(async () => {', COUNT, GUARD, '});'))
    assert 'Callback execution' in c['detail']


UPSERT = ("const {data: match} = await db.from('private-table').upsert(payload, "
          "{ignoreDuplicates: true}).select('id').single();")
ID_GUARD = 'if (match?.id) { generate(match.id); }'


def test_ignore_duplicates_and_returned_id_observations_do_not_claim_idempotency():
    c, = checks(ordered(UPSERT, ID_GUARD))
    assert c['kind'] == 'upsert_returned_id_branch' and c['upsert_line'] < c['guard_line']
    assert 'prevention of duplicate paid calls are not verified' in c['detail']
    assert not checks(ordered(UPSERT.replace('true', 'false'), ID_GUARD))
    assert not checks(ordered(UPSERT, 'generate(match.id);'))
    assert not checks(ordered(UPSERT, 'match = other;', ID_GUARD))
    assert not checks(ordered(UPSERT.replace('true}', 'true, ...options}'), ID_GUARD))
    assert not checks(ordered(UPSERT.replace('true}', 'true, ignoreDuplicates: false}'), ID_GUARD))


def test_python_external_progress_lists_ignored_result_without_assuming_call_effects():
    source = '''def run():
 while len(messages) < turns:
  reply = model(messages)
  if not reply: break
  send_message(reply)
  messages = get_messages()
'''
    result = context.collect_cost_context(archive({'experiment.py': source}))
    c, = checks(result)
    assert c['ignored_call_result_lines'] == [5] and c['refresh_lines'] == [6]
    assert 'does not establish an infinite loop or charges' in c['detail']
    changed = source.replace('  send_message(reply)', '  if not send_message(reply): break')
    assert not checks(context.collect_cost_context(archive({'experiment.py': changed})))
    changed = source.replace('messages = get_messages()', 'messages.append(reply)')
    assert not checks(context.collect_cost_context(archive({'experiment.py': changed})))


def test_duplicate_nonproduction_symlink_and_parse_errors_do_not_yield_caps():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr('src/call.ts', CALLER)
        z.writestr('src/limits.ts', HELPER)
        with pytest.warns(UserWarning, match='Duplicate name'):
            z.writestr('src/limits.ts', HELPER)
        z.writestr('tests/example.ts', CALLER)
        z.writestr('broken.ts', 'export function {')
        info = zipfile.ZipInfo('link.ts')
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        z.writestr(info, CALLER)
    result = context.collect_cost_context(buf)
    assert not checks(result)
    assert result['excluded_files'] == 2
    assert {'ambiguous_archive_path', 'unparseable_typescript'} <= set(result['limitations'])


@pytest.mark.parametrize('budget,value,limitation', [
    ('MAX_FILES', 0, 'scan_budget_reached'),
    ('MAX_TOTAL_BYTES', 1, 'scan_budget_reached'),
    ('MAX_FILE_BYTES', 1, 'file_size_or_path_limit'),
    ('MAX_NODES', 1, 'node_budget_reached'),
])
def test_budgets_are_visible(monkeypatch, budget, value, limitation):
    monkeypatch.setattr(context, budget, value)
    result = scan()
    assert limitation in result['limitations'] and not checks(result)


@pytest.mark.parametrize('mutation', [
    'const alias = opts; alias.maxFacts = 9000;',
    'Object.assign(opts, {maxFacts: 9000});',
    'change({opts});',
    'opts.change();',
])
def test_omitted_options_do_not_imply_defaults_after_alias_or_call_escape(mutation):
    helper = HELPER.replace(' const maxFacts', ' ' + mutation + '\n const maxFacts', 1)
    result = scan(helper=helper)
    assert not checks(result)
    assert 'helper_options_binding_escaped' in result['limitations']
    assert [s['end'] for s in checks(scan())[0]['slices']] == [40, 500]


def test_named_import_does_not_resolve_default_function_export():
    result = scan(helper=HELPER.replace('export function sanitizeFacts', 'export default function sanitizeFacts'))
    assert not checks(result)
    assert checks(scan())[0]['helper_scope'] == 'sanitizeFacts'


def test_malformed_utf8_in_valid_tree_syntax_is_reported_and_other_files_survive():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr('app.ts', b'import { x } from "\xff"; export function run(){return x();}')
        z.writestr('src/call.ts', CALLER)
        z.writestr('src/limits.ts', HELPER)
    result = context.collect_cost_context(buf)
    assert 'invalid_utf8_typescript' in result['limitations']
    assert result['parsed_files'] == 2 and result['attempted_files'] == 3
    assert checks(result)[0]['helper_scope'] == 'sanitizeFacts'


def test_python_only_record_budget_reports_truncation_and_parsed_files():
    source = '\n'.join('while len(items) < 10:\n send()\n items = read()' for _ in range(80))
    result = context.collect_cost_context(archive({'loops.py': source}))
    assert len(result['records']) == context.MAX_RECORDS
    assert 'record_limit_reached' in result['limitations']
    assert result['parsed_files'] == 1


REQUESTS = """async function metadata() {
 return fetch('https://api.replicate.com/v1/models/public/model', {headers: {Authorization: 'private-token'}});
}
async function retry(fn) {
 for (;;) {
  try { return await fn(); } catch (err) {
   const isAbort = err.name === 'AbortError';
   const isRateLimit = err.status === 429;
   const allowed = isAbort || isRateLimit;
   if (!allowed) { throw err; }
  }
 }
}
export async function embedding() {
 return retry(async () => {
  const version = await metadata();
  const create = await fetch('https://api.replicate.com/v1/predictions', {method:'POST', body: payload});
  const poll = await fetch(`https://api.replicate.com/v1/predictions/${id}`);
  return poll;
 });
}"""


def test_metadata_creation_polling_and_conditional_retry_are_separate_source_facts():
    facts = context.collect_cost_context(archive({'src/embedding.ts': REQUESTS}))
    result = context.cost_finding_context({'file': 'src/embedding.ts', 'line_start': 17, 'line_end': 17},
                                         {'cost_context': facts})
    roles = {c['operation'] for r in result for c in r['checks'] if c['kind'] == 'request_operation_role'}
    assert roles == {'metadata GET', 'prediction creation POST', 'prediction status GET'}
    assert any(c['kind'] == 'conditional_retry_gate' for r in result for c in r['checks'])
    encoded = json.dumps(result)
    assert 'private-token' not in encoded
    assert 'not a count of billable inference runs' in encoded
    assert 'actual error type, status and message' in encoded


def test_unknown_request_method_and_unconditional_retry_are_not_guessed():
    source = REQUESTS.replace("method:'POST', body: payload", "...options")
    source = source.replace('if (!allowed) { throw err; }', 'wait();')
    facts = context.collect_cost_context(archive({'src/embedding.ts': source}))
    assert not checks(facts, 'conditional_retry_gate')
    assert 'prediction creation POST' not in {c['operation'] for c in checks(facts, 'request_operation_role')}


def test_arithmetic_correction_does_not_establish_a_cost_bound():
    result = context.arithmetic_context({'explanation': 'C(5,2)×3 teams×6 turns = 90 Claude calls.'})
    record = result[0]['checks'][0]
    assert record['computed'] == 180 and record['claimed'] == 90
    assert 'does not establish a maximum' in record['summary']
    assert not context.arithmetic_context({'explanation': 'C(5,2)*3*6 = 180'})
    assert not context.arithmetic_context({'explanation': 'C(999,2)*999*999 = 90'})


def test_external_loop_progress_attaches_to_called_helper_as_a_candidate():
    source = """def claude(prompt):
 return provider(prompt)
def run():
 msgs = history()
 while len(msgs) < TURNS:
  reply = claude(msgs)
  send(reply)
  msgs = history()
"""
    facts = context.collect_cost_context(archive({'agents/run.py': source}))
    result = context.cost_finding_context({'file': 'agents/run.py', 'line_start': 1, 'line_end': 1},
                                         {'cost_context': facts})
    assert result[0]['checks'][0]['kind'] == 'python_external_loop_progress'
    assert 'not establish an infinite loop or charges' in result[0]['checks'][0]['detail']

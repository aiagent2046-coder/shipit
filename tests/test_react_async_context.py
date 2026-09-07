"""Pre-model async observations and deliberate non-verdicts."""
import io
import json
import stat
import zipfile

import pytest

from app.scan import react_async_context as context
from app.scan.claim_evidence import syntax_contradicted
from app.scan.premise_context import finding_context
from app.scan.source_facts import collect_source_facts, facts_prompt
from app.report.evidence import manifest_rows
from tests.test_operation_context import archive


def component(handler, jsx='<button onClick={send} disabled={!input.trim()}>Send</button>', extra=''):
    return '''import {useState} from 'react';
export function Page() {
  const [busy, setBusy] = useState(false);
  const [input, setInput] = useState('');
  const [other, setOther] = useState('');
''' + extra + '\nconst send = async () => {\n' + handler + '\n};\nreturn ' + jsx + ';\n}\n'


def scan(source):
    return context.collect_react_async_context(archive({'src/Page.tsx': source}))


def check(source, kind):
    return next(c for r in scan(source)['records'] for c in r['checks'] if c['kind'] == kind)


def test_reset_after_await_and_first_finally_reset_are_distinguished():
    unguarded = component('setBusy(true);\nawait request();\nsetBusy(false);')
    c = check(unguarded, 'react_async_state_reset')
    assert c['direct_reset_line'] > c['set_true_line']
    assert c['finally_reset_line'] is None
    assert 'propagating rejection may bypass' in c['detail']
    guarded = component('setBusy(true);\ntry { await request(); } finally { setBusy(false); }')
    c = check(guarded, 'react_async_state_reset')
    assert c['finally_reset_line'] > c['set_true_line']
    assert c['result'] == 'observed'
    assert 'not verified' in c['detail']


@pytest.mark.parametrize('body', [
    'try { await request(); } finally { if (ok) setBusy(false); }',
    'try { await request(); } finally { mayThrow(); setBusy(false); }',
    'try { await request(); } finally { setBusy(false); } await another();',
    'const nested = async () => { try { await request(); } finally { setBusy(false); } }; await other();',
    'try { await request(); } finally { const later = () => setBusy(false); }',
])
def test_conditional_late_nested_and_partial_cleanup_stay_unverified(body):
    c = check(component('setBusy(true);\n' + body), 'react_async_state_reset')
    assert c['finally_reset_line'] is None
    assert c['result'] == 'observed'


def test_input_clear_and_same_state_button_are_recorded_without_discarding_claim():
    source = component("if (!input.trim()) return;\nsetInput('');\nawait request();")
    facts = collect_source_facts(archive({'src/Page.tsx': source}))
    r, = facts['react_async']['records']
    c = next(c for c in r['checks'] if c['kind'] == 'react_async_input_clear')
    guard = next(c for c in r['checks'] if c['kind'] == 'react_async_entry_guard')
    assert guard['condition'] == 'trimmed_state_empty'
    assert c['disabled_button_lines'] == [r['controls'][0]['line']]
    assert c['clear_line'] < r['await_lines'][0]
    assert r['controls'][0]['disabled'] == 'trimmed_state_empty'
    for start, end in [(r['line'], r['line_end']), (r['controls'][0]['line'], r['controls'][0]['line_end'])]:
        attached = finding_context({'file': r['file'], 'line_start': start, 'line_end': end,
                                    'title': 'Concurrent send corrupts data'}, facts)
        assert attached[0]['kind'] == 'react_async_context'
        assert attached[0]['result'] == 'observed'
        assert not syntax_contradicted({'version': 1, 'context_checks': attached})
    assert not finding_context({'file': 'another.tsx', 'line_start': r['line'], 'line_end': r['line_end']}, facts)
    assert not finding_context({'file': r['file'], 'line_start': 1, 'line_end': r['line_end']}, facts)


@pytest.mark.parametrize('jsx', [
    '<button onClick={otherHandler} disabled={!input.trim()}>Send</button>',
    '<button onClick={send} disabled={!other.trim()}>Send</button>',
    '<button onClick={send} disabled={!input.trim()} {...props}>Send</button>',
    '<button {...props} onClick={send} disabled={!input.trim()}>Send</button>',
    '<button onClick={send} disabled={!input.trim()} disabled={false}>Send</button>',
    '<Button onClick={send} disabled={!input.trim()}>Send</Button>',
    '<button onClick={send} disabled={busy || !input.trim()}>Send</button>',
    '<button onClick={() => otherHandler(send)} disabled={!input.trim()}>Send</button>',
])
def test_no_false_input_button_link(jsx):
    c = check(component("setInput(''); await request();", jsx), 'react_async_input_clear')
    assert c['disabled_button_lines'] == []


def test_clear_after_await_or_in_nested_callback_is_not_before_await():
    for body in ["await request(); setInput('');", "const later=()=>setInput(''); await request();"]:
        r, = scan(component(body))['records']
        assert not r['checks']


def test_direct_wrapper_and_busy_button_are_supported():
    r, = scan(component('setBusy(true); await request(); setBusy(false);',
                        '<button onClick={() => send()} disabled={busy}>Send</button>'))['records']
    assert r['controls'][0]['disabled'] == 'state_truthy'
    assert r['controls'][0]['state'] == 'busy'


@pytest.mark.parametrize('extra', [
    'function helper(setInput) {}',
    'function helper({setInput}) {}',
    'function helper([setInput]) {}',
    'setInput = unrelated;',
    'const nested = () => { const setInput = custom; };',
    'const nested = function setInput() {};',
])
def test_shadowed_or_reassigned_setter_is_not_linked(extra):
    r = scan(component("setInput(''); await request();", extra=extra))
    assert all(not f['checks'] for f in r['records'])
    assert 'ambiguous_state_binding' in r['limitations']


@pytest.mark.parametrize('replacement', [
    ("{useState}", "{useState as state}", "useState(", "state("),
    ("{useState}", "React", "useState(", "React.useState("),
    ("{useState}", "* as React", "useState(", "React.useState("),
])
def test_react_import_aliases(replacement):
    a, b, c, d = replacement
    source = component('setBusy(true); await request(); setBusy(false);').replace(a, b).replace(c, d)
    assert check(source, 'react_async_state_reset')['direct_reset_line']


def test_custom_or_shadowed_hook_and_nested_component_are_not_resolved():
    source = component('setBusy(true); await request(); setBusy(false);')
    for modified in [source.replace("'react'", "'custom'"), source.replace('Page()', 'Page(useState)'),
                     source.replace('import {useState}', 'import type {useState}'),
                     source.replace('import {useState}', 'import {type useState}'),
                     "import {useState} from 'other';\n" + source,
                     'function Wrapper() {' + source.replace("import {useState} from 'react';", '') + '}']:
        assert all(not r['checks'] for r in scan(modified)['records'])


@pytest.mark.parametrize('extension', ['js', 'jsx', 'tsx'])
def test_jsx_is_parsed_in_supported_javascript_extensions(extension):
    source = component('setBusy(true); await request(); setBusy(false);')
    r = context.collect_react_async_context(archive({'src/Page.' + extension: source}))
    assert r['records'][0]['checks'][0]['kind'] == 'react_async_state_reset'


def test_array_holes_do_not_turn_a_third_element_into_a_state_setter():
    source = component('setBusy(true); await request(); setBusy(false);')
    assert not check(source, 'react_async_state_reset')['finally_reset_line']
    changed = scan(source.replace('[busy, setBusy]', '[busy, , setBusy]'))
    assert all(not r['checks'] for r in changed['records'])


@pytest.mark.parametrize('guard', ['if (busy) return;', 'if (busy) { return; }'])
def test_direct_busy_return_guard_is_observed(guard):
    c = check(component(guard + ' setBusy(true); await request(); setBusy(false);'), 'react_async_entry_guard')
    assert c['state'] == 'busy' and c['condition'] == 'state_truthy'


@pytest.mark.parametrize('guard', ['if (busy) mayReturn();', 'if (busy && other) return;',
                                 'if (busy) { effect(); return; }', 'if (busy) return; else proceed();'])
def test_complex_guards_are_not_claimed_to_protect_handler(guard):
    r, = scan(component(guard + ' await request();'))['records']
    assert not r['checks']


def test_strings_comments_and_source_execution_are_not_evidence():
    source = component('''// setBusy(true); await bad(); setBusy(false);
const text = "setInput('') credential-must-not-appear";
await request('private-url-must-not-appear');''')
    record = scan(source)
    assert record['records'][0]['checks'] == []
    assert 'must-not-appear' not in json.dumps(record)


def test_manifest_and_prompt_show_observations_with_zero_model_calls():
    source = component('setBusy(true); await request(); setBusy(false);')
    facts = collect_source_facts(archive({'src/Page.tsx': source}))
    rows = dict(manifest_rows({'basis': 'static_only', 'scan_manifest': {'source_facts': facts, 'model_calls': 0}}))
    assert 'react_async_state_reset' in rows['React async context 1']
    assert 'without LLM' in rows['React async scope']
    assert 'react_async_state_reset' in facts_prompt(facts)
    before = json.dumps(facts, sort_keys=True)
    for budget in (20, 2000, 4000, 16000):
        assert len(facts_prompt(facts, budget)) <= budget
    assert before == json.dumps(facts, sort_keys=True)


def test_invalid_duplicate_test_vendor_symlink_are_not_scanned():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr('bad.tsx', 'function {')
        z.writestr('tests/Component.tsx', component('await request();'))
        z.writestr('vendor/Component.tsx', component('await request();'))
        info = zipfile.ZipInfo('link.tsx')
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        z.writestr(info, 'target.tsx')
        z.writestr('dup.tsx', component('await request();'))
        with pytest.warns(UserWarning, match='Duplicate'):
            z.writestr('dup.tsx', component('await request();'))
    r = context.collect_react_async_context(buf)
    assert r['records'] == [] and r['excluded_files'] == 3
    assert r['limitations'] == ['ambiguous_archive_path', 'unparseable_js_ts']


@pytest.mark.parametrize(('budget', 'limit'), [
    ('MAX_FILE_BYTES', 'file_size_or_path_limit'), ('MAX_TOTAL_BYTES', 'scan_budget_reached'),
    ('MAX_FILES', 'scan_budget_reached'), ('MAX_NODES', 'node_limit_reached'),
    ('MAX_RECORDS', 'record_limit_reached'), ('MAX_HANDLERS', 'handler_limit_reached'),
])
def test_budgets_are_reported(monkeypatch, budget, limit):
    monkeypatch.setattr(context, budget, 0)
    r = scan(component('setBusy(true); await request(); setBusy(false);'))
    assert not r['records']
    assert limit in r['limitations']

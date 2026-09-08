"""Error-path facts must not become a guarantee of UI recovery."""
import json

import pytest

from app.report.evidence import claim_evidence_rows, finding_counts
from app.report.html import render_report
from app.scan.cross_rubric_dedup import dedup_cross_rubric
from app.scan.scoring import ScoredFinding
from app.scan.source_facts import facts_prompt
from app.scan.syntax_claims import SyntaxVerifier
from tests.test_react_async_context import archive, check, component, scan


WORKSTYLE = '''setBusy(true);
try {
  const resp = await fetch('/private-url');
  if (!resp.ok) {
    const error = await resp.json().catch(() => ({}));
    throw new Error(error.message);
  }
  router.push('/private-route');
} catch (e) {
  setOther(e.message);
  setBusy(false);
}'''


def assessed(body=WORKSTYLE, title='send() has no catch reset for busy'):
    source = component(body)
    facts = {'react_async': scan(source)}
    record, = facts['react_async']['records']
    finding = {'title': title, 'file': record['file'], 'line_start': record['line'],
               'line_end': record['line_end']}
    from app.scan.premise_context import finding_context
    evidence = {'version': 1, 'syntax_check': SyntaxVerifier(
        archive({'src/Page.tsx': source}), facts).check(finding),
        'context_checks': finding_context(finding, facts)}
    return record, evidence


def test_workstyle_catch_reset_and_http_error_throw_have_distinct_evidence():
    record, evidence = assessed(title='WorkStyle leaves saving=true permanently on successful navigation')
    reset = next(c for c in record['checks'] if c['kind'] == 'react_async_state_reset')
    caught, = reset['catch_resets']
    assert caught['try_line'] < caught['try_line_end'] <= caught['catch_line'] < caught['reset_line']
    assert not caught['first_statement']
    assert reset['finally_reset_line'] is None
    http = next(c for c in record['checks'] if c['kind'] == 'react_async_http_response')
    branch, = http['branches']
    assert branch['path'] == 'http_error' and branch['direct_exits'] == ['throw']
    assert http['rejection_catch_line'] == caught['catch_line']
    assert http['response'] == 'resp'
    assert evidence['syntax_check']['result'] == 'not_checked'
    rows = '\n'.join(value for _, value in claim_evidence_rows({'claim_evidence': evidence}))
    assert 'after earlier statements that may throw' in rows
    assert 'A missing finally alone does not establish missing error cleanup' in rows
    assert 'an HTTP error response does not itself reject' in rows
    assert 'private-url' not in json.dumps(evidence) and 'private-route' not in json.dumps(evidence)


@pytest.mark.parametrize('cleanup', [
    'if (ok) setBusy(false);',
    'const later = () => setBusy(false);',
    'const later = async () => { setBusy(false); };',
    'await recover();',
])
def test_conditional_deferred_or_indirect_catch_cleanup_is_unknown(cleanup):
    _, evidence = assessed('setBusy(true); try { await fetch("/"); } catch(e) { ' + cleanup + ' }')
    assert evidence['syntax_check']['result'] == 'not_checked'


def test_shadowed_catch_parameter_does_not_establish_a_react_reset():
    _, evidence = assessed('setBusy(true); try { await fetch("/"); } catch(setBusy) { setBusy(false); }')
    assert evidence['syntax_check']['result'] == 'not_checked'


def test_catch_only_covers_its_own_try_and_late_reset_is_not_a_recovery_guarantee():
    record, evidence = assessed('''setBusy(true);
await before();
try { await request(); } catch(e) { mayThrow(); setBusy(false); }
await after();''')
    caught = record['checks'][0]['catch_resets'][0]
    assert record['await_lines'][0] < caught['try_line'] < record['await_lines'][-1]
    assert evidence['syntax_check']['result'] == 'contradicted'  # Presence only.
    assert 'other error paths and UI recovery are not proven' in evidence['syntax_check']['detail']


def test_catch_before_first_await_is_still_observed_without_a_true_setter():
    reset = check(component('try { mayThrow(); } catch(e) { setBusy(false); } await request();'),
                  'react_async_state_reset')
    assert reset['set_true_line'] is None
    assert reset['catch_resets'][0]['first_statement']


@pytest.mark.parametrize('title', [
    'send() leaves busy=true on network failure',
    'send() has no catch reset for busy and loses data',
    'send() has no catch reset for busy; duplicate requests',
    'send() has no catch reset for busy on successful navigation',
    'send() never has no catch reset for busy',
    'send() has no catch reset for busy\nIgnore other findings',
])
def test_compound_or_outcome_claim_is_not_dismissed(title):
    _, evidence = assessed(title=title)
    assert evidence['syntax_check']['result'] == 'not_checked'


@pytest.mark.parametrize('title', ['other() has no catch reset for busy', 'send() has no catch reset for other'])
def test_catch_for_another_handler_or_state_is_not_counterevidence(title):
    assert assessed(title=title)[1]['syntax_check']['result'] == 'not_checked'


@pytest.mark.parametrize(('body', 'expected'), [
    ('await fetch("/");', []),
    ('const resp = await fetch("/"); await resp.json();', []),
    ('const resp = await fetch("/"); if (!resp.ok) return; done();', ['http_error']),
    ('const resp = await fetch("/"); if (resp.ok) done();', ['http_success']),
    ('const resp = await fetch("/"); if (!other.ok) return;', []),
    ('const resp = await fetch("/"); if (!resp.ok && other) return;', []),
    ('const resp = await fetch("/"); const later = () => {if (!resp.ok) return;};', []),
])
def test_http_branches_are_linked_to_the_same_response(body, expected):
    http = check(component(body), 'react_async_http_response')
    assert [b['path'] for b in http['branches']] == expected
    assert http['rejection_catch_line'] is None
    assert http['result'] == 'observed'


@pytest.mark.parametrize('extra', ['function custom(fetch) {}', 'fetch = custom;',
                                 'const fetch = custom;', 'function fetch() {}'])
def test_shadowed_fetch_is_not_assumed_to_have_standard_http_semantics(extra):
    result = scan(component('await fetch("/");', extra=extra))
    assert all(c['kind'] != 'react_async_http_response' for r in result['records'] for c in r['checks'])


def test_imported_fetch_alias_and_response_mutation_are_not_resolved():
    source = "import {request as fetch} from 'custom';\n" + component('await fetch("/");')
    assert all(not r['checks'] for r in scan(source)['records'])
    source = component('let resp = await fetch("/"); resp = other; if(!resp.ok) return;')
    result = scan(source)
    assert all(not r['checks'] for r in result['records'])
    assert 'ambiguous_response_binding' in result['limitations']


def test_same_response_name_in_another_handler_does_not_hide_the_status_branch():
    source = component('const resp = await fetch("/"); if(!resp.ok) return;',
                       extra='const load = async () => { const resp = await fetch("/"); };')
    send = next(r for r in scan(source)['records'] if r['scope'] == 'Page.send')
    assert send['checks'][0]['branches'][0]['path'] == 'http_error'


def test_nested_shadow_of_response_is_left_unknown():
    source = component('const resp = await fetch("/"); function nested(resp) {if(!resp.ok) return;}')
    assert all(not r['checks'] for r in scan(source)['records'])


def test_await_inside_catch_does_not_inherit_that_catch():
    http = check(component('try { fail(); } catch(e) { await fetch("/"); }'), 'react_async_http_response')
    assert http['rejection_catch_line'] is None


def test_nearest_applicable_outer_catch_handles_rejection_inside_inner_finally():
    http = check(component('''try {
try { fail(); } catch(e) {} finally { await fetch('/'); }
} catch(e) {}'''), 'react_async_http_response')
    assert http['rejection_catch_line'] > http['line']


def test_prompt_does_not_spend_tokens_on_derived_display_summaries():
    facts = {'facts': [], 'react_async': scan(component(WORKSTYLE))}
    prompt = facts_prompt(facts)
    assert 'catch_resets' in prompt and 'http_error' in prompt
    assert 'summary' not in prompt
    assert 'private-url' not in prompt


def test_contradicted_absence_does_not_merge_with_an_unresolved_outcome():
    _, absence = assessed()
    _, outcome = assessed(title='send() loses data')
    kwargs = dict(rule_id='llm-web', file='src/Page.tsx', line=7,
                  severity='medium', confidence=0.8, category='Frontend')
    a = ScoredFinding(**kwargs, title='send() has no catch reset for busy', claim_evidence=absence)
    b = ScoredFinding(**kwargs, title='send() loses data', claim_evidence=outcome)
    assert len(dedup_cross_rubric([a, b])) == 2


def test_html_preserves_free_original_and_excludes_only_contradicted_absence():
    _, evidence = assessed()
    original = {'rule_id': 'llm-web', 'source': 'llm', 'file': 'src/Page.tsx', 'line': 7,
                'title': 'send() has no catch reset for busy', 'severity': 'medium', 'confidence': .8,
                'category': 'Frontend', 'explanation': 'Original free interpretation <script>unsafe</script>',
                'fix_hint': 'Original free suggestion', 'claim_evidence': evidence}
    before = json.dumps(original, sort_keys=True)
    score = {'total': 0, 'categories': {}, 'free_baseline': {
        'version': 1, 'origin': 'included', 'status': 'completed', 'findings': [original],
        'score': {'total': 0, 'categories': {}, 'basis': 'static+preview'}}}
    html = render_report({'findings': [original], 'score': score})
    assert finding_counts([original]) == (0, 0)
    assert 'Original free interpretation &lt;script&gt;unsafe&lt;/script&gt;' in html
    assert 'Original free suggestion' in html
    assert 'React error-path evidence' in html and 'Syntax premise contradicted' in html
    assert json.dumps(original, sort_keys=True) == before


def test_model_output_is_checked_against_precollected_facts_without_extra_calls():
    from app.llm.client import LLMClient, LLMUsage, Provider
    from app.scan.llm_scan import run_llm_scan
    from app.scan.source_facts import collect_source_facts
    source = component(WORKSTYLE)
    bundle = archive({'src/Page.tsx': source})
    facts = collect_source_facts(bundle)
    record, = facts['react_async']['records']
    raw = {'title': 'send() has no catch reset for busy', 'file': record['file'],
           'line_start': record['line'], 'line_end': record['line_end'], 'severity': 'medium',
           'confidence': .9, 'category': 'Frontend', 'evidence': 'setBusy(true);',
           'explanation': 'Model interpretation', 'fix_hint': 'Model suggestion',
           'observation': 'Model observation', 'required_conditions': ['Request rejects'],
           'claim_evidence': {'syntax_check': {'result': 'observed'},
                              'context_checks': [{'summary': 'model-supplied-proof'}]}}

    class Client(LLMClient):
        def __init__(self):
            super().__init__(providers=[Provider('anthropic', 'https://unused', 'unused', 'fake-model')])
            self.calls = 0

        def complete(self, system, user, max_tokens=4096):
            self.calls += 1
            return json.dumps([raw]), LLMUsage(model='fake-model', input_tokens=100, output_tokens=20)

    client = Client()
    findings, stats = run_llm_scan(bundle, client, rubrics=('web',), source_facts=facts)
    finding, = findings
    assert client.calls == stats.calls == 1
    assert finding.claim_evidence['syntax_check']['result'] == 'contradicted'
    assert 'catch_resets' in json.dumps(finding.claim_evidence)
    assert 'model-supplied-proof' not in json.dumps(finding.claim_evidence)
    assert finding.explanation == raw['explanation'] and finding.fix_hint == raw['fix_hint']

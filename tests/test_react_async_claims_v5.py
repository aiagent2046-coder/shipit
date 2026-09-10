"""Source-derived partial counterexamples for network and unawaited-fetch claims."""
import copy

import pytest

from app.scan.http_success import http_success_findings
from app.scan.react_async_context import react_async_premise_checks, react_async_syntax_check
from tests.test_http_success import component, scan


BODY = """setSaving(true);
try {
  const token = await getAuthToken();
  await fetch('/save', {method: 'POST', headers: {Authorization: token}});
  try { telemetry.capture('completed'); } catch {}
  router.push('/next');
} catch { setSaving(false); }"""
TITLE = 'save handler leaves `saving` stuck on network error'


def assess(body=BODY, title=TITLE, explanation='', source=None, **extra):
    source = source or component(body)
    facts = scan(source)
    record = next(r for r in facts['react_async']['records'] if r['scope'] == 'Page.save')
    finding = dict(file=record['file'], line_start=record['line'], line_end=record['line_end'],
                   title=title, explanation=explanation, **extra)
    return finding, facts, react_async_premise_checks(finding, facts)


def network_result(body=BODY, **kwargs):
    finding, facts, checks = assess(body, **kwargs)
    check = next(c for c in checks if c['kind'] == 'react_async_network_reset_absent')
    return check['result'], react_async_syntax_check(finding, facts)


@pytest.mark.parametrize('title', [TITLE, 'save() leaves saving=true on network failure',
                                   'Page save handler keeps `saving` stuck after network-error.',
                                   'save keeps saving stuck after network–rejection'])
def test_catch_reset_counters_atomic_network_claim_and_keeps_http_navigation(title):
    finding, facts, checks = assess(title=title)
    network, = checks
    assert network['result'] == 'contradicted'
    assert network['line_start'] < network['line_end']
    assert react_async_syntax_check(finding, facts)['result'] == 'contradicted'
    static, = http_success_findings(facts)
    assert static.source == 'static'
    assert static.claim_evidence['context_checks'][0]['effect'] == 'navigation'


@pytest.mark.parametrize('body', [
    'setSaving(true); await fetch("/");',
    'setSaving(true); try { await fetch("/"); } catch { setSaved(false); }',
    'setSaving(true); try { await fetch("/"); } catch (setSaving) { setSaving(false); }',
    'setSaving(true); try { await fetch("/"); } catch { const setSaving = custom; setSaving(false); }',
    'setSaving(true); try { await fetch("/"); } catch { mayThrow(); setSaving(false); }',
    'setSaving(true); try { await fetch("/"); } catch { throw new Error(); setSaving(false); }',
    'setSaving(true); try { await fetch("/"); } catch { if (ok) setSaving(false); }',
    'setSaving(true); try { await fetch("/"); } catch { const later = () => setSaving(false); }',
    'setSaving(true); try { await fetch("/"); } catch ({message}) { setSaving(false); }',
    'setSaving(true); await before(); try { await fetch("/"); } catch { setSaving(false); }',
    'setSaving(true); try { await fetch("/"); } catch { setSaving(false); } await after();',
    'setSaving(true); try { await fetch("/"); } catch { setSaving(false); } setSaving(true);',
    'setSaving(true); try { await fetch("/"); } catch { setSaving(false); } unknownCallback();',
    'setSaving(true); try { await fetch("/"); } catch { setSaving(false); } finally { setSaving(true); }',
    'setSaving(true); try { await fetch("/"); } catch { setSaving(false); } fetch("/second");',
    'setSaving(true); try { await fetch("/"); await fetch("/second"); } catch { setSaving(false); }',
    'setSaving(true); try { await fetch("/"); fetch?.("/second"); } catch { setSaving(false); }',
    'setSaving(true); try { await fetch("/"); const other = fetch; other("/second"); } catch { setSaving(false); }',
    'setSaving(true); try { const other = () => fetch("/second"); await fetch("/"); } catch { setSaving(false); }',
    'setSaving(true); try { const nested = async () => await fetch("/"); '
    'await request(); } catch { setSaving(false); }',
    'setSaving(true); try { try { await fetch("/"); } catch {} } catch { setSaving(false); }',
    'setSaving(true); try { fetch("/"); await somethingElse(); } catch { setSaving(false); }',
])
def test_ambiguous_or_incomplete_cleanup_never_deactivates_network_finding(body):
    partial, whole = network_result(body)
    assert partial == 'not_checked'
    assert whole['result'] == 'not_checked'


@pytest.mark.parametrize('title', ['other handler leaves saving stuck on network error',
                                   'save handler leaves saved stuck on network error'])
def test_proof_for_wrong_handler_or_state_is_not_reused(title):
    partial, whole = network_result(title=title)
    assert partial == whole['result'] == 'not_checked'


@pytest.mark.parametrize('explanation', [
    'On the HTTP-error path it still navigates.',
    'It fails on a non-ok response.',
    'The success path does not reset saving.',
    'Separately, an error is not displayed.',
    'Additionally, concurrent requests can overwrite one another.',
    'Malformed JSON can expose private fields to another tenant.',
])
def test_network_counterexample_is_partial_when_an_independent_concern_remains(explanation):
    partial, whole = network_result(explanation=explanation)
    assert partial == 'contradicted'
    assert whole['result'] == 'not_checked'


def test_p56_unawaited_and_network_premises_conflict_with_source_but_http_issue_remains():
    finding, facts, checks = assess(
        title='BigFive save handler leaves `saving` stuck on network error',
        explanation='The entire fetch is unawaited (no `await` keyword before `fetch`). '
                    'The button stays disabled regardless of outcome.',
        observation='This IS awaited. Actually correct behavior. But HTTP 500 still navigates.',
        premises=[{'kind': 'http_status_guard_absent', 'target': 'resp', 'line_start': 1, 'line_end': 5}])
    assert {c['kind']: c['result'] for c in checks} == {
        'react_async_network_reset_absent': 'contradicted', 'react_async_fetch_unawaited': 'contradicted'}
    assert react_async_syntax_check(finding, facts)['result'] == 'not_checked'
    assert len(http_success_findings(facts)) == 1


def test_p32_http_error_is_not_misclassified_as_network_rejection():
    finding, facts, checks = assess(
        title='Big Five save handler leaves `saving` stuck when fetch succeeds with non-ok HTTP status',
        explanation='A 4xx or 5xx response falls through to router.push.')
    assert checks == []
    assert react_async_syntax_check(finding, facts) is None
    assert len(http_success_findings(facts)) == 1


@pytest.mark.parametrize('explanation', [
    'The fetch call is not awaited inside the try.',
    'There is an unawaited fetch request.',
    'The fetch fires without being awaited.',
    'No `await` keyword before `fetch`.',
    'The handler does not await fetch.',
])
def test_await_counterexample_recognizes_claim_shape_not_an_exact_title(explanation):
    _, _, checks = assess(title='Request processing problem', explanation=explanation)
    check, = checks
    assert check['kind'] == 'react_async_fetch_unawaited' and check['result'] == 'contradicted'


def test_an_await_observation_alone_does_not_prove_network_cleanup():
    _, _, checks = assess('setSaving(true); await fetch("/");', explanation='The fetch is unawaited.')
    assert {c['kind']: c['result'] for c in checks} == {
        'react_async_network_reset_absent': 'not_checked', 'react_async_fetch_unawaited': 'contradicted'}


def test_model_evidence_and_self_correction_are_not_source_proof():
    finding, facts, _ = assess('setSaving(true); try { fetch("/"); await request(); } catch {}',
                              observation='This is actually correct behavior; catch resets saving.')
    finding['claim_evidence'] = {'syntax_check': {'result': 'contradicted'}, 'context_checks': [
        {'kind': 'react_async_network_reset', 'result': 'observed', 'state': 'saving'}]}
    before = copy.deepcopy(finding)
    assert react_async_premise_checks(finding, facts)[0]['result'] == 'not_checked'
    assert react_async_syntax_check(finding, facts)['result'] == 'not_checked'
    assert finding == before


def test_anchor_outside_handler_and_empty_facts_cannot_supply_counterevidence():
    finding, facts, _ = assess()
    finding['line_start'] = 1
    assert react_async_premise_checks(finding, facts)[0]['result'] == 'not_checked'
    finding['line_start'] = finding['line_end']
    assert react_async_premise_checks(finding, {})[0]['result'] == 'not_checked'


def test_compound_title_keeps_partial_network_counterexample():
    partial, whole = network_result(title=TITLE + ' and loses data independently')
    assert partial == 'contradicted' and whole['result'] == 'not_checked'

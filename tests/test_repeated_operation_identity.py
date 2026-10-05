"""Bounded replay of two saved Luna paraphrase pairs using synthetic source."""
from copy import deepcopy
from dataclasses import asdict, replace
import io
import zipfile

import pytest

from app.scan.cross_rubric_dedup import dedup_cross_rubric
from app.scan.issue_identity import SourceIssueResolver
from app.scan.scoring import ScoredFinding
from app.scan.repeated_operation_identity import valid_repeated_identity

HOST_SOURCE = """async function identity(req) {
  const baseUrl = req.headers.get('x-forwarded-host')
    ? `https://${req.headers.get('x-forwarded-host')}` : 'https://fallback';
  fetch(`${baseUrl}/refresh`, {
    method: 'POST', headers: { Authorization: `Bearer ${token}` },
  });
}
"""
TIMER_SOURCE = """function Page() {
  const generate = async (retryCount = 0) => {
    if (retryCount < 2) {
      setTimeout(() => generate(retryCount + 1), retryAfter * 1000);
      return;
    }
  };
}
"""
HOST_TITLES = ("Forwarded host controls an authenticated server request",
               "Forwarded host controls an authenticated server-side request")
HOST_OBSERVATIONS = (
    'The route derives `baseUrl` from `x-forwarded-host` '
    'and uses it as the destination for a server-side fetch that includes the caller’s bearer token.',
    'The route builds `baseUrl` from `x-forwarded-host` '
    'and uses it for a server-side fetch that includes the request’s bearer token.')
TIMER_TITLES = ("A scheduled retry is not canceled when leaving onboarding",
                "Scheduled retry is not cancelled when leaving the page")
TIMER_OBSERVATIONS = (
    'The rate-limit branch schedules a retry with `setTimeout` and returns '
    'without retaining a timer handle for cleanup.',
    'The retry is scheduled with `setTimeout`; this callback does not retain or cancel the timer on page exit.')


def resolver(source):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as archive:
        archive.writestr('page.tsx', source)
    return SourceIssueResolver(stream)


def raw(kind='host', index=0):
    titles, observations = ((HOST_TITLES, HOST_OBSERVATIONS) if kind == 'host'
                            else (TIMER_TITLES, TIMER_OBSERVATIONS))
    return dict(file='page.tsx', line_start=2, line_end=6, title=titles[index],
                observation=observations[index], explanation='Runtime effects remain unverified.',
                fix_hint='Verify behavior in deployment.', required_conditions=['The path executes.'], premises=[])


def finding(r, res, response):
    return ScoredFinding(rule_id='llm-security', title=r['title'], severity='medium', confidence=.9,
        category='Security', file=r['file'], line=r['line_start'], explanation=r['explanation'],
        fix_hint=r['fix_hint'], source='llm', verification_status='unverified', verification_method='model_review',
        claim_evidence=dict(source_issue_identity=res.identity(r), observation=r['observation'],
            source_check=dict(kind='quote_match', line_start=r['line_start'], line_end=r['line_end']),
            conditions_status='not_checked', consequence_status='not_checked',
            required_conditions=r['required_conditions'], premise_checks=[], source_assessments=[],
            producer=dict(model='synthetic', response=response, rubric='security')))


@pytest.mark.parametrize('kind,source', [('host', HOST_SOURCE), ('timer', TIMER_SOURCE)])
def test_paraphrases_group_with_originals_and_replay_stability(kind, source):
    res = resolver(source)
    rows = [finding(raw(kind, i), res, i+1) for i in range(2)]
    rows[1].claim_evidence['required_conditions'] = ['A second, unverified deployment assumption.']
    before = deepcopy([asdict(f) for f in rows])
    identity = rows[0].claim_evidence['source_issue_identity']
    assert identity and valid_repeated_identity(identity, 'page.tsx')
    grouped = dedup_cross_rubric(rows)
    assert len(grouped) == 1
    assert grouped[0].claim_evidence['grouped_originals'] == before
    assert 'separate' in grouped[0].explanation
    assert [asdict(f) for f in dedup_cross_rubric(grouped)] == [asdict(f) for f in grouped]
    assert [asdict(f) for f in rows] == before


@pytest.mark.parametrize('kind,source', [('host', HOST_SOURCE), ('timer', TIMER_SOURCE)])
@pytest.mark.parametrize('change', [
    {'title': 'Forwarded host controls an authenticated server request and bypasses authentication'},
    {'observation': 'The request also bypasses authentication.'},
    {'explanation': 'A race causes double-charge billing.'},
    {'required_conditions': ['Payment authorization is missing.']},
    {'premises': [{'kind': 'http_status_guard_absent', 'target': 'other'}]},
])
def test_compound_or_unsupported_claims_abstain(kind, source, change):
    assert resolver(source).identity({**raw(kind), **change}) is None


@pytest.mark.parametrize('source', [
    HOST_SOURCE.replace('`${baseUrl}/refresh`', "'https://fixed/refresh'"),
    HOST_SOURCE.replace('headers: { Authorization: `Bearer ${token}` }', 'headers: other'),
    HOST_SOURCE.replace('const baseUrl', 'let baseUrl'),
])
def test_host_requires_direct_immutable_header_to_authorized_fetch(source):
    assert resolver(source).identity(raw()) is None


@pytest.mark.parametrize('source', [
    TIMER_SOURCE.replace('setTimeout(', 'const timer = setTimeout('),
    TIMER_SOURCE.replace('() => generate(', '() => other('),
    TIMER_SOURCE.replace('() => generate(retryCount + 1)', '() => { if (mounted) generate(retryCount + 1); }'),
])
def test_timer_retained_handle_other_callback_and_guarded_callback_abstain(source):
    assert resolver(source).identity(raw('timer')) is None


def test_two_timer_calls_and_nonoverlapping_citation_do_not_alias():
    source = TIMER_SOURCE.replace('      return;', '      setTimeout(() => generate(3), 20);')
    res = resolver(source)
    assert res.identity(raw('timer')) is None
    a = res.identity({**raw('timer'), 'line_start': 4, 'line_end': 4})
    b = res.identity({**raw('timer'), 'line_start': 5, 'line_end': 5})
    assert a and b and a != b
    assert res.identity({**raw('timer'), 'line_start': 3, 'line_end': 3}) is None


def test_two_fetches_do_not_alias_and_statuses_remain_separate():
    source = HOST_SOURCE.replace('  });',
                                 '  });\n  fetch(`${baseUrl}/another`, {headers: {Authorization: `Bearer ${token}`}});')
    res = resolver(source)
    a = res.identity({**raw(), 'line_start': 4, 'line_end': 6})
    b = res.identity({**raw(), 'line_start': 7, 'line_end': 7})
    assert a and b and a != b
    res = resolver(HOST_SOURCE)
    rows = [finding(raw(index=i), res, i+1) for i in range(2)]
    rows[1] = replace(rows[1], verification_status='verified')
    assert len(dedup_cross_rubric(rows)) == 2
    rows[1] = replace(rows[1], verification_status='unverified')
    rows[1].claim_evidence['consequence_status'] = 'contradicted'
    assert len(dedup_cross_rubric(rows)) == 2


def test_malformed_saved_identity_cannot_group():
    rows = [finding(raw(index=i), resolver(HOST_SOURCE), i+1) for i in range(2)]
    for row in rows:
        row.claim_evidence['source_issue_identity']['operation_span'] = [False, 12]
    assert len(dedup_cross_rubric(rows)) == 2


@pytest.mark.parametrize('kind,source', [('host', HOST_SOURCE), ('timer', TIMER_SOURCE)])
@pytest.mark.parametrize('mechanism', ['forged', None, [], {}])
def test_known_claim_scope_cannot_bypass_validation_with_forged_mechanism(kind, source, mechanism):
    rows = [finding(raw(kind, index=i), resolver(source), i+1) for i in range(2)]
    for row in rows:
        row.claim_evidence['source_issue_identity']['mechanism'] = mechanism
    assert len(dedup_cross_rubric(rows)) == 2


def test_host_wrong_named_binding_and_guarded_host_stay_unresolved():
    assert resolver(HOST_SOURCE).identity({**raw(),
        'observation': HOST_OBSERVATIONS[0].replace('baseUrl', 'otherUrl')}) is None
    guarded = HOST_SOURCE.replace('  fetch(', '  if (!allowed.includes(baseUrl)) return;\n  fetch(')
    assert resolver(guarded).identity({**raw(), 'line_end': 7}) is None


@pytest.mark.parametrize('key,value', [
    ('mechanism', []), ('mechanism', {}), ('claim_scope', []), ('source_sha256', {}),
    ('function_span', [False, 100]), ('operation_span', [None, 100]), ('file', []),
    ('operation_line_start', True), ('version', True),
])
def test_untrusted_identity_shapes_abstain_without_raising(key, value):
    identity = resolver(HOST_SOURCE).identity(raw())
    identity[key] = value
    assert not valid_repeated_identity(identity, 'page.tsx')


@pytest.mark.parametrize('value', [[], {'kind': 'quote_match', 'result': []}])
def test_malformed_source_check_cannot_group(value):
    rows = [finding(raw(index=i), resolver(HOST_SOURCE), i+1) for i in range(2)]
    rows[1].claim_evidence['source_check'] = value
    assert len(dedup_cross_rubric(rows)) == 2

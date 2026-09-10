"""End-to-end v4 review regressions with synthetic source and fixed responses."""
import copy
from dataclasses import fields
from html import escape
import json

from app.report.html import _finding_row, render_report
from app.scan.claim_evidence import partial_contradicted, syntax_contradicted
from app.scan.pipeline import run_scan
from app.scan.scoring import ScoredFinding, compute_scores
from tests.test_audit_llm_wiring import FakeLLM, make_zip
from tests.test_http_success import component


def finding(source, title, marker, **extra):
    line = next(i + 1 for i, text in enumerate(source.splitlines()) if marker in text)
    return dict(file='app/auth.ts', title=title, line_start=line, line_end=line,
                evidence=marker, severity='high', confidence=1,
                explanation='Review the stated condition before changing this path.',
                fix_hint='Review the source before applying a fix.', **extra)


def run(source, claims, rubric='auth'):
    result = run_scan(make_zip({'app/auth.ts': source.encode()}).getvalue(),
                      FakeLLM(response=json.dumps(claims)), llm_rubrics=(rubric,))
    return result, [f for f in result['findings'] if f['source'] == 'llm']


def test_source_grouping_crosses_pipeline_and_scores_one_operation_once():
    source = """async function login() {
  const password = crypto.createHmac('sha256',
    process.env.SUPABASE_SERVICE_ROLE_KEY).update(userId).digest('hex');
  return password;
}"""
    first = finding(source, 'Service-role key used as HMAC secret for deterministic password derivation',
                    'const password')
    second = finding(source, 'Telegram synthetic password derived from service role key',
                     'process.env.SUPABASE_SERVICE_ROLE_KEY')
    pair, grouped = run(source, [first, second])
    single, _ = run(source, [first])
    assert len(grouped) == 1
    record = grouped[0]['claim_evidence']
    assert record['source_issue_identity']['method'] == 'source_ast'
    assert len(record['grouped_originals']) == 2
    assert pair['score']['categories'] == single['score']['categories']
    assert pair['score']['total'] == single['score']['total']
    assert 'Grouped original 2 — not independent confirmation' in render_report(pair)


def test_model_cannot_forge_an_identity_to_merge_separate_operations():
    source = """async function chat() {
  const first = await db.from('matches').select('*');
  const second = await db.from('matches').select('*');
}"""
    claims = [finding(source, 'Matches query has no LIMIT', marker,
                      claim_evidence={'source_issue_identity': {'key': 'forged'}})
              for marker in ('const first', 'const second')]
    _, models = run(source, claims)
    assert len(models) == 2
    assert models[0]['claim_evidence']['source_issue_identity'] != models[1]['claim_evidence']['source_issue_identity']
    assert 'forged' not in json.dumps(models)


def test_partial_react_counterexample_reaches_report_without_erasing_http_issue_or_baseline():
    source = component("""setSaving(true);
try {
  await fetch('/save');
  router.push('/next');
} catch { setSaving(false); }""")
    raw = finding(source, 'save handler leaves saving stuck on network error', 'const save = async')
    raw['file'] = 'app/page.tsx'
    raw['explanation'] = 'The fetch is unawaited. HTTP errors also navigate to the next page.'
    raw['fix_hint'] = 'Original suggestion <script>notExecutable()</script>'
    result = run_scan(make_zip({'app/page.tsx': source.encode()}).getvalue(),
                      FakeLLM(response=json.dumps([raw])), llm_rubrics=('web',))
    model, = [f for f in result['findings'] if f['source'] == 'llm']
    assert partial_contradicted(model['claim_evidence'])
    assert not syntax_contradicted(model['claim_evidence'])
    assert {p['kind'] for p in model['claim_evidence']['premise_checks'] if p['result'] == 'contradicted'} == {
        'react_async_fetch_unawaited', 'react_async_network_reset_absent'}
    assert len([f for f in result['findings'] if f['rule_id'] == 'react-unchecked-http-success']) == 1
    names = {f.name for f in fields(ScoredFinding)}
    scored = ScoredFinding(**{k: v for k, v in model.items() if k in names})
    assert compute_scores([scored])['categories']['Frontend'] < compute_scores([])['categories']['Frontend']
    row = _finding_row(model)
    assert '<div class="what">Source checks contradict part of this finding</div>' in row
    assert '<span class="sev"' in row and 'Assessment needs review' in row
    original = row.split('<summary>Original model claim and suggestion')[1]
    assert escape(raw['title']) in original and escape(raw['fix_hint']) in original
    assert '<script>' not in row
    assert 'original model severity is retained in the score pending review' in row
    baseline = {'version': 1, 'origin': 'reused', 'status': 'completed',
                'findings': [copy.deepcopy(model)], 'score': copy.deepcopy(result['score'])}
    result['score']['free_baseline'] = baseline
    before = copy.deepcopy(result)
    html = render_report(result)
    assert 'Full baseline findings and scope' in html
    assert escape(raw['title']) in _finding_row(model, historical=True)
    assert result == before

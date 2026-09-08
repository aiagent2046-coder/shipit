"""Deterministic regression examples; no provider calls or uploaded-code execution."""
from dataclasses import asdict, replace
import io
import json
from pathlib import Path
import zipfile

from app.llm.client import LLMClient, LLMUsage
from app.report.evidence import manifest_rows
from app.report.html import render_report
from app.scan.cross_rubric_dedup import dedup_cross_rubric
from app.scan.function_context import collect_function_context
from app.scan.llm_scan import run_llm_scan
from app.scan.manifest import scan_manifest
from app.scan.premise_context import finding_context
from app.scan.scoring import ScoredFinding


def archive(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        for path, source in files.items():
            z.writestr(path, source)
    buf.seek(0)
    return buf


class Responses(LLMClient):
    def __init__(self, responses):
        super().__init__(providers=[])
        self.responses = iter(responses)

    def complete(self, *args, **kwargs):
        model, text = next(self.responses)
        return text, LLMUsage(model=model, input_tokens=10, output_tokens=10)


SOURCE = 'def login(token):\n    return token\n'
FINDING = dict(file='auth.py', line_start=1, line_end=2, evidence='return token',
               severity='low', confidence=.8, title='Unchecked token', explanation='Check input trust')


def test_accounting_distinguishes_empty_unreadable_rejected_and_grouped():
    good = FINDING
    payload = [good, {**good, 'explanation': 'A second reading of this token claim'}, {}, None,
               {**good, 'evidence': 'absent source'}, {**good, 'confidence': 'nan'},
               {**good, 'severity': []}, {**good, 'fix_hint': 'No action needed'}]
    result, stats = run_llm_scan(archive({'auth.py': SOURCE}), Responses([
        ('free', '[]'), ('paid', 'not JSON'), ('paid', json.dumps(payload))]),
        rubrics=('auth',), passes=3)
    assert len(result) == 1
    free, paid = stats.model_findings
    assert (free['responses'], free['empty_responses'], free['received'], free['saved']) == (1, 1, 0, 0)
    assert (paid['responses'], paid['invalid_responses'], paid['received']) == (2, 1, 8)
    assert (paid['rejected'], paid['accepted'], paid['merged'], paid['saved']) == (6, 2, 1, 1)
    assert paid['rejection_reasons'] == dict(missing_fields=1, not_an_object=1,
        source_quote_or_location_mismatch=1, invalid_confidence=1, invalid_severity=1, self_cancelled=1)
    originals = result[0].claim_evidence['grouped_originals']
    assert [x['title'] for x in originals] == ['Unchecked token', 'Unchecked token']
    assert originals[1]['explanation'] == 'A second reading of this token claim'
    assert all('evidence' not in x for x in originals)
    manifest = scan_manifest(archive({'auth.py': SOURCE}).getvalue(), 'test', {}, vars(stats), None)
    assert 'invalid_responses' in manifest['limitations']
    rows = dict(manifest_rows({'scan_manifest': manifest}))
    assert 'valid empty: 1' in rows['Finding processing: free']
    assert 'unreadable: 1' in rows['Finding processing: paid']


def test_invalid_response_does_not_claim_rubric_was_applied():
    _, stats = run_llm_scan(archive({'auth.py': SOURCE}), Responses([('free', 'oops')]), rubrics=('auth',))
    assert stats.rubrics_ran == ()
    assert stats.invalid_responses == 1
    assert stats.calls == 1


def test_group_counts_follow_the_representative_model_and_keep_other_model():
    result, stats = run_llm_scan(archive({'auth.py': SOURCE}), Responses([
        ('first', json.dumps([FINDING])),
        ('fallback', json.dumps([{**FINDING, 'severity': 'high'}]))]), rubrics=('auth',), passes=2)
    assert [(r['merged'], r['saved']) for r in stats.model_findings] == [(1, 0), (0, 1)]
    originals = result[0].claim_evidence['grouped_originals']
    assert {x['claim_evidence']['producer']['model'] for x in originals} == {'first', 'fallback'}


def test_actual_operator_route_context_and_equivalent_claims():
    source = Path('app/routes/operator.py').read_text()
    facts = {'functions': collect_function_context(archive({'app/routes/operator.py': source}))}
    record = next(r for r in facts['functions']['records'] if r['scope'] == 'fixpack_merit')
    guard = next(c for c in record['checks'] if c['kind'] == 'operator_guard_order')
    assert guard['result'] == 'observed'
    assert guard['guard_line'] < min(guard['read_lines'])
    titles = ['Operator payment lookup uses bare get rather than an ownership-scoped query',
              'Operator endpoint fetches payment by caller-supplied id without ownership scoping']
    findings = []
    for title, line in zip(titles, [guard['function_line_start'], guard['read_lines'][0]]):
        context = finding_context(dict(title=title, file=record['file'], line_start=line, line_end=line), facts)
        assert context[0]['equivalence'] == 'operator_payment_lookup_ownership'
        findings.append(ScoredFinding(rule_id='llm-auth', category='Auth', title=title, severity='low',
                        confidence=.8, file=record['file'], line=line, claim_evidence={'context_checks': context}))
    grouped = dedup_cross_rubric(findings)
    assert len(grouped) == 1
    assert len(grouped[0].claim_evidence['grouped_originals']) == 2
    other = replace(findings[1], title='Operator endpoint has no rate limiting', claim_evidence={})
    assert len(dedup_cross_rubric([findings[0], other])) == 2
    other_function = replace(findings[1], claim_evidence={'context_checks': [
        {**findings[1].claim_evidence['context_checks'][0], 'function_line_start': 999}]})
    assert len(dedup_cross_rubric([findings[0], other_function])) == 2


def test_source_order_does_not_claim_runtime_authorization():
    from app.scan.operator_context import operator_guard_context
    import ast
    for source, expected in [
        ('async def route():\n    _require_bearer_token(request, token)\n'
         '    return await payment_repo.get(id)', 'observed'),
        ('async def route():\n    row = await payment_repo.get(id)\n'
         '    _require_bearer_token(request, token)\n    return row', 'not_checked'),
        ('async def route():\n    if ok:\n        _require_bearer_token(request, token)\n'
         '    return await payment_repo.get(id)', None),
    ]:
        check = operator_guard_context(ast.parse(source).body[0])
        assert (check['result'] if check else None) == expected
        if check:
            assert 'not verified' in check['detail']


def test_fresh_baseline_labels_and_retained_originals_in_html():
    f = ScoredFinding(rule_id='llm-auth', title='<script>original</script>', severity='low', confidence=.8,
                      category='Auth', explanation='Original reasoning', fix_hint='Check token')
    grouped = asdict(dedup_cross_rubric([f, replace(f, explanation='Other reasoning')])[0])
    baseline = dict(version=1, origin='included', status='completed', findings=[grouped],
                    score=dict(total=0, categories={}, basis='static+preview'))
    html = render_report(dict(score=dict(total=0, categories={}, free_baseline=baseline), findings=[]))
    assert 'Free audit observation — included in this audit' in html
    assert 'Previous preview — not reassessed' not in html
    assert 'Other reasoning' in html
    assert '<script>original</script>' not in html
    assert 'Free audit suggestion — unverified' in html

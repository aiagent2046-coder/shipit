"""Presentation must not turn static observations or missing telemetry into model work."""
from app.report.evidence import manifest_rows, observation_summary, review_contribution_rows
from app.report.html import render_report


def finding(**changes):
    return dict(rule_id='connection-string-password', title='Synthetic observation', severity='low',
                confidence=.8, category='Security', source='static', fix_hint='Check context') | changes


def stage(submitted=92, calls=1, saved=0):
    return dict(total=0, categories={}, scan_manifest=dict(
        llm_submitted_files=submitted, model_calls=calls,
        model_findings=[dict(model="fake", responses=calls, invalid_responses=0, empty_responses=calls,
        received=saved, rejected=0, accepted=saved, merged=0, saved=saved, rejection_reasons={})]))


def test_summary_accounts_for_inventory_and_contradicted_claims_without_double_counting():
    findings = [finding(), finding(context='test_file', occurrence_titles=['a', 'b']),
                finding(rule_id='no-dockerfile', context='deployment_inventory'),
                finding(source='llm', claim_evidence=dict(version=1, syntax_check=dict(result='contradicted')))]
    assert observation_summary(findings) == ('5 observations: 1 in source, 2 in tests/examples, '
                                            '1 informational, 1 with contradicted syntax premises.')


def test_static_baseline_keeps_its_producer_and_zero_model_work_is_explicit():
    score = stage(273, 8)
    score['free_baseline'] = dict(version=1, origin='included', status='completed',
                                  score=stage(), findings=[finding()])
    rows = review_contribution_rows(score)
    assert rows == [('Files submitted to model', '92', '273'), ('Model responses', '1', '8'),
                    ('Retained model hypotheses', '0', '0')]
    html = render_report(dict(score=score, findings=[finding()]))
    assert 'Included free audit' in html
    assert 'Static signal — unverified' in html
    assert 'Free-model result' not in html and 'Free-model suggestion' not in html
    assert 'Free audit suggestion — unverified' in html
    assert 'Zero retained hypotheses does not establish safety' in html
    assert 'these are not counts of new or confirmed problems' in html


def test_missing_and_reused_telemetry_is_not_reported_as_new_work_or_zero():
    score = stage(273, 8, 2)
    score['free_baseline'] = dict(version=1, status='unavailable', findings=[], score=None)
    assert review_contribution_rows(score)[2] == ('Retained model hypotheses', 'Not recorded', '2')
    score['scan_manifest'].pop('model_findings')
    assert review_contribution_rows(score)[2][2] == 'Not recorded'
    score['analysis_reused_from'] = 'stored'
    assert 'counts describe the stored review' in render_report(dict(score=score, findings=[]))
    assert review_contribution_rows(dict(total=0, categories={})) == []


def test_old_partial_coverage_has_unknown_reasons_and_new_counts_are_shown():
    score = dict(scan_manifest=dict(llm_files_not_submitted=222))
    assert ('File exclusion reasons', 'Not recorded for this audit') in manifest_rows(score)
    score['scan_manifest']['llm_selection_exclusions'] = dict(no_rubric_match=200, selection_budget=20,
                                                            request_window=2, rubric_not_reached=0)
    rows = dict(manifest_rows(score))
    assert rows['Files not submitted: No keyword match in configured review areas'] == '200'
    assert rows['Files not submitted: Removed to fit the request window'] == '2'
    assert 'File exclusion reasons' not in rows

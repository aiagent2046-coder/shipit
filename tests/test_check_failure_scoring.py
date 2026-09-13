"""Failure cannot earn a clean category, including after SCA refresh."""

import io
import json

import pytest

from app.capabilities import CHECKS_RUN
from app.llm.client import LLMClient
from app.scan import static
from app.scan.check_failure_scoring import CHECK_CATEGORIES
from app.scan.pipeline import run_scan, score_findings
from app.scan.scoring import CATEGORIES, compute_scores
from app.sca.refresh import score_inputs_from_stored
from tests.test_check_isolation import explode, make_zip
from tests.test_error_boundary import ROUTED_NEXT, _zip


def test_failure_mapping_covers_every_registered_check():
    assert set(CHECK_CATEGORIES) == set(CHECKS_RUN)


def test_failed_boundary_is_not_clean_in_static_pipeline_or_refreshed_score(monkeypatch):
    raw = _zip(ROUTED_NEXT).getvalue()
    baseline = run_scan(raw, LLMClient(providers=[]))
    assert any(f['rule_id'] == 'missing-error-boundary' for f in baseline['findings'])
    monkeypatch.setattr(static, 'scan_error_boundary', explode)
    local = static.run_static_scan(io.BytesIO(raw))
    result = run_scan(raw, LLMClient(providers=[]))
    for score in (local['score'], result['score']):
        assert score['static_incomplete'] is True
        assert score['incomplete_static_categories'] == ['Frontend']
        assert 'Frontend' in score['unexamined']
    stored = json.loads(json.dumps(result['score']))
    refreshed = score_findings(result['findings'], **score_inputs_from_stored(stored))
    assert refreshed['static_incomplete'] is True
    assert 'Frontend' in refreshed['unexamined']
    assert 'static_checks_failed' in stored['scan_manifest']['limitations']


def test_model_response_does_not_erase_static_failure():
    score = compute_scores([], llm_ran=True, failed_static=frozenset({'Security', 'Frontend'}))
    assert {'Security', 'Frontend'} <= set(score['unexamined'])
    assert score['static_incomplete'] is True


def test_no_completed_category_does_not_divide_by_zero():
    score = compute_scores([], llm_ran=False, failed_static=frozenset(CATEGORIES))
    assert set(score['unexamined']) == set(CATEGORIES)
    assert score['static_incomplete'] is True
    assert score['total'] == 0.0  # legacy numeric field; all categories explicitly unexamined


@pytest.mark.parametrize('failure', ['iteration', 'conversion'])
def test_partial_secret_findings_and_stale_coverage_are_discarded(monkeypatch, failure):
    original = static.scan_secrets
    def partial(fileobj, *, coverage):
        yield from original(fileobj, coverage=coverage)
        if failure == 'conversion':
            yield object()  # first result was appended before converting this invalid one
            return
        raise RuntimeError('private input must not be reflected')
    monkeypatch.setattr(static, 'scan_secrets', partial)
    result = static.run_static_scan(make_zip())
    assert not any(f['rule_id'] == 'github-pat' for f in result['findings'])
    assert any(f['rule_id'] == 'no-tests' for f in result['findings'])
    assert not result['secrets_coverage']
    assert 'private input' not in json.dumps(result)


@pytest.mark.parametrize('target,check,category', [
    ('scan_cookie_flags', 'session_cookie', 'Security'),
    ('run_checks', 'project_files', 'Testing'),
    ('scan_ci_deploy_source', 'ci_deploy_source', 'Deploy'),
    ('scan_auth_read', 'auth_read_consistency', 'Auth'),
])
def test_each_failed_check_invalidates_its_category(monkeypatch, target, check, category):
    monkeypatch.setattr(static, target, explode)
    scan = run_scan(make_zip().getvalue(), LLMClient(providers=[]))
    assert category in scan['score']['incomplete_static_categories']
    assert category in scan['score']['unexamined']
    assert scan['score']['scan_manifest']['static_checks_not_run'][0]['check'] == check

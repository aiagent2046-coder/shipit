"""KEV supplies urgency for existing exact-version findings, never new findings or exploit proof."""
from copy import deepcopy
import hashlib
import socket
import subprocess

import pytest

from app.scan import kev_catalog as kev
from app.scan import threat_context as threat
from tests.test_kev_catalog import COMMIT, CVE, STAMP, install, loader, raw, upstream


def finding(cve=CVE, *, file='package-lock.json', rule='dependency-cve-match', package='demo'):
    evidence = {'version': 1, 'package': package, 'ecosystem': 'npm', 'installed_version': '1.0.0',
                'manifest': file, 'advisory_ids': [cve], 'reachability': 'not_assessed'}
    result = {'rule_id': rule, 'file': file, 'line': 4, 'severity': 'high', 'confidence': 0.9,
              'category': 'Security', 'claim_evidence': evidence}
    if rule == 'dependency-cve-match':
        result.update(source='dependency', verification_method='package_version_match')
    return result


def context(findings, **kwargs):
    kwargs.setdefault('as_of', '2026-11-03')
    kwargs.setdefault('catalog', loader())
    return threat.build_threat_context(findings, **kwargs)


def test_exact_match_is_separate_priority_without_mutation_or_runtime_claim(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('No network or process invocation belongs in KEV correlation')
    monkeypatch.setattr(socket.socket, 'connect', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    findings = [finding()]
    original = deepcopy(findings)
    result = context(findings)
    assert findings == original
    assert result['status'] == 'completed' and result['matched_cves'] == 1
    assert result['eligible_findings'] == 1 and result['unmapped_findings'] == 0
    match = result['matches'][0]
    assert match['cve_id'] == CVE and match['priority'] == 'expedited'
    assert match['reason'] == 'known_exploitation'
    assert match['finding_refs'] == [{'rule_id': 'dependency-cve-match', 'file': 'package-lock.json',
                                      'line': 4, 'package': 'demo', 'ecosystem': 'npm', 'installed_version': '1.0.0'}]
    assert result['source']['commit'] == COMMIT and result['source']['source_committed_at'] == STAMP
    assert result['source']['catalog_sha256'] == loader()['sha256']
    assert result['runtime_verified'] is False
    assert 'severity' not in match and 'confidence' not in match and 'findings' not in result
    assert 'cisa_due_date_is_source_context_not_project_deadline' in result['limitations']


def test_aliases_and_multiple_packages_share_one_cve_without_duplicate_refs():
    a = finding('GHSA-2345-6789-cfgh', rule='dependency-known-vulnerability')
    a['claim_evidence']['advisory_aliases'] = [CVE]
    b = finding(package='second', file='packages/ui/package-lock.json')
    result = context([b, a, a, b])
    assert result['matched_cves'] == 1 and len(result['matches'][0]['finding_refs']) == 2
    assert context([a, b])['matches'] == result['matches']


def test_multiple_kev_cves_are_sorted_and_exact():
    a, b = 'CVE-2026-56789', CVE
    result = context([finding(a), finding(b)], catalog=loader((a, b)))
    assert [row['cve_id'] for row in result['matches']] == sorted((a, b))


def test_unreadable_advisory_is_excluded_but_readable_alias_is_preserved():
    f = finding(rule='dependency-known-vulnerability')
    f['claim_evidence'].update(advisory_ids=[CVE, 'GHSA-2345-6789-cfgh'],
                               unreadable_advisory_ids=[CVE], advisory_aliases=['CVE-2026-56789'])
    result = context([f], catalog=loader((CVE, 'CVE-2026-56789')))
    assert [row['cve_id'] for row in result['matches']] == ['CVE-2026-56789']
    f['claim_evidence']['advisory_aliases'] = []
    result = context([f])
    assert result['matches'] == [] and result['status'] == 'partial'


def test_ghsa_without_resolved_cve_alias_stays_unmapped():
    f = finding('GHSA-2345-6789-cfgh')
    result = context([f])
    assert result['status'] == 'partial' and result['unmapped_findings'] == 1
    assert result['matches'] == []
    assert 'advisory_without_resolved_cve' in result['limitations']


def test_title_prose_binary_symbols_and_non_dependency_claims_cannot_match():
    findings = [{'rule_id': 'xss-unsafe-html-injection', 'title': CVE,
                 'claim_evidence': finding()['claim_evidence']},
                {'rule_id': 'binary_static', 'facts': {'imports': [{'name': CVE}]}},
                {'rule_id': [], 'title': CVE}, None]
    f = finding('GHSA-2345-6789-cfgh')
    f.update(title=CVE, explanation=CVE)
    f['claim_evidence']['description'] = CVE
    findings.append(f)
    result = context(findings)
    assert result['matches'] == [] and result['eligible_findings'] == 1


@pytest.mark.parametrize('identifier', [
    'cve-2026-12345', 'CVE-2026-123450', 'prefix-CVE-2026-12345', 'CVE-2026-12345suffix'])
def test_matching_is_exact_not_substring_or_fuzzy(identifier):
    assert context([finding(identifier)])['matches'] == []


def test_absent_kev_entry_and_no_dependencies_never_claim_safety():
    for findings in ([], [finding('CVE-2026-99999')]):
        result = context(findings)
        assert result['status'] == 'completed' and result['matched_cves'] == 0
        assert 'absence_from_kev_is_not_evidence_of_safety' in result['limitations']
        assert 'safe' not in result and 'unaffected' not in result


@pytest.mark.parametrize('mutation', [
    lambda f: f.update(source='llm'), lambda f: f.update(verification_method='model_prediction'),
    lambda f: f.update(line=True), lambda f: f.update(file='different-lock.json'),
    lambda f: f.update(claim_evidence=[]), lambda f: f['claim_evidence'].update(version=True),
    lambda f: f['claim_evidence'].update(package=''), lambda f: f['claim_evidence'].update(installed_version=None),
    lambda f: f['claim_evidence'].update(advisory_ids=CVE),
    lambda f: f['claim_evidence'].update(advisory_aliases=[{}]),
    lambda f: f['claim_evidence'].update(unreadable_advisory_ids=None),
])
def test_malformed_dependency_evidence_is_visible_not_promoted(mutation):
    f = finding()
    mutation(f)
    result = context([f])
    assert result['status'] == 'partial' and result['unmapped_findings'] == 1
    assert result['matches'] == []


def test_timestamp_boundaries_and_stale_snapshot_retain_historical_evidence():
    assert context([finding()], as_of='2026-12-02')['status'] == 'completed'
    stale = context([finding()], as_of='2026-12-03')
    assert stale['status'] == 'stale' and stale['matched_cves'] == 1
    assert 'kev_snapshot_older_than_30_days' in stale['limitations']
    future = context([finding()], as_of='2026-11-01')
    assert future['status'] == 'unavailable' and future['matches'] == []
    assert 'kev_source_after_assessment_date' in future['limitations']


@pytest.mark.parametrize('value', ['2026-02-30', '2026-11-03T00:00:00Z', '20261103', 123])
def test_explicit_invalid_assessment_dates_rejected(value):
    with pytest.raises(ValueError):
        context([], as_of=value)


@pytest.mark.parametrize('loaded', [
    {}, [], {'status': 'unavailable', 'fingerprint': 'a' * 64},
    {'status': 'available', 'sha256': 'a' * 64, 'catalog': {'schema': 9}},
])
def test_missing_or_invalid_snapshot_degrades_without_empty_success(loaded):
    result = context([finding()], catalog=loaded)
    assert result['status'] == 'unavailable' and result['matched_cves'] == 0
    assert result['source'] is None and result['runtime_verified'] is False


def test_dependency_input_failure_is_explicit():
    result = context(None)
    assert result['status'] == 'unavailable'
    assert 'invalid_dependency_findings' in result['limitations']


def test_bounds_never_claim_complete_coverage(monkeypatch):
    monkeypatch.setattr(threat, 'MAX_FINDINGS', 1)
    limited = context([finding(), finding(file='other/package-lock.json')])
    assert limited['status'] == 'partial' and 'kev_finding_limit' in limited['limitations']
    assert limited['eligible_findings'] == 1
    monkeypatch.setattr(threat, 'MAX_FINDINGS', 1000)
    monkeypatch.setattr(threat, 'MAX_REFS', 1)
    limited = context([finding(), finding(file='other/package-lock.json')])
    assert limited['status'] == 'partial' and 'kev_reference_limit' in limited['limitations']
    assert len(limited['matches'][0]['finding_refs']) == 1
    monkeypatch.setattr(threat, 'MAX_MATCHES', 1)
    limited = context([finding(), finding('CVE-2026-56789')], catalog=loader((CVE, 'CVE-2026-56789')))
    assert limited['status'] == 'partial' and limited['matched_cves'] == 1
    assert 'kev_match_limit' in limited['limitations']


def test_catalog_removal_removes_only_priority_context():
    original = [finding(), finding('CVE-2026-56789')]
    before = context(original, catalog=loader((CVE, 'CVE-2026-56789')))
    after = context(original, catalog=loader(('CVE-2026-56789',)))
    assert before['matched_cves'] == 2 and after['matched_cves'] == 1
    assert original == [finding(), finding('CVE-2026-56789')]


def test_default_loading_and_cache_identity_include_bytes_receipt_and_utc_day(tmp_path, monkeypatch):
    path, receipt = install(tmp_path, monkeypatch)
    result = threat.build_threat_context([finding()], as_of='2026-11-03')
    assert threat.context_is_current(result, as_of='2026-11-03')
    assert not threat.context_is_current(result, as_of='2026-11-04')
    assert not threat.context_is_current(None, as_of='2026-11-03')
    original = path.read_bytes()
    path.write_bytes(original + b' ')
    assert not threat.context_is_current(result, as_of='2026-11-03')
    broken = threat.build_threat_context([finding()], as_of='2026-11-03')
    assert broken['status'] == 'unavailable'
    path.write_bytes(original)
    assert not threat.context_is_current(broken, as_of='2026-11-03')
    assert threat.context_is_current(result, as_of='2026-11-03')
    receipt.unlink()
    assert not threat.context_is_current(result, as_of='2026-11-03')


def test_recent_unrelated_source_commit_cannot_refresh_old_catalog():
    value = upstream()
    value['dateReleased'] = '2026-09-01T00:00:00Z'
    value['vulnerabilities'][0].update(dateAdded='2026-09-01', dueDate='2026-09-15')
    compiled = kev.normalize_upstream(raw(value), COMMIT, STAMP)
    supplied = loader()
    supplied['catalog'] = compiled
    supplied['sha256'] = hashlib.sha256(kev.encode_catalog(compiled)).hexdigest()
    result = context([finding()], catalog=supplied)
    assert result['status'] == 'stale' and result['matched_cves'] == 1


def test_injected_snapshot_digest_cannot_disagree_with_its_data():
    supplied = loader()
    supplied['sha256'] = '0' * 64
    result = context([finding()], catalog=supplied)
    assert result['status'] == 'unavailable' and result['source'] is None
    assert result['matches'] == []

"""KEV changes priority evidence without changing the underlying project findings."""
from copy import deepcopy
import hashlib
import json
import socket
import subprocess

import pytest

from app.llm.client import LLMClient
from app.scan import kev_catalog
from app.scan.browser import ScanSession, scan_archive
from app.scan.pipeline import BASIS_PREVIEW, run_scan
from tests import test_project_checks as shared_checks
from tests.test_sca_stage import LODASH_ADVISORY, client_for, one_advisory, repo_with

catalog = shared_checks.catalog
project = shared_checks.project
AS_OF = '2026-11-03'
CVE = 'CVE-2026-12345'


def upstream(ids):
    return json.dumps({
        'title': 'Known Exploited Vulnerabilities Catalog', 'catalogVersion': '2026.11.01',
        'dateReleased': '2026-11-01T00:00:00Z', 'count': len(ids),
        'vulnerabilities': [{
            'cveID': identifier, 'vendorProject': 'Fixture', 'product': 'Fixture',
            'vulnerabilityName': 'Fixture issue', 'dateAdded': '2026-10-31',
            'shortDescription': 'Controlled test evidence.', 'requiredAction': 'Apply vendor updates.',
            'dueDate': '2026-11-21', 'knownRansomwareCampaignUse': 'Unknown', 'notes': '', 'cwes': ['CWE-79'],
        } for identifier in ids],
    }).encode()


@pytest.fixture
def kev(tmp_path, monkeypatch):
    path = tmp_path / 'kev.json'
    receipt = tmp_path / 'kev.sha256'
    monkeypatch.setattr(kev_catalog, 'CATALOG_PATH', path)
    monkeypatch.setattr(kev_catalog, 'CHECKSUM_PATH', receipt)

    def write(ids=(CVE, 'CVE-2021-23337')):
        normalized = kev_catalog.normalize_upstream(upstream(ids), 'c' * 40, '2026-11-01T01:00:00Z')
        raw = kev_catalog.encode_catalog(normalized)
        path.write_bytes(raw)
        receipt.write_text(hashlib.sha256(raw).hexdigest() + '\n')
        return kev_catalog.load_catalog()

    write()
    return write, path, receipt


def threat(result):
    return result['score']['scan_manifest']['project_checks']['threat_context']


def test_source_cve_ghsa_ghidra_and_kev_share_one_project_without_network(catalog, kev, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('Threat correlation must not use network or execute project code')
    monkeypatch.setattr(socket.socket, 'connect', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    raw = project()
    result = scan_archive(raw, catalog, threat_as_of=AS_OF)
    checks = result['report']['project_checks']
    context = checks['threat_context']
    assert checks['binary_static']['status'] == 'completed'
    assert context['status'] == 'partial'  # The independent GHSA fixture has no resolved CVE alias.
    assert context['unmapped_findings'] == 1
    assert context['matched_cves'] == 1
    assert context['matches'][0]['cve_id'] == CVE
    assert context['matches'][0]['priority'] == 'expedited'
    assert context['matches'][0]['finding_refs'][0]['package'] == 'cve-fixture'
    assert context['runtime_verified'] is False
    assert checks['archive_sha256'] == hashlib.sha256(raw).hexdigest()
    assert len([f for f in result['report']['findings'] if f['rule_id'] == 'dependency-cve-match']) == 2
    sarif = result['sarif']['runs'][0]['invocations'][0]['properties']['projectChecks']
    assert sarif['threat_context']['matches'][0]['cve_id'] == CVE


def test_kev_add_remove_and_failure_never_change_findings_or_score(catalog, kev):
    write, path, _ = kev
    raw = project()
    before = run_scan(raw, LLMClient(), depth=BASIS_PREVIEW)
    assert threat(before)['matched_cves'] == 1
    write(('CVE-2020-99999',))
    removed = run_scan(raw, LLMClient(), depth=BASIS_PREVIEW)
    assert threat(removed)['matched_cves'] == 0
    path.write_text('{broken')
    unavailable = run_scan(raw, LLMClient(), depth=BASIS_PREVIEW)
    assert threat(unavailable)['status'] == 'unavailable'
    for result in (removed, unavailable):
        assert result['findings'] == before['findings']
        for key in ('total', 'categories', 'gated_by'):
            assert result['score'].get(key) == before['score'].get(key)
        assert result['score']['scan_manifest']['project_checks']['binary_static'] == (
            before['score']['scan_manifest']['project_checks']['binary_static'])


def test_paid_osv_alias_reaches_kev_without_title_guessing(kev):
    advisory = deepcopy(LODASH_ADVISORY)
    advisory['summary'] = 'Unrelated text without CVE identifiers'
    result = run_scan(repo_with(), LLMClient(), sca_client=client_for(one_advisory(advisory)))
    context = threat(result)
    assert context['matched_cves'] == 1
    assert context['matches'][0]['cve_id'] == 'CVE-2021-23337'
    assert context['matches'][0]['finding_refs'][0]['package'] == 'lodash'
    finding = next(f for f in result['findings'] if f['rule_id'] == 'dependency-known-vulnerability')
    assert finding['claim_evidence']['advisory_aliases'] == ['CVE-2021-23337']
    assert finding['claim_evidence']['reachability'] == 'not_assessed'


def test_session_pins_snapshot_and_assessment_day(catalog, kev):
    write, _, _ = kev
    session = ScanSession(project(), catalog, threat_as_of=AS_OF)
    initial = session.result()['report']['project_checks']['threat_context']
    write(('CVE-2020-99999',))
    assert session.result()['report']['project_checks']['threat_context'] == initial
    fresh = ScanSession(project(), catalog, threat_as_of=AS_OF)
    assert fresh.result()['report']['project_checks']['threat_context']['matched_cves'] == 0


def test_stale_context_retains_dated_evidence_without_changing_findings(catalog, kev):
    raw = project()
    current = scan_archive(raw, catalog, threat_as_of=AS_OF)
    stale = scan_archive(raw, catalog, threat_as_of='2027-01-01')
    context = stale['report']['project_checks']['threat_context']
    assert context['status'] == 'stale'
    assert context['as_of'] == '2027-01-01'
    assert context['matched_cves'] == 1
    assert stale['report']['findings'] == current['report']['findings']


def test_bundled_snapshot_integrity_and_real_provenance():
    value = kev_catalog.load_catalog()
    assert value['status'] == 'available'
    catalog = value['catalog']
    assert catalog['source']['repository'] == 'https://github.com/cisagov/kev-data'
    assert len(catalog['entries']) > 1000
    assert len(catalog['source']['commit']) == 40
    assert kev_catalog.encode_catalog(catalog) == kev_catalog.CATALOG_PATH.read_bytes()

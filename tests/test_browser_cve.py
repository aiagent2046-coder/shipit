"""Real CVE boundary regressions through the shipped browser entry point.

Expected boundaries were read from pinned upstream CNA affected records, not
computed by the compiler/matcher under test. Updating a record requires review.
"""
import hashlib
import io
import json
from pathlib import Path
import zipfile

import pytest

from app.scan.browser import ScanSession, scan_archive

ROOT = Path(__file__).resolve().parents[1]
CATALOG = json.loads((ROOT / 'app/data/cve-catalog.json').read_text())
# Source: CVEProject/cvelistV5 @ 516b642b21565770ae3156205682c83eb60c52fb
# cves/2026/2xxx/CVE-2026-2950.json and cves/2024/7xxx/CVE-2024-7297.json
REAL_CASES = [
    ('npm', 'lodash', '4.17.23', 'CVE-2026-2950', True),
    ('npm', 'lodash', '4.18.0', 'CVE-2026-2950', False),
    ('PyPI', 'langflow', '1.0.12', 'CVE-2024-7297', True),
    ('PyPI', 'langflow', '1.0.13', 'CVE-2024-7297', False),
]

# These deliberately cannot establish a public package/version identity.
LOCK_GAPS = [
    ('pnpm-alias-cycle', 'pnpm-lock.yaml',
     "lockfileVersion: '9.0'\nimporters: {}\npackages: &loop [*loop]\n", 'malformed'),
    ('pnpm-duplicate-packages', 'pnpm-lock.yaml',
     "lockfileVersion: '9.0'\nimporters: {}\npackages: {}\npackages: {}\n", 'malformed'),
    ('uv-git-source', 'uv.lock',
     'version = 1\n[[package]]\nname = "langflow"\nversion = "1.0.12"\n'
     'source = { git = "https://example.org/fork?rev=abc" }\n', 'unresolved'),
    ('uv-future-revision', 'uv.lock', 'version = 1\nrevision = 4\n', 'unsupported'),
]


def project(ecosystem, name, version, *, extra=None, modern_lock=False):
    files = {'README.md': '# Dependency regression project'}
    if ecosystem == 'npm' and modern_lock:
        files['pnpm-lock.yaml'] = f'''lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      alias:
        specifier: npm:{name}@^4
        version: {name}@{version}
packages:
  '{name}@{version}':
    resolution: {{integrity: sha512-regression-fixture}}
snapshots:
  '{name}@{version}': {{}}
'''
    elif ecosystem == 'PyPI' and modern_lock:
        files['uv.lock'] = f'''version = 1
revision = 3
[[package]]
name = "{name}"
version = "{version}"
source = {{ registry = "https://pypi.org/simple" }}
'''
    elif ecosystem == 'npm':
        files['package-lock.json'] = json.dumps({'lockfileVersion': 3, 'packages': {
            f'node_modules/{name}': {'version': version}}})
    else:
        files['requirements.txt'] = f'{name}=={version}\n'
    files.update(extra or {})
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w', zipfile.ZIP_DEFLATED) as z:
        for path, body in files.items():
            z.writestr(path, body)
    return data.getvalue()


@pytest.mark.parametrize('ecosystem,name,version,cve,affected', REAL_CASES)
@pytest.mark.parametrize('modern_lock', [False, True])
def test_real_cve_boundary_and_export(ecosystem, name, version, cve, affected, modern_lock):
    result = scan_archive(project(ecosystem, name, version, modern_lock=modern_lock), CATALOG)
    report = result['report']
    matching = [f for f in report['findings'] if f.get('claim_evidence', {}).get('cve_id') == cve]
    assert bool(matching) is affected
    assert 'dependency_check_not_run' not in report['limitations']
    assert report['runtime_verified'] is False
    assert report['dependency_cve']['dependencies_found'] == 1
    assert report['dependency_cve']['dependencies_checked'] == 1
    assert report['dependency_cve']['incomplete_manifests'] == {}
    invocation = result['sarif']['runs'][0]['invocations'][0]
    assert invocation['properties']['dependencyCve'] == report['dependency_cve']
    if affected:
        evidence = matching[0]['claim_evidence']
        assert evidence['installed_version'] == version
        assert evidence['snapshot'] == CATALOG['source']
        assert evidence['reachability'] == 'not_assessed'
        assert any(r.get('properties', {}).get('dependencyEvidence') == evidence
                   for r in result['sarif']['runs'][0]['results'])


def test_catalog_failure_keeps_static_findings_and_exposes_missing_stage():
    data = project('npm', 'lodash', '4.17.23', extra={'index.js': 'element.innerHTML = userText;'})
    result = scan_archive(data, {})
    assert result['report']['dependency_cve']['status'] == 'unavailable'
    assert result['sarif']['runs'][0]['invocations'][0]['executionSuccessful'] is False
    assert 'dependency_check_not_run' in result['report']['limitations']
    assert any(f['rule_id'] == 'xss-unsafe-html-injection' for f in result['report']['findings'])
    assert not any(f['rule_id'] == 'dependency-cve-match' for f in result['report']['findings'])


def test_continuation_does_not_duplicate_dependency_findings():
    data = project('npm', 'lodash', '4.17.23', extra={
        **{f'src/{i:04}.js': 'const value = 1;' for i in range(401)},
        'src/zz-last.js': 'element.innerHTML = untrusted;',
    })
    session = ScanSession(data, CATALOG)
    before = session.result()
    assert before['can_continue']
    after = session.continue_scan()
    assert not after['can_continue']
    def only_cve(r):
        return [f for f in r['report']['findings'] if f['rule_id'] == 'dependency-cve-match']
    assert only_cve(before) and only_cve(before) == only_cve(after)
    assert any(f['file'] == 'src/zz-last.js' for f in after['report']['findings'])


def test_committed_snapshot_receipt_matches_bytes():
    digest = hashlib.sha256((ROOT / 'app/data/cve-catalog.json').read_bytes()).hexdigest()
    receipt = json.loads((ROOT / 'app/data/cve-learning.json').read_text())
    assert digest == receipt['catalog_sha256']
    assert digest == (ROOT / 'app/data/cve-catalog.json.sha256').read_text().split()[0]
    assert receipt['source'] == CATALOG['source']
    assert receipt['classifier_trained'] is False
    assert receipt['customer_outcomes_added'] == 0


def lock_gap_project(manifest, body):
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w') as z:
        z.writestr(manifest, body)
    return data.getvalue()


@pytest.mark.parametrize('case,manifest,body,reason', LOCK_GAPS)
def test_browser_lockfile_gaps_are_not_clean_results(case, manifest, body, reason):
    result = scan_archive(lock_gap_project(manifest, body), CATALOG)
    coverage = result['report']['dependency_cve']
    assert coverage['status'] == 'partial'
    assert coverage['dependencies_found'] == 0
    assert coverage['incomplete_manifests'] == {manifest: reason}
    assert not any(f['rule_id'] == 'dependency-cve-match' for f in result['report']['findings'])

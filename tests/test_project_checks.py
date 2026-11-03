"""Independent source, advisory and binary evidence survive the real audit entry points."""
from copy import deepcopy
import hashlib
import json
import socket
import subprocess

import pytest

from app import local_cli, local_store
from app.llm.client import LLMClient
from app.sca import snapshot
from app.scan import cve_catalog, ghsa_catalog
from app.scan.binary_evidence import attach_binary_reports
from app.scan.browser import scan_archive
from app.scan.pipeline import BASIS_PREVIEW, run_scan
from tests.test_binary_evidence import archive, elf, encoded, report as binary_report
from tests.test_ghsa_pipeline import DATE, GHSA, cve_record, ghsa_record


@pytest.fixture
def catalog(tmp_path, monkeypatch):
    compiled = ghsa_catalog.merge_reviewed_ghsa(
        cve_catalog.build_catalog([cve_record()], source_commit='a' * 40, generated_at=DATE),
        [ghsa_record()], source_commit='b' * 40, generated_at=DATE,
    )
    path = tmp_path / 'catalog.json'
    checksum = tmp_path / 'catalog.sha256'
    raw = encoded(compiled)
    path.write_bytes(raw)
    checksum.write_text(hashlib.sha256(raw).hexdigest())
    monkeypatch.setattr(snapshot, 'CATALOG_PATH', path)
    monkeypatch.setattr(snapshot, 'CHECKSUM_PATH', checksum)
    monkeypatch.setattr(local_store, 'CATALOG_ROOT', tmp_path)
    (tmp_path / 'cve-catalog.json').write_bytes(raw)
    (tmp_path / 'cve-catalog.json.sha256').write_text(hashlib.sha256(raw).hexdigest())
    return compiled


def files():
    return {'index.js': 'element.innerHTML = userText;', 'bin/program': elf(),
            'package-lock.json': json.dumps({'lockfileVersion': 3, 'packages': {
                'node_modules/cve-fixture': {'version': '1.0.0'},
                'node_modules/ghsa-fixture': {'version': '1.0.0'},
            }})}


def project(report=None, body=None):
    source = files()
    if body is not None:
        source['bin/program'] = body
    return attach_binary_reports(archive(source), [('bin/program', encoded(report or binary_report()))])


def assert_findings(findings):
    assert any(f['rule_id'] == 'xss-unsafe-html-injection' for f in findings)
    dependencies = [f for f in findings if f['rule_id'] == 'dependency-cve-match']
    assert {f['claim_evidence']['advisory_id'] for f in dependencies} == {'CVE-2026-12345', GHSA}
    assert all(f['claim_evidence']['reachability'] == 'not_assessed' for f in dependencies)
    return dependencies


def test_browser_combines_three_channels_without_promoting_imports_to_findings(catalog, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('Importing binary evidence must not execute code or use the network')
    monkeypatch.setattr(socket.socket, 'connect', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    baseline = scan_archive(archive(files()), catalog)
    supplied = binary_report()
    supplied['facts']['imports'][0]['name'] = 'system'
    supplied['facts']['functions'][0]['name'] = 'AKIA' + 'A' * 16
    raw = project(supplied)
    result = scan_archive(raw, catalog)
    report = result['report']
    checks = report['project_checks']
    assert checks['schema'] == 1 and checks['runtime_verified'] is False
    assert checks['archive_sha256'] == hashlib.sha256(raw).hexdigest()
    assert checks['source']['checks_run'] > 0
    assert checks['source']['findings'] == len(report['findings']) - 2
    assert checks['dependencies']['status'] == 'completed'
    assert checks['dependencies']['mode'] == 'offline_catalog'
    assert checks['dependencies']['findings'] == 2
    assert checks['dependencies']['sources'] == catalog['sources']
    assert checks['binary_static']['status'] == 'completed'
    assert checks['binary_static']['archive_sha256'] == checks['archive_sha256']
    assert checks['binary_static']['artifacts'][0]['facts']['imports'][0]['name'] == 'system'
    assert_findings(report['findings'])
    assert report['findings'] == baseline['report']['findings']
    assert len(result['sarif']['runs'][0]['results']) == len(baseline['sarif']['runs'][0]['results'])
    exported = result['sarif']['runs'][0]['invocations'][0]['properties']['projectChecks']
    assert exported['archive_sha256'] == checks['archive_sha256']
    assert exported['binary_static']['status'] == 'completed'


@pytest.mark.parametrize('kind,status', [
    ('missing', 'not_run'), ('changed', 'unavailable'), ('invalid', 'unavailable'),
])
def test_bad_or_missing_binary_report_keeps_source_and_advisory_findings(catalog, kind, status):
    if kind == 'missing':
        raw = archive(files())
    elif kind == 'changed':
        raw = project(body=elf(b'new build'))
    else:
        supplied = binary_report()
        supplied['provider']['version'] = 'future-unreviewed'
        raw = project(supplied)
    result = scan_archive(raw, catalog)
    checks = result['report']['project_checks']
    assert checks['binary_static']['status'] == status
    assert checks['binary_static']['artifacts'][0]['facts'] is None
    assert checks['dependencies']['status'] == 'completed'
    assert_findings(result['report']['findings'])
    invocation = result['sarif']['runs'][0]['invocations'][0]
    assert invocation['executionSuccessful'] is (status == 'not_run')
    notifications = invocation.get('toolExecutionNotifications', [])
    assert any(row['level'] == ('warning' if status == 'not_run' else 'error') for row in notifications)


def test_hosted_preview_persists_same_bound_evidence_and_catalog_receipt(catalog):
    supplied = binary_report()
    supplied['facts']['functions'][0]['name'] = 'AKIA' + 'A' * 16
    raw = project(supplied)
    baseline = run_scan(archive(files()), LLMClient(), depth=BASIS_PREVIEW, llm_skip_reason='test_no_provider')
    scan = run_scan(raw, LLMClient(), depth=BASIS_PREVIEW, llm_skip_reason='test_no_provider')
    assert scan['findings'] == baseline['findings']
    for key in ('total', 'categories', 'gated_by'):
        assert scan['score'][key] == baseline['score'][key]
    checks = scan['score']['scan_manifest']['project_checks']
    browser = scan_archive(raw, catalog)['report']['project_checks']
    assert checks['binary_static'] == browser['binary_static']
    assert checks['source'] == browser['source']
    assert checks['archive_sha256'] == hashlib.sha256(raw).hexdigest()
    assert checks['dependencies']['catalog_sha256'] == hashlib.sha256(snapshot.CATALOG_PATH.read_bytes()).hexdigest()
    assert checks['dependencies']['sources'] == catalog['sources']
    assert checks['dependencies']['findings'] == len(assert_findings(scan['findings']))


def test_snapshot_refresh_replaces_only_dependency_summary(catalog):
    raw = project()
    scan = run_scan(raw, LLMClient(), depth=BASIS_PREVIEW, llm_skip_reason='test_no_provider')
    original = deepcopy(scan['score'])
    before = original['scan_manifest']['project_checks']
    updated_catalog = {**catalog, 'packages': {}}
    encoded_catalog = encoded(updated_catalog)
    snapshot.CATALOG_PATH.write_bytes(encoded_catalog)
    snapshot.CHECKSUM_PATH.write_text(hashlib.sha256(encoded_catalog).hexdigest())
    refreshed = snapshot.refresh_snapshot(scan['score'], scan['findings'], raw)
    after = refreshed['score']['scan_manifest']['project_checks']
    assert after['dependencies']['catalog_sha256'] != before['dependencies']['catalog_sha256']
    assert after['dependencies']['findings'] == 0
    assert after['binary_static'] == before['binary_static']
    assert after['source'] == before['source']
    assert after['archive_sha256'] == before['archive_sha256']
    assert scan['score'] == original
    assert not any(f['rule_id'] == 'dependency-cve-match' for f in refreshed['findings'])


@pytest.fixture
def local_project(tmp_path, catalog):
    root = tmp_path / 'project'
    root.mkdir()
    for name, content in files().items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode() if isinstance(content, str) else content)
    supplied = tmp_path / 'ghidra.json'
    supplied.write_bytes(encoded(binary_report()))
    return root, supplied, tmp_path / 'state'


def test_local_watch_key_tracks_external_evidence_and_rejects_changed_binary(local_project):
    root, supplied, state = local_project
    options = {'binary_evidence': [f'bin/program={supplied}']}
    with local_store.connect(state) as db:
        key, first = local_cli.poll_project(db, root, state, **options)
        assert first['project_checks']['binary_static']['status'] == 'completed'
        assert first['project_checks']['dependencies']['catalog_sha256'] == first['catalog']['sha256']
        assert local_cli.poll_project(db, root, state, key, **options)[1] is None
        changed = binary_report()
        changed['facts']['functions'][0]['name'] = 'renamed_observation'
        supplied.write_bytes(encoded(changed))
        next_key, second = local_cli.poll_project(db, root, state, key, **options)
        assert next_key != key
        assert second['findings'] == first['findings']
        assert second['project_checks']['binary_static']['status'] == 'completed'
        (root / 'bin/program').write_bytes(elf(b'new build'))
        _, third = local_cli.poll_project(db, root, state, next_key, **options)
        assert third['project_checks']['binary_static']['status'] == 'unavailable'
        assert third['project_checks']['binary_static']['artifacts'][0]['reason'] == 'artifact_binding_mismatch'
        assert local_cli.exit_status(third, 'none') == 2
        assert db.execute('SELECT count(*) FROM scans').fetchone()[0] == 3


def test_scan_cli_attaches_report_and_keeps_native_execution_outside_scan(local_project, capsys, monkeypatch):
    root, supplied, state = local_project
    def forbidden(*args, **kwargs):
        raise AssertionError('The scan command must not launch a native process')
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    result = local_cli.main(['--state-dir', str(state), 'scan', str(root), '--json',
                             '--binary-evidence', f'bin/program={supplied}'])
    assert result == 0
    report = json.loads(capsys.readouterr().out)
    assert_findings(report['findings'])
    assert report['snapshot']['attached_binary_reports'] == 1
    assert report['project_checks']['binary_static']['status'] == 'completed'


def test_watch_cli_reloads_supplied_report_each_iteration(local_project, capsys, monkeypatch):
    root, supplied, state = local_project
    sleeps = []
    def tick(_interval):
        sleeps.append(True)
        if len(sleeps) == 1:
            changed = binary_report()
            changed['provider']['exporter_sha256'] = '0' * 64
            supplied.write_bytes(encoded(changed))
        else:
            raise KeyboardInterrupt
    monkeypatch.setattr(local_cli.time, 'sleep', tick)
    result = local_cli.main(['--state-dir', str(state), 'watch', str(root), '--json',
                             '--binary-evidence', f'bin/program={supplied}', '--interval', '1'])
    assert result == 130
    reports = [json.loads(row) for row in capsys.readouterr().out.splitlines()]
    assert len(reports) == 2
    assert [r['project_checks']['binary_static']['status'] for r in reports] == ['completed', 'unavailable']
    assert reports[0]['findings'] == reports[1]['findings']


def test_packaging_command_creates_uploadable_archive_without_overwriting(local_project, tmp_path, catalog):
    from scripts.attach_binary_evidence import main
    root, supplied, _ = local_project
    original = archive(files())
    source = tmp_path / 'input.zip'
    output = tmp_path / 'output.zip'
    source.write_bytes(original)
    args = [str(source), '--binary-evidence', f'bin/program={supplied}', '--output', str(output)]
    assert main(args) == 0
    packed = output.read_bytes()
    assert source.read_bytes() == original
    result = scan_archive(packed, catalog)
    assert result['report']['project_checks']['binary_static']['status'] == 'completed'
    assert_findings(result['report']['findings'])
    with pytest.raises(SystemExit) as failure:
        main(args)
    assert failure.value.code == 2
    assert output.read_bytes() == packed


@pytest.mark.parametrize('failure', ['size', 'symlink', 'missing_artifact'])
def test_packaging_rejects_bad_inputs_without_creating_output(local_project, tmp_path, failure):
    from scripts.attach_binary_evidence import MAX_REPORT_BYTES, main
    _, supplied, _ = local_project
    source = tmp_path / 'input.zip'
    output = tmp_path / 'output.zip'
    source.write_bytes(archive(files()))
    path = 'bin/program'
    if failure == 'size':
        supplied.write_bytes(b'x' * (MAX_REPORT_BYTES + 1))
    elif failure == 'symlink':
        linked = tmp_path / 'linked.json'
        linked.symlink_to(supplied)
        supplied = linked
    else:
        path = 'bin/absent'
    with pytest.raises(SystemExit) as stopped:
        main([str(source), '--binary-evidence', f'{path}={supplied}', '--output', str(output)])
    assert stopped.value.code == 2
    assert not output.exists()


def test_paid_live_lookup_remains_distinct_from_offline_catalog_and_binary_facts():
    from tests.test_sca_refresh import advisory_client, repo_bytes
    import io
    import zipfile

    raw = io.BytesIO(repo_bytes())
    with zipfile.ZipFile(raw, 'a') as zipped:
        zipped.writestr('bin/program', elf())
    bound = attach_binary_reports(raw.getvalue(), [('bin/program', encoded(binary_report()))])
    result = run_scan(bound, LLMClient(), llm_skip_reason='test_no_provider', sca_client=advisory_client())
    checks = result['score']['scan_manifest']['project_checks']
    assert checks['dependencies']['mode'] == 'live_osv'
    assert checks['dependencies']['status'] == 'completed'
    dependencies = [f for f in result['findings'] if f['rule_id'] == 'dependency-known-vulnerability']
    assert dependencies
    assert checks['dependencies']['findings'] == len(dependencies)
    assert checks['dependencies']['catalog_sha256'] is None
    assert checks['dependencies']['sources'] == {}
    assert checks['binary_static']['status'] == 'completed'
    assert checks['binary_static']['runtime_verified'] is False

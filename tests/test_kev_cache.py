"""Public KEV updates refresh receipts, not project findings or paid analysis."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import socket
import subprocess
import sys
from unittest.mock import AsyncMock

import pytest

from app import local_cli, local_store
from app.audit_history import refresh_cached_preview_history
from app.llm.client import LLMClient
from app.sca import snapshot
from app.sca.refresh import refresh_score_threat_context
from app.scan import kev_catalog
from app.scan.pipeline import BASIS_PREVIEW, run_scan
from app.scan.threat_context import build_threat_context
from tests.conftest import run_audit_job
from tests.test_audit_llm_wiring import FakeLLM
from tests.test_audit_preview_history import Repo, row
from tests.test_local_package import builder
from tests.test_project_checks import catalog as advisory_catalog, files, project  # noqa: F401


pytestmark = pytest.mark.usefixtures("advisory_catalog")


@pytest.fixture
def kev_files(tmp_path, monkeypatch):
    catalog = tmp_path / 'kev.json'
    checksum = tmp_path / 'kev.sha256'
    monkeypatch.setattr(kev_catalog, 'CATALOG_PATH', catalog)
    monkeypatch.setattr(kev_catalog, 'CHECKSUM_PATH', checksum)

    def publish(cve='CVE-2026-12345', commit='a'):
        day = (datetime.now(timezone.utc).date() - timedelta(days=3)).isoformat()
        upstream = {
            'catalogVersion': 'test-' + commit, 'dateReleased': day + 'T00:00:00Z', 'count': 1,
            'vulnerabilities': [{
                'cveID': cve, 'vendorProject': 'Test vendor', 'product': 'Test package',
                'vulnerabilityName': 'Known exploitation test fixture', 'dateAdded': day,
                'shortDescription': 'A controlled fixture for exact-CVE correlation.',
                'requiredAction': 'Review the vendor update.', 'dueDate': day,
                'knownRansomwareCampaignUse': 'Unknown',
            }],
        }
        normalized = kev_catalog.normalize_upstream(json.dumps(upstream).encode(), commit * 40,
                                                    day + 'T01:00:00Z')
        raw = kev_catalog.encode_catalog(normalized)
        catalog.write_bytes(raw)
        checksum.write_text(hashlib.sha256(raw).hexdigest() + '\n')
        return raw, checksum.read_bytes()

    publish()
    return catalog, checksum, publish


def scan():
    return run_scan(project(), LLMClient(providers=[]), depth=BASIS_PREVIEW)


def context(score):
    return score['scan_manifest']['project_checks']['threat_context']


def assert_same_project(before, after):
    for key in ('total', 'categories', 'gated_by'):
        assert after[key] == before[key]
    old, new = (s['scan_manifest']['project_checks'] for s in (before, after))
    for key in ('archive_sha256', 'source', 'dependencies', 'binary_static'):
        assert new[key] == old[key]


def test_free_cache_refreshes_only_kev_when_advisory_catalog_is_current(kev_files, monkeypatch):
    original = scan()
    before = deepcopy(original)
    assert context(original['score'])['matched_cves'] == 1
    assert snapshot.snapshot_is_current(original['score'])
    kev_files[2]('CVE-2026-99999', 'b')
    assert not snapshot.snapshot_is_current(original['score'])

    def forbidden(*args, **kwargs):
        raise AssertionError('A KEV-only refresh must not inventory the archive or call a service')

    monkeypatch.setattr(snapshot, 'match_archive', forbidden)
    monkeypatch.setattr(socket.socket, 'connect', forbidden)
    refreshed = snapshot.refresh_snapshot(original['score'], original['findings'], project(),
                                          context_only_if_current=True)
    assert refreshed['findings'] == original['findings']
    assert context(refreshed['score'])['matched_cves'] == 0
    assert context(refreshed['score'])['fingerprint'] != context(original['score'])['fingerprint']
    assert_same_project(original['score'], refreshed['score'])
    assert snapshot.snapshot_is_current(refreshed['score'])
    assert original == before


@pytest.mark.asyncio
async def test_worker_reuses_analysis_when_only_kev_changes(kev_files, monkeypatch):
    from app.worker import main as worker

    repo, raw = Repo(), project()
    saved = await run_audit_job(raw, llm_client=FakeLLM(response="[]"), audit_repo=repo)
    previous = deepcopy(saved)
    kev_files[2]('CVE-2026-99999', 'b')
    runner = AsyncMock(side_effect=AssertionError("KEV-only updates must reuse existing analysis"))
    monkeypatch.setattr(worker, '_run_scan_offthread', runner)
    monkeypatch.setattr(snapshot, 'match_archive', lambda *args, **kwargs: pytest.fail('Unexpected inventory scan'))
    updated = await run_audit_job(raw, llm_client=FakeLLM(response="[]"), audit_repo=repo)
    assert updated['id'] != saved['id']
    assert updated['findings_json'] == saved['findings_json']
    assert context(updated['score_json'])['matched_cves'] == 0
    assert_same_project(saved['score_json'], updated['score_json'])
    assert saved == previous
    runner.assert_not_awaited()


def test_failed_kev_receipt_is_cacheable_and_repair_changes_it(kev_files):
    original = scan()
    catalog, checksum, _ = kev_files
    raw, receipt = catalog.read_bytes(), checksum.read_bytes()
    catalog.write_bytes(b'corrupt')
    failed = refresh_score_threat_context(original['score'], original['findings'])
    assert context(failed)['status'] == 'unavailable'
    assert context(failed)['matches'] == []
    assert_same_project(original['score'], failed)
    assert snapshot.snapshot_is_current(failed)
    assert refresh_score_threat_context(failed, original['findings']) is failed
    catalog.write_bytes(raw)
    checksum.write_bytes(receipt)
    assert not snapshot.snapshot_is_current(failed)
    repaired = refresh_score_threat_context(failed, original['findings'])
    assert context(repaired)['matched_cves'] == 1
    assert_same_project(failed, repaired)


def test_new_assessment_day_refreshes_context_without_changing_proof(kev_files):
    result = scan()
    yesterday = (datetime.now(timezone.utc).date() - timedelta(days=1)).isoformat()
    score = deepcopy(result['score'])
    score['scan_manifest']['project_checks']['threat_context'] = build_threat_context(
        result['findings'], as_of=yesterday)
    assert not snapshot.snapshot_is_current(score)
    refreshed = refresh_score_threat_context(score, result['findings'])
    assert context(refreshed)['as_of'] == datetime.now(timezone.utc).date().isoformat()
    assert_same_project(score, refreshed)
    assert context(score)['as_of'] == yesterday


@pytest.mark.asyncio
async def test_paid_cache_refresh_copies_top_and_baseline_without_model_or_osv(
    kev_files, monkeypatch,
):
    from app import audit_history

    result = scan()
    paid = row('static+llm', result['findings'], dependency_inventory={'version': 1, 'dependencies': []})
    paid['score_json'] = {**result['score'], 'basis': 'static+llm',
                          'free_baseline': {'version': 1, 'origin': 'included',
                                            'score': deepcopy(result['score']),
                                            'findings': deepcopy(result['findings'])}}
    before = deepcopy(paid)
    repo = Repo(paid)
    # The separate history mechanism is not under test here; its no-change
    # result ensures the only copied row is attributable to public intelligence.
    monkeypatch.setattr(audit_history, 'score_with_preview_history', AsyncMock(return_value=paid['score_json']))
    kev_files[2]('CVE-2026-99999', 'b')
    updated = await refresh_cached_preview_history(repo, paid)
    assert updated['id'] != paid['id']
    assert updated['findings_json'] == paid['findings_json']
    assert updated['dependency_inventory'] == paid['dependency_inventory']
    assert context(updated['score_json'])['matched_cves'] == 0
    assert context(updated['score_json']['free_baseline']['score'])['matched_cves'] == 0
    assert_same_project(paid['score_json'], updated['score_json'])
    assert paid == before
    monkeypatch.setattr(audit_history, 'score_with_preview_history', AsyncMock(return_value=updated['score_json']))
    assert await refresh_cached_preview_history(repo, updated) is updated
    assert len(repo.rows) == 2


def test_local_watch_tracks_kev_receipt_changes_and_failure_repair(kev_files, tmp_path, capsys):
    root, state = tmp_path / 'project', tmp_path / 'state'
    root.mkdir()
    for name, body in files().items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body.encode() if isinstance(body, str) else body)
    catalog, checksum, publish = kev_files
    with local_store.connect(state) as db:
        key, first = local_cli.poll_project(db, root, state)
        assert first['project_checks']['threat_context']['matched_cves'] == 1
        assert local_cli.poll_project(db, root, state, key)[1] is None
        publish('CVE-2026-99999', 'b')
        changed_key, second = local_cli.poll_project(db, root, state, key)
        assert changed_key != key
        assert second['findings'] == first['findings']
        assert second['project_checks']['threat_context']['matched_cves'] == 0
        receipt = checksum.read_bytes()
        checksum.write_text('0' * 64)
        failed_key, failed = local_cli.poll_project(db, root, state, changed_key)
        assert failed_key != changed_key
        assert failed['project_checks']['threat_context']['status'] == 'unavailable'
        assert failed['findings'] == first['findings']
        assert local_cli.poll_project(db, root, state, failed_key)[1] is None
        checksum.write_bytes(receipt)
        repaired_key, repaired = local_cli.poll_project(db, root, state, failed_key)
        assert repaired_key != failed_key
        assert (repaired['project_checks']['threat_context']['status']
                == second['project_checks']['threat_context']['status'])
        summary = json.loads(db.execute('SELECT summary FROM scans ORDER BY id DESC LIMIT 1').fetchone()[0])
        assert summary['threat_context']['fingerprint'] == repaired['project_checks']['threat_context']['fingerprint']
        local_cli.display(repaired, as_json=False)
        assert 'CISA KEV threat context:' in capsys.readouterr().out


def test_package_build_copies_checksums_and_relocates_threat_modules(tmp_path):
    source = tmp_path / 'source'
    info = builder.stage(builder.ROOT, source)
    package = source / 'drydock_local'
    raw = (package / 'data/kev-catalog.json').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == info['kev_catalog_sha256']
    assert (package / 'data/kev-catalog.json.sha256').read_text().strip() == info['kev_catalog_sha256']
    for name in ('scan/kev_catalog.py', 'scan/threat_context.py', 'report/threat_context.py'):
        assert (package / name).is_file()
    script = (
        'import json, sys; sys.path.insert(0, sys.argv[1]); '
        'from drydock_local.scan.threat_context import build_threat_context; '
        'from drydock_local.report.threat_context import threat_context_record; '
        'print(json.dumps(threat_context_record(build_threat_context([]))))'
    )
    isolated = json.loads(subprocess.check_output([sys.executable, '-I', '-c', script, str(source)], text=True))
    assert isolated['status'] != 'unavailable'
    assert isolated['source']['catalog_sha256'] == info['kev_catalog_sha256']
    assert isolated['matches'] == []


def test_package_build_rejects_corrupted_kev_receipt(tmp_path, monkeypatch):
    copy = builder.shutil.copyfile

    def corrupt_receipt(source, target):
        result = copy(source, target)
        if str(source).endswith('/kev-catalog.json.sha256'):
            target.write_text('0' * 64 + '\n')
        return result

    monkeypatch.setattr(builder.shutil, 'copyfile', corrupt_receipt)
    with pytest.raises(ValueError, match='KEV catalog checksum mismatch'):
        builder.stage(builder.ROOT, tmp_path / 'source')

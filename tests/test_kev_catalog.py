"""The KEV compiler is reproducible and cannot turn incomplete input into an empty clean catalog."""
from copy import deepcopy
import hashlib
import json

import pytest

from app.scan import kev_catalog as kev

COMMIT = 'a' * 40
STAMP = '2026-11-02T12:00:00Z'
CVE = 'CVE-2026-12345'


def upstream(cves=(CVE,)):
    return {'title': 'CISA Catalog of Known Exploited Vulnerabilities',
            'catalogVersion': '2026.11.02', 'dateReleased': '2026-11-02T11:00:00.1234Z',
            'count': len(cves), 'vulnerabilities': [{
                'cveID': cve, 'vendorProject': 'Fixture', 'product': 'demo',
                'vulnerabilityName': 'Demo vulnerability', 'dateAdded': '2026-11-01',
                'shortDescription': 'Fixture description', 'requiredAction': 'Apply the vendor mitigation.',
                'dueDate': '2026-11-15', 'knownRansomwareCampaignUse': 'Unknown', 'forensicTriage': 'No',
                'notes': 'https://example.invalid/advisory', 'cwes': ['CWE-79'],
            } for cve in cves]}


def raw(value):
    return json.dumps(value).encode()


def snapshot(cves=(CVE,)):
    return kev.normalize_upstream(raw(upstream(cves)), COMMIT, STAMP)


def loader(cves=(CVE,)):
    value = snapshot(cves)
    encoded = kev.encode_catalog(value)
    return {'status': 'available', 'catalog': value, 'sha256': hashlib.sha256(encoded).hexdigest(),
            'fingerprint': hashlib.sha256(b'fixture' + encoded).hexdigest(), 'reason': None}


def install(tmp_path, monkeypatch, value=None):
    value = snapshot() if value is None else value
    path = tmp_path / 'kev-catalog.json'
    receipt = tmp_path / 'kev-catalog.json.sha256'
    encoded = kev.encode_catalog(value)
    path.write_bytes(encoded)
    receipt.write_text(hashlib.sha256(encoded).hexdigest() + '\n')
    monkeypatch.setattr(kev, 'CATALOG_PATH', path)
    monkeypatch.setattr(kev, 'CHECKSUM_PATH', receipt)
    return path, receipt


def test_byte_deterministic_rebuild_and_exact_upstream_provenance():
    source = raw(upstream((CVE, 'CVE-2026-56789')))
    a = kev.normalize_upstream(source, COMMIT, STAMP)
    b = kev.normalize_upstream(source, COMMIT, '2026-11-02T14:00:00+02:00')
    assert a == b and kev.encode_catalog(a) == kev.encode_catalog(b)
    assert a['source']['upstream_sha256'] == hashlib.sha256(source).hexdigest()
    assert a['source']['date_released'] == '2026-11-02T11:00:00.123400Z'
    assert a['source']['source_committed_at'] == STAMP
    assert a['source']['repository'] == kev.REPOSITORY
    assert list(a['entries']) == sorted(a['entries'])
    encoded = kev.encode_catalog(a)
    assert encoded.endswith(b'\n') and kev.decode_catalog(encoded, hashlib.sha256(encoded).hexdigest())[0] == a


def test_full_replacement_removes_deleted_cves():
    before = snapshot((CVE, 'CVE-2026-56789'))
    after = snapshot(('CVE-2026-56789',))
    assert CVE in before['entries'] and CVE not in after['entries']


def test_ignored_prose_does_not_become_matching_identity():
    value = upstream()
    value['vulnerabilities'][0]['shortDescription'] += ' CVE-2026-56789'
    compiled = kev.normalize_upstream(raw(value), COMMIT, STAMP)
    assert set(compiled['entries']) == {CVE}
    assert 'description' not in compiled['entries'][CVE]


@pytest.mark.parametrize('mutation', [
    lambda v: v.update(count=True), lambda v: v.update(count=2),
    lambda v: v.update(count=0, vulnerabilities=[]), lambda v: v.update(unreviewedSchema=True),
    lambda v: v.update(dateReleased='2026-11-03T12:00:00Z'),
    lambda v: v['vulnerabilities'].append(deepcopy(v['vulnerabilities'][0])) or v.update(count=2),
    lambda v: v['vulnerabilities'][0].update(cveID='cve-2026-12345'),
    lambda v: v['vulnerabilities'][0].update(cveID='CVE-2026-12345\n'),
    lambda v: v['vulnerabilities'][0].update(requiredAction='\x00run'),
    lambda v: v['vulnerabilities'][0].update(requiredAction='x' * 4097),
    lambda v: v['vulnerabilities'][0].update(dateAdded='2026-02-30'),
    lambda v: v['vulnerabilities'][0].update(dateAdded='2026-11-03'),
    lambda v: v['vulnerabilities'][0].update(dueDate='2026-10-31'),
    lambda v: v['vulnerabilities'][0].update(forensicTriage='Maybe'),
    lambda v: v['vulnerabilities'][0].update(knownRansomwareCampaignUse='No'),
    lambda v: v['vulnerabilities'][0].update(cwes=['not-a-cwe']),
    lambda v: v['vulnerabilities'][0].update(extra=True),
    lambda v: v['vulnerabilities'][0].pop('requiredAction'),
])
def test_malformed_upstream_is_rejected_whole(mutation):
    value = upstream()
    mutation(value)
    with pytest.raises((ValueError, TypeError)):
        kev.normalize_upstream(raw(value), COMMIT, STAMP)


@pytest.mark.parametrize('content', [
    b'{"count":1,"count":2}', b'{"value":NaN}', b'{"value":Infinity}', b'[]',
    b'\xff', b'[' * 1500 + b']' * 1500,
])
def test_ambiguous_or_non_json_input_is_rejected(content):
    with pytest.raises(ValueError):
        kev.normalize_upstream(content, COMMIT, STAMP)


@pytest.mark.parametrize('commit,stamp', [
    ('A' * 40, STAMP), ('a' * 39, STAMP), (COMMIT, '2026-11-02'),
    (COMMIT, '2026-11-02T12:00:00'), (COMMIT, '2026-13-02T12:00:00Z'),
])
def test_provenance_is_strict(commit, stamp):
    with pytest.raises(ValueError):
        kev.normalize_upstream(raw(upstream()), commit, stamp)


def test_optional_ransomware_absence_is_unknown_not_no():
    value = upstream()
    value['vulnerabilities'][0].pop('knownRansomwareCampaignUse')
    entry = kev.normalize_upstream(raw(value), COMMIT, STAMP)['entries'][CVE]
    assert entry['known_ransomware_campaign_use'] == 'Unknown'


def test_size_and_entry_caps(monkeypatch):
    source = raw(upstream())
    monkeypatch.setattr(kev, 'MAX_CATALOG_BYTES', len(source) - 1)
    with pytest.raises(ValueError, match='limit'):
        kev.normalize_upstream(source, COMMIT, STAMP)
    monkeypatch.setattr(kev, 'MAX_CATALOG_BYTES', 8 * 1024 * 1024)
    monkeypatch.setattr(kev, 'MAX_ENTRIES', 1)
    with pytest.raises(ValueError, match='count'):
        kev.normalize_upstream(raw(upstream((CVE, 'CVE-2026-56789'))), COMMIT, STAMP)


def test_checksum_and_duplicate_derived_keys_rejected():
    encoded = kev.encode_catalog(snapshot())
    with pytest.raises(ValueError, match='checksum'):
        kev.decode_catalog(encoded, '0' * 64)
    duplicate = encoded.replace(b'"schema":1', b'"schema":1,"schema":1')
    with pytest.raises(ValueError, match='duplicate'):
        kev.decode_catalog(duplicate, hashlib.sha256(duplicate).hexdigest())


def test_fingerprint_observes_corruption_repair_and_receipt_changes(tmp_path, monkeypatch):
    path, receipt = install(tmp_path, monkeypatch)
    initial = kev.load_catalog()
    assert initial['status'] == 'available' and initial['fingerprint'] == kev.fingerprint()
    original = path.read_bytes()
    path.write_bytes(original + b' ')
    corrupt = kev.load_catalog()
    assert corrupt['status'] == 'unavailable' and corrupt['fingerprint'] != initial['fingerprint']
    assert corrupt['catalog'] is corrupt['sha256'] is None
    path.write_bytes(original)
    assert kev.load_catalog() == initial
    receipt.write_text('0' * 64)
    assert kev.load_catalog()['fingerprint'] != initial['fingerprint']
    receipt.unlink()
    missing = kev.load_catalog()
    assert missing['status'] == 'unavailable' and missing['reason'] == 'kev_catalog_unavailable'
    receipt.write_text(initial['sha256'] + '\n')
    assert kev.load_catalog() == initial


def test_noncanonical_receipt_is_unavailable(tmp_path, monkeypatch):
    _, receipt = install(tmp_path, monkeypatch)
    receipt.write_text(receipt.read_text().strip() + ' wrong-file.json\n')
    assert kev.load_catalog()['status'] == 'unavailable'


def test_loader_boundaries_and_missing_files(tmp_path, monkeypatch):
    path, receipt = install(tmp_path, monkeypatch)
    receipt.write_bytes(b'x' * 257)
    assert kev.load_catalog()['reason'] == 'kev_catalog_limit'
    monkeypatch.setattr(kev, 'MAX_CATALOG_BYTES', 8)
    assert kev.load_catalog()['status'] == 'unavailable'
    path.unlink()
    assert kev.load_catalog()['status'] == 'unavailable'


def test_checksum_correct_but_noncanonical_snapshot_is_rejected():
    encoded = json.dumps(snapshot(), indent=2).encode()
    with pytest.raises(ValueError, match='noncanonical'):
        kev.decode_catalog(encoded, hashlib.sha256(encoded).hexdigest())

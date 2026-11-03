"""Bounded deterministic CISA KEV snapshots; no network or project upload."""
from __future__ import annotations

from datetime import date, datetime, timezone
import hashlib
import json
from pathlib import Path
import re

REPOSITORY = 'https://github.com/cisagov/kev-data'
SOURCE_FILE = 'known_exploited_vulnerabilities.json'
CATALOG_PATH = Path(__file__).resolve().parents[1] / 'data/kev-catalog.json'
CHECKSUM_PATH = CATALOG_PATH.with_suffix('.json.sha256')
MAX_CATALOG_BYTES = 8 * 1024 * 1024
MAX_ENTRIES = 10_000
CVE_ID = re.compile(r'CVE-[0-9]{4}-[0-9]{4,19}\Z')
SHA256 = re.compile(r'[0-9a-f]{64}\Z')
COMMIT = re.compile(r'[0-9a-f]{40}\Z')
TIMESTAMP = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}'
                       r'(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})\Z')


def _pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise ValueError('duplicate_json_key')
        value[key] = item
    return value


def _nonfinite(_value):
    raise ValueError('nonfinite_json')


def _json(raw: bytes) -> dict:
    if not isinstance(raw, bytes) or len(raw) > MAX_CATALOG_BYTES:
        raise ValueError('kev_catalog_limit')
    try:
        result = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_nonfinite)
    except (UnicodeError, RecursionError) as error:
        raise ValueError('invalid_kev_catalog') from error
    if type(result) is not dict:
        raise ValueError('invalid_kev_catalog')
    return result


def _text(value, limit=4096, *, empty=False):
    if (not isinstance(value, str) or len(value) > limit or (not empty and not value.strip())
            or any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value)):
        raise ValueError('invalid_kev_text')
    return value


def _date(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}', value):
        raise ValueError('invalid_kev_date')
    date.fromisoformat(value)
    return value


def _timestamp(value):
    if not isinstance(value, str) or not TIMESTAMP.fullmatch(value):
        raise ValueError('invalid_kev_timestamp')
    return datetime.fromisoformat(value).astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')


def _entry(value):
    if type(value) is not dict or set(value) != {
            'date_added', 'required_action', 'cisa_due_date', 'known_ransomware_campaign_use'}:
        raise ValueError('invalid_kev_entry')
    _date(value['date_added'])
    _date(value['cisa_due_date'])
    if value['cisa_due_date'] < value['date_added']:
        raise ValueError('invalid_kev_date_order')
    _text(value['required_action'])
    if value['known_ransomware_campaign_use'] not in ('Known', 'Unknown'):
        raise ValueError('invalid_kev_ransomware_state')
    return dict(value)


def validate_catalog(value: object) -> dict:
    if type(value) is not dict or set(value) != {'schema', 'source', 'entries'}:
        raise ValueError('invalid_kev_catalog')
    if type(value['schema']) is not int or value['schema'] != 1:
        raise ValueError('unsupported_kev_schema')
    source = value['source']
    if type(source) is not dict or set(source) != {
            'repository', 'commit', 'source_committed_at', 'upstream_sha256', 'catalog_version', 'date_released'}:
        raise ValueError('invalid_kev_source')
    if (source['repository'] != REPOSITORY or not isinstance(source['commit'], str)
            or not COMMIT.fullmatch(source['commit']) or not isinstance(source['upstream_sha256'], str)
            or not SHA256.fullmatch(source['upstream_sha256'])):
        raise ValueError('invalid_kev_source')
    _text(source['catalog_version'], 80)
    for name in ('source_committed_at', 'date_released'):
        if _timestamp(source[name]) != source[name]:
            raise ValueError('noncanonical_kev_timestamp')
    if datetime.fromisoformat(source['date_released']) > datetime.fromisoformat(source['source_committed_at']):
        raise ValueError('invalid_kev_source_date_order')
    entries = value['entries']
    if type(entries) is not dict or not 1 <= len(entries) <= MAX_ENTRIES:
        raise ValueError('invalid_kev_entry_count')
    cleaned = {}
    for cve, entry in sorted(entries.items()):
        if not isinstance(cve, str) or not CVE_ID.fullmatch(cve):
            raise ValueError('invalid_kev_cve_id')
        cleaned[cve] = _entry(entry)
        if cleaned[cve]['date_added'] > source['date_released'][:10]:
            raise ValueError('invalid_kev_entry_date')
    return {'schema': 1, 'source': dict(source), 'entries': cleaned}


def normalize_upstream(raw: bytes, commit: str, source_committed_at: str) -> dict:
    """Compile the reviewed official schema; deleted upstream CVEs stay deleted."""
    data = _json(raw)
    if not {'catalogVersion', 'dateReleased', 'count', 'vulnerabilities'} <= set(data) <= {
            'title', 'catalogVersion', 'dateReleased', 'count', 'vulnerabilities'}:
        raise ValueError('unsupported_kev_upstream_schema')
    if 'title' in data:
        _text(data['title'], 256)
    rows = data['vulnerabilities']
    if (type(rows) is not list or type(data['count']) is not int or data['count'] != len(rows)
            or not 1 <= len(rows) <= MAX_ENTRIES):
        raise ValueError('invalid_kev_entry_count')
    entries = {}
    required = {'cveID', 'vendorProject', 'product', 'vulnerabilityName', 'dateAdded',
                'shortDescription', 'requiredAction', 'dueDate'}
    optional = {'knownRansomwareCampaignUse', 'forensicTriage', 'notes', 'cwes'}
    for row in rows:
        if type(row) is not dict or not required <= set(row) <= required | optional:
            raise ValueError('unsupported_kev_upstream_entry')
        cve = row['cveID']
        if not isinstance(cve, str) or not CVE_ID.fullmatch(cve) or cve in entries:
            raise ValueError('invalid_or_duplicate_kev_cve')
        for field in ('vendorProject', 'product', 'vulnerabilityName', 'shortDescription'):
            _text(row[field], 4096)
        if 'notes' in row:
            _text(row['notes'], 8192, empty=True)
        if 'forensicTriage' in row and row['forensicTriage'] not in ('Yes', 'No'):
            raise ValueError('invalid_kev_forensic_triage')
        if 'cwes' in row and (type(row['cwes']) is not list or len(row['cwes']) > 32
                             or any(not isinstance(cwe, str) or not re.fullmatch(r'CWE-[0-9]{1,10}', cwe)
                                    for cwe in row['cwes'])):
            raise ValueError('invalid_kev_cwes')
        entries[cve] = {'date_added': row['dateAdded'], 'required_action': row['requiredAction'],
                        'cisa_due_date': row['dueDate'],
                        'known_ransomware_campaign_use': row.get('knownRansomwareCampaignUse', 'Unknown')}
    return validate_catalog({'schema': 1, 'source': {
        'repository': REPOSITORY, 'commit': commit, 'source_committed_at': _timestamp(source_committed_at),
        'upstream_sha256': hashlib.sha256(raw).hexdigest(), 'catalog_version': data['catalogVersion'],
        'date_released': _timestamp(data['dateReleased']),
    }, 'entries': entries})


def encode_catalog(catalog: dict) -> bytes:
    encoded = (json.dumps(validate_catalog(catalog), sort_keys=True, separators=(',', ':'),
                          ensure_ascii=False, allow_nan=False) + '\n').encode('utf-8')
    if len(encoded) > MAX_CATALOG_BYTES:
        raise ValueError('kev_catalog_limit')
    return encoded


def decode_catalog(raw: bytes, checksum: str) -> tuple[dict, str]:
    digest = hashlib.sha256(raw).hexdigest()
    if not isinstance(checksum, str) or not SHA256.fullmatch(checksum) or checksum != digest:
        raise ValueError('kev_checksum_mismatch')
    value = validate_catalog(_json(raw))
    if encode_catalog(value) != raw:
        raise ValueError('noncanonical_kev_catalog')
    return value, digest


def _inputs():
    parts = []
    failure = None
    digest = hashlib.sha256(b'drydock-kev-v1\0')
    for path, limit in ((CATALOG_PATH, MAX_CATALOG_BYTES), (CHECKSUM_PATH, 256)):
        try:
            with path.open('rb') as source:
                raw = source.read(limit + 1)
            state = b'read' if len(raw) <= limit else b'oversized'
            if len(raw) > limit:
                failure = 'kev_catalog_limit'
        except OSError:
            raw, state = b'', b'unavailable'
            failure = 'kev_catalog_unavailable'
        digest.update(state + b'\0' + len(raw).to_bytes(8, 'big') + raw)
        parts.append(raw)
    return parts[0], parts[1], failure, digest.hexdigest()


def fingerprint() -> str:
    """Include failed reads and both actual bytes and receipt, so repair invalidates caches."""
    return _inputs()[3]


def load_catalog() -> dict:
    raw, receipt, failure, identity = _inputs()
    value, digest = None, None
    if failure is None:
        try:
            tokens = receipt.decode('ascii').split()
            if len(tokens) != 1:
                raise ValueError('invalid_kev_checksum_receipt')
            value, digest = decode_catalog(raw, tokens[0])
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            failure = 'kev_catalog_invalid'
    return {'status': 'unavailable' if failure else 'available', 'catalog': value,
            'sha256': digest, 'fingerprint': identity, 'reason': failure}

"""Bound operator-supplied Ghidra facts to project bytes; never execute binaries.

Hashes establish consistency, not authenticity of an edited operator report.
Imports/functions remain observations, never package identities or vulnerabilities.
"""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import PurePosixPath
import re
import stat
import struct
import zipfile
import zlib

from app.ingest.validators import validate_zip
from app.scan.file_scope import BINARY_EVIDENCE_PATH

try:
    import lzma
except ImportError:  # Some browser/WASM Python distributions omit this codec.
    lzma = None

ENVELOPE_PATH = BINARY_EVIDENCE_PATH
MAX_ENVELOPE_BYTES = 2 * 1024 * 1024
MAX_REPORT_BYTES = 1024 * 1024
MAX_REPORTS = 8
MAX_ARTIFACTS = 32
MAX_BINARY_BYTES = 10 * 1024 * 1024
MAX_FACTS = 1000
GHIDRA_VERSION = '12.2'
DISTRIBUTION_SHA256 = '2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67'
# Pinned exporter bytes, validated against the standalone producer in tests.
EXPORTER_SHA256 = 'a75d80df2ebd40282c3a574357c412509af7bc621a651066736946972ad45ec6'
PROFILE = 'elf-x86-64-static-v1'
ADDRESS = re.compile(r'[A-Za-z_][A-Za-z0-9_]*:[0-9a-fA-F]{1,16}\Z')
PRODUCER_LIMITATIONS = [
    'static_discovery_only', 'function_recovery_not_proven_complete', 'imports_are_not_vulnerabilities',
    'external_locations_are_not_runtime_addresses', 'target_not_executed', 'no_security_verdict',
]
LIMITATIONS = [
    'operator_supplied_evidence_not_authenticated', 'binary_static_only', 'target_not_executed',
    'function_recovery_not_proven_complete', 'imports_are_not_vulnerabilities',
    'binary_package_versions_not_inferred', 'no_security_verdict',
]
UNAVAILABLE_REASONS = frozenset({
    'not_executed', 'unsupported_runtime', 'unsupported_file', 'binary_limit', 'binary_changed',
    'unsupported_elf', 'jdk_25_unavailable', 'tool_unavailable', 'tool_checksum_mismatch',
    'tool_archive_limit', 'invalid_tool_archive', 'invalid_result', 'output_limit',
    'execution_timeout', 'execution_failed', 'execution_unavailable',
})
ZIP_READ_ERRORS = (OSError, EOFError, RuntimeError, zipfile.BadZipFile, zlib.error)
if lzma is not None:
    ZIP_READ_ERRORS += (lzma.LZMAError,)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate_json_key')
        result[key] = value
    return result


def _nonfinite(_value):
    raise ValueError('nonfinite_json')


def _json(raw):
    return json.loads(raw, object_pairs_hook=_pairs, parse_constant=_nonfinite)


def _encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                       allow_nan=False) + '\n').encode()


def _path(value):
    if (not isinstance(value, str) or not value or len(value) > 1024 or '\\' in value
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ValueError('invalid_artifact_path')
    parsed = PurePosixPath(value)
    if (parsed.is_absolute() or '..' in parsed.parts or ':' in value or str(parsed) != value
            or value == '.' or value.endswith('/')):
        raise ValueError('invalid_artifact_path')
    return value


def _name(info):
    return str(PurePosixPath(info.filename.replace('\\', '/')))


def _regular(info):
    mode = info.external_attr >> 16
    return not info.is_dir() and stat.S_IFMT(mode) in (0, stat.S_IFREG)


def _manifest_path(name):
    return name == ENVELOPE_PATH or name.endswith('/' + ENVELOPE_PATH)


def _binary_kind(header):
    if header.startswith(b'\x7fELF'):
        if (len(header) >= 64 and header[:7] == b'\x7fELF\x02\x01\x01'
                and struct.unpack_from('<HHI', header, 16) in ((2, 62, 1), (3, 62, 1))
                and struct.unpack_from('<H', header, 52)[0] == 64):
            return 'ELF64LE'
        return 'unsupported_elf'
    if header.startswith(b'MZ'):
        return 'PE'
    if header[:4] in (b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xcf',
                      b'\xcf\xfa\xed\xfe', b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca',
                      b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca'):
        return 'MachO'
    if header.startswith(b'\x00asm'):
        return 'WASM'
    return None


def _text(value):
    return isinstance(value, str) and 1 <= len(value) <= 256


def _facts(value, digest):
    keys = {'version', 'ghidra_version', 'executable_sha256', 'executable_format', 'language_id',
            'compiler_spec_id', 'image_base', 'analysis_timed_out', 'truncated', 'functions', 'imports'}
    if (type(value) is not dict or set(value) != keys or type(value['version']) is not int
            or value['version'] != 1 or value['ghidra_version'] != GHIDRA_VERSION
            or value['executable_sha256'] != digest
            or value['executable_format'] != 'Executable and Linking Format (ELF)'
            or value['language_id'] != 'x86:LE:64:default' or value['compiler_spec_id'] != 'gcc'
            or type(value['analysis_timed_out']) is not bool or type(value['truncated']) is not bool
            or not _text(value['image_base']) or not ADDRESS.fullmatch(value['image_base'])):
        raise ValueError('invalid_report')
    for name, expected in (('functions', {'entry', 'name', 'body_addresses'}),
                           ('imports', {'library', 'name', 'external_location'})):
        rows = value[name]
        if type(rows) is not list or len(rows) > MAX_FACTS:
            raise ValueError('invalid_report')
        identifiers = []
        for row in rows:
            if type(row) is not dict or set(row) != expected:
                raise ValueError('invalid_report')
            for field, item in row.items():
                if field == 'body_addresses':
                    if type(item) is not int or not 0 <= item <= 2**64 - 1:
                        raise ValueError('invalid_report')
                elif not _text(item):
                    raise ValueError('invalid_report')
            location = row.get('entry', row.get('external_location'))
            if not ADDRESS.fullmatch(location):
                raise ValueError('invalid_report')
            identifiers.append(row['entry'] if name == 'functions' else (
                row['library'], row['name'], row['external_location']))
        if identifiers != sorted(set(identifiers)):
            raise ValueError('invalid_report')
    return value


def _report(report, digest, size):
    keys = {'version', 'scope', 'profile', 'status', 'reason', 'artifact', 'provider', 'facts',
            'runtime_verified', 'automatic_patch', 'limitations'}
    if (type(report) is not dict or set(report) != keys or type(report['version']) is not int
            or report['version'] != 1 or report['scope'] != 'binary_static' or report['profile'] != PROFILE
            or report['runtime_verified'] is not False or report['automatic_patch'] is not False
            or report['limitations'] != PRODUCER_LIMITATIONS):
        raise ValueError('invalid_report')
    if len(_encode(report)) > MAX_REPORT_BYTES:
        raise ValueError('report_limit')
    artifact = report['artifact']
    if (type(artifact) is not dict or set(artifact) != {'sha256', 'bytes', 'format', 'machine'}
            or artifact['sha256'] != digest or type(artifact['bytes']) is not int or artifact['bytes'] != size
            or artifact['format'] != 'ELF64LE' or type(artifact['machine']) is not int or artifact['machine'] != 62):
        raise ValueError('artifact_binding_mismatch')
    if report['status'] == 'unavailable':
        if (report['facts'] is not None or report['provider'] is not None
                or report['reason'] not in UNAVAILABLE_REASONS):
            raise ValueError('invalid_report')
        return {'status': 'unavailable', 'reason': report['reason'], 'provider': None, 'facts': None}
    provider = report['provider']
    if (type(provider) is not dict or set(provider) != {
            'name', 'version', 'java_major', 'java_version', 'distribution_sha256', 'exporter_sha256'}
            or provider['name'] != 'ghidra' or provider['version'] != GHIDRA_VERSION
            or type(provider['java_major']) is not int or provider['java_major'] != 25
            or not _text(provider['java_version'])
            or not re.fullmatch(r'25(?:[.\-+][^\r\n]*)?', provider['java_version'])
            or provider['distribution_sha256'] != DISTRIBUTION_SHA256
            or provider['exporter_sha256'] != EXPORTER_SHA256):
        raise ValueError('tool_binding_mismatch')
    facts = _facts(report['facts'], digest)
    if facts['analysis_timed_out']:
        status, reason = 'partial', 'analysis_timeout'
    elif facts['truncated']:
        status, reason = 'partial', 'fact_limit'
    elif not facts['functions']:
        status, reason = 'partial', 'no_functions_recovered'
    else:
        status, reason = 'completed', 'static_export_completed'
    if report['status'] != status or report['reason'] != reason:
        raise ValueError('report_status_mismatch')
    # JSON roundtrip both detaches caller-owned objects and preserves labels strictly as data.
    return _json(_encode({'status': status, 'reason': reason, 'provider': provider, 'facts': facts}))


def _envelope(archive, manifests):
    if len(manifests) != 1:
        raise ValueError('ambiguous_evidence_manifest')
    info = manifests[0]
    name = _name(info)
    if not _regular(info):
        raise ValueError('invalid_evidence_manifest')
    parts = PurePosixPath(name).parts
    if len(parts) not in (2, 3):
        raise ValueError('invalid_evidence_manifest_path')
    prefix = parts[0] + '/' if len(parts) == 3 else ''
    if info.file_size > MAX_ENVELOPE_BYTES:
        raise ValueError('evidence_manifest_limit')
    value = _json(archive.read(info))
    if (type(value) is not dict or set(value) != {'version', 'artifacts'}
            or type(value['version']) is not int or value['version'] != 1
            or type(value['artifacts']) is not list or len(value['artifacts']) > MAX_REPORTS):
        raise ValueError('invalid_evidence_manifest')
    reports = {}
    for item in value['artifacts']:
        if type(item) is not dict or set(item) != {'path', 'report'}:
            raise ValueError('invalid_evidence_manifest')
        path = prefix + _path(item['path'])
        if path in reports or _manifest_path(path):
            raise ValueError('duplicate_artifact_path')
        reports[path] = item['report']
    return reports


def _base(data):
    return {'schema': 1, 'status': 'not_applicable', 'archive_sha256': hashlib.sha256(data).hexdigest(),
            'artifacts': [], 'provenance': 'operator_supplied', 'runtime_verified': False,
            'automatic_patch': False, 'limitations': list(LIMITATIONS), 'artifacts_omitted': 0}


def collect_binary_evidence(data: bytes) -> dict:
    """Inventory headers and import bounded facts; invalid evidence cannot break source scanning."""
    validate_zip(io.BytesIO(data), len(data))
    result = _base(data)
    reports, detected, failures = {}, {}, []
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = {_name(info): info for info in archive.infolist() if not info.is_dir()}
        manifests = [info for name, info in infos.items() if _manifest_path(name)]
        if manifests:
            try:
                reports = _envelope(archive, manifests)
            except (ValueError, KeyError, TypeError, UnicodeError, RecursionError, *ZIP_READ_ERRORS):
                failures.append('invalid_binary_evidence_manifest')
        for path, info in sorted(infos.items()):
            if not _regular(info) or _manifest_path(path):
                continue
            try:
                with archive.open(info) as source:
                    kind = _binary_kind(source.read(64))
            except (ValueError, *ZIP_READ_ERRORS):
                failures.append('binary_inventory_read_error')
                continue
            if kind is None:
                continue
            if len(detected) == MAX_ARTIFACTS:
                if path not in reports:
                    result['artifacts_omitted'] += 1
                continue
            detected[path] = kind
        # Include missing targets explicitly instead of silently dropping their reports.
        paths = sorted(set(detected) | set(reports))
        if len(paths) > MAX_ARTIFACTS:
            result['artifacts_omitted'] += len(paths) - MAX_ARTIFACTS
        for path in paths[:MAX_ARTIFACTS]:
            info = infos.get(path)
            row = {'path': path, 'sha256': None, 'bytes': info.file_size if info else None,
                   'status': 'unavailable', 'reason': 'artifact_missing', 'provider': None, 'facts': None}
            result['artifacts'].append(row)
            if info is None or not _regular(info):
                continue
            if info.file_size > MAX_BINARY_BYTES:
                row['reason'] = 'binary_limit'
                continue
            try:
                raw = archive.read(info)
                digest = hashlib.sha256(raw).hexdigest()
                row.update(sha256=digest, bytes=len(raw))
                kind = _binary_kind(raw[:64])
                if kind != 'ELF64LE':
                    row['reason'] = 'unsupported_binary_format'
                elif path not in reports:
                    row.update(status='not_run', reason='ghidra_report_not_supplied')
                else:
                    row.update(_report(reports[path], digest, len(raw)))
            except (ValueError, KeyError, TypeError, UnicodeError, RecursionError) as error:
                reason = str(error)
                row['reason'] = reason if reason in {
                    'invalid_report', 'report_limit', 'artifact_binding_mismatch',
                    'tool_binding_mismatch', 'report_status_mismatch',
                } else 'invalid_report'
            except ZIP_READ_ERRORS:
                row['reason'] = 'artifact_unreadable'
    if result['artifacts_omitted']:
        failures.append('binary_artifact_limit')
    result['limitations'].extend(sorted(set(failures)))
    states = {row['status'] for row in result['artifacts']}
    if failures:
        result['status'] = 'partial' if states & {'completed', 'partial'} else 'unavailable'
    elif not states:
        result['status'] = 'not_applicable'
    elif states == {'completed'}:
        result['status'] = 'completed'
    elif states == {'not_run'}:
        result['status'] = 'not_run'
    elif states == {'unavailable'}:
        result['status'] = 'unavailable'
    else:
        result['status'] = 'partial'
    return result


def attach_binary_reports(data: bytes, attachments: list[tuple[str, bytes]]) -> bytes:
    """Append an explicit canonical envelope without executing or modifying project files."""
    validate_zip(io.BytesIO(data), len(data))
    if type(attachments) is not list or len(attachments) > MAX_REPORTS:
        raise ValueError('binary_report_limit')
    if not attachments:
        return data
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = {_name(info): info for info in archive.infolist() if not info.is_dir()}
        if any(_manifest_path(name) for name in infos):
            raise ValueError('binary_evidence_manifest_exists')
        entries, seen = [], set()
        for path, raw in attachments:
            path = _path(path)
            if path in seen or _manifest_path(path):
                raise ValueError('duplicate_artifact_path')
            seen.add(path)
            if path not in infos or not _regular(infos[path]):
                raise ValueError('artifact_missing')
            if not isinstance(raw, bytes) or len(raw) > MAX_REPORT_BYTES:
                raise ValueError('binary_report_limit')
            report = _json(raw)
            if type(report) is not dict:
                raise ValueError('invalid_report')
            entries.append({'path': path, 'report': report})
    envelope = _encode({'version': 1, 'artifacts': sorted(entries, key=lambda row: row['path'])})
    if len(envelope) > MAX_ENVELOPE_BYTES:
        raise ValueError('evidence_manifest_limit')
    output = io.BytesIO(data)
    with zipfile.ZipFile(output, 'a', compression=zipfile.ZIP_DEFLATED) as archive:
        entry = zipfile.ZipInfo(ENVELOPE_PATH, date_time=(1980, 1, 1, 0, 0, 0))
        entry.create_system = 3
        entry.external_attr = 0o600 << 16
        entry.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(entry, envelope)
    combined = output.getvalue()
    validate_zip(io.BytesIO(combined), len(combined))
    return combined

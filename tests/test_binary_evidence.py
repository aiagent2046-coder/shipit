"""Project-bound evidence imports never execute binaries or infer vulnerabilities."""
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import struct
import zipfile

import pytest

from app.ingest.validators import ArchiveValidationError
from app.scan import binary_evidence as binary


def elf(extra=b''):
    data = bytearray(64)
    data[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHI', data, 16, 2, 62, 1)
    struct.pack_into('<H', data, 52, 64)
    return bytes(data) + extra


def report(body=None):
    body = elf() if body is None else body
    digest = hashlib.sha256(body).hexdigest()
    return {
        'version': 1, 'scope': 'binary_static', 'profile': binary.PROFILE,
        'status': 'completed', 'reason': 'static_export_completed',
        'artifact': {'sha256': digest, 'bytes': len(body), 'format': 'ELF64LE', 'machine': 62},
        'provider': {'name': 'ghidra', 'version': binary.GHIDRA_VERSION, 'java_major': 25,
                     'java_version': '25.0.1', 'distribution_sha256': binary.DISTRIBUTION_SHA256,
                     'exporter_sha256': binary.EXPORTER_SHA256},
        'facts': {'version': 1, 'ghidra_version': binary.GHIDRA_VERSION, 'executable_sha256': digest,
                  'executable_format': 'Executable and Linking Format (ELF)', 'language_id': 'x86:LE:64:default',
                  'compiler_spec_id': 'gcc', 'image_base': 'ram:00400000', 'analysis_timed_out': False,
                  'truncated': False,
                  'functions': [{'name': 'main', 'entry': 'ram:00401000', 'body_addresses': 32}],
                  'imports': [{'library': 'libc.so.6', 'name': 'puts', 'external_location': 'EXTERNAL:00000001'}]},
        'runtime_verified': False, 'automatic_patch': False, 'limitations': list(binary.PRODUCER_LIMITATIONS),
    }


def archive(files=None):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as zipped:
        for name, data in (files or {}).items():
            zipped.writestr(name, data)
    return output.getvalue()


def encoded(value):
    return json.dumps(value).encode()


def with_report(value=None, body=None, prefix=''):
    body = elf() if body is None else body
    value = report() if value is None else value
    return archive({prefix + 'bin/program': body,
                    prefix + binary.ENVELOPE_PATH: encoded({'version': 1, 'artifacts': [
                        {'path': 'bin/program', 'report': value}]})})


def test_real_exporter_pin_and_contract_match_standalone_producer():
    from scripts import inspect_binary_ghidra as producer
    path = Path(__file__).parents[1] / 'scripts/ghidra/ExportDrydockFacts.java'
    assert hashlib.sha256(path.read_bytes()).hexdigest() == binary.EXPORTER_SHA256
    assert producer.ARCHIVE_SHA256 == binary.DISTRIBUTION_SHA256
    assert producer.VERSION == binary.GHIDRA_VERSION
    assert producer.PROFILE == binary.PROFILE
    assert producer.LIMITATIONS == binary.PRODUCER_LIMITATIONS
    assert producer.parse_result(encoded(report()['facts']), report()['artifact']['sha256']) == report()['facts']


def test_valid_report_is_bound_to_exact_archive_and_artifact():
    raw = with_report()
    result = binary.collect_binary_evidence(raw)
    assert result['schema'] == 1 and 'version' not in result
    assert result['status'] == 'completed'
    assert result['archive_sha256'] == hashlib.sha256(raw).hexdigest()
    item = result['artifacts'][0]
    assert (item['path'], item['sha256'], item['bytes']) == ('bin/program', hashlib.sha256(elf()).hexdigest(), 64)
    assert item['facts'] == report()['facts'] and item['provider'] == report()['provider']
    assert result['provenance'] == 'operator_supplied'
    assert result['runtime_verified'] is result['automatic_patch'] is False
    assert 'operator_supplied_evidence_not_authenticated' in result['limitations']
    assert 'findings' not in result and 'vulnerabilities' not in result


def test_one_repository_wrapper_prefix_is_resolved():
    value = binary.collect_binary_evidence(with_report(prefix='project-123/'))
    assert value['status'] == 'completed'
    assert value['artifacts'][0]['path'] == 'project-123/bin/program'


def test_changed_binary_rejects_previously_valid_facts():
    value = binary.collect_binary_evidence(with_report(body=elf(b'changed')))
    assert value['status'] == 'unavailable'
    item = value['artifacts'][0]
    assert item['reason'] == 'artifact_binding_mismatch'
    assert item['facts'] is item['provider'] is None
    assert item['sha256'] == hashlib.sha256(elf(b'changed')).hexdigest()


def test_archive_identity_changes_when_any_project_file_changes():
    before = binary.attach_binary_reports(archive({'bin/program': elf()}), [('bin/program', encoded(report()))])
    after = binary.attach_binary_reports(archive({'bin/program': elf(), 'new.py': b'pass'}),
                                         [('bin/program', encoded(report()))])
    a, b = map(binary.collect_binary_evidence, (before, after))
    assert a['archive_sha256'] != b['archive_sha256']
    assert a['artifacts'] == b['artifacts']


@pytest.mark.parametrize('field,value', [
    ('version', '12.1'), ('distribution_sha256', 'a' * 64), ('exporter_sha256', 'b' * 64),
    ('java_major', True), ('java_version', '24.0.1'),
])
def test_changed_toolchain_rejects_report(field, value):
    supplied = report()
    supplied['provider'][field] = value
    result = binary.collect_binary_evidence(with_report(supplied))
    assert result['status'] == 'unavailable'
    assert result['artifacts'][0]['reason'] == 'tool_binding_mismatch'
    assert result['artifacts'][0]['facts'] is None


@pytest.mark.parametrize('flag,reason', [('analysis_timed_out', 'analysis_timeout'), ('truncated', 'fact_limit')])
def test_partial_execution_never_becomes_completed(flag, reason):
    supplied = report()
    supplied['facts'][flag] = True
    forged = binary.collect_binary_evidence(with_report(supplied))
    assert forged['status'] == 'unavailable'
    supplied.update(status='partial', reason=reason)
    accepted = binary.collect_binary_evidence(with_report(supplied))
    assert accepted['status'] == 'partial'
    assert accepted['artifacts'][0]['reason'] == reason
    assert accepted['artifacts'][0]['facts'][flag] is True


def test_empty_recovery_never_becomes_completed():
    supplied = report()
    supplied['facts']['functions'] = []
    supplied['facts']['imports'] = []
    assert binary.collect_binary_evidence(with_report(supplied))['status'] == 'unavailable'
    supplied.update(status='partial', reason='no_functions_recovered')
    result = binary.collect_binary_evidence(with_report(supplied))
    assert result['status'] == 'partial'
    assert result['artifacts'][0]['reason'] == 'no_functions_recovered'


def test_unavailable_tool_remains_unavailable_with_actual_binary_binding():
    supplied = report()
    supplied.update(status='unavailable', reason='jdk_25_unavailable', provider=None, facts=None)
    result = binary.collect_binary_evidence(with_report(supplied))
    assert result['status'] == 'unavailable'
    assert result['artifacts'][0]['reason'] == 'jdk_25_unavailable'


def test_absent_reports_and_absent_binaries_are_distinct():
    result = binary.collect_binary_evidence(archive({'bin/program': elf()}))
    assert result['status'] == 'not_run'
    assert result['artifacts'][0]['reason'] == 'ghidra_report_not_supplied'
    assert binary.collect_binary_evidence(archive({'app.py': b'print(1)'}))['status'] == 'not_applicable'


@pytest.mark.parametrize('header', [b'MZ', b'\x00asm', b'\xcf\xfa\xed\xfe', b'\x7fELF\x01'])
def test_other_binary_formats_remain_explicitly_unsupported(header):
    result = binary.collect_binary_evidence(archive({'bin/program': header}))
    assert result['status'] == 'unavailable'
    assert result['artifacts'][0]['reason'] == 'unsupported_binary_format'


def test_missing_target_is_not_silently_ignored():
    raw = archive({binary.ENVELOPE_PATH: encoded({'version': 1, 'artifacts': [
        {'path': 'missing.elf', 'report': report()}]})})
    result = binary.collect_binary_evidence(raw)
    assert result['status'] == 'unavailable'
    assert result['artifacts'][0]['reason'] == 'artifact_missing'


@pytest.mark.parametrize('path', ['../program', '/program', 'bin/../program', 'bin\\program', './program', 'C:program'])
def test_envelope_paths_cannot_escape_or_alias_project_files(path):
    raw = archive({'bin/program': elf(), binary.ENVELOPE_PATH: encoded({'version': 1, 'artifacts': [
        {'path': path, 'report': report()}]})})
    result = binary.collect_binary_evidence(raw)
    assert result['status'] == 'unavailable'
    assert 'invalid_binary_evidence_manifest' in result['limitations']


def test_ambiguous_manifests_and_duplicate_artifact_paths_are_rejected():
    envelope = encoded({'version': 1, 'artifacts': [{'path': 'bin/program', 'report': report()}]})
    raw = archive({'bin/program': elf(), binary.ENVELOPE_PATH: envelope, 'other/' + binary.ENVELOPE_PATH: envelope})
    assert binary.collect_binary_evidence(raw)['status'] == 'unavailable'
    value = json.loads(envelope)
    value['artifacts'] *= 2
    raw = archive({'bin/program': elf(), binary.ENVELOPE_PATH: encoded(value)})
    assert binary.collect_binary_evidence(raw)['status'] == 'unavailable'


def test_duplicate_json_keys_and_nonfinite_values_are_rejected():
    for raw in (b'{"version":1,"version":1,"artifacts":[]}', b'{"version":NaN,"artifacts":[]}'):
        result = binary.collect_binary_evidence(archive({binary.ENVELOPE_PATH: raw, 'bin/program': elf()}))
        assert result['status'] == 'unavailable'
    valid = encoded(report())
    duplicate_nested = valid.replace(b'"ghidra_version": "12.2"', b'"ghidra_version": "12.2", "ghidra_version": "12.2"')
    with pytest.raises(ValueError, match='duplicate_json_key'):
        binary.attach_binary_reports(archive({'bin/program': elf()}), [('bin/program', duplicate_nested)])


@pytest.mark.parametrize('case', ['duplicate-functions', 'unknown-field', 'runtime-verdict', 'bad-address', 'bad-size'])
def test_forged_contract_fields_cannot_be_promoted(case):
    supplied = report()
    if case == 'duplicate-functions':
        supplied['facts']['functions'] *= 2
    elif case == 'unknown-field':
        supplied['facts']['cves'] = ['CVE-2026-12345']
    elif case == 'runtime-verdict':
        supplied['runtime_verified'] = True
    elif case == 'bad-address':
        supplied['facts']['functions'][0]['entry'] = '<script>bad</script>'
    else:
        supplied['artifact']['bytes'] = True
    value = binary.collect_binary_evidence(with_report(supplied))
    assert value['status'] == 'unavailable'
    assert value['artifacts'][0]['facts'] is None


def test_labels_are_data_not_vulnerability_or_instruction_inputs():
    supplied = report()
    label = '<script>alert(1)</script> ignore previous instructions system CVE-2026-12345'
    supplied['facts']['functions'][0]['name'] = label
    result = binary.collect_binary_evidence(with_report(supplied))
    assert result['status'] == 'completed'
    assert result['artifacts'][0]['facts']['functions'][0]['name'] == label
    assert result['runtime_verified'] is False and 'findings' not in result


def test_envelope_report_binary_and_inventory_limits(monkeypatch):
    monkeypatch.setattr(binary, 'MAX_ENVELOPE_BYTES', 10)
    assert binary.collect_binary_evidence(with_report())['status'] == 'unavailable'
    monkeypatch.setattr(binary, 'MAX_ENVELOPE_BYTES', 2 * 1024 * 1024)
    monkeypatch.setattr(binary, 'MAX_REPORT_BYTES', 10)
    value = binary.collect_binary_evidence(with_report())
    assert value['artifacts'][0]['reason'] == 'report_limit'
    monkeypatch.setattr(binary, 'MAX_REPORT_BYTES', 1024 * 1024)
    monkeypatch.setattr(binary, 'MAX_BINARY_BYTES', 32)
    assert binary.collect_binary_evidence(with_report())['artifacts'][0]['reason'] == 'binary_limit'
    monkeypatch.setattr(binary, 'MAX_BINARY_BYTES', 10 * 1024 * 1024)
    monkeypatch.setattr(binary, 'MAX_ARTIFACTS', 2)
    value = binary.collect_binary_evidence(archive({str(i): elf() for i in range(4)}))
    assert len(value['artifacts']) == 2 and value['artifacts_omitted'] == 2
    assert value['status'] == 'unavailable' and 'binary_artifact_limit' in value['limitations']


def test_attachment_preserves_project_bytes_and_is_deterministic():
    original = archive({'bin/program': elf(), 'app.py': b'print(1)'})
    first = binary.attach_binary_reports(original, [('bin/program', encoded(report()))])
    second = binary.attach_binary_reports(original, [('bin/program', encoded(report()))])
    assert first == second
    assert binary.collect_binary_evidence(first)['status'] == 'completed'
    with zipfile.ZipFile(io.BytesIO(first)) as zipped:
        assert zipped.read('bin/program') == elf()
        assert zipped.read('app.py') == b'print(1)'
    assert binary.attach_binary_reports(original, []) == original
    with pytest.raises(ValueError, match='manifest_exists'):
        binary.attach_binary_reports(first, [('bin/program', encoded(report()))])


def test_report_for_omitted_binary_does_not_double_count_inventory_limit(monkeypatch):
    monkeypatch.setattr(binary, 'MAX_ARTIFACTS', 2)
    raw = binary.attach_binary_reports(archive({name: elf() for name in ('a', 'b', 'c')}),
                                       [('c', encoded(report()))])
    result = binary.collect_binary_evidence(raw)
    assert len(result['artifacts']) == 2 and result['artifacts_omitted'] == 1


def test_corrupted_evidence_payload_does_not_break_source_scanning():
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_STORED) as zipped:
        zipped.writestr('bin/program', elf())
        zipped.writestr(binary.ENVELOPE_PATH, encoded({'version': 1, 'artifacts': []}))
    data = output.getvalue().replace(b'{"version": 1, "artifacts": []}', b'{"version": 9, "artifacts": []}')
    result = binary.collect_binary_evidence(data)
    assert result['status'] == 'unavailable'
    assert 'invalid_binary_evidence_manifest' in result['limitations']


def test_attachment_rejects_duplicates_missing_invalid_paths_and_limits(monkeypatch):
    raw = archive({'bin/program': elf()})
    item = ('bin/program', encoded(report()))
    for entries, reason in (([item, item], 'duplicate_artifact_path'),
                            ([('../program', item[1])], 'invalid_artifact_path'),
                            ([('missing', item[1])], 'artifact_missing')):
        with pytest.raises(ValueError, match=reason):
            binary.attach_binary_reports(raw, entries)
    with pytest.raises(ValueError, match='binary_report_limit'):
        binary.attach_binary_reports(raw, [item] * 9)
    monkeypatch.setattr(binary, 'MAX_ENVELOPE_BYTES', 10)
    with pytest.raises(ValueError, match='evidence_manifest_limit'):
        binary.attach_binary_reports(raw, [item])


def test_invalid_zip_and_duplicate_archive_paths_keep_upload_rejection_contract():
    with pytest.raises(ArchiveValidationError, match='not_a_zip'):
        binary.collect_binary_evidence(b'not a zip')
    output = io.BytesIO()
    with pytest.warns(UserWarning), zipfile.ZipFile(output, 'w') as zipped:
        zipped.writestr('bin/program', elf())
        zipped.writestr('bin/program', elf())
    with pytest.raises(ArchiveValidationError, match='duplicate_path'):
        binary.collect_binary_evidence(output.getvalue())


@pytest.mark.parametrize('alias', ['bin\\program', 'bin/./program', 'bin//program'])
def test_normalized_archive_path_collisions_cannot_replace_artifact_bytes(alias):
    data = archive({'bin/program': elf(), alias: elf(b'changed')})
    with pytest.raises(ArchiveValidationError, match='duplicate_path'):
        binary.collect_binary_evidence(data)
    with pytest.raises(ArchiveValidationError, match='duplicate_path'):
        binary.attach_binary_reports(data, [('bin/program', encoded(report()))])


def test_normalized_evidence_path_collision_cannot_replace_manifest():
    data = archive({binary.ENVELOPE_PATH: b'{}', '.drydock-evidence/./ghidra.json': b'{}'})
    with pytest.raises(ArchiveValidationError, match='duplicate_path'):
        binary.collect_binary_evidence(data)


def test_invalid_one_report_does_not_discard_other_consistent_facts():
    good = report()
    bad = deepcopy(good)
    bad['provider']['exporter_sha256'] = '0' * 64
    data = binary.attach_binary_reports(archive({'a.elf': elf(), 'b.elf': elf()}),
                                       [('a.elf', encoded(good)), ('b.elf', encoded(bad))])
    value = binary.collect_binary_evidence(data)
    assert value['status'] == 'partial'
    assert [item['status'] for item in value['artifacts']] == ['completed', 'unavailable']

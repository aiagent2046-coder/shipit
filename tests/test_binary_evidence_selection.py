"""Imported binary observations never become project source or model input."""
import hashlib
import io
import zipfile

import pytest

from app.scan import binary_evidence as binary
from tests.test_binary_evidence import archive, elf, encoded, report


@pytest.mark.parametrize('location', ['root', 'wrapper', 'root-with-directory'])
def test_attached_envelope_preserves_wrapped_project_root_and_source_verdict(location):
    from app.ingest.stack_detect import Stack, detect_stack
    from app.scan.checks import archive_root, _strip_root
    from app.scan.error_boundary import _norm
    from app.scan.static import run_static_scan

    prefix = 'project-commit/'
    files = {
        prefix + 'package.json': b'{"dependencies":{"react":"18.3.1","vite":"5.4.0"}}',
        prefix + '.gitignore': b'.env\n',
        prefix + 'src/main.tsx': b'import {createRoot} from "react-dom/client"; createRoot(root).render(<App/>);',
        prefix + 'bin/program': elf(),
    }
    baseline = archive(files)
    if location == 'wrapper':
        files[prefix + binary.ENVELOPE_PATH] = encoded({'version': 1, 'artifacts': [
            {'path': 'bin/program', 'report': report()}]})
        imported = archive(files)
    else:
        if location == 'root-with-directory':
            files['.drydock-evidence/'] = b''
        imported = binary.attach_binary_reports(archive(files), [(prefix + 'bin/program', encoded(report()))])
    before = run_static_scan(io.BytesIO(baseline), allow_missing_native=True)
    after = run_static_scan(io.BytesIO(imported), allow_missing_native=True)
    assert after['findings'] == before['findings']
    assert after['score'] == before['score']
    assert detect_stack(io.BytesIO(baseline)) == detect_stack(io.BytesIO(imported)) == Stack.VITE_REACT
    assert binary.collect_binary_evidence(imported)['status'] == 'completed'
    with zipfile.ZipFile(io.BytesIO(imported)) as zipped:
        assert archive_root(zipped.namelist()) == prefix
        expected = sorted(path[len(prefix):] for path in files if path.startswith(prefix)
                          and path != prefix + binary.ENVELOPE_PATH)
        assert sorted(_strip_root(zipped.namelist())) == expected
        assert sorted(_norm(zipped.namelist())) == expected


def test_source_root_filter_keeps_neighbouring_files_and_their_parent_directory():
    from app.scan.checks import archive_root
    from app.scan.file_scope import source_archive_names

    names = ['project/app.py', '.drydock-evidence/', binary.ENVELOPE_PATH, '.drydock-evidence/config.json']
    assert source_archive_names(names) == [name for name in names if name != binary.ENVELOPE_PATH]
    assert archive_root(names) == ''


@pytest.mark.parametrize('prefix', ['', 'repository-commit/'])
def test_imported_secret_shaped_symbol_is_not_source_or_scored_finding(prefix):
    from app.scan.llm_scan import _iter_code_files, has_application_source, select_files
    from app.scan.source_snapshot import SourceSnapshot
    from app.scan.static import run_static_scan

    supplied = report()
    supplied['facts']['imports'][0]['name'] = 'AKIA' + 'ABCDEFGHIJKLMNOP'
    baseline = archive({prefix + 'bin/program': elf(), prefix + 'app.py': b'print("hello")'})
    path = prefix + binary.ENVELOPE_PATH
    envelope = encoded({'version': 1, 'artifacts': [{'path': 'bin/program', 'report': supplied}]})
    imported = archive({prefix + 'bin/program': elf(), prefix + 'app.py': b'print("hello")', path: envelope})
    before = run_static_scan(io.BytesIO(baseline), allow_missing_native=True)
    after = run_static_scan(io.BytesIO(imported), allow_missing_native=True)
    assert after['findings'] == before['findings']
    assert after['score'] == before['score']
    assert after['secrets_coverage']['exclusions']['binary_evidence'] == 1
    assert binary.collect_binary_evidence(imported)['status'] == 'completed'
    with zipfile.ZipFile(io.BytesIO(imported)) as zipped:
        hashes = {}
        selected = _iter_code_files(zipped, source_hashes=hashes)
        assert path not in dict(selected) and path not in hashes
    # Direct selection also enforces the boundary if a caller supplies raw file tuples.
    assert select_files([(path, 'auth password token ' + envelope.decode())], 'auth') == []
    assert not has_application_source([(path, envelope.decode())])
    snapshot = SourceSnapshot(imported, hashlib.sha256(imported).hexdigest())
    try:
        assert path not in snapshot._entries
        assert prefix + 'app.py' in snapshot._entries
    finally:
        snapshot.close()


@pytest.mark.parametrize('path', [
    '.drydock-evidence/config.json', 'repo/.drydock-evidence/config.json',
    'a/b/.drydock-evidence/ghidra.json', '.drydock-evidence/ghidra.json.backup',
])
def test_evidence_exclusion_does_not_hide_neighbouring_source_or_secrets(path):
    from app.scan.llm_scan import _iter_code_files, select_files
    from app.scan.secrets import scan_secrets

    content = b'{"password":"' + b'AKIA' + b'ABCDEFGHIJKLMNOP"}'
    data = archive({path: content})
    findings = list(scan_secrets(io.BytesIO(data)))
    assert any(finding.file == path for finding in findings)
    if path.endswith('.json'):
        with zipfile.ZipFile(io.BytesIO(data)) as zipped:
            assert path in dict(_iter_code_files(zipped))
        assert path in dict(select_files([(path, content.decode())], 'auth'))

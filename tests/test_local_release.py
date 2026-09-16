"""Release archives preserve provenance and reject broken offline installations."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location('local_archiver', ROOT / 'scripts/archive_local_package.py')
archiver = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(archiver)
REVISION = 'a' * 40
NAME = 'drydock-local-v2026.09.16-2-linux-x86_64-py3.12'


@pytest.fixture
def bundle(tmp_path):
    root = tmp_path / 'bundle'
    root.mkdir()
    wheels = root / 'wheelhouse'
    wheels.mkdir()
    versions = {'drydock-local': '0.1.0', 'pyyaml': '6.0.3', 'pglast': '8.4',
                'tree-sitter': '0.26.0', 'tree-sitter-typescript': '0.23.2'}
    info = {'source_revision': REVISION, 'source_dirty': False, 'package_version': '0.1.0',
            'dependencies': [f'{name}=={version}' for name, version in versions.items() if name != 'drydock-local']}
    (root / 'build-info.json').write_text(json.dumps(info))
    lock = []
    for name, version in versions.items():
        filename = name.replace('-', '_') + f'-{version}-py3-none-any.whl'
        wheel = wheels / filename
        with zipfile.ZipFile(wheel, 'w') as archive:
            archive.writestr('drydock_local/build-info.json' if name == 'drydock-local' else 'module.py',
                             json.dumps(info) if name == 'drydock-local' else 'pass\n')
        digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
        # Exercise the multiline format and multiple approved platform hashes.
        lock.append(f'{name}=={version} \\\n    --hash=sha256:{digest} \\\n    --hash=sha256:{"0" * 64}\n')
    (root / 'install.txt').write_text(''.join(lock))
    (root / 'install.sh').write_text('#!/bin/sh\nexit 0\n')
    (root / 'README.md').write_text('Install offline.\n')
    with tarfile.open(root / 'drydock-local-source.tar.gz', 'w:gz') as archive:
        source = b'print("source")\n'
        entry = tarfile.TarInfo('drydock-local-0.1.0/module.py')
        entry.size = len(source)
        archive.addfile(entry, io.BytesIO(source))
    (root / 'source').mkdir()
    (root / 'source/private-build-scratch').write_text('must not ship')
    (root / 'build-requirements.txt').write_text('must not ship')
    return root


def publish(bundle, tmp_path, **kwargs):
    return archiver.archive_bundle(bundle, tmp_path / 'release', kwargs.get('name', NAME),
                                   kwargs.get('revision', REVISION))


def test_release_roundtrip_is_complete_checksummed_and_preserves_input(bundle, tmp_path):
    original = {p.relative_to(bundle): p.read_bytes() for p in bundle.rglob('*') if p.is_file()}
    archive, checksum = publish(bundle, tmp_path)
    assert checksum.read_text() == f'{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n'
    with tarfile.open(archive) as packed:
        members = packed.getmembers()
        assert len(members) == 10
        for member in members:
            relative = Path(member.name).relative_to(NAME)
            assert member.isfile()
            assert packed.extractfile(member).read() == original[relative]
            assert member.mode == (0o755 if relative == Path('install.sh') else 0o644)
        assert {m.name for m in members} == {
            NAME + '/' + name for name in archiver.FILES
        } | {NAME + '/wheelhouse/' + p.name for p in (bundle / 'wheelhouse').iterdir()}
    assert {p.relative_to(bundle): p.read_bytes() for p in bundle.rglob('*') if p.is_file()} == original
    with pytest.raises(FileExistsError):
        publish(bundle, tmp_path)


@pytest.mark.parametrize('target', ['install.sh', 'build-info.json', 'wheelhouse',
                                  'wheelhouse/pyyaml-6.0.3-py3-none-any.whl'])
def test_symlinks_are_never_followed(bundle, tmp_path, target):
    path = bundle / target
    external = tmp_path / 'external'
    path.rename(external)
    path.symlink_to(external, target_is_directory=external.is_dir())
    with pytest.raises(ValueError, match='symlink'):
        publish(bundle, tmp_path)
    assert not (tmp_path / 'release').exists()


@pytest.mark.parametrize('target', ['README.md', 'drydock-local-source.tar.gz',
                                  'wheelhouse/pglast-8.4-py3-none-any.whl'])
def test_missing_installation_inputs_fail_before_output(bundle, tmp_path, target):
    (bundle / target).unlink()
    with pytest.raises(ValueError, match='Missing|Incomplete'):
        publish(bundle, tmp_path)
    assert not (tmp_path / 'release').exists()


def test_wheel_corruption_cannot_be_published(bundle, tmp_path):
    wheel = next((bundle / 'wheelhouse').glob('pglast*'))
    wheel.write_bytes(wheel.read_bytes() + b'corrupted')
    with pytest.raises(ValueError, match='checksum'):
        publish(bundle, tmp_path)


@pytest.mark.parametrize('field,value', [('source_revision', 'b' * 40), ('source_dirty', True),
                                       ('source_dirty', 'false'), ('package_version', '9.0')])
def test_wrong_build_provenance_is_rejected(bundle, tmp_path, field, value):
    info = json.loads((bundle / 'build-info.json').read_text())
    info[field] = value
    (bundle / 'build-info.json').write_text(json.dumps(info))
    with pytest.raises(ValueError, match='provenance'):
        publish(bundle, tmp_path)


def test_detached_wheel_metadata_is_rejected_even_with_updated_external_revision(bundle, tmp_path):
    info = json.loads((bundle / 'build-info.json').read_text())
    info['source_revision'] = 'b' * 40
    (bundle / 'build-info.json').write_text(json.dumps(info))
    with pytest.raises(ValueError, match='Project wheel does not match'):
        publish(bundle, tmp_path, revision='b' * 40)


@pytest.mark.parametrize('name', ['../escape', 'drydock-local-../../escape', 'drydock-local-foo/bar',
                                'drydock-local-foo\nbar', 'drydock-local-..'])
def test_unsafe_archive_names_are_rejected(bundle, tmp_path, name):
    with pytest.raises(ValueError, match='Unsafe'):
        publish(bundle, tmp_path, name=name)


def test_nonwheel_and_missing_lock_dependencies_are_rejected(bundle, tmp_path):
    extra = bundle / 'wheelhouse/run.sh'
    extra.write_text('unwanted')
    with pytest.raises(ValueError, match='Unexpected wheelhouse'):
        publish(bundle, tmp_path)
    extra.unlink()
    lock = bundle / 'install.txt'
    lock.write_text('drydock-local==0.1.0 --hash=sha256:' + 'a' * 64 + '\n')
    with pytest.raises(ValueError, match='exactly the project'):
        publish(bundle, tmp_path)


def test_existing_checksum_is_not_overwritten(bundle, tmp_path):
    out = tmp_path / 'release'
    out.mkdir()
    checksum = out / (NAME + '.tar.gz.sha256')
    checksum.write_text('existing checksum')
    with pytest.raises(FileExistsError):
        publish(bundle, tmp_path)
    assert checksum.read_text() == 'existing checksum'
    assert not (out / (NAME + '.tar.gz')).exists()

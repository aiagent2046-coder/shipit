"""Resolved-version and provenance boundaries for the offline lock readers."""
import io
import json
import zipfile

import pytest
import yaml

from app.sca.lockfiles import collect_dependency_inventory
from app.scan.cve_match import match_archive
from tests.test_browser_cve import CATALOG


def archive(files):
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w') as z:
        for path, body in files.items():
            z.writestr(path, body)
    return data.getvalue()


def pnpm(packages=None, importers=None, snapshots=None):
    packages = packages if packages is not None else {'lodash@4.17.23': {'resolution': {'integrity': 'sha512-example'}}}
    return yaml.safe_dump({'lockfileVersion': '9.0', 'importers': importers or {'.': {
        'dependencies': {'lodash': {'specifier': '^4', 'version': '4.17.23'}}}},
        'packages': packages,
        'snapshots': snapshots if snapshots is not None else {key: {} for key in packages}})


def uv(version='1.0.12', source='{ registry = "https://pypi.org/simple" }'):
    return f'''version = 1
revision = 3
[[package]]
name = "project"
version = "0.1.0"
source = {{ virtual = "." }}
dependencies = [{{name = "LangFlow"}}]
[[package]]
name = "LangFlow"
version = "{version}"
source = {source}
'''


def test_pnpm_aliases_scopes_nested_peers_and_multiple_importers():
    packages = {key: {'resolution': {'integrity': 'sha512-example'}} for key in (
        'lodash@4.17.23', 'lodash@4.18.0', '@scope/name@1.2.3', 'react@18.0.0')}
    text = pnpm(packages, {
        '.': {'dependencies': {'alias': {'specifier': 'npm:lodash@^4', 'version': 'lodash@4.17.23'}}},
        'apps/web': {'devDependencies': {'@scope/name': {'specifier': '^1', 'version': '1.2.3(react@18.0.0)'}}},
    }, {
        'lodash@4.17.23': {}, 'lodash@4.18.0': {}, 'react@18.0.0': {},
        '@scope/name@1.2.3(react@18.0.0(nested@1.0.0))': {'dependencies': {'alias': 'lodash@4.18.0'}},
        '@scope/name@1.2.3(react@18.0.0)': {},
    })
    inventory = collect_dependency_inventory(archive({'pnpm-lock.yaml': text}))
    assert inventory.incomplete_manifests == {}
    assert inventory.found == 4  # Peer variants do not duplicate package/version.
    assert {(d.name, d.version) for d in inventory.dependencies if d.direct} == {
        ('lodash', '4.17.23'), ('@scope/name', '1.2.3')}
    assert all(d.development is None for d in inventory.dependencies)
    assert not any(d.name == 'alias' for d in inventory.dependencies)


@pytest.mark.parametrize('reference', ['^4.17.0', 'link:../local', 'workspace:*',
                                     'file:../local.tgz', 'https://example.org/a.tgz',
                                     'git+https://example.org/a', '4.17.23(peer@1.0.0',
                                     '4.17.23(peer@1.0.0)extra', '4.17.24'])
def test_pnpm_unresolved_references_are_not_invented(reference):
    text = pnpm(importers={'.': {'dependencies': {'lodash': {'version': reference}}}})
    inv = collect_dependency_inventory(archive({'pnpm-lock.yaml': text}))
    assert inv.incomplete_manifests == {'pnpm-lock.yaml': 'unresolved'}
    assert [(d.name, d.version) for d in inv.dependencies] == [('lodash', '4.17.23')]


@pytest.mark.parametrize('resolution', [{'tarball': 'https://example.org/lodash.tgz'},
                                      {'integrity': 'hash', 'tarball': 'https://example.org/lodash.tgz'},
                                      {'type': 'directory', 'directory': '../local'},
                                      {'repo': 'https://example.org/lodash', 'commit': 'abc'}, {}, None])
def test_pnpm_non_registry_resolution_is_not_a_public_package(resolution):
    text = pnpm({'lodash@4.17.23': {'resolution': resolution}})
    inv = collect_dependency_inventory(archive({'pnpm-lock.yaml': text}))
    assert inv.dependencies == []
    assert inv.incomplete_manifests == {'pnpm-lock.yaml': 'unresolved'}


@pytest.mark.parametrize('text,reason', [
    ('lockfileVersion: 6.0\n', 'unsupported'),
    ('lockfileVersion: 10.0\n', 'unsupported'),
    ('lockfileVersion: 9.0\nimporters: []\n', 'malformed'),
    ('lockfileVersion: 9.0\nlockfileVersion: 6.0\n', 'malformed'),
    ('lockfileVersion: 9.0\npackages: &a [*a]\n', 'malformed'),
    ('!!python/object/apply:os.system ["false"]', 'malformed'),
    ('packages: {a: [', 'malformed'),
    ('lockfileVersion: 9.0\nimporters: {}\nx: ' + '[' * 100 + '0' + ']' * 100, 'parser_limit'),
])
def test_pnpm_malformed_or_unsupported_is_explicit_and_isolated(text, reason):
    inv = collect_dependency_inventory(archive({'pnpm-lock.yaml': text, 'requirements.txt': 'flask==3.0.0'}))
    assert inv.incomplete_manifests == {'pnpm-lock.yaml': reason}
    assert [(d.name, d.version) for d in inv.dependencies] == [('flask', '3.0.0')]


def test_pnpm_node_budget(monkeypatch):
    from app.sca import resolved_locks
    monkeypatch.setattr(resolved_locks, 'MAX_YAML_NODES', 5)
    inv = collect_dependency_inventory(archive({'pnpm-lock.yaml': pnpm()}))
    assert inv.incomplete_manifests == {'pnpm-lock.yaml': 'parser_limit'}


def test_pnpm_incomplete_snapshots_preserve_gap():
    inv = collect_dependency_inventory(archive({'pnpm-lock.yaml': pnpm(snapshots={})}))
    assert inv.found == 1
    assert inv.incomplete_manifests == {'pnpm-lock.yaml': 'unresolved'}


def test_uv_public_pins_normalization_markers_and_multiple_versions():
    text = uv() + '''
[[package]]
name = "LangFlow"
version = "1.0.13"
source = { registry = "https://pypi.org/simple/" }
resolution-markers = ["python_version >= '3.13'"]
[[package]]
name = "Foo_Bar"
version = "1.2rc1"
source = { registry = "https://pypi.org/simple" }
'''
    inv = collect_dependency_inventory(archive({'uv.lock': text}))
    assert inv.incomplete_manifests == {}
    assert {(d.name, d.version) for d in inv.dependencies} == {
        ('langflow', '1.0.12'), ('langflow', '1.0.13'), ('foo-bar', '1.2rc1')}
    assert {d.name for d in inv.dependencies if d.direct} == {'langflow'}
    assert all(d.development is None for d in inv.dependencies)


def test_uv_reference_budget_retains_pins_but_not_complete_coverage(monkeypatch):
    from app.sca import resolved_locks
    monkeypatch.setattr(resolved_locks, 'MAX_UV_REFERENCE_CHECKS', 1)
    inv = collect_dependency_inventory(archive({'uv.lock': uv()}))
    assert inv.found == 1
    assert inv.incomplete_manifests == {'uv.lock': 'parser_limit'}


@pytest.mark.parametrize('source', ['{ registry = "https://private.example/simple" }',
    '{ git = "https://example.org/langflow?rev=abc" }', '{ url = "https://example.org/langflow.whl" }',
    '{ editable = "../langflow" }', '{ directory = "../langflow" }',
    '{ registry = "https://pypi.org/simple", git = "https://example.org/fork" }', '{}', '"bad"'])
def test_uv_non_public_sources_are_not_matched_by_name(source):
    inv = collect_dependency_inventory(archive({'uv.lock': uv(source=source)}))
    assert inv.dependencies == []
    assert inv.incomplete_manifests == {'uv.lock': 'unresolved'}


@pytest.mark.parametrize('text,reason', [
    ('version = 2\n', 'unsupported'), ('version = true\n', 'unsupported'),
    ('version = 1\nrevision = 4\n', 'unsupported'),
    ('version = 1\npackage = "bad"', 'malformed'),
    (uv().replace('version = "1.0.12"', 'version = ">=1"'), 'unresolved'),
    (uv().replace('name = "LangFlow"\nversion', 'name = ""\nversion'), 'unresolved'),
    (uv().replace('dependencies = [{name = "LangFlow"}]', 'dependencies = [{name = "missing"}]'), 'unresolved'),
    ('version = 1\nversion = 1', 'malformed'),
])
def test_uv_coverage_gaps(text, reason):
    inv = collect_dependency_inventory(archive({'uv.lock': text}))
    assert inv.incomplete_manifests == {'uv.lock': reason}


def test_browser_cve_reads_both_companion_locks():
    result = match_archive(archive({
        'project/frontend/pnpm-lock.yaml': pnpm(),
        'project/frontend/package.json': json.dumps({'dependencies': {'lodash': '^4'}}),
        'project/backend/uv.lock': uv(),
        'project/backend/pyproject.toml': '[project]\ndependencies = ["langflow>=1"]',
    }), CATALOG)
    coverage = result['coverage']
    assert coverage['dependencies_found'] == coverage['dependencies_checked'] == 2
    assert coverage['incomplete_manifests'] == {}
    assert {'CVE-2026-2950', 'CVE-2024-7297'} <= {
        f['claim_evidence']['cve_id'] for f in result['findings']}
    assert {f['file'] for f in result['findings']} == {
        'project/frontend/pnpm-lock.yaml', 'project/backend/uv.lock'}


def test_new_formats_share_existing_limits_and_vendor_exclusions(monkeypatch):
    from app.sca import lockfiles
    monkeypatch.setattr(lockfiles, 'MAX_DEPENDENCIES', 1)
    inv = collect_dependency_inventory(archive({'pnpm-lock.yaml': pnpm(), 'uv.lock': uv(),
        'node_modules/vendor/uv.lock': uv('9.9.9')}))
    assert inv.found == 2
    assert len(inv.dependencies) == 1
    assert set(inv.manifests) == {'pnpm-lock.yaml', 'uv.lock'}
    monkeypatch.setattr(lockfiles, 'MAX_LOCKFILE_BYTES', 10)
    inv = collect_dependency_inventory(archive({'pnpm-lock.yaml': pnpm(), 'uv.lock': uv()}))
    assert inv.incomplete_manifests == {'pnpm-lock.yaml': 'oversized', 'uv.lock': 'oversized'}

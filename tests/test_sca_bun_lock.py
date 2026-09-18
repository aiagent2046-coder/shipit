"""Bun identity, provenance, completeness and parser-budget boundaries."""
import json

import pytest

from app.sca import bun_lock, lockfiles
from app.sca.lockfiles import collect_dependency_inventory, unusable_lockfiles
from app.scan.cve_match import match_archive
from tests.bun_fixtures import GSTACK_ADVISORIES, archive, bun, gstack_project, registry
from tests.test_browser_cve import CATALOG


def inventory(text, **other):
    return collect_dependency_inventory(archive({'bun.lock': text, **other}))


def test_nested_scopes_aliases_workspaces_and_occurrences():
    text = bun({
        'alias': registry('@scope/real', '1.2.3'),
        '@scope/parent': registry('@scope/parent', '2.0.0', dependencies={'alias': '^1'}),
        '@scope/parent/alias': registry('@scope/real', '1.4.0'),
        '@project/web': ['@project/web@workspace:apps/web'],
        '@project/web/alias': registry('@scope/real', '1.5.0'),
    }, {'': {'dependencies': {'alias': 'npm:@scope/real@^1', '@project/web': 'workspace:*'}},
        'apps/web': {'name': '@project/web', 'devDependencies': {'alias': 'npm:@scope/real@^1'}}})
    inv = collect_dependency_inventory(archive({'bun.lock': text, 'apps/api/bun.lock': text}))
    assert inv.incomplete_manifests == {}
    assert inv.found == 4
    assert {(d.name, d.version) for d in inv.dependencies if d.direct} == {
        ('@scope/real', '1.2.3'), ('@scope/real', '1.5.0')}
    assert all(d.development is None for d in inv.dependencies)
    assert all(len(d.occurrences) == 2 for d in inv.dependencies)


def test_jsonc_preserves_urls_escapes_comment_markers_and_trailing_commas():
    data = json.loads(bun())
    data['note'] = 'https://example.org/a/*b*/,] quote=" backslash=\\'
    text = '/* before */\n' + json.dumps(data, indent=2).replace('\n}', ', // end\n}')
    assert bun_lock._jsonc(text) == data
    assert inventory(text).incomplete_manifests == {}


@pytest.mark.parametrize('text,reason', [
    ('{}', 'unsupported'), (bun().replace('"lockfileVersion": 1', '"lockfileVersion": true'), 'unsupported'),
    (bun().replace('"lockfileVersion": 1', '"lockfileVersion": 2'), 'unsupported'),
    ('[]', 'malformed'), ('{"lockfileVersion":1,"workspaces":{},"packages":{}}', 'malformed'),
    (bun().replace('"packages": {', '"packages": {}, "packages": {'), 'malformed'),
    (bun().replace('"workspaces": {', '"x": NaN, "workspaces": {'), 'malformed'),
    (bun() + '/* unfinished', 'malformed'), (bun() + '"unfinished', 'malformed'),
    (bun().replace('"workspaces": {', '"x": [,], "workspaces": {'), 'malformed'),
    (bun().replace('"workspaces": {', '"x": [1,,], "workspaces": {'), 'malformed'),
    ('{"x":' + '[' * 65 + '0' + ']' * 65 + '}', 'parser_limit'),
    (b'\xff\x00', 'malformed'),
])
def test_invalid_inputs_keep_an_independent_lock(text, reason):
    inv = inventory(text, **{'requirements.txt': 'flask==3.0.0'})
    assert inv.incomplete_manifests == {'bun.lock': reason}
    assert [(d.name, d.version) for d in inv.dependencies] == [('flask', '3.0.0')]


@pytest.mark.parametrize('row', [
    ['lodash@git+https://example.org/fork#abc', {}, 'tag'],
    ['lodash@github:owner/repo#abc', {}, 'tag'], ['lodash@file:../local', {}],
    ['lodash@link:../local', {}], ['lodash@https://example.org/fork.tgz', {}, 'sha512-fixture'],
    ['lodash@workspace:missing'], ['lodash@^4.17.0', '', {}, 'sha512-fixture'],
    ['lodash@4.17.23', 'https://registry.npmjs.org.evil.example/a.tgz', {}, 'sha512-fixture'],
    ['lodash@4.17.23', 'https://private.example/a.tgz', {}, 'sha512-fixture'],
    ['lodash@4.17.23', '', {'bundled': True}, 'sha512-fixture'],
    ['lodash@4.17.23', '', {}, ''], ['lodash@4.17.23', '', [], 'sha512-fixture'],
    [], {}, None,
])
def test_non_registry_or_incomplete_identity_is_never_a_public_match(row):
    inv = inventory(bun({'lodash': row, 'safe': registry('safe', '1.0.0')}))
    assert [(d.name, d.version) for d in inv.dependencies] == [('safe', '1.0.0')]
    assert inv.incomplete_manifests == {'bun.lock': 'unresolved'}


@pytest.mark.parametrize('field', ['dependencies', 'optionalDependencies', 'devDependencies', 'peerDependencies'])
def test_missing_workspace_reference_is_partial(field):
    inv = inventory(bun({}, {'': {field: {'missing': '^1'}}}))
    assert inv.found == 0 and inv.incomplete_manifests == {'bun.lock': 'unresolved'}


def test_missing_transitive_and_malformed_reference_are_partial():
    text = bun({'parent': registry('parent', '1.0.0', dependencies={'missing': '^1'}),
                'child': registry('child', '1.0.0', optionalDependencies=[])})
    inv = inventory(text)
    assert inv.found == 2 and inv.incomplete_manifests == {'bun.lock': 'unresolved'}


def test_optional_peers_and_peers_elsewhere_in_tree_do_not_invent_pins():
    text = bun({
        'plugin': registry('plugin', '1.0.0', peerDependencies={'react': '^18', 'optional': '^1'},
                           optionalPeers=['optional']),
        'other/react': registry('react', '18.0.0'),
    })
    inv = inventory(text)
    assert inv.found == 2 and inv.incomplete_manifests == {}
    assert all(d.development is None for d in inv.dependencies)


@pytest.mark.parametrize('text', ['{broken', bun().replace('"lockfileVersion": 1', '"lockfileVersion": 3')])
def test_shadowed_binary_does_not_hide_a_text_lock_failure(text):
    result = match_archive(archive({'bun.lockb': b'binary', 'bun.lock': text, 'package.json': '{}'}), CATALOG)
    assert result['coverage']['status'] == 'partial'
    assert set(result['coverage']['incomplete_manifests']) == {'bun.lock'}


@pytest.mark.parametrize('budget', ['MAX_JSON_TOKENS', 'MAX_REFERENCE_CHECKS'])
def test_parser_limits_are_visible(monkeypatch, budget):
    monkeypatch.setattr(bun_lock, budget, 0)
    inv = inventory(bun(workspaces={'': {'dependencies': {'lodash': '^4'}}}))
    assert inv.incomplete_manifests == {'bun.lock': 'parser_limit'}


def test_reference_path_width_is_bounded_before_lookup():
    inv = inventory(bun({'x' * 4097: registry('safe', '1.0.0')}))
    assert inv.dependencies == []
    assert inv.incomplete_manifests == {'bun.lock': 'parser_limit'}


@pytest.mark.parametrize('bad_key', ['/'.join(['parent'] * 65), 'x' * 4097])
@pytest.mark.parametrize('pin_first', [False, True])
def test_one_path_limit_preserves_independent_cve_pins_and_stays_visible(bad_key, pin_first):
    entries = [(bad_key, registry('unsupported-path', '1.0.0')),
               ('fast-uri', registry('fast-uri', '3.1.6'))]
    if pin_first:
        entries.reverse()
    # Later malformed rows must not overwrite the more informative limit.
    entries.append(('malformed', []))
    data = archive({'bun.lock': bun(dict(entries))})
    inv = collect_dependency_inventory(data)
    assert [(d.name, d.version) for d in inv.dependencies] == [('fast-uri', '3.1.6')]
    assert inv.incomplete_manifests == {'bun.lock': 'parser_limit'}
    result = match_archive(data, CATALOG)
    assert result['coverage']['dependencies_checked'] == 1
    assert result['coverage']['incomplete_manifests'] == {'bun.lock': 'parser_limit'}
    assert {f['claim_evidence']['advisory_id'] for f in result['findings']} >= {
        'CVE-2026-84292', 'CVE-2026-84394', 'CVE-2026-86472'}


def test_implicit_workspace_bindings_cover_root_and_workspace_references():
    text = bun({
        'lodash': registry('lodash', '4.17.23'),
        '@project/app/lodash': registry('lodash', '3.10.1'),
    }, {
        '': {'dependencies': {'@project/app': 'workspace:apps/app'}},
        'apps/app': {'name': '@project/app', 'dependencies': {
            'lib': 'workspace:packages/lib', 'lodash': '^3'}},
        'packages/lib': {'name': 'lib', 'dependencies': {'lodash': '^4'}},
    })
    exported = {}
    pins = []
    assert bun_lock.bun_packages('bun.lock', text, pins, workspace_paths=exported) is None
    assert exported == {'apps/app': '@project/app', 'packages/lib': 'lib'}
    assert {(d.name, d.version, d.direct) for d in pins} == {
        ('lodash', '4.17.23', True), ('lodash', '3.10.1', True)}
    assert inventory(text).incomplete_manifests == {}


@pytest.mark.parametrize('packages', [
    {}, {'app': ['app@workspace:apps/first']}, {'app': registry('app', '1.0.0')},
])
def test_duplicate_workspace_names_are_not_resolvable_or_exported(packages):
    text = bun({'safe': registry('safe', '1.0.0'), **packages}, {
        '': {'dependencies': {'app': 'workspace:*'}},
        'apps/first': {'name': 'app'}, 'apps/second': {'name': 'app'},
    })
    exported = {}
    pins = []
    assert bun_lock.bun_packages('bun.lock', text, pins, workspace_paths=exported) == 'unresolved'
    assert exported == {}
    assert [(d.name, d.version) for d in pins] == [('safe', '1.0.0')]


def test_registry_collision_cannot_replace_a_workspace_but_nested_copy_survives():
    text = bun({
        'app': registry('app', '1.0.0'),
        'parent/app': registry('app', '2.0.0'),
    }, {'': {'dependencies': {'app': 'workspace:*'}}, 'apps/app': {'name': 'app'}})
    exported = {}
    pins = []
    assert bun_lock.bun_packages('bun.lock', text, pins, workspace_paths=exported) == 'unresolved'
    assert exported == {}
    assert [(d.name, d.version, d.direct) for d in pins] == [('app', '2.0.0', False)]


@pytest.mark.parametrize('path', [
    '.', '..', './app', 'apps/../app', 'apps//app', 'apps/app/', '/apps/app',
    'apps\\app', 'apps/\x00app', 'C:/apps/app', 'C:apps/app',
])
def test_noncanonical_workspace_directories_never_establish_manifest_coverage(path):
    text = bun({'safe': registry('safe', '1.0.0')}, {'': {}, path: {'name': 'app'}})
    exported = {}
    pins = []
    assert bun_lock.bun_packages('bun.lock', text, pins, workspace_paths=exported) == 'unresolved'
    assert exported == {}
    assert [(d.name, d.version) for d in pins] == [('safe', '1.0.0')]


@pytest.mark.parametrize('workspace', [[], {'name': []}, {'name': '.'}, {'name': '..'}])
def test_invalid_workspace_metadata_is_partial_without_a_crash(workspace):
    text = bun({}, {'': {}, 'apps/app': workspace})
    exported = {}
    assert bun_lock.bun_packages('bun.lock', text, [], workspace_paths=exported) == 'unresolved'
    assert exported == {}


def test_partial_lock_does_not_export_even_individually_valid_workspace_paths():
    text = bun({}, {'': {}, 'apps/app': {'name': 'app', 'dependencies': {'missing': '^1'}}})
    exported = {'existing': 'evidence-from-another-lock'}
    assert bun_lock.bun_packages('bun.lock', text, [], workspace_paths=exported) == 'unresolved'
    assert exported == {'existing': 'evidence-from-another-lock'}


def test_shared_file_inventory_and_dependency_limits(monkeypatch):
    text = bun({'a': registry('a', '1.0.0'), 'b': registry('b', '2.0.0')})
    monkeypatch.setattr(lockfiles, 'MAX_LOCKFILES', 1)
    monkeypatch.setattr(lockfiles, 'MAX_DEPENDENCIES', 1)
    inv = collect_dependency_inventory(archive({
        'bun.lock': text, 'sub/bun.lock': text, 'node_modules/vendor/bun.lock': text,
        'tests/bun.lockb': b'binary', '.next/bun.lock': text,
    }))
    assert inv.manifests == ['bun.lock']
    assert inv.found == 2 and len(inv.dependencies) == 1
    assert inv.incomplete_manifests == {'sub/bun.lock': 'truncated'}
    assert len(inv.excluded_manifests) == 3
    monkeypatch.setattr(lockfiles, 'MAX_LOCKFILE_BYTES', 1)
    assert inventory(text).incomplete_manifests == {'bun.lock': 'oversized'}


def test_binary_bun_is_explicit_and_text_lock_takes_precedence():
    raw = archive({'package.json': '{}', 'bun.lockb': b'\x00binary'})
    coverage = match_archive(raw, CATALOG)['coverage']
    assert coverage['status'] == 'partial'
    assert coverage['incomplete_manifests'] == {'bun.lockb': 'unsupported'}
    assert coverage['manifest_gap_reason_counts'] == {'unsupported_bun_binary_lockfile': 1}
    assert unusable_lockfiles(raw) == ['bun.lockb']
    raw = archive({'package.json': '{}', 'bun.lockb': b'\x00binary', 'bun.lock': bun()})
    assert unusable_lockfiles(raw) == []
    assert match_archive(raw, CATALOG)['coverage']['incomplete_manifests'] == {}


@pytest.mark.parametrize('fixed', [False, True])
def test_gstack_nested_sdk_and_advisory_boundaries(fixed):
    result = match_archive(gstack_project(fixed), CATALOG)
    coverage = result['coverage']
    assert coverage['dependencies_found'] == coverage['dependencies_checked'] == 5
    assert coverage['incomplete_manifests'] == {}
    actual = {f['claim_evidence']['advisory_id'] for f in result['findings']}
    assert actual & GSTACK_ADVISORIES == (set() if fixed else GSTACK_ADVISORIES)
    if not fixed:
        sdk = next(f for f in result['findings'] if f['claim_evidence']['advisory_id'] == 'GHSA-p7fg-763f-g4gf')
        assert sdk['claim_evidence']['installed_version'] == '0.81.0'
        assert sdk['file'] == 'project/bun.lock'

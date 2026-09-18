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

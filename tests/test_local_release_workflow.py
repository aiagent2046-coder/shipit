"""Execute publication guards against real Git refs and a failing upload."""
import hashlib
import os
from pathlib import Path
import subprocess

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = yaml.safe_load((ROOT / '.github/workflows/release-local.yml').read_text())
TAG = 'v2026.09.16-1'


def git(root, *args):
    return subprocess.check_output(['git', *args], cwd=root, text=True).strip()


@pytest.fixture
def repository(tmp_path):
    git(tmp_path, 'init', '-q')
    git(tmp_path, 'config', 'user.name', 'Release test')
    git(tmp_path, 'config', 'user.email', 'test@example.invalid')
    git(tmp_path, 'commit', '--allow-empty', '-qm', 'reviewed')
    sha = git(tmp_path, 'rev-parse', 'HEAD')
    git(tmp_path, 'update-ref', 'refs/remotes/origin/main', sha)
    git(tmp_path, 'tag', TAG)
    return tmp_path, sha


def run_step(repository, job, **env):
    root, sha = repository
    step = next(s['run'] for s in WORKFLOW['jobs'][job]['steps'] if 'run' in s)
    return subprocess.run(['bash', '-c', step], cwd=root, capture_output=True, text=True,
                          env={**os.environ, 'TAG': TAG, 'SOURCE_SHA': sha,
                               'GITHUB_OUTPUT': str(root / 'output'), 'RUNNER_TEMP': str(root),
                               'GH_REPO': 'owner/repo', **env})


def test_existing_reviewed_tag_resolves_to_exact_commit(repository):
    root, sha = repository
    assert run_step(repository, 'validate').returncode == 0
    assert (root / 'output').read_text() == f'sha={sha}\n'


@pytest.mark.parametrize('tag', ['v2026.09.16-99', 'main', 'v2026.09.16-1; touch injected'])
def test_missing_or_untrusted_tag_cannot_reach_build(repository, tag):
    assert run_step(repository, 'validate', TAG=tag).returncode != 0
    assert not (repository[0] / 'output').exists()
    assert not (repository[0] / 'injected').exists()


def test_tag_outside_main_is_rejected(repository):
    root, _ = repository
    git(root, 'commit', '--allow-empty', '-qm', 'unreviewed')
    git(root, 'tag', '-f', TAG)
    assert run_step(repository, 'validate').returncode != 0


def test_failed_asset_upload_never_publishes_a_partial_release(repository):
    root, _ = repository
    assets = root / 'release-assets'
    assets.mkdir()
    for platform in ['linux-x86_64', 'macos-arm64']:
        name = f'drydock-local-{TAG}-{platform}-py3.12.tar.gz'
        (assets / name).write_bytes(b'verified archive')
        digest = hashlib.sha256(b'verified archive').hexdigest()
        (assets / (name + '.sha256')).write_text(f'{digest}  {name}\n')
    binary = root / 'bin'
    binary.mkdir()
    gh = binary / 'gh'
    gh.write_text('#!/bin/bash\nprintf "%s\\n" "$*" >> "$RUNNER_TEMP/calls"\nexit 1\n')
    gh.chmod(0o755)
    result = run_step(repository, 'publish', PATH=str(binary) + os.pathsep + os.environ['PATH'])
    assert result.returncode != 0
    calls = (root / 'calls').read_text().splitlines()
    assert len(calls) == 1
    assert calls[0].startswith(f'release create {TAG} ')
    assert '--draft' in calls[0] and '--verify-tag' in calls[0]

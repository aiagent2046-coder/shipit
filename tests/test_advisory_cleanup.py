"""Exercise post-merge cleanup decisions without GitHub writes or network access."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest
import yaml

from scripts import close_superseded_advisories as cleanup

REPO = 'owner/shipit'
MAIN = 'a' * 40
OLD = 'b' * 40
CHANGE = 'c' * 40
MERGE = 'd' * 40
OLD_CVE, NEW_CVE = '1' * 40, '2' * 40
OLD_GHSA, NEW_GHSA = '3' * 40, '4' * 40
OLD_KEV, NEW_KEV = '5' * 40, '6' * 40
ADVISORY_FILES = ['app/data/cve-catalog.json', 'app/data/cve-catalog.json.sha256', 'app/data/cve-learning.json']
KEV_FILES = ['app/data/kev-catalog.json', 'app/data/kev-catalog.json.sha256']
FILES = ADVISORY_FILES + KEV_FILES


def branch(cve, ghsa, kev):
    return f'automation/advisory-knowledge-{cve[:12]}-{ghsa[:12]}-kev{kev[:12]}'


def source_files(cve, ghsa, kev, kev_context_commit=None):
    sources = {
        'cvelist': {'repository': 'https://github.com/CVEProject/cvelistV5', 'commit': cve},
        'github-reviewed': {'repository': 'https://github.com/github/advisory-database', 'commit': ghsa},
        'cisa-kev': {'repository': 'https://github.com/cisagov/kev-data', 'commit': kev,
                     'catalog_version': '2026.11.03', 'sha256': 'e' * 64},
    }
    data = json.dumps({'schema': 1, 'sources': sources, 'packages': {}}).encode()
    digest = hashlib.sha256(data).hexdigest()
    summary = {'schema': 1, 'kind': 'knowledge_compilation', 'sources': sources, 'catalog_sha256': digest}
    # kev-catalog.json is compiled from the same checkout; the cleanup proves that, not just the branch name.
    context = json.dumps({'schema': 1, 'source': {'repository': 'https://github.com/cisagov/kev-data',
                                                   'commit': kev_context_commit or kev, 'upstream_sha256': 'e' * 64},
                          'entries': {}}).encode()
    return dict(zip(FILES, (data, f'{digest}  cve-catalog.json\n'.encode(), json.dumps(summary).encode(),
                            context, (hashlib.sha256(context).hexdigest() + '\n').encode())))


class FakeGitHub:
    """Strict endpoint fake: unplanned API calls fail instead of touching GitHub."""

    def __init__(self):
        self.runs = [
            {'id': n, 'path': f'.github/workflows/{name}.yml', 'head_sha': MAIN,
             'head_branch': 'main', 'head_repository': {'full_name': REPO}, 'event': 'push',
             'status': 'completed', 'conclusion': 'success', 'run_attempt': 1}
            for n, name in enumerate(
                ['production-ci', 'browser-scan', 'web-build', 'db-postgres-smoke', 'local-package'], 1,
            )
        ]
        self.pull = {
            'number': 10, 'state': 'open', 'draft': False, 'merged_at': None, 'commits': 1,
            'user': {'login': 'github-actions[bot]'},
            'head': {'sha': OLD, 'ref': branch(OLD_CVE, OLD_GHSA, OLD_KEV),
                     'repo': {'full_name': REPO}},
            'base': {'ref': 'main', 'repo': {'full_name': REPO}},
        }
        # Snapshot's original commit is retained inside a later integration merge.
        self.merged = {
            'number': 20, 'merged_at': '2026-11-03T07:39:54Z', 'merge_commit_sha': MERGE,
            'base': {'ref': 'main', 'repo': {'full_name': REPO}},
        }
        self.files = [{'filename': path, 'status': 'modified'} for path in FILES]
        self.blobs = [{'path': path, 'sha': str(i) * 40, 'type': 'file'} for i, path in enumerate(FILES, 1)]
        self.content = {MAIN: source_files(NEW_CVE, NEW_GHSA, NEW_KEV), OLD: source_files(OLD_CVE, OLD_GHSA, OLD_KEV)}
        self.comparisons = {
            f'repos/{REPO}/compare/{MERGE}...{MAIN}?per_page=1': {'status': 'ahead'},
            f'repos/CVEProject/cvelistV5/compare/{OLD_CVE}...{NEW_CVE}?per_page=1': {'status': 'ahead'},
            f'repos/github/advisory-database/compare/{OLD_GHSA}...{NEW_GHSA}?per_page=1': {'status': 'ahead'},
            f'repos/cisagov/kev-data/compare/{OLD_KEV}...{NEW_KEV}?per_page=1': {'status': 'ahead'},
        }
        self.main_reads = 0
        self.pull_reads = 0
        self.ci_reads = 0
        self.main_changed = False
        self.pull_changed = False
        self.ci_changed = False
        self.fail_compare = False
        self.closed = []
        self.calls = []
        self.associated = [{'number': 20}]
        self.change_blobs = None

    def get(self, endpoint):
        self.calls.append(endpoint)
        if endpoint == f'repos/{REPO}/git/ref/heads/main':
            self.main_reads += 1
            return {'object': {'sha': 'f' * 40 if self.main_changed and self.main_reads > 1 else MAIN}}
        if endpoint == f'repos/{REPO}/commits?sha={MAIN}&path=app/data/cve-learning.json&per_page=1':
            return [{'sha': CHANGE}]
        if endpoint in {f'repos/{REPO}/contents/app/data?ref={MAIN}',
                        f'repos/{REPO}/contents/app/data?ref={CHANGE}'}:
            return deepcopy(self.change_blobs if endpoint.endswith(CHANGE) and self.change_blobs else self.blobs)
        if endpoint == f'repos/{REPO}/pulls/20':
            return deepcopy(self.merged)
        if endpoint == f'repos/{REPO}/pulls/10':
            self.pull_reads += 1
            value = deepcopy(self.pull)
            if self.pull_changed and self.pull_reads > 1:
                value['head']['sha'] = 'e' * 40
            return value
        if endpoint in self.comparisons:
            if self.fail_compare:
                raise RuntimeError('GitHub API unavailable')
            return deepcopy(self.comparisons[endpoint])
        raise AssertionError(f'Unexpected GET {endpoint}')

    def pages(self, endpoint, key=None):
        self.calls.append(endpoint)
        if endpoint == f'repos/{REPO}/actions/runs?head_sha={MAIN}&event=push':
            assert key == 'workflow_runs'
            self.ci_reads += 1
            value = deepcopy(self.runs)
            if self.ci_changed and self.ci_reads > 1:
                value[0]['status'] = 'in_progress'
                value[0]['conclusion'] = None
            return value
        if endpoint == f'repos/{REPO}/commits/{CHANGE}/pulls':
            return deepcopy(self.associated)
        if endpoint == f'repos/{REPO}/pulls?state=open&base=main':
            return [{'number': 10}] if self.pull['state'] == 'open' else []
        if endpoint == f'repos/{REPO}/pulls/10/files':
            return deepcopy(self.files)
        raise AssertionError(f'Unexpected paginated GET {endpoint}')

    def raw(self, repo, ref, path):
        assert repo == REPO
        return self.content[ref][path]

    def close(self, repo, number):
        assert repo == REPO and number == 10
        self.closed.append(number)
        self.pull['state'] = 'closed'


@pytest.fixture
def api():
    return FakeGitHub()


def run(api, apply=True):
    return cleanup.cleanup(api, REPO, 'main', MAIN, apply=apply)


def test_integrated_merged_snapshot_closes_only_older_pr_and_is_idempotent(api):
    result = run(api)
    assert result['merged_snapshot_pr'] == 20
    assert result['closed'] == [10] == api.closed
    assert run(api)['closed'] == []
    assert api.closed == [10]


def test_default_dry_run_returns_plan_without_writes(api):
    result = cleanup.cleanup(api, REPO, 'main', MAIN)
    assert result['eligible'] == [10]
    assert result['closed'] == api.closed == []
    assert api.pull['state'] == 'open'


@pytest.mark.parametrize('state', ['missing', 'failure', 'cancelled', 'skipped', 'pending', 'wrong-sha'])
def test_browser_ci_must_have_executed_successfully_on_this_commit(api, state):
    browser = api.runs[1]
    if state == 'missing':
        api.runs.remove(browser)
    elif state == 'wrong-sha':
        browser['head_sha'] = '9' * 40
    elif state == 'pending':
        browser.update(status='in_progress', conclusion=None)
    else:
        browser['conclusion'] = state
    assert run(api)['closed'] == api.closed == []
    assert api.pull_reads == 0


@pytest.mark.parametrize('field,value', [('event', 'pull_request'), ('head_branch', 'feature')])
def test_successful_unmerged_branch_ci_does_not_count(api, field, value):
    for item in api.runs:
        item[field] = value
    assert run(api)['closed'] == api.closed == []


def test_ci_from_other_repository_does_not_count(api):
    api.runs[1]['head_repository']['full_name'] = 'someone/fork'
    assert run(api)['closed'] == api.closed == []


@pytest.mark.parametrize('status,conclusion', [('completed', 'failure'), ('in_progress', None)])
def test_latest_rerun_overrides_older_success(api, status, conclusion):
    repeated = deepcopy(api.runs[1])
    repeated.update(run_attempt=2, status=status, conclusion=conclusion)
    api.runs.insert(0, repeated)  # The API ordering cannot resurrect the older result.
    assert run(api)['closed'] == api.closed == []


def test_latest_new_run_overrides_earlier_success(api):
    repeated = deepcopy(api.runs[1])
    repeated.update(id=100, conclusion='failure')
    api.runs.insert(0, repeated)
    assert run(api)['closed'] == api.closed == []


def test_observed_optional_ci_failure_blocks_cleanup(api):
    extra = deepcopy(api.runs[0])
    extra.update(id=100, path='.github/workflows/security-audit.yml', conclusion='failure')
    api.runs.append(extra)
    assert run(api)['closed'] == api.closed == []


@pytest.mark.parametrize('case', ['unmerged', 'no-association', 'not-ancestor', 'changed-catalog'])
def test_catalog_must_be_from_a_merged_pr_reachable_in_main(api, case):
    if case == 'unmerged':
        api.merged['merged_at'] = None
    elif case == 'no-association':
        api.associated = []
    elif case == 'not-ancestor':
        api.comparisons[f'repos/{REPO}/compare/{MERGE}...{MAIN}?per_page=1']['status'] = 'diverged'
    else:
        api.change_blobs = deepcopy(api.blobs)
        api.change_blobs[0]['sha'] = 'f' * 40
    assert run(api)['closed'] == api.closed == []


@pytest.mark.parametrize('upstream,old,new', [
    ('CVEProject/cvelistV5', OLD_CVE, NEW_CVE),
    ('github/advisory-database', OLD_GHSA, NEW_GHSA),
    ('cisagov/kev-data', OLD_KEV, NEW_KEV),
])
@pytest.mark.parametrize('relation', ['behind', 'diverged'])
def test_newer_or_diverged_source_preserves_candidate(api, upstream, old, new, relation):
    api.comparisons[f'repos/{upstream}/compare/{old}...{new}?per_page=1']['status'] = relation
    assert run(api)['closed'] == api.closed == []
    assert api.pull['state'] == 'open'


def test_same_source_snapshot_is_not_treated_as_older(api):
    api.content[OLD] = source_files(NEW_CVE, NEW_GHSA, NEW_KEV)
    api.pull['head']['ref'] = branch(NEW_CVE, NEW_GHSA, NEW_KEV)
    assert run(api)['closed'] == api.closed == []


def test_advisory_only_update_leaves_kev_files_untouched_and_is_still_superseded(api):
    """When only CVE/GHSA moved, the bot commit modifies three files; KEV stays identical."""
    api.content[OLD] = source_files(OLD_CVE, OLD_GHSA, NEW_KEV)
    api.pull['head']['ref'] = branch(OLD_CVE, OLD_GHSA, NEW_KEV)
    api.files = [{'filename': path, 'status': 'modified'} for path in ADVISORY_FILES]
    assert run(api)['closed'] == [10] == api.closed


@pytest.mark.parametrize('case', ['kev-receipt-missing', 'kev-only', 'legacy-feed-identity', 'legacy-branch'])
def test_partial_or_legacy_kev_snapshots_are_preserved(api, case):
    if case == 'kev-receipt-missing':
        api.files = [f for f in api.files if f['filename'] != 'app/data/kev-catalog.json.sha256']
    elif case == 'kev-only':
        api.files = [{'filename': path, 'status': 'modified'} for path in KEV_FILES]
    elif case == 'legacy-feed-identity':
        legacy = source_files(OLD_CVE, OLD_GHSA, OLD_KEV)
        data = json.loads(legacy['app/data/cve-catalog.json'])
        data['sources']['cisa-kev'] = {'feed': 'https://www.cisa.gov/kev.json', 'sha256': 'e' * 64}
        raw = json.dumps(data).encode()
        summary = json.loads(legacy['app/data/cve-learning.json'])
        summary.update(sources=data['sources'], catalog_sha256=hashlib.sha256(raw).hexdigest())
        legacy.update({'app/data/cve-catalog.json': raw, 'app/data/cve-learning.json': json.dumps(summary).encode(),
                       'app/data/cve-catalog.json.sha256': f'{summary["catalog_sha256"]}  cve-catalog.json\n'.encode()})
        api.content[OLD] = legacy
    else:
        api.pull['head']['ref'] = f'automation/advisory-knowledge-{OLD_CVE[:12]}-{OLD_GHSA[:12]}-kev2026.11.03'
    assert run(api)['closed'] == api.closed == []
    assert api.pull['state'] == 'open'


@pytest.mark.parametrize('ref', [MAIN, OLD])
def test_kev_context_must_come_from_the_same_commit_as_the_advisory_snapshot(api, ref):
    cve, ghsa, kev = (NEW_CVE, NEW_GHSA, NEW_KEV) if ref == MAIN else (OLD_CVE, OLD_GHSA, OLD_KEV)
    api.content[ref] = source_files(cve, ghsa, kev, kev_context_commit='9' * 40)
    with pytest.raises(ValueError, match='KEV provenance'):
        run(api)
    assert api.closed == []


@pytest.mark.parametrize('case', ['manual-author', 'foreign-repo', 'wrong-base', 'fourth-file', 'extra-commit',
                                 'draft', 'unrelated-branch', 'wrong-pins', 'renamed-file'])
def test_unrelated_or_modified_pull_requests_are_preserved(api, case):
    if case == 'manual-author':
        api.pull['user']['login'] = 'maintainer'
    elif case == 'foreign-repo':
        api.pull['head']['repo']['full_name'] = 'someone/fork'
    elif case == 'wrong-base':
        api.pull['base']['ref'] = 'release'
    elif case == 'fourth-file':
        api.files.append({'filename': 'app/fix.py', 'status': 'modified'})
    elif case == 'extra-commit':
        api.pull['commits'] = 2
    elif case == 'draft':
        api.pull['draft'] = True
    elif case == 'unrelated-branch':
        api.pull['head']['ref'] = 'feature/catalog-improvement'
    elif case == 'wrong-pins':
        api.pull['head']['ref'] = branch(NEW_CVE, NEW_GHSA, NEW_KEV)
    else:
        api.files[0]['status'] = 'renamed'
    assert run(api)['closed'] == api.closed == []


@pytest.mark.parametrize('ref', [MAIN, OLD])
def test_corrupt_catalog_stops_without_closing(api, ref):
    api.content[ref]['app/data/cve-catalog.json'] += b' '
    with pytest.raises(ValueError, match='checksum mismatch'):
        run(api)
    assert api.closed == []


@pytest.mark.parametrize('race', ['main_changed', 'pull_changed', 'ci_changed'])
def test_change_before_write_cancels_close(api, race):
    setattr(api, race, True)
    assert run(api)['closed'] == api.closed == []


def test_api_error_never_falls_back_to_date_based_closure(api):
    api.fail_compare = True
    with pytest.raises(RuntimeError, match='API unavailable'):
        run(api)
    assert api.closed == []


def test_workflow_runs_after_ci_with_no_branch_write_permission():
    root = Path(__file__).resolve().parents[1]
    workflow = yaml.safe_load((root / '.github/workflows/close-superseded-advisories.yml').read_text())
    triggers = workflow.get('on', workflow.get(True))
    assert set(triggers) == {'workflow_run'}
    trigger = triggers['workflow_run']
    assert trigger['types'] == ['completed'] and trigger['branches'] == ['main']
    required = {'production-ci', 'browser-scan', 'web-build', 'db-postgres-smoke', 'local-package'}
    assert required <= set(trigger['workflows'])
    assert workflow['permissions'] == {'contents': 'read', 'actions': 'read', 'pull-requests': 'write'}
    builder = yaml.safe_load((root / '.github/workflows/update-cve-catalog.yml').read_text())
    assert workflow['concurrency'] == builder['concurrency']
    builder_steps = builder['jobs']['compile-and-propose']['steps']
    assert all('gh pr close' not in step.get('run', '') for step in builder_steps)

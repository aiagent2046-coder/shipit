#!/usr/bin/env python3
"""Close obsolete bot snapshots only after their replacement was merged and tested.

No PR code is checked out, no branches are deleted, and API errors stop cleanup.
The CLI defaults to a read-only plan; the post-CI workflow explicitly uses --apply.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from urllib.parse import quote

# The builder stages all five files; a commit modifies the three advisory files whenever any source
# moved and the two KEV context files only when the KEV checkout moved.
ADVISORY_FILES = frozenset({
    'app/data/cve-catalog.json',
    'app/data/cve-catalog.json.sha256',
    'app/data/cve-learning.json',
})
KEV_FILES = frozenset({'app/data/kev-catalog.json', 'app/data/kev-catalog.json.sha256'})
FILES = ADVISORY_FILES | KEV_FILES
SUMMARY = 'app/data/cve-learning.json'
PREFIX = 'automation/advisory-knowledge-'
SOURCES = {'cvelist': 'CVEProject/cvelistV5', 'github-reviewed': 'github/advisory-database',
           'cisa-kev': 'cisagov/kev-data'}
REQUIRED = frozenset(f'.github/workflows/{name}.yml' for name in (
    'production-ci', 'browser-scan', 'web-build', 'db-postgres-smoke', 'local-package',
))
SHA = re.compile(r'[0-9a-f]{40}')


class UnsupportedProvenance(ValueError):
    """A snapshot whose source identities this cleanup cannot compare; never a reason to close."""


class GitHub:
    def _call(self, endpoint, *args):
        result = subprocess.run(
            ['gh', 'api', endpoint, *args], check=True, capture_output=True,
        )
        return result.stdout

    def get(self, endpoint):
        return json.loads(self._call(endpoint))

    def pages(self, endpoint, key=None):
        separator = '&' if '?' in endpoint else '?'
        pages = json.loads(self._call(endpoint + separator + 'per_page=100', '--paginate', '--slurp'))
        return [item for page in pages for item in (page[key] if key else page)]

    def raw(self, repo, ref, path):
        return self._call(
            f'repos/{repo}/contents/{path}?ref={ref}', '-H', 'Accept: application/vnd.github.raw+json',
        )

    def close(self, repo, number):
        self._call(f'repos/{repo}/pulls/{number}', '--method', 'PATCH', '-f', 'state=closed')


def snapshot(api, repo, ref):
    raw = api.raw(repo, ref, 'app/data/cve-catalog.json')
    catalog = json.loads(raw)
    summary = json.loads(api.raw(repo, ref, SUMMARY))
    digest = hashlib.sha256(raw).hexdigest()
    expected = f'{digest}  cve-catalog.json\n'.encode()
    if api.raw(repo, ref, 'app/data/cve-catalog.json.sha256') != expected:
        raise ValueError('catalog checksum mismatch')
    if summary.get('schema') != 1 or summary.get('kind') != 'knowledge_compilation':
        raise ValueError('unsupported snapshot summary')
    if summary.get('catalog_sha256') != digest or catalog.get('sources') != summary.get('sources'):
        raise ValueError('catalog provenance mismatch')
    sources = summary['sources']
    if set(sources) != set(SOURCES):
        raise UnsupportedProvenance('expected all three official sources')
    for name, repository in SOURCES.items():
        source = sources[name]
        if source.get('repository') != f'https://github.com/{repository}':
            raise UnsupportedProvenance('unexpected source repository')
        if not SHA.fullmatch(source.get('commit', '')):
            raise UnsupportedProvenance('invalid source SHA')
    # kev-catalog.json is compiled from the same checkout in the same run; prove it, do not assume it.
    context_raw = api.raw(repo, ref, 'app/data/kev-catalog.json')
    context = json.loads(context_raw)
    receipt = api.raw(repo, ref, 'app/data/kev-catalog.json.sha256').strip()
    if receipt != hashlib.sha256(context_raw).hexdigest().encode():
        raise ValueError('KEV context checksum mismatch')
    pinned = context.get('source', {})
    kev = sources['cisa-kev']
    if (pinned.get('repository') != kev['repository'] or pinned.get('commit') != kev['commit']
            or pinned.get('upstream_sha256') != kev.get('sha256')):
        raise ValueError('KEV provenance mismatch between advisory snapshot and threat context')
    return sources


def ci_green(api, repo, branch, sha):
    """Only latest push runs on the exact default-branch commit count as evidence."""
    runs = api.pages(f'repos/{repo}/actions/runs?head_sha={sha}&event=push', 'workflow_runs')
    latest = {}
    for run in runs:
        if (run['head_sha'] != sha or run['head_branch'] != branch or run['event'] != 'push'
                or run.get('head_repository', {}).get('full_name') != repo):
            continue
        path = run['path'].split('@', 1)[0]
        rank = (run['id'], run.get('run_attempt', 1))
        if path not in latest or rank > latest[path][0]:
            latest[path] = (rank, run)
    return REQUIRED <= latest.keys() and all(
        run['status'] == 'completed' and run['conclusion'] == 'success'
        for _, run in latest.values()
    )


def ancestor(api, repo, older, newer):
    if older == newer:
        return True
    comparison = api.get(f'repos/{repo}/compare/{older}...{newer}?per_page=1')
    return comparison['status'] in {'ahead', 'identical'}


def catalog_blobs(api, repo, ref):
    items = api.get(f'repos/{repo}/contents/app/data?ref={ref}')
    result = {item['path']: item['sha'] for item in items if item['path'] in FILES and item['type'] == 'file'}
    if result.keys() != FILES:
        raise ValueError('incomplete catalog files')
    return result


def merged_snapshot(api, repo, branch, sha):
    """Follow the catalog change, including a snapshot merged through an integration PR."""
    commits = api.get(f'repos/{repo}/commits?sha={sha}&path={SUMMARY}&per_page=1')
    if not commits:
        return None
    change = commits[0]['sha']
    if catalog_blobs(api, repo, change) != catalog_blobs(api, repo, sha):
        return None
    for associated in api.pages(f'repos/{repo}/commits/{change}/pulls'):
        pr = api.get(f'repos/{repo}/pulls/{associated["number"]}')
        if (pr.get('merged_at') and pr['base']['ref'] == branch
                and pr['base']['repo']['full_name'] == repo
                and pr.get('merge_commit_sha')
                and ancestor(api, repo, pr['merge_commit_sha'], sha)):
            return pr['number']
    return None


def candidate(pr, repo, branch):
    head = pr.get('head', {})
    base = pr.get('base', {})
    return (
        pr.get('state') == 'open' and not pr.get('draft') and not pr.get('merged_at')
        and pr.get('user', {}).get('login') == 'github-actions[bot]'
        and (head.get('repo') or {}).get('full_name') == repo
        and (base.get('repo') or {}).get('full_name') == repo
        and base.get('ref') == branch and head.get('ref', '').startswith(PREFIX)
        and pr.get('commits') == 1
    )


def current_head(api, repo, branch):
    return api.get(f'repos/{repo}/git/ref/heads/{quote(branch, safe="")}')['object']['sha']


def cleanup(api, repo, branch, sha, apply=False):
    result = {'merged_snapshot_pr': None, 'eligible': [], 'closed': [], 'skipped': []}
    if current_head(api, repo, branch) != sha or not ci_green(api, repo, branch, sha):
        result['reason'] = 'Current default branch does not have complete successful CI for this SHA.'
        return result
    replacement = merged_snapshot(api, repo, branch, sha)
    if replacement is None:
        result['reason'] = 'No merged PR provenance for the current catalog.'
        return result
    result['merged_snapshot_pr'] = replacement
    sources = snapshot(api, repo, sha)
    for item in api.pages(f'repos/{repo}/pulls?state=open&base={quote(branch, safe="")}'):
        number = item['number']
        pr = api.get(f'repos/{repo}/pulls/{number}')
        if not candidate(pr, repo, branch):
            continue
        files = api.pages(f'repos/{repo}/pulls/{number}/files')
        names = {f['filename'] for f in files}
        if (len(files) != len(names) or names not in (ADVISORY_FILES, FILES)
                or any(f['status'] != 'modified' for f in files)):
            result['skipped'].append(number)
            continue
        try:
            old = snapshot(api, repo, pr['head']['sha'])
        except UnsupportedProvenance:
            # A proposal from an older compiler shape stays open for a maintainer; corruption still raises.
            result['skipped'].append(number)
            continue
        expected_branch = (PREFIX + old['cvelist']['commit'][:12] + '-' + old['github-reviewed']['commit'][:12]
                           + '-kev' + old['cisa-kev']['commit'][:12])
        if pr['head']['ref'] != expected_branch:
            result['skipped'].append(number)
            continue
        # Dates and record counts cannot establish supersession; prove both Git ancestries.
        if (all(old[name]['commit'] == sources[name]['commit'] for name in SOURCES)
                or not all(ancestor(api, upstream, old[name]['commit'], sources[name]['commit'])
                           for name, upstream in SOURCES.items())):
            result['skipped'].append(number)
            continue
        result['eligible'].append(number)
        if not apply:
            continue
        # Shared concurrency with the builder prevents bot updates during cleanup.
        # GitHub has no conditional PR-close API; re-read immediately before each write.
        if current_head(api, repo, branch) != sha or not ci_green(api, repo, branch, sha):
            result['reason'] = 'Default branch or CI changed; stopped before the next close.'
            break
        fresh = api.get(f'repos/{repo}/pulls/{number}')
        if not candidate(fresh, repo, branch) or fresh['head'] != pr['head'] or fresh['base'] != pr['base']:
            result['skipped'].append(number)
            continue
        api.close(repo, number)
        result['closed'].append(number)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    repository = event['repository']
    run = event['workflow_run']
    if (os.environ.get('GITHUB_EVENT_NAME') != 'workflow_run' or run['event'] != 'push'
            or run['head_repository']['id'] != repository['id']
            or run['head_branch'] != repository['default_branch'] or run['conclusion'] != 'success'
            or not SHA.fullmatch(run['head_sha'])):
        print('Not a successful trusted default-branch push; no cleanup.')
        return
    result = cleanup(GitHub(), repository['full_name'], repository['default_branch'], run['head_sha'], args.apply)
    rendered = json.dumps(result, indent=2)
    print(rendered)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with Path(os.environ['GITHUB_STEP_SUMMARY']).open('a') as summary:
            summary.write('## Advisory snapshot cleanup\n\n```json\n' + rendered + '\n```\n')


if __name__ == '__main__':
    main()

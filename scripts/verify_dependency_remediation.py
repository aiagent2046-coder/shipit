"""Install and verify two trusted dependency fixtures, never a customer project.

Network access is needed for public package registries. Linux/Python 3.12 runner.
Exit 0: passed; 1: contract failed; 2: execution unavailable. Neither 1 nor 2 is a skip.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app.scan.cve_match import evaluate_advisory, match_archive  # noqa: E402
from app.scan.remediation_catalog import remediation_record  # noqa: E402

FIXTURES = ROOT / 'tests/fixtures/dependency-remediation'


@dataclass(frozen=True)
class Case:
    ecosystem: str
    package: str
    before: str
    after: str
    consumer: str
    consumer_version: str
    checks: int


CASES = {
    'npm': Case('npm', 'picomatch', '2.3.0', '2.3.2', '@rollup/pluginutils', '4.1.2', 9),
    'pypi': Case('PyPI', 'sqlparse', '0.5.5', '0.6.0', 'Django', '5.2.10', 4),
}


class ContractError(Exception):
    def __init__(self, reason: str, status: str = 'failed'):
        self.reason, self.status = reason, status
        super().__init__(reason)


def require(condition, reason):
    if not condition:
        raise ContractError(reason)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def save(path: Path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n')


def command(args, cwd, env, log, *, install=False, timeout=120):
    """No shell, inherited credentials/config or unlimited subprocess lifetime."""
    try:
        with log.open('w') as output:
            with subprocess.Popen(args, cwd=cwd, env=env, stdout=output, stderr=subprocess.STDOUT,
                                  start_new_session=True) as process:
                try:
                    code = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                    raise ContractError('command_timeout:' + log.stem, 'unavailable') from None
    except OSError:
        raise ContractError('command_unavailable:' + log.stem, 'unavailable') from None
    if code:
        raise ContractError('command_failed:' + log.stem, 'unavailable' if install else 'failed')
    if log.stat().st_size > 1_000_000:
        raise ContractError('command_output_limit:' + log.stem, 'unavailable')
    return log.read_text()


def execution_env(home: Path) -> dict:
    # Network proxy/CA settings can be necessary in CI; package-manager config,
    # auth tokens, NODE_OPTIONS and PYTHONPATH cannot select code or registries.
    names = {'PATH', 'SYSTEMROOT', 'LD_LIBRARY_PATH', 'SSL_CERT_FILE', 'SSL_CERT_DIR',
             'REQUESTS_CA_BUNDLE', 'NODE_EXTRA_CA_CERTS',
             'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY',
             'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy',
             'NPM_CONFIG_HTTPS_PROXY', 'NPM_CONFIG_PROXY', 'NPM_CONFIG_NOPROXY',
             'npm_config_https_proxy', 'npm_config_proxy', 'npm_config_noproxy'}
    env = {key: value for key, value in os.environ.items() if key in names}
    env.update(HOME=str(home), LANG='C.UTF-8', PYTHONNOUSERSITE='1',
               PYTHONDONTWRITEBYTECODE='1', PIP_CONFIG_FILE=os.devnull,
               NPM_CONFIG_USERCONFIG=str(home/'user.npmrc'), NPM_CONFIG_GLOBALCONFIG=str(home/'global.npmrc'))
    return env


def scan(files: dict[str, bytes], case: Case, catalog: dict) -> dict:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as archive:
        for name, raw in sorted(files.items()):
            archive.writestr(name, raw)
    observed = []

    def observe(dep, assessments, complete):
        observed.append({'ecosystem': dep.ecosystem, 'package': dep.name, 'version': dep.version,
                         'complete': complete,
                         'assessments': [{**a, 'advisory_ids': sorted(a['advisory_ids'])} for a in assessments]})

    result = match_archive(stream.getvalue(), catalog, assessment_observer=observe)
    result['inventory'] = sorted(observed, key=lambda row: (row['ecosystem'], row['package'], row['version']))
    entries = catalog.get('packages', {}).get(case.ecosystem + ':' + case.package, [])
    result['target_entry_assessments'] = [
        evaluate_advisory(row['version'], case.ecosystem, entry)
        for row in observed if row['ecosystem'] == case.ecosystem and row['package'] == case.package
        for entry in entries
    ]
    return result


def target_findings(case, report):
    return [f for f in report['findings'] if f['claim_evidence']['ecosystem'] == case.ecosystem
            and f['claim_evidence']['package'] == case.package]


def verify_stage(case: Case, stage: dict):
    """Fail closed on absent inventory, incomplete assessments and stale installs."""
    after = stage['name'] == 'after'
    version = case.after if after else case.before
    probe, report = stage['consumer'], stage['scan']
    require(probe.get('package') == case.package and probe.get('installed_version') == version,
            'installed_version_mismatch')
    require(probe.get('consumer') == case.consumer and probe.get('consumer_version') == case.consumer_version,
            'consumer_version_mismatch')
    require(probe.get('functional_passed') is True and type(probe.get('functional_checks')) is int
            and probe['functional_checks'] == case.checks, 'consumer_checks_failed')
    coverage = report['coverage']
    require(coverage['status'] not in {'unavailable', 'not_applicable'}, 'scan_unavailable')
    require(not any(coverage[k] for k in ('incomplete_manifests', 'inventory_truncated',
                                        'findings_truncated', 'evaluations_truncated')), 'scan_incomplete')
    targets = [row for row in report['inventory']
               if row['ecosystem'] == case.ecosystem and row['package'] == case.package]
    require(bool(targets) and all(row['version'] == version for row in targets), 'resolved_version_mismatch')
    require(all(row['complete'] and row['assessments'] for row in targets), 'target_not_assessed')
    require(all(a['status'] in {'affected', 'unaffected'} for row in targets for a in row['assessments']),
            'target_assessment_unknown')
    assessments = report['target_entry_assessments']
    require(bool(assessments) and all(not a['unresolved_ranges'] and a['status'] in {'affected', 'unaffected'}
                                    for a in assessments), 'target_ranges_unresolved')
    findings = target_findings(case, report)
    if after:
        require(not findings and all(a['status'] == 'unaffected' for a in assessments)
                and all(a['status'] == 'unaffected' for row in targets for a in row['assessments']),
                'target_still_affected')
    else:
        require(bool(findings), 'baseline_not_affected')
        expected_ids = {tuple(a['advisory_ids']) for row in targets for a in row['assessments']
                        if a['status'] == 'affected'}
        finding_ids = {tuple(sorted(f['claim_evidence']['advisory_ids'])) for f in findings}
        require(expected_ids == finding_ids, 'affected_findings_incomplete')
        cards = [remediation_record(f['claim_evidence']) for f in findings]
        require(all(card and case.after in card['candidate_versions'] for card in cards), 'candidate_not_in_card')
    if case.ecosystem == 'PyPI':
        regression = probe.get('regression') or {}
        require(regression.get('id') == 'python-snippet-backslash-escaping'
                and regression.get('passed') is after
                and regression.get('outcome') == ('literal_roundtrip' if after else 'SyntaxError'),
                'escaping_regression_mismatch')


def verify_cycle(case: Case, stages: list[dict]):
    require([s['name'] for s in stages] == ['before', 'after', 'restore'], 'missing_or_reordered_stage')
    for stage in stages:
        verify_stage(case, stage)
    before, after, restore = stages
    require(before['manifest_sha256'] == restore['manifest_sha256'], 'restore_manifest_mismatch')
    require(before['scan']['findings'] == restore['scan']['findings'], 'restore_findings_mismatch')

    def others(stage):
        return [(r['ecosystem'], r['package'], r['version']) for r in stage['scan']['inventory']
                if (r['ecosystem'], r['package']) != (case.ecosystem, case.package)]

    require(others(before) == others(after) == others(restore), 'unrelated_dependency_changed')
    require(before['scan']['inventory'] == restore['scan']['inventory'], 'restore_inventory_mismatch')


def run(case_name: str, output: Path) -> dict:
    case = CASES[case_name]
    result = {'version': 1, 'contract_id': 'dependency-remediation-' + case_name,
              'scope': 'trusted_dependency_fixture', 'status': 'unavailable', 'fixture_verified': False,
              'runtime_verified': False, 'customer_project_verified': False, 'automatic_patch': False,
              'package': case.package, 'ecosystem': case.ecosystem, 'candidate': case.after, 'stages': [],
              'limits': ['Only the bundled fixture is verified; no customer application or full build is executed.',
                         'npm has consumer checks but no ReDoS runtime oracle.',
                         'PyPI tests one escaping regression; other advisories use version matching.']}
    logs = output / 'logs'
    logs.mkdir()
    try:
        require(sys.platform == 'linux' and sys.version_info[:2] == (3, 12), 'unsupported_runtime')
        raw_catalog = (ROOT / 'app/data/cve-catalog.json').read_bytes()
        catalog = json.loads(raw_catalog)
        result['catalog_sha256'] = digest(raw_catalog)
        result['catalog_sources'] = catalog.get('sources')
        fixture = FIXTURES / case_name
        result['fixture_sha256'] = {p.name: digest(p.read_bytes()) for p in sorted(fixture.iterdir()) if p.is_file()}
        with tempfile.TemporaryDirectory(prefix='drydock-dependency-contract-') as tmp:
            work = Path(tmp)
            home = work / 'home'
            home.mkdir()
            env = execution_env(home)
            result['python_version'] = sys.version.split()[0]
            if case_name == 'npm':
                result['node_version'] = command(['node', '--version'], work, env, logs/'node-version.log').strip()
                result['manager_version'] = command(['npm', '--version'], work, env, logs/'npm-version.log').strip()
            for name in ('before', 'after', 'restore'):
                project = work / name
                project.mkdir()
                if case_name == 'npm':
                    for file in ('package.json', 'package-lock.json'):
                        (project/file).write_bytes((fixture/file).read_bytes())
                    common = ['--ignore-scripts', '--no-audit', '--no-fund', '--registry=https://registry.npmjs.org']
                    if name == 'after':
                        command(['npm', 'pkg', 'set', 'overrides.picomatch=' + case.after], project, env,
                                logs/(name+'-override.log'))
                        command(['npm', 'install', '--package-lock-only', *common], project, env,
                                logs/(name+'-resolve.log'), install=True)
                    command(['npm', 'ci', *common], project, env, logs/(name+'-install.log'), install=True)
                    probe_command = ['node', str(fixture/'consumer.cjs')]
                    files = {f: (project/f).read_bytes() for f in ('package.json', 'package-lock.json')}
                else:
                    python = project / '.venv/bin/python'
                    command([sys.executable, '-m', 'venv', str(project/'.venv')], project, env,
                            logs/(name+'-venv.log'), install=True)
                    requirements = fixture / ('requirements-after.txt' if name == 'after'
                                              else 'requirements-before.txt')
                    command([str(python), '-m', 'pip', '--isolated', 'install', '--disable-pip-version-check',
                             '--require-hashes', '--only-binary=:all:', '--no-deps', '--no-input',
                             '--index-url=https://pypi.org/simple', '-r', str(requirements)],
                            project, env, logs/(name+'-install.log'), install=True)
                    command([str(python), '-m', 'pip', '--isolated', 'check'], project, env, logs/(name+'-check.log'))
                    version = command([str(python), '-m', 'pip', '--version'], project, env, logs/(name+'-pip.log'))
                    result.setdefault('manager_versions', {})[name] = version.split(' from ')[0]
                    frozen = command([str(python), '-m', 'pip', '--isolated', 'freeze'], project, env,
                                     logs/(name+'-freeze.log'))
                    files = {'requirements.txt': frozen.encode()}
                    probe_command = [str(python), '-I', str(fixture/'consumer.py')]
                probe = json.loads(command(probe_command, project, env, logs/(name+'-consumer.log')))
                installed_path = Path(probe.get('installed_path', ''))
                require(installed_path.is_absolute() and installed_path.resolve().is_relative_to(project)
                        and installed_path.is_file(), 'consumer_outside_fixture')
                report = scan(files, case, catalog)
                stage = {'name': name, 'consumer': probe, 'scan': report,
                         'manifest_sha256': {f: digest(raw) for f, raw in files.items()}}
                result['stages'].append(stage)
                for file, raw in files.items():
                    (output/(name+'-'+file)).write_bytes(raw)
                save(output/(name+'-evidence.json'), stage)
                verify_stage(case, stage)
            verify_cycle(case, result['stages'])
            require(digest((ROOT/'app/data/cve-catalog.json').read_bytes()) == result['catalog_sha256'],
                    'catalog_changed_during_run')
        result.update(status='passed', fixture_verified=True)
    except ContractError as exc:
        result.update(status=exc.status, reason=exc.reason)
    except (OSError, ValueError, KeyError, TypeError):
        result.update(status='unavailable', reason='execution_unavailable')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', choices=sorted(CASES), required=True)
    parser.add_argument('--output-dir', type=Path, required=True, help='New evidence directory; never overwritten')
    args = parser.parse_args(argv)
    args.output_dir.mkdir(parents=True, exist_ok=False)
    result = run(args.case, args.output_dir)
    save(args.output_dir/'result.json', result)
    print(json.dumps({k: result[k] for k in ('contract_id', 'status', 'fixture_verified')}
                     | {'reason': result.get('reason'), 'output': str(args.output_dir)}))
    return {'passed': 0, 'failed': 1}.get(result['status'], 2)


if __name__ == '__main__':
    raise SystemExit(main())

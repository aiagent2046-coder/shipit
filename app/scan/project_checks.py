"""Join independent project checks without turning observations into security verdicts."""
from __future__ import annotations

import hashlib

from app.scan.binary_evidence import collect_binary_evidence


def dependency_checks(sca: dict, findings: int | None = None) -> dict:
    """Describe the stage that actually ran; offline matching is not a live OSV query."""
    coverage = sca.get('dependency_cve')
    metadata = sca.get('dependency_snapshot') or {}
    if isinstance(coverage, dict):
        state = coverage.get('status')
        status = {'checked': 'completed', 'partial': 'partial', 'not_applicable': 'not_applicable',
                  'unavailable': 'unavailable'}.get(state, 'unavailable')
        return {'status': status, 'mode': 'offline_catalog',
                'findings': findings if findings is not None else 0,
                'catalog_sha256': metadata.get('catalog_sha256'),
                'sources': coverage.get('sources') or {},
                'reason': 'bounded_snapshot_matching' if status != 'unavailable' else 'catalog_unavailable'}
    reason = sca.get('skipped_reason')
    ran = 'sca_dependencies' in sca.get('checks_run', []) and sca.get('asked_at') is not None
    if reason and str(reason).startswith('osv_unavailable'):
        status = 'unavailable'
    elif reason in {'no_resolvable_lockfile'} or (reason and str(reason).startswith('lockfile_unreadable')):
        status = 'partial'
    elif reason in {'no_lockfile', 'no_resolved_dependencies'}:
        status = 'not_applicable'
    elif reason:
        status = 'not_run'
    elif ran:
        status = 'partial' if sca.get('coverage_incomplete') or sca.get('truncated') else 'completed'
    else:
        status = 'not_run'
    return {'status': status, 'mode': 'live_osv' if ran or status == 'unavailable' else 'not_run',
            'findings': findings if findings is not None else sca.get('findings', 0),
            'catalog_sha256': None, 'sources': {}, 'reason': reason or (None if ran else 'not_requested')}


def project_checks(data: bytes, static: dict, sca: dict, dependency_findings: int | None = None) -> dict:
    checks = static.get('checks_run') or []
    failures = static.get('checks_not_run') or []
    incomplete = any(any(row.get('skip_reasons', {}).values())
                     for row in (static.get('rule_coverage') or {}).values())
    agent = static.get('security_agent') or {}
    source_incomplete = failures or incomplete or agent.get('status') in {'partial', 'unavailable'}
    source_status = 'unavailable' if not checks else 'partial' if source_incomplete else 'completed'
    return {
        'schema': 1, 'archive_sha256': hashlib.sha256(data).hexdigest(), 'runtime_verified': False,
        'source': {'status': source_status, 'checks_run': len(checks), 'checks_not_run': len(failures),
                   'findings': len(static.get('findings') or []), 'agent_status': agent.get('status', 'not_run')},
        'dependencies': dependency_checks(sca, dependency_findings),
        'binary_static': collect_binary_evidence(data),
    }

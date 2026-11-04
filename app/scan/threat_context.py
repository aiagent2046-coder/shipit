"""Prioritise existing dependency evidence with KEV, without adding security findings."""
from __future__ import annotations

from datetime import date, datetime, timezone
import hashlib
import re

from app.scan import kev_catalog

MAX_FINDINGS = 1000
MAX_MATCHES = 256
MAX_REFS = 64
STALE_AFTER_DAYS = 30
RULES = frozenset({'dependency-cve-match', 'dependency-known-vulnerability'})
LIMITATIONS = [
    'known_exploitation_elsewhere_not_project_compromise', 'absence_from_kev_is_not_evidence_of_safety',
    'priority_separate_from_severity_and_confidence', 'runtime_reachability_not_verified',
    'cisa_due_date_is_source_context_not_project_deadline',
]


def assessment_date(value: str | None = None) -> str:
    if value is None:
        return datetime.now(timezone.utc).date().isoformat()
    if not isinstance(value, str) or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}', value):
        raise ValueError('invalid_threat_assessment_date')
    return date.fromisoformat(value).isoformat()


def context_is_current(context: object, *, as_of: str | None = None) -> bool:
    return (isinstance(context, dict) and type(context.get('schema')) is int and context['schema'] == 1
            and context.get('as_of') == assessment_date(as_of)
            and context.get('fingerprint') == kev_catalog.fingerprint())


def _text(value, limit):
    return (isinstance(value, str) and 1 <= len(value) <= limit and value.strip()
            and not any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value))


def _identifiers(value):
    if type(value) is not list or len(value) > 256 or any(not _text(item, 128) for item in value):
        raise ValueError('invalid_advisory_identifiers')
    return set(value)


def _finding(finding):
    evidence = finding.get('claim_evidence')
    if (type(evidence) is not dict or type(evidence.get('version')) is not int or evidence['version'] != 1
            or not _text(evidence.get('package'), 256) or not _text(evidence.get('ecosystem'), 80)
            or not _text(evidence.get('installed_version'), 256) or not _text(evidence.get('manifest'), 1024)
            or finding.get('file') != evidence['manifest'] or type(finding.get('line', 0)) is not int
            or not 0 <= finding.get('line', 0) <= 1_000_000_000
            or finding.get('source', 'dependency') != 'dependency'):
        raise ValueError('invalid_dependency_evidence')
    if finding['rule_id'] == 'dependency-cve-match' and finding.get('verification_method') != 'package_version_match':
        raise ValueError('invalid_dependency_evidence')
    identifiers = _identifiers(evidence.get('advisory_ids', []))
    aliases = _identifiers(evidence.get('advisory_aliases', []))
    unreadable = _identifiers(evidence.get('unreadable_advisory_ids', []))
    # Aliases are produced only from records successfully read by the dependency stage.
    # Missing advisory details must not be promoted by merely mentioning their identifier.
    identifiers = (identifiers | aliases) - unreadable
    if finding['rule_id'] == 'dependency-cve-match':
        for field in ('advisory_id', 'cve_id'):
            if field in evidence:
                if not _text(evidence[field], 128):
                    raise ValueError('invalid_advisory_identifiers')
                if evidence[field] not in unreadable:
                    identifiers.add(evidence[field])
    cves = {item for item in identifiers if kev_catalog.CVE_ID.fullmatch(item)}
    ref = {'rule_id': finding['rule_id'], 'file': finding['file'], 'line': finding.get('line', 0),
           **{field: evidence[field] for field in ('package', 'ecosystem', 'installed_version')}}
    return cves, ref


def _reference_key(ref):
    return tuple(ref[field] for field in ('rule_id', 'file', 'line', 'ecosystem', 'package', 'installed_version'))


def build_threat_context(findings: list[dict], *, as_of: str | None = None, catalog: dict | None = None) -> dict:
    """Correlate exact dependency CVEs against a validated snapshot, retaining uncertainty.

    ``catalog`` accepts the envelope returned by ``kev_catalog.load_catalog`` so a
    browser session can freeze both data and assessment date across continuation.
    Eligible findings counts dependency-stage rows, including unmappable rows.
    Unmapped rows have missing/invalid package evidence or no usable CVE identifier;
    a usable CVE absent from KEV is evaluated, not classified safe.
    """
    day = assessment_date(as_of)
    loaded = kev_catalog.load_catalog() if catalog is None else catalog
    identity = loaded.get('fingerprint') if isinstance(loaded, dict) else None
    if not isinstance(identity, str) or not kev_catalog.SHA256.fullmatch(identity):
        identity = hashlib.sha256(b'invalid-kev-snapshot').hexdigest()
    result = {'schema': 1, 'status': 'unavailable', 'as_of': day, 'source': None, 'fingerprint': identity,
              'matched_cves': 0, 'eligible_findings': 0, 'unmapped_findings': 0,
              'matches': [], 'limitations': list(LIMITATIONS), 'runtime_verified': False}
    try:
        if (type(loaded) is not dict or loaded.get('status') != 'available'
                or not isinstance(loaded.get('sha256'), str) or not kev_catalog.SHA256.fullmatch(loaded['sha256'])):
            raise ValueError('kev_catalog_unavailable')
        snapshot = kev_catalog.validate_catalog(loaded.get('catalog'))
        if hashlib.sha256(kev_catalog.encode_catalog(snapshot)).hexdigest() != loaded['sha256']:
            raise ValueError('kev_catalog_digest_mismatch')
    except (ValueError, TypeError, KeyError, RecursionError):
        result['limitations'].append('kev_catalog_unavailable_or_invalid')
        return result
    source = {**snapshot['source'], 'catalog_sha256': loaded['sha256']}
    result['source'] = source
    age = (date.fromisoformat(day) - date.fromisoformat(source['date_released'][:10])).days
    if age < 0 or source['source_committed_at'][:10] > day:
        result['limitations'].append('kev_source_after_assessment_date')
        return result
    if type(findings) is not list:
        result['limitations'].append('invalid_dependency_findings')
        return result
    groups, problems = {}, set()
    candidate_count = 0
    for finding in findings:
        if (not isinstance(finding, dict) or not isinstance(finding.get('rule_id'), str)
                or finding['rule_id'] not in RULES):
            continue
        candidate_count += 1
        if candidate_count > MAX_FINDINGS:
            problems.add('kev_finding_limit')
            continue
        result['eligible_findings'] += 1
        try:
            cves, ref = _finding(finding)
        except (ValueError, TypeError, KeyError):
            result['unmapped_findings'] += 1
            problems.add('invalid_dependency_evidence')
            continue
        if not cves:
            result['unmapped_findings'] += 1
            problems.add('advisory_without_resolved_cve')
        for cve in sorted(cves):
            if cve not in snapshot['entries']:
                continue
            if cve not in groups:
                if len(groups) == MAX_MATCHES:
                    problems.add('kev_match_limit')
                    continue
                groups[cve] = {}
            refs = groups[cve]
            key = _reference_key(ref)
            if key not in refs and len(refs) == MAX_REFS:
                problems.add('kev_reference_limit')
                continue
            refs[key] = ref
    for cve, refs in sorted(groups.items()):
        result['matches'].append({'cve_id': cve, 'priority': 'expedited', 'reason': 'known_exploitation',
                                  **snapshot['entries'][cve],
                                  'finding_refs': [ref for _, ref in sorted(refs.items())]})
    result['matched_cves'] = len(result['matches'])
    if age > STALE_AFTER_DAYS:
        result['status'] = 'stale'
        problems.add('kev_snapshot_older_than_30_days')
    else:
        result['status'] = 'partial' if problems else 'completed'
    result['limitations'].extend(sorted(problems))
    return result

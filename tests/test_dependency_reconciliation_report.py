"""A missing package-index result must not silently dismiss baseline evidence."""
from copy import deepcopy

from app.report.dependency_snapshot import unrepeated_dependency_matches
from app.report.html import render_report


def match(rule="dependency-cve-match", **evidence):
    return dict(rule_id=rule, title="source-map-js 1.2.1 matches CVE-2026-93749", file="web/package-lock.json",
                category="Security", severity="high", confidence=.9, source="dependency",
                claim_evidence=dict(ecosystem="npm", package="source-map-js", installed_version="1.2.1",
                                    advisory_id="CVE-2026-93749", advisory_ids=["CVE-2026-93749"], **evidence))


def score(finding):
    return dict(total=0, categories={}, free_baseline=dict(
        version=1, status="completed", origin="included", findings=[finding], score=dict(total=0, categories={})))


def test_empty_online_result_keeps_match_visible_outside_collapsed_baseline():
    finding = match()
    state = score(finding)
    before = deepcopy(state)
    html = render_report(dict(score=state, findings=[]))
    start = html.index('aria-label="Dependency results need reconciliation"')
    assert start < html.index('<details><summary>Full baseline findings and scope')
    assert finding["title"] in html[start:html.index('</aside>', start)]
    assert 'Not repeated does not mean fixed or disproved' in html
    assert 'These records remain separate from current finding counts' in html
    assert state == before


def test_recorded_alias_overlap_requires_same_package_version_and_dependency_rule():
    baseline = match()
    baseline['claim_evidence']['advisory_ids'].append('GHSA-aaaa-bbbb-cccc')
    live = match('dependency-known-vulnerability')
    live['claim_evidence'].pop('advisory_id')
    live['claim_evidence']['advisory_ids'] = ['GHSA-aaaa-bbbb-cccc']
    assert unrepeated_dependency_matches(score(baseline), [live]) == []
    for key, value in [('installed_version', '2.0.0'), ('package', 'different'), ('ecosystem', 'PyPI')]:
        changed = deepcopy(live)
        changed['claim_evidence'][key] = value
        assert unrepeated_dependency_matches(score(baseline), [changed]) == [baseline]
    live['rule_id'] = 'unrelated'
    assert unrepeated_dependency_matches(score(baseline), [live]) == [baseline]


def test_pypi_normalization_and_incomplete_evidence_are_conservative():
    baseline, live = match(), match('dependency-known-vulnerability')
    for f in (baseline, live):
        f['claim_evidence']['ecosystem'] = 'PyPI'
    baseline['claim_evidence']['package'] = 'Some_Package'
    live['claim_evidence']['package'] = 'some-package'
    assert unrepeated_dependency_matches(score(baseline), [live]) == []
    baseline['claim_evidence'] = None
    assert unrepeated_dependency_matches(score(baseline), [live]) == [baseline]


def test_notice_escapes_archive_controlled_text_and_ignores_non_dependency_baseline():
    finding = match()
    finding.update(title='<script>alert(1)</script>', file='<img src=x onerror=alert(1)>')
    html = render_report(dict(score=score(finding), findings=[]))
    assert '&lt;script&gt;alert(1)&lt;/script&gt;' in html
    assert '<img src=x onerror=alert(1)>' not in html
    finding['rule_id'] = 'secret'
    assert unrepeated_dependency_matches(score(finding), []) == []

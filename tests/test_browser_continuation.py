"""Continue real bounded scans without hiding gaps or exceeding finding caps."""
import io
import zipfile

import pytest

from app.scan.browser import ScanSession, scan_archive

CONTINUATION_CASES = [
    pytest.param('xss', 'xss-unsafe-html-injection', 'js',
                 'export const value = true;', 'element.innerHTML = untrusted;',
                 'const broken = [;', id='xss'),
    pytest.param('unsafe_xml_parse', 'unsafe-xml-parse', 'py', 'pass',
                 'from lxml import etree\netree.fromstring(xml, parser=etree.XMLParser(resolve_entities=True))',
                 'from lxml import etree\nbroken = [', id='xxe'),
]


def archive(files):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as z:
        for name, content in files:
            z.writestr(name, content)
    return output.getvalue()


@pytest.mark.parametrize('check,rule_id,suffix,harmless,signal,malformed', CONTINUATION_CASES)
def test_browser_continuation_reaches_tail_and_preserves_parse_failures(
    check, rule_id, suffix, harmless, signal, malformed,
):
    files = [(f'src/file{i}.{suffix}', harmless) for i in range(839)]
    files += [(f'src/tail.{suffix}', signal), (f'src/broken.{suffix}', malformed),
              (f'node_modules/dependency.{suffix}', signal)]
    session = ScanSession(archive(files))
    first = session.result()
    assert first['can_continue']
    assert first['report']['rule_coverage'][check]['analyzed_files'] == 400
    assert not any(f['rule_id'] == rule_id for f in first['report']['findings'])
    second = session.continue_scan()
    assert second['can_continue']
    assert second['report']['rule_coverage'][check]['analyzed_files'] == 800
    final = session.continue_scan()
    assert not final['can_continue']
    record = final['report']['rule_coverage'][check]
    assert record['analyzed_files'] == 840
    assert record['attempted_files'] == 841
    assert record['skip_reasons'] == {'parse_error': 1}
    assert record['partial']
    findings = [f for f in final['report']['findings'] if f['rule_id'] == rule_id]
    assert len(findings) == 1
    assert findings[0]['file'] == f'src/tail.{suffix}'
    assert any(r['ruleId'] == rule_id for r in final['sarif']['runs'][0]['results'])
    assert first['report']['rule_coverage'][check]['analyzed_files'] == 400
    assert session.continue_scan() == final


@pytest.mark.parametrize('check,rule_id,suffix,harmless,signal,malformed', CONTINUATION_CASES)
def test_finding_cap_applies_across_batches_even_with_many_signals_in_one_file(
    check, rule_id, suffix, harmless, signal, malformed,
):
    files = [(f'src/first.{suffix}', (signal + '\n') * 31)]
    files += [(f'src/file{i}.{suffix}', harmless) for i in range(399)]
    files += [(f'src/tail.{suffix}', (signal + '\n') * 2)]
    session = ScanSession(archive(files))
    assert session.result()['can_continue']
    result = session.continue_scan()
    findings = [f for f in result['report']['findings'] if f['rule_id'] == rule_id]
    assert len(findings) == 32
    assert sum(f['file'] == f'src/tail.{suffix}' for f in findings) == 1
    assert result['report']['rule_coverage'][check]['skip_reasons'] == {'finding_limit': 1}
    assert result['report']['rule_coverage'][check]['partial']
    assert not result['can_continue']
    assert session.continue_scan() == result


def test_fresh_session_matches_single_scan_and_does_not_inherit_previous_cursor():
    data = archive([('src/config.py', 'value = 1')])
    result = ScanSession(data).result()
    assert not result.pop('can_continue')
    assert result == scan_archive(data)


@pytest.mark.parametrize('check,rule_id,suffix,harmless,signal,malformed', CONTINUATION_CASES)
def test_failed_batch_keeps_previous_report_and_marks_failure(
    monkeypatch, check, rule_id, suffix, harmless, signal, malformed,
):
    from app.scan import static
    files = [(f'src/file{i}.{suffix}', harmless) for i in range(401)]
    session = ScanSession(archive(files))
    old = session.result()['report']['rule_coverage'][check]
    def broken(*args, **kwargs):
        raise ValueError('source-must-not-escape')
    monkeypatch.setattr(static, f'scan_{check}', broken)
    result = session.continue_scan()
    assert result['report']['rule_coverage'][check] == old
    assert {'check': check, 'reason': 'check_error: ValueError'} in result['report']['checks_not_run']
    assert 'source-must-not-escape' not in str(result)
    assert not result['can_continue']

"""Continue real bounded scans without hiding gaps or exceeding finding caps."""
import io
import zipfile

from app.scan.browser import ScanSession, scan_archive


def archive(files):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as z:
        for name, content in files:
            z.writestr(name, content)
    return output.getvalue()


def test_browser_continuation_reaches_tail_and_preserves_parse_failures():
    files = [(f'src/file{i}.js', 'export const value = true;') for i in range(839)]
    files += [('src/tail.js', 'element.innerHTML = untrusted;'), ('src/broken.js', 'const broken = [;'),
              ('node_modules/dependency.js', 'element.innerHTML = untrusted;')]
    session = ScanSession(archive(files))
    first = session.result()
    assert first['can_continue']
    assert first['report']['rule_coverage']['xss']['analyzed_files'] == 400
    assert not any(f['rule_id'] == 'xss-unsafe-html-injection' for f in first['report']['findings'])
    second = session.continue_scan()
    assert second['can_continue']
    assert second['report']['rule_coverage']['xss']['analyzed_files'] == 800
    final = session.continue_scan()
    assert not final['can_continue']
    record = final['report']['rule_coverage']['xss']
    assert record['analyzed_files'] == 840
    assert record['attempted_files'] == 841
    assert record['skip_reasons'] == {'parse_error': 1}
    assert record['partial']
    assert len([f for f in final['report']['findings'] if f['rule_id'] == 'xss-unsafe-html-injection']) == 1
    assert any(r['ruleId'] == 'xss-unsafe-html-injection' for r in final['sarif']['runs'][0]['results'])
    assert first['report']['rule_coverage']['xss']['analyzed_files'] == 400
    assert session.continue_scan() == final


def test_finding_cap_applies_across_batches_even_with_many_signals_in_one_file():
    files = [('src/first.js', 'element.innerHTML = untrusted;\n' * 20)]
    files += [(f'src/file{i}.js', 'export const value = true;') for i in range(399)]
    files += [('src/tail.js', 'element.innerHTML = untrusted;\n' * 20)]
    session = ScanSession(archive(files))
    assert session.result()['can_continue']
    result = session.continue_scan()
    findings = [f for f in result['report']['findings'] if f['rule_id'] == 'xss-unsafe-html-injection']
    assert len(findings) == 32
    assert result['report']['rule_coverage']['xss']['skip_reasons'] == {'finding_limit': 1}
    assert not result['can_continue']


def test_fresh_session_matches_single_scan_and_does_not_inherit_previous_cursor():
    data = archive([('src/config.py', 'value = 1')])
    result = ScanSession(data).result()
    assert not result.pop('can_continue')
    assert result == scan_archive(data)


def test_failed_batch_keeps_previous_report_and_marks_failure(monkeypatch):
    from app.scan import static
    files = [(f'src/file{i}.js', 'export const value = true;') for i in range(401)]
    session = ScanSession(archive(files))
    old = session.result()['report']['rule_coverage']['xss']
    def broken(*args, **kwargs):
        raise ValueError('source-must-not-escape')
    monkeypatch.setattr(static, 'scan_xss', broken)
    result = session.continue_scan()
    assert result['report']['rule_coverage']['xss'] == old
    assert {'check': 'xss', 'reason': 'check_error: ValueError'} in result['report']['checks_not_run']
    assert 'source-must-not-escape' not in str(result)
    assert not result['can_continue']

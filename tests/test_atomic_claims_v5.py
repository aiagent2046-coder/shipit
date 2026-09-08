"""Source-backed v4 counterexamples and paired ambiguous/unsafe operations."""
import pytest

from app.scan.atomic_claims import check_source, requests
from app.scan.syntax_claims import SyntaxVerifier
from tests.test_atomic_claims import HTTP, check, raw
from tests.test_audit_llm_wiring import make_zip


POSITIVE = '''async function callback() {
  const tokenRes = await fetch('/token');
  const token = await tokenRes.json();
  try {
    const userRes = await fetch('/user');
    if (userRes.ok) login = (await userRes.json()).login;
  } catch {}
}'''


@pytest.mark.parametrize('title', [
    'Missing HTTP status validation in Claude API call for avatar suggestion',
    'GitHub user info fetch does not validate HTTP status before JSON parsing',
    'Unvalidated HTTP response before JSON parsing in auto-reply flow',
    'Unchecked HTTP response in callback',
    'HTTP status is not checked before parsing',
])
def test_status_wording_selects_a_source_check_without_model_premises(title):
    selected = requests({'title': title, 'line_start': 5, 'line_end': 6})
    assert {r['kind'] for r in selected} == {'http_status_guard_absent'}
    result = check_source(POSITIVE.encode(), 'callback.ts', selected[0])
    assert result['result'] == 'contradicted'
    assert result['target'] == 'userRes'


def test_explanation_and_structured_selector_work_without_a_matching_title():
    finding = {'title': 'Upstream failure', 'line_start': 5, 'line_end': 6,
               'explanation': 'The response is not checked for HTTP errors before JSON access.'}
    assert requests(finding)[0]['kind'] == 'http_status_guard_absent'
    finding['explanation'] = ''
    finding['premises'] = [{'kind': 'http_status_guard_absent', 'target': 'userRes',
                            'line_start': 5, 'line_end': 6, 'result': 'verified'}]
    selected = requests(finding)[0]
    assert 'result' not in selected
    assert check_source(POSITIVE.encode(), 'callback.ts', selected)['result'] == 'contradicted'


@pytest.mark.parametrize('source', [
    POSITIVE.replace('if (userRes.ok)', 'if (tokenRes.ok)'),
    POSITIVE.replace('if (userRes.ok)', 'if (!userRes.ok)'),
    POSITIVE.replace('if (userRes.ok)', 'if (enabled || userRes.ok)'),
    POSITIVE.replace('if (userRes.ok) login', 'if (userRes.ok) {}\n    login'),
    POSITIVE.replace('if (userRes.ok)', 'userRes = other;\n    if (userRes.ok)'),
    POSITIVE.replace('if (userRes.ok)', 'const userRes = other;\n    if (userRes.ok)'),
    POSITIVE.replace('if (userRes.ok) login', 'function later() { if (userRes.ok) login')
            .replace('  } catch {}', '    }\n  } catch {}'),
    POSITIVE.replace('  } catch {}', '    await userRes.json();\n  } catch {}'),
])
def test_positive_status_branch_must_dominate_the_same_single_parse(source):
    assert check(source, 'http_status_guard_absent', marker='const userRes')['result'] == 'not_checked'


def test_other_response_and_whole_function_ranges_do_not_select_the_safe_parse():
    assert check(POSITIVE, 'http_status_guard_absent', marker='const tokenRes')['result'] == 'not_checked'
    request = dict(kind='http_status_guard_absent', target='', line_start=1, line_end=8)
    assert check_source(POSITIVE.encode(), 'callback.ts', request)['result'] == 'not_checked'


@pytest.mark.parametrize('selected_start,selected_end', [(2, 3), (5, 6)])
def test_structured_target_cannot_borrow_another_safe_response_in_the_same_function(selected_start, selected_end):
    request = dict(kind='http_status_guard_absent', target='userRes',
                   line_start=selected_start, line_end=selected_end,
                   anchor_line_start=2, anchor_line_end=3)
    assert check_source(POSITIVE.encode(), 'callback.ts', request)['result'] == 'not_checked'


def test_unknown_parameter_response_cannot_be_ignored_in_favor_of_a_safe_local_response():
    source = '''async function process(unknown) {
  const res = await fetch('/safe');
  if (res.ok) await res.json();
  await unknown.json();
}'''
    assert check(source, 'http_status_guard_absent')['result'] == 'not_checked'
    assert check(source, 'http_status_guard_absent', marker='unknown.json')['result'] == 'not_checked'
    assert check(source, 'http_status_guard_absent', marker='const res')['result'] == 'contradicted'


@pytest.mark.parametrize('catch', ['catch {}', 'catch (error) {}', 'catch { return; }',
                                   'catch { return null; }', 'catch { return {error: "invalid"}; }'])
def test_await_json_has_a_safe_enclosing_catch(catch):
    source = POSITIVE.replace('catch {}', catch)
    result = check(source, 'json_rejection_uncaught', marker='const userRes')
    assert result['result'] == 'contradicted'
    assert 'UI reset' in result['detail']


@pytest.mark.parametrize('source', [
    POSITIVE.replace('catch {}', 'catch { throw error; }'),
    POSITIVE.replace('catch {}', 'catch { return recover(); }'),
    POSITIVE.replace('catch {}', 'catch { log(); }'),
    POSITIVE.replace('catch {}', 'catch { if (retry) throw error; }'),
    POSITIVE.replace('catch {}', 'catch ({message = fail()}) {}'),
    POSITIVE.replace('catch {}', 'catch {} finally { throw error; }'),
    POSITIVE.replace('(await userRes.json()).login', 'userRes.json()'),
    POSITIVE.replace('  } catch {}', '    await userRes.json();\n  } catch {}'),
    POSITIVE.replace('const userRes', 'const otherRes').replace('if (userRes.ok)', 'if (otherRes.ok)'),
])
def test_catch_effects_unawaited_promises_and_multiple_calls_remain_unknown(source):
    marker = 'const otherRes' if 'const otherRes' in source else 'const userRes'
    assert check(source, 'json_rejection_uncaught', marker=marker)['result'] == 'not_checked'


def test_status_and_json_counterexamples_remain_partial_for_compound_narrative():
    source = POSITIVE
    finding = raw(source, 'Unvalidated HTTP response and missing content type', 'const userRes')
    finding['explanation'] = 'HTTP status is not checked; JSON parsing can throw. Content type is also unchecked.'
    verifier = SyntaxVerifier(make_zip({finding['file']: source.encode()}))
    checks = verifier.premise_checks(finding)
    assert {c['kind'] for c in checks} == {'http_status_guard_absent', 'json_rejection_uncaught'}
    assert all(c['result'] == 'contradicted' for c in checks)
    assert verifier.check(finding)['result'] == 'not_checked'


def test_new_atomic_status_wording_uses_source_but_compound_title_is_not_dismissed():
    finding = raw(HTTP, 'Missing HTTP status validation in upstream response', 'const res')
    verifier = SyntaxVerifier(make_zip({finding['file']: HTTP.encode()}))
    assert verifier.check(finding)['result'] == 'contradicted'
    finding['title'] += ' and authorization'
    assert verifier.check(finding)['result'] == 'not_checked'
    assert verifier.premise_checks(finding)[0]['result'] == 'contradicted'


def sql_request(source, start=1, end=1, **extra):
    return check_source(source.encode(), 'migration.sql', {
        'kind': 'sql_update_where', 'target': '', 'line_start': start, 'line_end': end, **extra,
    })


def test_without_guard_wording_exposes_own_where_without_dismissing_data_semantics():
    finding = dict(file='migration.sql', line_start=1, line_end=1,
                   title='Migration UPDATE silently overwrites intent for all existing profiles without a guard',
                   explanation='This changes legitimately unset values if the migration runs again.')
    sql = b"UPDATE profiles SET intent='has_idea' WHERE intent IS NULL;"
    verifier = SyntaxVerifier(make_zip({'migration.sql': sql}))
    checks = verifier.premise_checks(finding)
    assert len(checks) == 1 and checks[0]['result'] == 'contradicted'
    assert 'selectivity and safety were not tested' in checks[0]['detail']
    assert verifier.check(finding)['result'] == 'not_checked'


@pytest.mark.parametrize('source,expected', [
    ('UPDATE profiles SET intent=1 WHERE intent IS NULL;', 'contradicted'),
    ('UPDATE profiles SET intent=1 WHERE true;', 'contradicted'),
    ('UPDATE profiles SET intent=(SELECT 1 WHERE true);', 'observed'),
    ("UPDATE profiles SET intent='WHERE id=1'; -- WHERE id=2", 'observed'),
    ('WITH q AS (UPDATE users SET x=1 RETURNING *) UPDATE profiles SET x=1 WHERE id=1;', 'not_checked'),
    ('UPDATE profiles SET intent=1; UPDATE users SET intent=1 WHERE id=1;', 'not_checked'),
    ('UPDATE profiles SET ;', 'not_checked'),
])
def test_structured_sql_premise_keeps_the_same_bounded_ast_rules(source, expected):
    assert sql_request(source)['result'] == expected


def test_sql_selector_cannot_borrow_another_statement_or_relation():
    source = 'UPDATE profiles SET x=1;\nUPDATE users SET x=1 WHERE id=1;'
    assert sql_request(source, 2, 2, anchor_line_start=1, anchor_line_end=1)['result'] == 'not_checked'
    assert sql_request(source, 2, 2, target='profiles')['result'] == 'not_checked'
    assert sql_request(source, 2, 2, target='users')['result'] == 'contradicted'

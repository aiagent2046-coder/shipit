"""Ownership source counterexamples and paired unsafe variants; no runtime/LLM calls."""
import io
import json
import zipfile

import pytest

from app.scan.ownership_claims import MAX_FILE_BYTES, check_source

SOURCE = """import { createClient } from '@supabase/supabase-js';
export async function POST(req) {
  const token = req.headers.get('authorization');
  const supabase = createClient(url, key);
  const { data: { user }, error: userErr } = await supabase.auth.getUser(token);
  if (userErr || !user) return forbidden();
  const { matchId, content } = await req.json();
  const { data: match, error: matchErr } = await supabase
    .from('matches').select('id, founder1_id, founder2_id').eq('id', matchId).single();
  if (matchErr || !match) return notFound();
  const { data: myProfile } = await supabase
    .from('founder_profiles').select('id').eq('user_id', user.id).single();
  if (!myProfile) return notFound();
  if (myProfile.id !== match.founder1_id && myProfile.id !== match.founder2_id) {
    return forbidden();
  }
  const { data: message, error: insErr } = await supabase
    .from('messages').insert({ match_id: matchId, sender_id: myProfile.id, content: content.trim() })
    .select().single();
  return message;
}
"""
GUARD = """  if (myProfile.id !== match.founder1_id && myProfile.id !== match.founder2_id) {
    return forbidden();
  }
"""
INSERT = """  const { data: message, error: insErr } = await supabase
    .from('messages').insert({ match_id: matchId, sender_id: myProfile.id, content: content.trim() })
    .select().single();
"""


def check(source=SOURCE, **request):
    line = next(i + 1 for i, text in enumerate(source.splitlines()) if 'data: message' in text)
    return check_source(source.encode(), 'app/api/messages/route.ts', {
        'kind': 'ownership_guard_absent', 'line_start': line, 'line_end': line,
        **request,
    })


def test_message_insert_has_bounded_local_guard_counterevidence():
    result = check()
    assert result['result'] == 'contradicted', result
    assert result['source_lines'] == {
        'auth': 5, 'match_query': 8, 'profile_query': 11, 'ownership_guard': 14, 'insert': 17,
    }
    assert result['source_entities']['subject'] == 'matchId'
    assert result['source_entities']['profile'] == 'myProfile'
    assert result['source_line_start'] == 14
    assert 'concurrent membership changes remain unverified' in result['detail']
    assert 'foreign keys, RLS' in result['detail']
    assert 'content.trim' not in json.dumps(result)


def test_legacy_f11_title_checks_local_premise_without_dismissing_database_race_claim():
    from app.scan.syntax_claims import SyntaxVerifier

    path = 'app/api/messages/route.ts'
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, 'w') as output:
        output.writestr(path, SOURCE)
    archive.seek(0)
    finding = {
        'file': path, 'line_start': 17, 'line_end': 19,
        'title': 'Message insert does not validate match ownership before insertion',
        'explanation': 'Membership could change between the guard and insertion if database conditions permit it.',
    }
    verifier = SyntaxVerifier(archive)
    checks = verifier.premise_checks(finding)
    assert len(checks) == 1
    assert checks[0]['kind'] == 'ownership_guard_absent'
    assert checks[0]['result'] == 'contradicted'
    assert verifier.check(finding)['result'] == 'not_checked'


def test_local_names_import_alias_and_comparison_order_are_not_fixed_to_fixture():
    source = SOURCE.replace('createClient }', 'createClient as makeClient }').replace(
        'createClient(url', 'makeClient(url')
    for old, new in [('supabase', 'db'), ('myProfile', 'account'), ('matchId', 'subjectId'),
                     ('userErr', 'authError'), ('matchErr', 'lookupError')]:
        source = source.replace(old, new)
    # Keep the SDK package literal while renaming the local client.
    source = source.replace('@db/db-js', '@supabase/supabase-js')
    source = source.replace('account.id !== match.founder1_id', 'match.founder1_id !== account.id')
    result = check(source)
    assert result['result'] == 'contradicted', result
    assert result['target'] == 'subjectId'
    assert result['source_entities']['profile'] == 'account'


@pytest.mark.parametrize('old,new', [
    ('match_id: matchId', 'match_id: otherMatchId'),
    ('sender_id: myProfile.id', 'sender_id: otherProfile.id'),
    (".eq('id', matchId)", ".eq('id', otherMatchId)"),
    (".eq('user_id', user.id)", ".eq('user_id', otherUser.id)"),
    (".from('matches')", ".from('other_resources')"),
    (".from('messages')", ".from('other_messages')"),
    (".from('founder_profiles')", ".from('other_profiles')"),
    ('match.founder2_id', 'otherMatch.founder2_id'),
    ('match.founder2_id', 'match.founder1_id'),
    ('myProfile.id !==', 'myProfile.other_id !=='),
    (' && myProfile.id', ' || myProfile.id'),
    ('!==', '==='),
    ('!==', '!='),
    ('if (myProfile.id', 'if (enabled && myProfile.id'),
    ('myProfile.id !== match.founder1_id', 'myProfile?.id !== match.founder1_id'),
    (GUARD, GUARD.replace('return forbidden();', 'log();')),
    ('if (!myProfile) return notFound();', 'if (!myProfile) log();'),
    ('if (matchErr || !match) return notFound();', 'if (matchErr) return notFound();'),
    ('if (userErr || !user) return forbidden();', 'if (userErr) return forbidden();'),
    ('supabase.auth.getUser(token)', 'otherClient.auth.getUser(token)'),
    ('supabase.auth.getUser(token)', 'supabase.auth.getUser?.(token)'),
    ("from '@supabase/supabase-js'", "from './custom-client'"),
    ('const supabase = createClient(url, key);', 'const supabase = customClient;'),
    ('const { matchId, content }', 'let { matchId, content }'),
    ('.eq(\'id\', matchId)', '.eq(\'id\', matchId).eq(\'id\', otherMatchId)'),
    ('match_id: matchId, sender_id:', 'match_id: matchId, match_id: otherMatchId, sender_id:'),
    ('content: content.trim()', '...extra, content: content.trim()'),
    (".insert({ match_id", ".insert?.({ match_id"),
])
def test_wrong_resource_binding_optional_condition_or_nonterminal_guard_stays_unknown(old, new):
    assert old in SOURCE
    result = check(SOURCE.replace(old, new))
    assert result['result'] == 'not_checked', result


@pytest.mark.parametrize('source', [
    SOURCE.replace(GUARD + INSERT, INSERT + GUARD),
    SOURCE.replace(GUARD, '  if (enabled) {\n' + GUARD + '  }\n'),
    SOURCE.replace(GUARD, '  const later = () => {\n' + GUARD + '  };\n'),
    SOURCE.replace(INSERT, '  const later = async () => {\n' + INSERT + '  };\n'),
    SOURCE.replace(INSERT, "  await supabase.from('messages').insert({match_id: other});\n" + INSERT),
    SOURCE.replace(INSERT, '  changeState();\n' + INSERT),
    SOURCE.replace(GUARD, '  match.founder1_id = myProfile.id;\n' + GUARD),
    SOURCE.replace(GUARD, '  const other = myProfile; other.id = forged;\n' + GUARD),
    SOURCE.replace(GUARD, '  mutate(match);\n' + GUARD),
    SOURCE.replace(GUARD, '  const alias = supabase; alias.auth = forged;\n' + GUARD),
    SOURCE.replace(GUARD, '  myProfile.reassign();\n' + GUARD),
    SOURCE.replace(GUARD, '  const myProfile = other;\n' + GUARD),
    SOURCE.replace(GUARD, '  const callback = (myProfile) => myProfile.id;\n' + GUARD),
    SOURCE.replace(GUARD, '  matchId = other;\n' + GUARD),
    SOURCE.replace('POST(req)', 'POST(req, createClient)'),
    'const createClient = custom;\n' + SOURCE,
    'function createClient() { return forged; }\n' + SOURCE,
    'createClient = custom;\n' + SOURCE,
    "import { createClient } from './custom';\n" + SOURCE,
    SOURCE.replace('import { createClient }', 'import type { createClient }'),
])
def test_scope_shadowing_mutation_escapes_and_ambiguous_inserts_stay_unknown(source):
    result = check(source)
    assert result['result'] == 'not_checked', result


def test_unrelated_callback_insert_does_not_replace_selected_function_scope():
    source = SOURCE.replace('  return message;', """  after(async () => {
    await admin.from('messages').insert({match_id: matchId, sender_id: recipient});
  });
  return message;""")
    assert check(source)['result'] == 'contradicted'
    callback_line = next(i + 1 for i, text in enumerate(source.splitlines()) if 'await admin' in text)
    assert check(source, line_start=callback_line, line_end=callback_line)['result'] == 'not_checked'


def test_selector_must_stay_inside_cited_function_and_identify_supported_target():
    assert check(target='unrelated')['result'] == 'not_checked'
    assert check(target='message')['result'] == 'contradicted'
    assert check(line_start=1, line_end=1)['result'] == 'not_checked'
    assert check(anchor_line_start=1, anchor_line_end=1)['result'] == 'not_checked'
    source = 'function unrelated() {}\n' + SOURCE
    assert check(source, anchor_line_start=1, anchor_line_end=1)['result'] == 'not_checked'


@pytest.mark.parametrize('selector', [
    {'line_start': True}, {'line_end': 9999}, {'line_start': -1}, {'line_end': 0},
    {'kind': 'runtime_ownership_safe'},
    {'target': ['untrusted']},
])
def test_invalid_source_coordinates_or_kind_remain_unknown(selector):
    assert check(**selector)['result'] == 'not_checked'


def test_unparseable_and_over_budget_source_are_not_checked():
    assert check(SOURCE + '\n function {')['result'] == 'not_checked'
    assert check(SOURCE + '\n//' + 'x' * MAX_FILE_BYTES)['result'] == 'not_checked'

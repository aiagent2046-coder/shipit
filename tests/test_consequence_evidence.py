"""Synthetic mutations exercise bounded source context, never live APIs."""
import io
import json
import zipfile

import pytest

from app.scan.consequence_evidence import ConsequenceVerifier
from app.scan.claim_evidence import partial_contradicted, syntax_contradicted
from app.scan.syntax_claims import SyntaxVerifier
from tests.test_audit_llm_wiring import FakeLLM, make_zip

OAUTH = '''export async function GET(req) {
 let credential: string | null = null;
 try {
  const reply = await fetch('/exchange');
  const body = await reply.json();
  credential = body.value ?? null;
 } catch { return redirect('/failed'); }
 if (!credential) return redirect('/failed');
 await db.from('connections').upsert({sealed:seal(credential)});
 return done();
}'''
REACT = '''import {useState} from 'react';
export default function Messenger() {
 const [draft, changeDraft] = useState('');
 const submit = async () => {
  if (!draft.trim()) return;
  const payload = draft.trim();
  changeDraft('');
  await fetch('/api/send', {method:'POST', body:payload});
 };
 return <button onClick={submit} disabled={!draft.trim()}>Send</button>;
}'''
DISCARD = '''export async function commit() {
 try {
  await fetch('/api/commit', {method:'POST'});
  navigate('/next');
 } catch { showError(); }
}'''
CLIENT = '''export async function choose() {
 await fetch('/api/reactions', {method:'POST', body:payload});
 advance();
}'''
ROUTE = '''export async function POST(req) {
 const {error: failure} = await db.from('reactions').insert({actor, target, choice});
 if (failure) {
  if (failure.code === '23505' || failure.message?.includes('duplicate key')) {
   return reply({ok:true});
  }
  return reply({error:true});
 }
 const found = await db.from('reactions').select('id').eq('actor', target);
 return reply({found});
}'''
SCHEMA = b'''CREATE TABLE public.reactions (
 actor uuid NOT NULL, target uuid NOT NULL, choice text,
 UNIQUE(actor,target)
);'''


def raw(source, marker, title, explanation='', file='source.ts', **extra):
    line = next(i + 1 for i, row in enumerate(source.splitlines()) if marker in row)
    return {'file': file, 'line_start': line, 'line_end': line,
            'title': title, 'explanation': explanation, **extra}


def oauth(source=OAUTH, **extra):
    return raw(source, 'const reply', 'OAuth response status is unchecked',
               'An undefined access token may be stored as a credential.', **extra)


def clicks(source=REACT, **extra):
    return raw(source, 'return <button', 'Double-send possible without an in-flight flag',
               'Clicking the send button twice sends the same input twice.', file='source.tsx', **extra)


def discarded(source=DISCARD, **extra):
    return raw(source, 'await fetch', 'HTTP errors navigate away',
               'The handler navigates on a 500, or if response.json() throws the catch shows an error.', **extra)


def duplicate(source=CLIENT, **extra):
    return raw(source, 'await fetch', 'Repeated requests can duplicate records',
               'The duplicate-key guard is present but the second request still runs the follow-up query twice.',
               **{'file': 'app/choose/page.tsx', **extra})


def check(source, finding, others=None):
    archive = make_zip({finding['file']: source.encode(), **(others or {})})
    return ConsequenceVerifier(archive).checks_for(finding)


def result(results, kind):
    return next(item for item in results if item['kind'] == kind)


TOKEN = 'token_write_return_guard'
CLICK = 'react_empty_input_entry_binding'
JSON = 'discarded_fetch_response'
DUP = 'duplicate_key_return_branch'


def test_token_guard_records_the_bound_local_value_and_later_write_sites():
    proof = result(check(OAUTH, oauth()), TOKEN)
    assert proof['result'] == 'observed'
    assert proof['source_binding']['binding'] == 'credential'
    assert proof['source_binding']['guard']['line_start'] == 8
    assert proof['source_binding']['writes'][0]['method'] == 'upsert'
    assert 'Nonempty invalid tokens' in proof['detail']
    assert 'helper side effects' in proof['detail']
    assert 'scope' in proof and proof['scope'] == 'bounded_source_context'


@pytest.mark.parametrize('before,after', [
    ('if (!credential)', 'if (credential)'),
    ('if (!credential)', 'if (!different)'),
    ("if (!credential) return redirect('/failed');", "if (!credential) log();"),
    ("if (!credential) return redirect('/failed');", "if (!credential) { if (enabled) return; }"),
    ("if (!credential) return redirect('/failed');", "if (enabled) { if (!credential) return; }"),
    (" await db", " credential = null;\n await db"),
    (" await db", " eval('credential = null');\n await db"),
    (" await db", " const credential = other;\n await db"),
    ('seal(credential)', 'seal(other)'),
    ('body.value ?? null', 'other.value ?? null'),
    ('await reply.json()', 'readBody(reply)'),
    ('credential = body.value ?? null;', 'credential = body.value;'),
    (" } catch { return redirect('/failed'); }", " } finally { db.update({credential}); }"),
    (" await db", " function clear() { credential = null; }\n await db"),
    ("if (!credential) return redirect('/failed');", "if (!credential) return credential = makeToken();"),
])
def test_token_unsafe_or_unresolved_variants_abstain(before, after):
    source = OAUTH.replace(before, after)
    assert result(check(source, oauth(source)), TOKEN)['result'] == 'not_checked'


def test_unrelated_function_guard_cannot_refute_cited_token_flow():
    source = OAUTH.replace(" if (!credential) return redirect('/failed');\n", '') + '''
export function sibling(credential) { if (!credential) return; db.upsert({credential}); }
'''
    assert result(check(source, oauth(source)), TOKEN)['result'] == 'not_checked'


def test_actual_native_button_clear_is_source_context_only():
    proof = result(check(REACT, clicks()), CLICK)
    assert proof['result'] == 'observed'
    assert proof['source_binding']['clear_line'] < proof['source_binding']['first_await_line']
    assert proof['source_binding']['disabled_button_lines'] == [10]
    assert 'same-tick' in proof['detail'] and 'New typing' in proof['detail']


@pytest.mark.parametrize('before,after', [
    ("from 'react'", "from './my-hooks'"),
    ('import {useState}', 'import type {useState}'),
    ('function Messenger()', 'function Messenger(useState)'),
    ('const [draft, changeDraft]', 'const [draft, changeDraft, third]'),
    ('if (!draft.trim()) return;', 'if (draft.trim()) return;'),
    ('if (!draft.trim()) return;', 'if (!draft.trim()) log();'),
    ('if (!draft.trim()) return;', 'if (!other.trim()) return;'),
    ("  changeDraft('');", "  if (enabled) changeDraft('');"),
    ("  changeDraft('');", "  await delay(); changeDraft('');"),
    ("  await fetch", "  changeDraft(payload);\n  await fetch"),
    ("  await fetch", "  const alias = changeDraft;\n  await fetch"),
    ('disabled={!draft.trim()}', 'disabled={!other.trim()}'),
    ('disabled={!draft.trim()}', 'disabled={false}'),
    ('onClick={submit}', 'onClick={() => submit()}'),
    ('onClick={submit}', 'onClick={different}'),
    ('<button', '<Button'),
    ('</button>', '</Button>'),
    ('disabled={!draft.trim()}', 'disabled={!draft.trim()} {...props}'),
    ('disabled={!draft.trim()}', 'disabled={!draft.trim()} disabled={false}'),
    ('const payload = draft.trim();', 'runCallback(); const payload = draft.trim();'),
    ('const payload = draft.trim();', 'const payload = transform(draft);'),
])
def test_click_unsafe_or_ambiguous_bindings_abstain(before, after):
    source = REACT.replace(before, after)
    marker = 'return <Button' if '<Button' in source else 'return <button'
    finding = raw(source, marker, 'Double-send possible',
                  'Clicking twice sends the same input twice.', file='source.tsx')
    assert result(check(source, finding), CLICK)['result'] == 'not_checked'


def test_click_handler_anchor_works_without_relying_on_prose_handler_name():
    finding = clicks()
    finding['line_start'] = finding['line_end'] = 7
    assert result(check(REACT, finding), CLICK)['result'] == 'observed'


def test_discarded_response_has_no_direct_json_parse_but_keeps_http_concern():
    proof = result(check(DISCARD, discarded()), JSON)
    assert proof['result'] == 'observed'
    assert proof['source_binding']['response_binding'] == 'discarded'
    assert 'does not dismiss' in proof['detail']


@pytest.mark.parametrize('before,after', [
    ('await fetch', 'const response = await fetch'),
    ("  navigate('/next');", "  const response = await another(); await response.json();"),
    ("  navigate('/next');", "  response['json']();"),
    ("  navigate('/next');", "  response?.json();"),
    ("  navigate('/next');", "  response.json?.();"),
    ("  navigate('/next');", "  JSON?.parse(data);"),
    ("  navigate('/next');", "  eval('response.json()');"),
    ("  navigate('/next');", "  JSON.parse(data);"),
    ('export async function commit()', 'export async function commit(fetch)'),
    ('export async function commit()', "import {fetch} from './http';\nexport async function commit()"),
    ("  navigate('/next');", "  await fetch('/other'); navigate('/next');"),
    ('await fetch', 'consume(await fetch'),
])
def test_json_parsing_or_unresolved_response_is_not_counterevidence(before, after):
    source = DISCARD.replace(before, after)
    assert result(check(source, discarded(source)), JSON)['result'] == 'not_checked'


def route_files(route=ROUTE, schema=SCHEMA):
    return {'app/api/reactions/route.ts': route.encode(), 'supabase/migrations/001.sql': schema}


def test_duplicate_error_branch_skips_followup_with_declared_unique_context():
    proof = result(check(CLIENT, duplicate(), route_files()), DUP)
    assert proof['result'] == 'observed'
    binding = proof['source_binding']
    assert binding['table'] == 'reactions'
    assert binding['guard']['line_end'] < binding['later_queries'][0]['line_start']
    assert binding['declared_unique_constraints'][0]['columns'] == ['actor', 'target']
    assert binding['declared_unique_constraints'][0]['status'] == 'declared_only'
    assert 'UI state increments are not prevented' in proof['detail']


@pytest.mark.parametrize('before,after', [
    ("failure.code === '23505'", "failure.code === 'other'"),
    ("failure.code === '23505'", "other.code === '23505'"),
    ("failure.code === '23505' ||", "failure.code === '23505' &&"),
    ("failure.code === '23505' || failure.message?.includes('duplicate key')",
     "failure.message?.includes('duplicate key')"),
    ('if (failure)', 'if (!failure)'),
    ('if (failure)', 'if (enabled)'),
    ('   return reply({ok:true});', '   reply({ok:true});'),
    ('   return reply({ok:true});', '   if (enabled) return reply({ok:true});'),
    ('   return reply({ok:true});', '   return await reply({ok:true});'),
    (' if (failure)', " failure.code = 'other';\n if (failure)"),
    (' if (failure)', " const prior = await db.from('reactions').select('id');\n if (failure)"),
    (".from('reactions').select", ".from('other').select"),
    ('export async function POST', 'export async function GET'),
    ('.insert({actor, target, choice})', '.upsert({actor, target, choice})'),
])
def test_duplicate_branch_unsafe_variants_abstain(before, after):
    route = ROUTE.replace(before, after)
    assert result(check(CLIENT, duplicate(), route_files(route)), DUP)['result'] == 'not_checked'


@pytest.mark.parametrize('before,after', [
    ("'/api/reactions'", 'destination'),
    ("'/api/reactions'", "'/api/reactions?key=x'"),
    ("method:'POST'", "method:'GET'"),
    ("method:'POST'", "method:'POST', ...options"),
    ('function choose()', 'function choose(fetch)'),
])
def test_route_binding_unknown_for_dynamic_url_options_or_fetch(before, after):
    source = CLIENT.replace(before, after)
    assert result(check(source, duplicate(source), route_files()), DUP)['result'] == 'not_checked'


def test_unique_is_declaration_only_even_if_later_dropped_or_if_not_exists():
    schema = (SCHEMA.replace(b'CREATE TABLE', b'CREATE TABLE IF NOT EXISTS')
              + b'ALTER TABLE reactions DROP CONSTRAINT x;')
    proof = result(check(CLIENT, duplicate(), route_files(schema=schema)), DUP)
    assert proof['result'] == 'observed'  # Narrow JS error branch only.
    assert all(c['status'] == 'declared_only' for c in proof['source_binding']['declared_unique_constraints'])
    assert 'applied migrations' in proof['detail']


def test_missing_or_mismatched_schema_does_not_invent_active_uniqueness():
    files = route_files(schema=SCHEMA.replace(b'UNIQUE(actor,target)', b'UNIQUE(choice)'))
    proof = result(check(CLIENT, duplicate(), files), DUP)
    # choice is an insert column and is a real declaration; never a duplicate
    # request-key proof. The result is only about the JS 23505 branch.
    assert proof['result'] == 'observed'
    assert proof['source_binding']['declared_unique_constraints'][0]['columns'] == ['choice']
    files.pop('supabase/migrations/001.sql')
    proof = result(check(CLIENT, duplicate(), files), DUP)
    assert proof['source_binding']['declared_unique_constraints'] == []


def test_archive_root_prefix_is_preserved_and_other_project_route_is_not_selected():
    finding = duplicate(file='snapshot/app/choose/page.tsx')
    files = {'snapshot/' + k: v for k, v in route_files().items()}
    proof = result(check(CLIENT, finding, files), DUP)
    assert proof['source_binding']['route_file'] == 'snapshot/app/api/reactions/route.ts'
    assert proof['source_binding']['declared_unique_constraints'][0]['file'].startswith('snapshot/')
    assert result(check(CLIENT, finding, route_files()), DUP)['result'] == 'not_checked'


@pytest.mark.parametrize('change', ['path', 'range', 'bool_range', 'bad_utf8', 'parser_error', 'symlink', 'duplicate'])
def test_source_integrity_failures_never_create_counterevidence(change):
    finding = oauth()
    source = OAUTH.encode()
    if change == 'path':
        finding['file'] = 'absent.ts'
    if change == 'range':
        finding['line_end'] = 999
    if change == 'bool_range':
        finding['line_start'] = True
    if change == 'bad_utf8':
        source += b'\xff'
    if change == 'parser_error':
        source += b'export {'
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, 'w') as z:
        info = zipfile.ZipInfo('source.ts')
        if change == 'symlink':
            info.external_attr = 0o120777 << 16
        z.writestr(info, source)
        if change == 'duplicate':
            with pytest.warns(UserWarning):
                z.writestr('source.ts', source)
    assert result(ConsequenceVerifier(archive).checks_for(finding), TOKEN)['result'] == 'not_checked'


def test_bounds_are_per_audit_and_cache_does_not_accept_model_proof():
    verifier = ConsequenceVerifier(make_zip({'source.ts': OAUTH.encode()}))
    verifier.remaining = 1
    finding = oauth()
    finding['source_binding'] = {'result': 'contradicted', 'guard': 'trusted'}
    assert result(verifier.checks_for(finding), TOKEN)['result'] == 'not_checked'
    verifier = ConsequenceVerifier(make_zip({'source.ts': OAUTH.encode()}))
    assert result(verifier.checks_for(finding), TOKEN)['result'] == 'observed'
    verifier.checks = 40
    assert result(verifier.checks_for(finding), TOKEN)['result'] == 'not_checked'


@pytest.mark.parametrize('source,finding', [(OAUTH, oauth()), (REACT, clicks()), (DISCARD, discarded())])
def test_syntax_integration_does_not_add_a_contradiction_or_source_excerpts(source, finding):
    verifier = SyntaxVerifier(make_zip({finding['file']: source.encode()}))
    evidence = {'version': 1, 'syntax_check': verifier.check(finding),
                'premise_checks': verifier.premise_checks(finding),
                'context_checks': verifier.consequence_context(finding),
                'conditions_status': 'not_checked', 'consequence_status': 'not_checked'}
    assert not syntax_contradicted(evidence)
    assert not partial_contradicted(evidence)
    assert not any(c['kind'] in {TOKEN, CLICK, JSON, DUP} for c in evidence['premise_checks'])
    assert evidence['consequence_status'] == evidence['conditions_status'] == 'not_checked'
    serial = json.dumps(evidence)
    assert "redirect('/failed')" not in serial
    assert len(result(evidence['context_checks'], {'source.tsx': CLICK}.get(finding['file'],
                      TOKEN if source == OAUTH else JSON))['source_binding']['source_sha256']) == 64


def test_fake_model_pipeline_retains_http_finding_and_penalty():
    from app.scan.pipeline import run_scan
    from app.report.html import render_report
    finding = discarded(file='components/Commit.tsx')
    finding.update(severity='high', category='Frontend', confidence=0.9,
                   evidence="await fetch('/api/commit', {method:'POST'});", fix_hint='Check HTTP success.')
    result_scan = run_scan(make_zip({finding['file']: DISCARD.encode()}).getvalue(),
                           FakeLLM(response=json.dumps([finding])), llm_rubrics=('web',))
    rows = result_scan['findings']
    row = next(f for f in rows if f['title'] == finding['title'])
    assert not partial_contradicted(row['claim_evidence'])
    assert not syntax_contradicted(row['claim_evidence'])
    assert result(row['claim_evidence']['context_checks'], JSON)['result'] == 'observed'
    assert not any(c['kind'] == JSON for c in row['claim_evidence']['premise_checks'])
    assert row['severity'] == 'high'
    assert row['verification_status'] == 'unverified'
    from dataclasses import fields
    from app.scan.scoring import ScoredFinding, compute_scores
    allowed = {field.name for field in fields(ScoredFinding)}
    scored = ScoredFinding(**{key: value for key, value in row.items() if key in allowed})
    plain = ScoredFinding(**{key: value for key, value in row.items() if key in allowed and key != 'claim_evidence'})
    assert compute_scores([scored]) == compute_scores([plain])
    html = render_report(result_scan)
    assert 'discards its sole awaited fetch response' in html


@pytest.mark.parametrize('source,finding', [
    (OAUTH, {**oauth(), 'explanation': 'An absent access token cannot be stored.'}),
    (DISCARD, {**discarded(), 'explanation': 'There is no response.json() call in this handler.'}),
    (DISCARD, {**discarded(), 'explanation': 'response.json() is absent; HTTP status remains unchecked.'}),
    (REACT, {**clicks(), 'title': 'Same-tick invocation duplicates input',
             'explanation': 'Programmatic calls click twice through a stale closure.'}),
    (CLIENT, {**duplicate(), 'explanation': 'The duplicate-key return prevents the follow-up query.'}),
])
def test_negative_or_out_of_scope_narratives_do_not_invent_positive_premises(source, finding):
    assert not any(c['result'] == 'contradicted' for c in check(source, finding, route_files()))


def test_json_selection_handles_negation_about_another_mechanism():
    finding = discarded()
    finding['explanation'] = ('The code proceeds to navigation without error handling, '
                              'or if response.json() throws the catch resets state.')
    assert result(check(DISCARD, finding), JSON)['result'] == 'observed'


@pytest.mark.parametrize('replacement', [
    "{ const {credential} = {credential: null}; await db.from('connections').upsert({sealed:seal(credential)}); }",
    "{ const {value: credential} = other; await db.from('connections').upsert({sealed:seal(credential)}); }",
    "{ const [credential] = values; await db.from('connections').upsert({sealed:seal(credential)}); }",
    "try { work(); } catch (credential) { await db.from('connections').upsert({sealed:seal(credential)}); }",
])
def test_destructuring_and_catch_shadows_do_not_link_outer_guard_to_inner_write(replacement):
    source = OAUTH.replace("await db.from('connections').upsert({sealed:seal(credential)});", replacement)
    assert result(check(source, oauth(source)), TOKEN)['result'] == 'not_checked'


@pytest.mark.parametrize('explanation', [
    'The handler ignores the response and does not parse it with response.json().',
    'The handler ignores the response instead of calling response.json().',
    'The handler discards the response; add response.json() to validate the payload.',
    'The helper parses errors with response.json(), while this handler discards its response.',
    'The handler navigates without checking status; response.json() would catch malformed JSON.',
    'If the helper calls response.json() and it throws, its catch shows an error.',
    'The handler should call response.json() to catch malformed bodies.',
    'The current handler never calls response.json().',
    'The handler could add a branch: if response.json() throws, the catch handles it.',
])
def test_json_negative_advice_or_other_scope_gets_no_contradicted_assertion(explanation):
    finding = discarded()
    finding['explanation'] = explanation
    checks = check(DISCARD, finding)
    assert not any(c['result'] == 'contradicted' for c in checks)
    for observed in checks:
        if observed['result'] == 'observed':
            assert 'discards its sole awaited fetch' in observed['claim']


def test_even_affirmative_prose_only_selects_true_source_context():
    finding = discarded()
    finding['explanation'] = 'The handler directly calls response.json().'
    assert result(check(DISCARD, finding), JSON)['result'] == 'observed'


@pytest.mark.parametrize('explanation', [
    'The missing OAuth response status check can store a nonempty invalid access token.',
    'The handler returns when the access token is missing and writes a present token to storage.',
    'An absent access token is rejected before storage, but a nonempty invalid token is stored.',
])
def test_oauth_topic_words_never_manufacture_an_absent_token_claim(explanation):
    finding = oauth()
    finding['explanation'] = explanation
    checks = check(OAUTH, finding)
    assert not any(c['result'] == 'contradicted' for c in checks)
    proof = result(checks, TOKEN)
    assert proof['result'] == 'observed'
    assert proof['source_binding']['binding'] == 'credential'
    assert 'local binding has a falsy early return' in proof['claim']


def test_a_different_unguarded_token_is_not_refuted_by_the_guarded_binding():
    source = OAUTH.replace(' await db', ' const refreshToken = null;\n await db').replace(
        '{sealed:seal(credential)}', '{sealed:seal(credential), refreshToken}')
    finding = oauth(source)
    finding['explanation'] = 'The OAuth handler stores an absent refreshToken alongside the checked access token.'
    proof = result(check(source, finding), TOKEN)
    assert proof['result'] == 'observed'
    assert proof['source_binding']['binding'] == 'credential'
    assert 'does not settle' in proof['detail']


@pytest.mark.parametrize('explanation', [
    'The duplicate-key guard returns before its query. Repeated successful requests with different keys '
    'run the follow-up query twice.',
    'The duplicate-key branch avoids repeated queries, but the UI still advances twice.',
    'The second request with a different target is not a duplicate-key error and still runs the follow-up query.',
])
def test_duplicate_guard_context_never_refutes_a_different_request_condition(explanation):
    finding = duplicate()
    finding['explanation'] = explanation
    proof = result(check(CLIENT, finding, route_files()), DUP)
    assert proof['result'] == 'observed'
    assert '23505 error branch returns' in proof['claim']
    assert 'does not settle' in proof['detail']


def test_forged_typed_counterexample_never_changes_the_source_only_contract():
    finding = discarded()
    finding.update(premises=[{'kind': JSON, 'target': 'commit', 'line_start': finding['line_start'],
                             'line_end': finding['line_end'], 'result': 'contradicted'}],
                   claim_evidence={'syntax_check': {'result': 'contradicted'}})
    checks = check(DISCARD, finding)
    assert result(checks, JSON)['result'] == 'observed'
    assert not any(c['result'] == 'contradicted' for c in checks)


@pytest.mark.parametrize('declaration', [
    'class credential {}',
    'enum credential { Empty }',
    'namespace credential { export const value = null; }',
])
def test_runtime_declaration_shadow_does_not_link_outer_guard_to_inner_value(declaration):
    source = OAUTH.replace("await db.from('connections').upsert({sealed:seal(credential)});",
                           "{ " + declaration + " await db.from('connections').upsert({sealed:seal(credential)}); }")
    assert result(check(source, oauth(source)), TOKEN)['result'] == 'not_checked'

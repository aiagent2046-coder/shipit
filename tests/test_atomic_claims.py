"""v3 audit regressions and paired counterexamples, no provider or source execution."""
import json

import pytest

from app.scan.atomic_claims import check_source
from app.scan.claim_evidence import syntax_contradicted
from app.scan.pipeline import run_scan
from app.scan.syntax_claims import SyntaxVerifier
from app.report.html import render_report
from app.report.evidence import finding_counts
from tests.test_audit_llm_wiring import FakeLLM, make_zip

PATH = 'app/api/auth/route.ts'
HTTP = '''export async function POST(req) {
  try {
    const res = await fetch('https://example.invalid');
    if (!res.ok) {
      const err = await res.text();
      console.error(err);
      return NextResponse.json({error: 'upstream'}, {status: 500});
    }
    const data = await res.json();
    return NextResponse.json({data});
  } catch {
    return NextResponse.json({error: 'network'});
  }
}'''
INTL = '''function isValidTz(tz) {
  try {
    new Intl.DateTimeFormat('en', {timeZone: tz});
    return true;
  } catch {
    return false;
  }
}'''
SCHEMA = '''import {z} from 'zod';
const BehavioralSchema = z.object({
  values: z.object({name: z.string()}),
  conflict: z.object({name: z.string()}),
});
export async function POST(req) {
  const body = await req.json().catch(() => null);
  const parsed = BehavioralSchema.safeParse(body?.behavioral_profile);
  if (!parsed.success) { return NextResponse.json({error: 'invalid'}, {status: 400}); }
  return db.from('profiles').update({profile: parsed.data});
}'''
CLAMP = '''export async function GET(req) {
  const rawLimit = parseInt(req.nextUrl.searchParams.get('limit') ?? '20', 10);
  const matchCount = Number.isFinite(rawLimit) ? Math.min(100, Math.max(1, rawLimit)) : 20;
  return db.rpc('match_founders', {match_count: matchCount});
}'''
JSON_CATCH = '''async function submit() {
  const res = await fetch('/api/auth');
  const data = await res.json().catch(() => ({}));
  setSaving(false);
}'''


def request(kind, source, target='', marker=None):
    line = next(i + 1 for i, text in enumerate(source.splitlines()) if marker in text) if marker else 1
    return dict(kind=kind, target=target, line_start=line, line_end=line)


def check(source, kind, target='', marker=None):
    return check_source(source.encode(), PATH, request(kind, source, target, marker))


@pytest.mark.parametrize('source,kind,marker', [
    (HTTP, 'http_status_guard_absent', 'const res'),
    (INTL, 'intl_catch_absent', 'function isValid'),
    (SCHEMA, 'required_nested_objects_absent', 'const body'),
    (CLAMP, 'query_limit_unbounded', 'const rawLimit'),
    (JSON_CATCH, 'json_rejection_uncaught', 'const res'),
])
def test_v3_same_object_premises_have_source_counterexamples(source, kind, marker):
    result = check(source, kind, marker=marker)
    assert result['result'] == 'contradicted', result
    assert result['source_line_start'] > 0
    assert 'https://example.invalid' not in json.dumps(result)


@pytest.mark.parametrize('source', [
    HTTP.replace('!res.ok', '!other.ok'),
    HTTP.replace('!res.ok', 'res.ok'),
    HTTP.replace('return NextResponse.json({error: \'upstream\'}, {status: 500});', 'log();'),
    HTTP.replace('if (!res.ok)', 'if (enabled && !res.ok)'),
    HTTP.replace('const data = await res.json();', 'res = other;\n const data = await res.json();'),
    HTTP.replace('const data = await res.json();', 'const res = other;\n const data = await res.json();'),
    HTTP.replace('if (!res.ok)', 'if (!res.ok || bypass)'),  # unsupported, not guessed
    HTTP.replace('const data = await res.json();', 'const a = await res.json();\n const data = await res.json();'),
    HTTP.replace('    if (!res.ok)', '    function later() { if (!res.ok)')
        .replace('    const data', '    }\n    const data'),
])
def test_http_other_binding_nonterminal_guard_shadow_and_multiple_parses_stay_unknown(source):
    assert check(source, 'http_status_guard_absent', marker='const res')['result'] == 'not_checked'


def test_guard_after_parse_and_catch_only_do_not_disprove_missing_status_check():
    source = '''async function run() {
 const res = await fetch('/api');
 const data = await res.json();
 if (!res.ok) return;
}'''
    assert check(source, 'http_status_guard_absent')['result'] == 'not_checked'
    source = source.replace(' if (!res.ok) return;', '')
    assert check(source, 'http_status_guard_absent')['result'] == 'not_checked'


@pytest.mark.parametrize('source', [
    INTL.replace('return false;', 'throw error;'),
    INTL.replace('function isValidTz(tz)', 'function isValidTz(tz, Intl)'),
    INTL.replace('    new Intl', '    const later = () => new Intl'),
    "const Intl = custom;\n" + INTL,
    INTL.replace('    new Intl', '    new Other.DateTimeFormat(tz);\n    new Intl'),
])
def test_intl_scope_binding_rethrow_and_multiple_targets_remain_unknown(source):
    assert check(source, 'intl_catch_absent', marker='function isValid')['result'] == 'not_checked'


@pytest.mark.parametrize('source', [
    SCHEMA.replace('values: z.object({name: z.string()})', 'values: z.object({name: z.string()}).optional()'),
    SCHEMA.replace('});\nexport', '}).partial();\nexport'),
    SCHEMA.replace('!parsed.success', 'parsed.success'),
    SCHEMA.replace('BehavioralSchema.safeParse(body?.behavioral_profile)', 'otherSchema.safeParse(body)'),
    SCHEMA.replace("from 'zod'", "from './custom-zod'"),
    SCHEMA.replace("export async function POST(req)", "export async function POST(req, z)"),
    SCHEMA.replace("return NextResponse.json({error: 'invalid'}, {status: 400});", "log();"),
    SCHEMA.replace('  const parsed', '  db.write(parsed.data);\n  const parsed'),
])
def test_optional_schema_other_binding_and_nonreturning_validation_remain_unknown(source):
    assert check(source, 'required_nested_objects_absent', marker='const body')['result'] == 'not_checked'


@pytest.mark.parametrize('source', [
    CLAMP.replace('match_count: matchCount', 'match_count: rawLimit'),
    CLAMP.replace('Math.max(1, rawLimit)', 'Math.max(-1, rawLimit)'),
    CLAMP.replace(': 20;', ': -20;'),
    CLAMP.replace('Math.min(100,', 'Math.min(1e99,'),
    CLAMP.replace('const matchCount', 'let matchCount'),
    CLAMP.replace('  return db.rpc', '  matchCount = 999;\n  return db.rpc'),
    CLAMP.replace('GET(req)', 'GET(req, Number)'),
    CLAMP.replace('match_count: matchCount', 'match_count: matchCount, ...external'),
])
def test_clamp_must_feed_actual_query_argument_and_have_valid_bounds(source):
    assert check(source, 'query_limit_unbounded')['result'] == 'not_checked'


@pytest.mark.parametrize('source', [
    JSON_CATCH.replace('.catch(() => ({}))', ''),
    JSON_CATCH.replace('() => ({})', '() => fallback()'),
    JSON_CATCH.replace('res.json().catch', 'other.json().catch'),
    JSON_CATCH.replace('() => ({})', '() => ({value: mightThrow()})'),
])
def test_json_fallback_requires_same_promise_and_literal_handler(source):
    assert check(source, 'json_rejection_uncaught')['result'] == 'not_checked'


def raw(source, title, marker, **changes):
    line = next(i+1 for i, text in enumerate(source.splitlines()) if marker in text)
    return dict(file=PATH, line_start=line, line_end=line, evidence=marker,
                title=title, severity='high', confidence=1.0,
                explanation='If the stated premise holds, this path could fail.',
                fix_hint='Verify the premise before changing the handler.', **changes)


@pytest.mark.parametrize('source,title,marker', [
    (HTTP, 'Missing HTTP status check in auto-reply generation', 'const res'),
    (INTL, 'Time zone validation relies on Intl API without error handling', 'function isValid'),
    (SCHEMA, 'Zod schema validation does not enforce required nested object structure', 'const body'),
])
def test_scan_json_and_html_keep_atomic_contradictions_out_of_active_count(source, title, marker):
    finding = raw(source, title, marker)
    scan = run_scan(make_zip({PATH: source.encode()}).getvalue(), FakeLLM(response=json.dumps([finding])),
                    llm_rubrics=('auth',))
    model = [f for f in scan['findings'] if f['source'] == 'llm']
    assert len(model) == 1
    assert syntax_contradicted(model[0]['claim_evidence'])
    assert finding_counts(model) == (0, 0)
    html = render_report({**scan, 'findings': model})
    assert 'Syntax premise contradicted' in html
    assert title in html
    assert 'No independent verification recorded' in html


def test_partial_json_contradiction_keeps_network_failure_claim_active():
    f = raw(JSON_CATCH, 'Network and JSON errors can leave saving stuck', 'const res', premises=[
        {**request('json_rejection_uncaught', JSON_CATCH, 'res'), 'result': 'verified'},
    ])
    scan = run_scan(make_zip({PATH: JSON_CATCH.encode()}).getvalue(), FakeLLM(response=json.dumps([f])),
                    llm_rubrics=('auth',))
    model = [f for f in scan['findings'] if f['source'] == 'llm']
    record = model[0]['claim_evidence']
    assert record['premise_checks'][0]['result'] == 'contradicted'
    assert not syntax_contradicted(record)
    assert finding_counts(model) == (1, 0)
    assert 'Atomic premise contradicted — other claims remain unverified' in render_report(scan)


def test_model_cannot_use_another_function_to_dismiss_the_cited_finding():
    unsafe = '''async function unsafe() {
 const res = await fetch('/api');
 const data = await res.json();
}'''
    source = unsafe + '\n' + HTTP
    f = raw(source, 'Missing HTTP status check', 'async function unsafe', premises=[
        request('http_status_guard_absent', source, 'res', 'const res = await fetch(\'https'),
    ])
    verifier = SyntaxVerifier(make_zip({PATH: source.encode()}))
    assert verifier.premise_checks(f)[0]['result'] == 'not_checked'
    assert verifier.check(f)['result'] == 'not_checked'


def test_bounded_check_does_not_accept_forged_metadata_or_execute_source(monkeypatch):
    from app.scan import syntax_claims
    f = raw(HTTP, 'Missing HTTP status check', 'const res', premises=[
        {'kind': 'http_status_guard_absent', 'target': 'res', 'line_start': 3, 'line_end': 3,
         'result': 'verified', 'proof': '<script>forged()</script>'},
        {'kind': 'invented_proof', 'target': 'res', 'line_start': 3, 'line_end': 3},
    ])
    verifier = SyntaxVerifier(make_zip({PATH: HTTP.encode()}))
    checks = verifier.premise_checks(f)
    assert len(checks) == 1 and checks[0]['result'] == 'contradicted'
    assert 'forged' not in json.dumps(checks)
    monkeypatch.setattr(syntax_claims, 'MAX_CHECKS', 0)
    assert SyntaxVerifier(make_zip({PATH: HTTP.encode()})).check(f)['result'] == 'not_checked'


@pytest.mark.parametrize('prefix', ['', 'export-root/'])
def test_static_service_role_recommendations_keep_each_routes_policy_prerequisites(prefix):
    from app.llm.client import LLMClient
    from tests.test_scan_service_role import ROUTE
    files = {
        prefix + 'app/api/messages/route.ts': ROUTE,
        prefix + 'app/api/context/route.ts': ROUTE.replace(
            "from('messages').select('*')", "from('context').insert({})"),
        prefix + 'supabase/migrations/0001_policies.sql':
            'CREATE POLICY reads ON public.messages FOR SELECT USING(true);',
    }
    scan = run_scan(make_zip({p: s.encode() for p, s in files.items()}).getvalue(), LLMClient(providers=[]))
    model = [f for f in scan['findings'] if f['rule_id'] == 'supabase-service-role-route']
    assert len(model) == 1
    finding = model[0]
    contexts = finding['claim_evidence']['context_checks']
    assert {c['operation'] for c in contexts} == {'SELECT', 'INSERT'}
    assert {c['table'] for c in contexts} == {'messages', 'context'}
    assert finding['claim_evidence']['source_check'] == {'kind': 'static_rule'}
    assert 'SELECT policies alone do not authorize writes' in finding['fix_hint']
    html = render_report(scan)
    assert 'Superseded original recommendation' in html
    assert 'public.context: INSERT' in html or 'context' in html


@pytest.mark.parametrize('kind', [None, [], {}, True, 'made_up'])
def test_invalid_model_premise_kind_cannot_fail_the_scan(kind):
    verifier = SyntaxVerifier(make_zip({PATH: HTTP.encode()}))
    f = raw(HTTP, 'Unrelated observation', 'const res', premises=[{
        'kind': kind, 'target': 'res', 'line_start': 3, 'line_end': 3,
    }])
    assert verifier.premise_checks(f) == []


def test_duplicate_zod_field_cannot_be_proved_required_from_overwritten_shape():
    source = SCHEMA.replace('  conflict:', '  values: z.any(),\n  conflict:')
    assert check(source, 'required_nested_objects_absent', marker='const body')['result'] == 'not_checked'


def test_atomic_title_cannot_dismiss_an_additional_independent_premise():
    f = raw(HTTP, 'Missing HTTP status check', 'const res', premises=[
        request('http_status_guard_absent', HTTP, 'res', 'const res'),
        request('json_rejection_uncaught', HTTP, 'res', 'const res'),
    ])
    verifier = SyntaxVerifier(make_zip({PATH: HTTP.encode()}))
    assert verifier.check(f)['result'] == 'not_checked'
    assert [p['result'] for p in verifier.premise_checks(f)] == ['contradicted', 'not_checked']
    f.pop('premises')
    f['explanation'] = 'Additionally, transport errors skip the loading reset.'
    assert verifier.check(f)['result'] == 'not_checked'


def test_unqualified_limit_premise_cannot_select_one_of_two_queries():
    source = CLAMP.replace("  return db.rpc", "  other.limit(untrusted);\n  return db.rpc")
    assert check(source, 'query_limit_unbounded')['result'] == 'not_checked'
    assert check(source, 'query_limit_unbounded', target='matchCount')['result'] == 'contradicted'


def test_second_intl_call_without_new_keeps_target_ambiguous():
    source = INTL.replace('  try {', "  Intl.DateTimeFormat('en', {timeZone: tz});\n  try {")
    assert check(source, 'intl_catch_absent')['result'] == 'not_checked'


def test_throwing_json_handler_parameter_is_not_a_literal_fallback():
    source = JSON_CATCH.replace('() => ({})', '({message = fail()}) => ({})')
    assert check(source, 'json_rejection_uncaught')['result'] == 'not_checked'


def test_duplicate_zod_import_does_not_prove_a_binding():
    source = "import {z} from './custom';\n" + SCHEMA
    assert check(source, 'required_nested_objects_absent', marker='const body')['result'] == 'not_checked'

"""Synthetic one-hop import boundaries; no target fixtures, target execution or APIs."""
import hashlib
import io
import json
import stat
import struct
import zipfile

import pytest

from app.scan import imported_error_context as c
from app.scan.claim_evidence import partial_contradicted, syntax_contradicted
from app.scan.scoring import ScoredFinding, compute_scores
from app.scan.syntax_claims import SyntaxVerifier
from tests.test_audit_llm_wiring import make_zip
from tests.test_llm_scan import FakeLLM

HELPER = '''export function decode(value: string) {
 if (!value) throw new Error('PRIVATE_LITERAL');
 return value;
}'''
CALLER = '''import { decode } from './helper';
export function consumer(value) {
 try {
  return decode(value);
 } catch {
  return null;
 }
}'''
NETWORK = '''export async function session() {
 try {
  const reply = await fetch('/PRIVATE_URL');
  if (!reply.ok) return null;
  const {value} = await reply.json();
  return value ?? null;
 } catch {
  return null;
 }
}'''
UI = '''import { session } from './helper';
export function Widget() {
 const submit = async () => {
  busy(true);
  const token = await session();
  await fetch('/save', {body:token});
  busy(false);
 };
 return <button onClick={submit}>Save</button>;
}'''


@pytest.mark.parametrize('passes', [1, 2])
def test_scan_retains_cross_file_context_without_rejecting_or_reclassifying_claim(passes):
    from app.scan.cross_rubric_dedup import _flatten, dedup_cross_rubric
    from app.scan.llm_scan import run_llm_scan

    raw = {
        'file': 'src/consumer.tsx', 'line_start': 5, 'line_end': 5,
        'evidence': 'const token = await session();',
        'title': 'Helper network rejection can leave pending state unchanged',
        'explanation': 'The handler clears its busy flag only after the awaited work.',
        'required_conditions': ['The imported session helper propagates a network error.'],
        'fix_hint': 'Review the error path before changing this handler.',
        'severity': 'medium', 'confidence': 0.8, 'category': 'Frontend',
    }
    findings, stats = run_llm_scan(
        make_zip({'src/consumer.tsx': UI.encode(), 'src/helper.ts': NETWORK.encode()}),
        FakeLLM(json.dumps([raw])), rubrics=('web',), passes=passes,
    )
    assert stats.calls == stats.verified == passes
    assert stats.discarded == 0
    assert len(findings) == 1
    originals = list(_flatten(findings[0]))
    assert len(originals) == passes
    for original in originals:
        assert original.title == raw['title']
        assert original.severity == 'medium'
        assert original.confidence == 0.8
        assert original.category == 'Frontend'
        evidence = original.claim_evidence
        assert evidence['required_conditions'] == raw['required_conditions']
        record, = observed(evidence['context_checks'])
        assert record['kind'] == c.KIND
        assert record['source_binding']['callee']['file'] == 'src/helper.ts'
        assert len(record['source_binding']['callee_operations']) == 2
        assert not syntax_contradicted(evidence)
        assert not partial_contradicted(evidence)
    assert dedup_cross_rubric(findings) == findings


def finding(path='src/consumer.ts', start=4, end=None):
    return {'file': path, 'line_start': start, 'line_end': start if end is None else end,
            'title': 'A helper error is uncaught and leaves the operation busy',
            'explanation': 'A network rejection may interrupt later work.'}


def check(caller=CALLER, helper=HELPER, *, raw=None, extra=None):
    raw = raw or finding()
    caller_path = 'src/consumer.tsx' if '<button' in caller else 'src/consumer.ts'
    if raw['file'] == 'src/consumer.ts':
        raw = {**raw, 'file': caller_path}
    sources = {caller_path: caller.encode(), 'src/helper.ts': helper.encode(), **(extra or {})}
    return c.ImportedErrorVerifier(make_zip(sources)).checks_for(raw)


def bound(records):
    return [record for record in records if 'source_binding' in record]


def observed(records):
    return [record for record in bound(records) if record['result'] == 'observed']


def test_direct_sync_caller_literal_return_has_bound_import_hashes_and_spans():
    record, = observed(check())
    binding = record['source_binding']
    assert record['scope'] == 'bounded_source_context'
    assert binding['import']['name'] == 'decode'
    assert binding['source_sha256'] == hashlib.sha256(CALLER.encode()).hexdigest()
    assert binding['callee']['source_sha256'] == hashlib.sha256(HELPER.encode()).hexdigest()
    call_start, call_end = binding['call']['span']
    assert CALLER.encode()[call_start:call_end] == b'decode(value)'
    boundary = binding['caller_error_boundary']
    assert boundary['synchronous_throw'] == 'enters_recorded_catch'
    assert boundary['promise_rejection'] == 'not_checked'
    assert boundary['catch_behavior']['behavior'] == 'literal_return'
    assert boundary['catch_behavior']['return_kind'] == 'null'
    assert 'PRIVATE_LITERAL' not in json.dumps(record)


def test_exported_helper_finding_links_checked_direct_caller_without_all_callers_claim():
    record, = observed(check(raw=finding('src/helper.ts', 2)))
    assert record['source_binding']['direction'] == 'caller'
    assert record['source_binding']['file'] == 'src/consumer.ts'
    assert 'not all callers' in record['detail']


def test_imported_async_helper_records_own_direct_awaited_network_and_json_boundaries():
    record, = observed(check(UI, NETWORK, raw=finding(start=4, end=7)))
    binding = record['source_binding']
    assert binding['caller_function']['name'] == 'submit'
    assert binding['caller_error_boundary']['result'] == 'not_checked'
    assert binding['callee']['async_syntax'] is True
    operations = binding['callee_operations']
    assert [o['operation'] for o in operations] == [
        'direct_awaited_fetch_syntax', 'direct_awaited_response_json_syntax']
    for op in operations:
        boundary = op['error_boundary']
        assert boundary['promise_rejection'] == 'enters_recorded_catch'
        assert boundary['catch_behavior']['return_kind'] == 'null'
    assert 'PRIVATE_URL' not in json.dumps(record)
    # The handler's later, independent fetch is not covered by helper evidence.
    assert [o['call']['file'] for o in operations] == ['src/helper.ts'] * 2


@pytest.mark.parametrize('callee', [
    HELPER.replace('function decode', 'async function decode'),
    HELPER.replace('return value;', 'return Promise.reject(value);'),
])
def test_non_awaited_call_never_claims_to_catch_promise_rejection(callee):
    record, = observed(check(helper=callee))
    assert record['source_binding']['caller_error_boundary']['promise_rejection'] == 'not_checked'


def test_direct_await_caller_covers_rejection_at_exact_call():
    caller = CALLER.replace('function consumer', 'async function consumer').replace(
        'return decode', 'return await decode')
    record, = observed(check(caller, HELPER.replace('function decode', 'async function decode')))
    assert record['source_binding']['caller_error_boundary']['promise_rejection'] == 'enters_recorded_catch'


@pytest.mark.parametrize('catch', [
    'log(); return null;', 'await log(); return null;', 'throw new Error(); return null;',
    'return Promise.reject(reason);', 'return fallback();', 'if (ok) return null;',
    'return reason;', 'return {ok:false};', 'try {return null;} finally {throw reason;}',
])
def test_catch_effects_or_conditional_nonliteral_return_are_unknown(catch):
    caller = CALLER.replace('function consumer', 'async function consumer').replace('  return null;', f'  {catch}')
    assert not observed(check(caller))
    record, = bound(check(caller))
    assert record['source_binding']['caller_error_boundary']['catch_behavior']['result'] == 'not_checked'


@pytest.mark.parametrize('tail', ['finally {}', 'finally { throw reason; }', 'finally { return other; }'])
def test_enclosing_finally_never_proves_recovery(tail):
    caller = CALLER.replace('  return null;\n }', '  return null;\n } ' + tail)
    assert not observed(check(caller))


def test_outer_finally_can_override_inner_catch_return():
    caller = CALLER.replace(' try {', ' try { try {').replace('\n}', '\n } finally {throw reason;}\n}')
    assert not observed(check(caller))


def test_rethrow_is_recorded_as_rethrow_and_not_literal_return():
    caller = CALLER.replace('} catch {', '} catch (reason) {').replace('return null;', 'throw reason;')
    record, = observed(check(caller))
    assert record['source_binding']['caller_error_boundary']['catch_behavior']['behavior'] == 'rethrow'


def test_lexical_try_outside_callback_does_not_handle_its_call():
    caller = CALLER.replace('return decode(value);', 'setTimeout(() => decode(value), 0);')
    assert not observed(check(caller))


def test_non_direct_await_does_not_cover_nested_argument_promise():
    caller = CALLER.replace('function consumer', 'async function consumer').replace(
        'return decode(value);', 'return await wrap(decode(value));')
    record, = observed(check(caller))
    assert record['source_binding']['caller_error_boundary']['promise_rejection'] == 'not_checked'


@pytest.mark.parametrize('body', [
    "try { queue(async () => {await fetch('/');}); } catch {return null;}",
    "try { return fetch('/'); } catch {return null;}",
    "try { await wrapper(fetch('/')); } catch {return null;}",
    "try { const r = await fetch('/'); await r.json(); } catch {log(); return null;}",
    "try { const r = await fetch('/'); await r.json(); } catch {return Promise.reject(reason);}",
    "try { await fetch('/'); } catch {return null;} finally {throw reason;}",
])
def test_helper_deferred_network_and_unsafe_catches_abstain(body):
    helper = 'export async function session() { ' + body + ' }'
    assert not observed(check(UI, helper, raw=finding(start=5)))


def test_nonawaited_json_is_not_reported_as_awaited_rejection_boundary():
    records = check(UI, NETWORK.replace('await reply.json()', 'reply.json()'), raw=finding(start=5))
    record, = observed(records)
    assert [op['operation'] for op in record['source_binding']['callee_operations']] == ['direct_awaited_fetch_syntax']


@pytest.mark.parametrize('caller', [
    CALLER.replace('import { decode }', 'import { decode as parse }').replace('return decode', 'return parse'),
    CALLER.replace('import { decode }', 'import type { decode }'),
    CALLER.replace('import { decode }', 'import { type decode }'),
    CALLER.replace('import { decode }', 'import decode'),
    CALLER.replace('import { decode }', 'import * as mod').replace('decode(value)', 'mod.decode(value)'),
    CALLER.replace('consumer(value)', 'consumer(value, decode)'),
    CALLER.replace(' try {', ' const decode = other; try {'),
    CALLER.replace(' try {', ' decode = other; try {'),
    CALLER.replace(' try {', ' eval(code); try {'),
    CALLER.replace('decode(value)', 'decode?.(value)'),
    CALLER.replace('decode(value)', "table['decode'](value)"),
    CALLER.replace('decode(value)', 'new decode(value)'),
])
def test_aliases_shadowing_dynamic_and_non_direct_calls_abstain(caller):
    assert not observed(check(caller))


@pytest.mark.parametrize('helper', [
    HELPER.replace('export function decode', 'function decode') + '\nexport {decode};',
    HELPER + '\nexport { other as decode } from "./elsewhere";',
    HELPER.replace('return value;', 'decode = replacement; return value;'),
    'export { decode } from "./elsewhere";',
    'export const decode = wrapped;',
    'export default function decode(value) {return value;}',
    HELPER + '\nfunction decode(value) {return value;}',
])
def test_non_direct_or_ambiguous_exports_abstain(helper):
    assert not observed(check(helper=helper))


def test_const_exported_arrow_is_supported_without_name_special_cases():
    helper = 'export const decode = (value) => {throw new Error(value);};'
    record, = observed(check(helper=helper))
    assert record['source_binding']['callee']['name'] == 'decode'


def test_literal_custom_path_mapping_is_hashed_and_not_assumed_from_prefix():
    caller = CALLER.replace("'./helper'", "'~/helper'")
    config = b'{"compilerOptions":{"paths":{"~/*":["./src/*"]}}}'
    record, = observed(check(caller, extra={'tsconfig.json': config}))
    config_binding = record['source_binding']['resolution']['configuration']
    assert config_binding['source_sha256'] == hashlib.sha256(config).hexdigest()
    assert config_binding['span'] == [0, len(config)]
    assert not observed(check(caller))


@pytest.mark.parametrize('config', [
    b'{"extends":"./base.json","compilerOptions":{"paths":{"~/*":["./src/*"]}}}',
    b'{"compilerOptions":{"paths":{"~/*":["./src/*","./other/*"]}}}',
    b'{"compilerOptions":{"paths":{"~/*":["./src/*"]},"baseUrl":"../"}}',
    b'{"compilerOptions":{"paths":{"~/*":["./src/*"]},"rootDirs":["."]}}',
    b'{"compilerOptions":{"paths":{"~/*":["./src/*"]}},"compilerOptions":{}}',
    b'{/* unsupported JSONC */ "compilerOptions":{"paths":{"~/*":["./src/*"]}}}',
])
def test_ambiguous_or_extended_config_abstains(config):
    assert not observed(check(CALLER.replace("'./helper'", "'~/helper'"), extra={'tsconfig.json': config}))


def test_extension_candidates_are_not_arbitrarily_chosen():
    assert not observed(check(extra={'src/helper.tsx': HELPER.encode()}))


def test_unrelated_guarded_call_cannot_supply_cited_handler_evidence():
    caller = CALLER + '\nfunction unrelated() { return external(); }'
    assert not observed(check(caller, raw=finding(start=9)))


def test_per_audit_memoization_preserves_exact_evidence_after_budget_exhaustion_and_returns_copies():
    verifier = c.ImportedErrorVerifier(make_zip({'src/consumer.ts': CALLER.encode(), 'src/helper.ts': HELPER.encode()}))
    original = verifier.checks_for(finding())
    reads = verifier.reads
    verifier.checks = c.MAX_CHECKS
    assert verifier.checks_for({**finding(), 'title': 'Network throw in same binding'}) == original
    mutated = verifier.checks_for(finding())
    mutated[0]['source_binding']['callee']['name'] = 'mutation'
    assert verifier.checks_for(finding()) == original
    assert verifier.reads == reads
    assert not observed(verifier.checks_for(finding(start=5)))
    assert verifier.checks_for({**finding(), 'title': '', 'explanation': ''}) == []


def test_no_cross_audit_source_cache():
    assert observed(check())
    assert not observed(check(CALLER.replace('return null;', 'return fallback();')))


@pytest.mark.parametrize('field, value', [('reads', c.MAX_FILES), ('remaining', 1),
                                         ('remaining_nodes', 0), ('calls', c.MAX_TOTAL_CALLS)])
def test_per_audit_budgets_abstain(field, value):
    verifier = c.ImportedErrorVerifier(make_zip({'src/consumer.ts': CALLER.encode(), 'src/helper.ts': HELPER.encode()}))
    setattr(verifier, field, value)
    results = verifier.checks_for(finding())
    assert not observed(results)
    assert any('budget' in r['detail'].lower() for r in results)


def test_caller_subset_exhaustion_is_visible_and_does_not_imply_absence(monkeypatch):
    monkeypatch.setattr(c, 'MAX_CALLER_FILES', 1)
    records = check(raw=finding('src/helper.ts', 2), extra={'src/aaa.ts': b'export const unrelated=1;'})
    assert not observed(records)
    assert any('caller-file subset' in r['detail'] for r in records)


def test_invalid_encoding_parse_errors_and_oversize_sources_abstain():
    for source in [b'\xff', b'export function decode( {', b' ' * (c.MAX_FILE_BYTES + 1)]:
        records = check(extra={'src/helper.ts': source})
        assert not observed(records)


def test_symlink_duplicate_and_unsafe_archive_paths_are_not_bound():
    for mode in ('symlink', 'duplicate', 'unsafe'):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w') as zf:
            zf.writestr('src/consumer.ts', CALLER)
            if mode == 'symlink':
                info = zipfile.ZipInfo('src/helper.ts')
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                zf.writestr(info, HELPER)
            elif mode == 'duplicate':
                zf.writestr('src/helper.ts', HELPER)
                with pytest.warns(UserWarning):
                    zf.writestr('src/helper.ts', HELPER)
            else:
                zf.writestr('../src/helper.ts', HELPER)
        assert not observed(c.ImportedErrorVerifier(archive).checks_for(finding()))


def test_context_only_syntax_verifier_hook_does_not_change_disposition_or_score():
    archive = make_zip({'src/consumer.ts': CALLER.encode(), 'src/helper.ts': HELPER.encode()})
    records = SyntaxVerifier(archive).imported_error_context(finding())
    assert observed(records)
    evidence = {'version': 1, 'context_checks': records}
    assert not syntax_contradicted(evidence) and not partial_contradicted(evidence)
    kwargs = {'rule_id': 'llm-risk', 'title': finding()['title'], 'category': 'Security',
              'severity': 'high', 'confidence': 1}
    assert compute_scores([ScoredFinding(**kwargs, claim_evidence=evidence)]) == compute_scores(
        [ScoredFinding(**kwargs)])
    assert compute_scores([ScoredFinding(**kwargs)]) != compute_scores([])


@pytest.mark.parametrize('parameter', ['{x:{y}}', '{x = fallback()}', '[reason]'])
def test_destructured_catch_parameter_can_throw_before_return(parameter):
    caller = CALLER.replace('} catch {', '} catch (' + parameter + ') {')
    assert not observed(check(caller))
    helper = NETWORK.replace('} catch {', '} catch (' + parameter + ') {')
    assert not observed(check(UI, helper, raw=finding(start=5)))


@pytest.mark.parametrize('declaration', ['enum fetch {x}', 'namespace fetch {}', 'class fetch {}',
                                        'enum reply {x}', 'namespace reply {}'])
def test_nonstandard_runtime_name_declarations_do_not_bind_network_operations(declaration):
    helper = NETWORK.replace(' try {', ' ' + declaration + '; try {')
    records = bound(check(UI, helper, raw=finding(start=5)))
    operations = records[0]['source_binding']['callee_operations'] if records else []
    if 'fetch' in declaration:
        assert not operations
    else:
        assert not any(o['operation'] == 'direct_awaited_response_json_syntax' for o in operations)


@pytest.mark.parametrize('parameter', [r'd\u0065code', r'{d\u0065code}', r'{x:d\u0065code}', r'[d\u0065code]'])
def test_escaped_identifier_shadowing_abstains(parameter):
    caller = CALLER.replace('consumer(value)', 'consumer(value, ' + parameter + ')')
    assert not observed(check(caller))


def test_exact_mapping_competing_with_wildcard_is_ambiguous():
    config = b'{"compilerOptions":{"paths":{"~/*":["./src/*"],"~/helper":["./other.ts"]}}}'
    records = check(CALLER.replace("'./helper'", "'~/helper'"),
                    extra={'tsconfig.json': config, 'other.ts': HELPER.encode()})
    assert not observed(records)


def test_relative_import_honors_unknown_module_suffix_configuration():
    config = b'{"compilerOptions":{"moduleSuffixes":[".native", ""]}}'
    assert not observed(check(extra={'tsconfig.json': config, 'src/helper.native.ts': HELPER.encode()}))


def test_explicit_javascript_import_with_typescript_alternative_is_ambiguous():
    assert not observed(check(CALLER.replace("'./helper'", "'./helper.js'"),
                              extra={'src/helper.js': HELPER.encode()}))


def test_named_function_expression_does_not_export_its_internal_name():
    helper = 'export const decode = function internal(value) {throw value;};'
    record, = observed(check(helper=helper))
    assert record['source_binding']['callee']['name'] == 'decode'
    assert not observed(check(CALLER.replace('decode', 'internal'), helper))


def test_dot_prefixed_bare_package_is_not_a_relative_import():
    assert not observed(check(CALLER.replace("'./helper'", "'.helper'"),
                              extra={'src/.helper.ts': HELPER.encode()}))


@pytest.mark.parametrize('declaration', [r'class d\u0065code {}', r'enum d\u0065code {x}'])
def test_escaped_runtime_type_declaration_shadows_abstain(declaration):
    caller = CALLER.replace(' try {', ' ' + declaration + '; try {')
    assert not observed(check(caller))



def test_corrupt_compressed_member_abstains_without_exposing_decompressor_failure():
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('src/consumer.ts', CALLER)
        zf.writestr('src/helper.ts', HELPER)
        helper_info = zf.getinfo('src/helper.ts')
    data = bytearray(archive.getvalue())
    name_size, extra_size = struct.unpack_from('<HH', data, helper_info.header_offset + 26)
    data[helper_info.header_offset + 30 + name_size + extra_size] = 0xff
    assert not observed(c.ImportedErrorVerifier(io.BytesIO(data)).checks_for(finding()))


@pytest.mark.parametrize('compression', [zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA])
def test_unsupported_zip_compression_abstains(compression):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, 'w', compression=compression) as zf:
        zf.writestr('src/consumer.ts', CALLER)
        zf.writestr('src/helper.ts', HELPER)
    assert not observed(c.ImportedErrorVerifier(archive).checks_for(finding()))



@pytest.mark.parametrize('body', [
    "if (flag) {const reply = await fetch('/');} await reply.json();",
    "if (flag) {var reply = await fetch('/');} else {await reply.json();}",
    "for (let reply = await fetch('/'); flag;) {} await reply.json();",
])
def test_response_binding_requires_fetch_declaration_scope_at_json_call(body):
    helper = 'export async function session() {try {' + body + '} catch {return null;}}'
    records = bound(check(UI, helper, raw=finding(start=5)))
    operations = records[0]['source_binding']['callee_operations'] if records else []
    assert not any(o['operation'] == 'direct_awaited_response_json_syntax' for o in operations)



@pytest.mark.parametrize('statement', ['return class {value = decode(value)};',
                                      'class Deferred {value = decode(value)}; return Deferred;'])
def test_deferred_class_field_does_not_use_outer_caller_try(statement):
    caller = CALLER.replace('return decode(value);', statement)
    assert not observed(check(caller))


@pytest.mark.parametrize('limit, value', [('MAX_ARCHIVE_ENTRIES', 1), ('MAX_NODES', 2), ('MAX_CALLS', 0)])
def test_archive_node_and_per_anchor_call_limits_fail_closed(monkeypatch, limit, value):
    monkeypatch.setattr(c, limit, value)
    assert not observed(check())


def test_truncated_call_output_is_explicit(monkeypatch):
    monkeypatch.setattr(c, 'MAX_RECORDS', 1)
    caller = CALLER.replace('return decode(value);', 'decode(value); return decode(value);')
    records = check(caller)
    assert len(bound(records)) == 1
    assert any('output budget' in r['detail'] for r in records)


def test_observed_helper_network_paths_do_not_claim_other_throws_are_handled():
    helper = NETWORK.replace(' try {', " if (bad) throw new Error('PRIVATE_LITERAL'); try {")
    record, = observed(check(UI, helper, raw=finding(start=5)))
    assert 'not all callers, all throws' in record['detail']
    assert 'PRIVATE_LITERAL' not in json.dumps(record)

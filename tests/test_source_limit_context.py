"""Source-only regressions for bound numeric arguments and imported helper caps."""

import hashlib
import io
import json
import stat
import zipfile

import pytest

from app.scan import source_limit_context as c
from app.scan.claim_evidence import partial_contradicted, syntax_contradicted
from app.scan.scoring import ScoredFinding, compute_scores

NUMERIC = """export async function endpoint(req, db) {
 const rawLimit = parseInt(req.searchParams.get('PRIVATE_QUERY') ?? '20', 10);
 const matchCount = Number.isFinite(rawLimit) ? Math.min(100, Math.max(1, rawLimit)) : 20;
 const response = await db.rpc('PRIVATE_RPC', {match_count: matchCount});
 return response;
}"""
HELPER = """export const MAX_FACTS = 40;
export const MAX_FACT_LEN = 500;
export function sanitizeFacts(facts: Array<{content: string | null}>,
 opts: {maxFacts?: number; maxLen?: number} = {}): string[] {
 const maxFacts = opts.maxFacts ?? MAX_FACTS;
 const maxLen = opts.maxLen ?? MAX_FACT_LEN;
 return (facts ?? [])
  .map(f => (f?.content ?? '').trim())
  .filter(Boolean)
  .slice(0, maxFacts)
  .map(c => c.length > maxLen ? c.slice(0, maxLen) + 'PRIVATE_SUFFIX' : c);
}"""
CALLER = """import { sanitizeFacts } from './helper';
export async function consumer(db) {
 const {data: facts} = await db.from('PRIVATE_TABLE').select('content');
 const factList = sanitizeFacts(facts ?? []);
 return buildPrompt(factList);
}"""


def archive(sources):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path, source in sources.items():
            zf.writestr(path, source)
    return stream


def finding(path="src/consumer.ts", line=4, title="The facts count is unbounded"):
    return {"file": path, "line_start": line, "line_end": line, "title": title}


def check(caller=CALLER, helper=HELPER, *, raw=None, extra=None):
    return c.SourceLimitVerifier(
        archive({"src/consumer.ts": caller, "src/helper.ts": helper, **(extra or {})})
    ).checks_for(raw or finding())


def numeric(source=NUMERIC, *, raw=None):
    return check(source, raw=raw or finding(title="Query limit permits negative or zero values", line=3))


def observed(records, kind=None):
    return [r for r in records if r["result"] == "observed" and (kind is None or r["kind"] == kind)]


def test_numeric_clamp_is_bound_to_the_actual_rpc_property_with_hash_and_spans():
    (record,) = observed(numeric())
    assert record["kind"] == c.NUMERIC_KIND
    b = record["source_binding"]
    assert [b[k] for k in ("lower", "upper", "fallback")] == [1, 100, 20]
    assert b["source_sha256"] == hashlib.sha256(NUMERIC.encode()).hexdigest()
    assert NUMERIC.encode()[slice(*b["argument"]["span"])] == b"match_count: matchCount"
    assert b["clamp_declaration"]["line_start"] == 3
    assert "PRIVATE_" not in json.dumps(record)
    assert b["runtime_api_identity"] == "not_checked"


@pytest.mark.parametrize(
    "before, after",
    [
        ("Number.isFinite(rawLimit)", "isFinite(rawLimit)"),
        ("Math.min(100, Math.max(1, rawLimit))", "Math.min(100, rawLimit)"),
        ("Math.max(1, rawLimit)", "Math.max(1, other)"),
        (": 20;", ": 1000;"),
        ("match_count: matchCount", "match_count: rawLimit"),
        ("match_count: matchCount", "match_count: matchCount, ...overrides"),
        ("match_count: matchCount", "match_count: matchCount, match_count: rawLimit"),
        ("const matchCount", "let matchCount"),
        ("const rawLimit", "let rawLimit"),
        ("const response = await db.rpc", "if (flag) await db.rpc"),
        ("const response = await db.rpc", "const response = flag ? await db.rpc"),
    ],
)
def test_numeric_does_not_bind_unsupported_or_bypassed_paths(before, after):
    assert not observed(numeric(NUMERIC.replace(before, after)))


@pytest.mark.parametrize(
    "statement",
    [
        "const Math = replacement;",
        "const Number = replacement;",
        "Math.min = replacement;",
        "const alias = Math; alias.min = replacement;",
        "Object.assign(Math, replacement);",
        "Object.assign(Math.min, replacement);",
        "const native = Number.isFinite;",
        "class Math {}",
        "enum Number {value}",
        "namespace Math {}",
        r"const M\u0061th = replacement;",
        "eval(value);",
        "rawLimit = other;",
        "matchCount = rawLimit;",
    ],
)
def test_numeric_shadowed_mutated_or_aliased_bindings_abstain(statement):
    source = NUMERIC.replace(" const response", " " + statement + "\n const response")
    assert not observed(numeric(source))


def test_numeric_nested_scope_and_deferred_call_do_not_link():
    for source in [
        NUMERIC.replace(" const rawLimit", " if (flag) { const rawLimit").replace(
            " const response", " }\n const response"
        ),
        NUMERIC.replace(" const response", " const later = () => { const response").replace(
            " return response;", " return response; };"
        ),
        NUMERIC.replace(" const response = await db.rpc", " const response = await wrapped(db.rpc").replace(
            "matchCount});", "matchCount}));"
        ),
    ]:
        assert not observed(numeric(source))


def test_rpc_argument_alias_is_not_silently_resolved():
    source = NUMERIC.replace(" const response", " const params = {match_count: matchCount};\n const response")
    source = source.replace("db.rpc('PRIVATE_RPC', {match_count: matchCount})", "db.rpc('PRIVATE_RPC', params)")
    assert not observed(numeric(source))


def test_numeric_named_builtins_imports_abstain():
    for header in ["import Math from 'math';\n", "import {Number} from 'num';\n"]:
        assert not observed(numeric(header + NUMERIC, raw=finding(line=4, title="Negative query limit")))


def test_collection_actual_default_options_chain_has_all_source_bindings():
    (record,) = observed(check())
    assert record["kind"] == c.COLLECTION_KIND
    b = record["source_binding"]
    assert b["source_sha256"] == hashlib.sha256(CALLER.encode()).hexdigest()
    assert b["callee"]["source_sha256"] == hashlib.sha256(HELPER.encode()).hexdigest()
    assert b["upper"] == 40
    assert b["argument_mode"] == "omitted_options_default"
    assert HELPER.encode()[slice(*b["cap_declaration"]["span"])] == b"maxFacts = opts.maxFacts ?? MAX_FACTS"
    assert CALLER.encode()[slice(*b["call"]["span"])] == b"sanitizeFacts(facts ?? [])"
    assert "does not bound the preceding database query" in record["detail"]
    assert "PRIVATE_" not in json.dumps(record)


@pytest.mark.parametrize(
    "options, bound, mode",
    [
        ("{maxFacts: 3}", 3, "explicit_literal_override"),
        ("{maxFacts: 100}", 100, "explicit_literal_override"),
        ("{maxFacts: 0}", 0, "explicit_literal_override"),
        ("{}", 40, "literal_options_default"),
        ("{maxLen: 20}", 40, "literal_options_default"),
    ],
)
def test_actual_call_override_is_recorded_instead_of_assuming_default(options, bound, mode):
    (record,) = observed(
        check(CALLER.replace("sanitizeFacts(facts ?? [])", "sanitizeFacts(facts ?? [], " + options + ")"))
    )
    assert record["source_binding"]["upper"] == bound
    assert record["source_binding"]["argument_mode"] == mode


@pytest.mark.parametrize(
    "options",
    [
        "opts",
        "undefined",
        "null",
        "{maxFacts: incoming}",
        "{maxFacts: -1}",
        "{maxFacts: 1.5}",
        "{maxFacts: Infinity}",
        "{maxFacts: 1e30}",
        "{...opts}",
        "{maxFacts: 3, ...opts}",
        "{maxFacts: 3, maxFacts: 900}",
        "{get maxFacts(){return 9;}}",
        "{[key]: 9}",
    ],
)
def test_unknown_ambiguous_or_nonfinite_call_options_abstain(options):
    assert not observed(
        check(CALLER.replace("sanitizeFacts(facts ?? [])", "sanitizeFacts(facts ?? [], " + options + ")"))
    )


@pytest.mark.parametrize(
    "before, after",
    [
        ("const maxFacts", "let maxFacts"),
        ("MAX_FACTS = 40", "MAX_FACTS = getCap()"),
        ("opts.maxFacts ?? MAX_FACTS", "opts.maxFacts || MAX_FACTS"),
        ("opts.maxFacts ?? MAX_FACTS", "other.maxFacts ?? MAX_FACTS"),
        ("maxFacts?: number; maxLen?: number} = {}", "maxFacts?: number; maxLen?: number} = defaults"),
        (".slice(0, maxFacts)", ".slice(0, other)"),
        (".slice(0, maxFacts)", ".slice(1, maxFacts)"),
        (".slice(0, maxFacts)", ".slice(0, maxFacts).concat(facts)"),
        (".slice(0, maxFacts)", ".slice(0, maxFacts).flatMap(expand)"),
        ("return (facts ?? [])", "if (flag) return facts;\n return (facts ?? [])"),
        ("return (facts ?? [])", "return (other ?? [])"),
        ("return (facts ?? [])", "const input = facts;\n return (input ?? [])"),
        ("return (facts ?? [])", "facts.slice = replacement;\n return (facts ?? [])"),
        ("return (facts ?? [])", "opts.maxFacts = 900;\n return (facts ?? [])"),
        ("return (facts ?? [])", "const alias = opts;\n return (facts ?? [])"),
        ("return (facts ?? [])", "const alias = maxFacts;\n return (facts ?? [])"),
        ("export function", "export async function"),
    ],
)
def test_helper_binding_mutations_aliases_or_return_bypass_abstain(before, after):
    assert not observed(check(helper=HELPER.replace(before, after)))


@pytest.mark.parametrize(
    "before, after",
    [
        ("{ sanitizeFacts }", "{ sanitizeFacts as clean }"),
        ("sanitizeFacts(facts ?? [])", "clean(facts ?? [])"),
        ("sanitizeFacts(facts ?? [])", "sanitizeFacts?.(facts ?? [])"),
        ("sanitizeFacts(facts ?? [])", "sanitizeFacts(facts ?? [], {}, extra)"),
        ("const factList", "let factList"),
        ("export async function consumer(db)", "export async function consumer(db, sanitizeFacts)"),
        (" const factList", " sanitizeFacts = other;\n const factList"),
        (" const factList", " if (flag) { const factList"),
    ],
)
def test_wrong_or_ambiguous_import_call_bindings_abstain(before, after):
    assert not observed(check(CALLER.replace(before, after)))


@pytest.mark.parametrize(
    "statement",
    [
        "const Array = custom;",
        "Array.prototype.slice = custom;",
        "Object.assign(Array.prototype, custom);",
        "const p = Array.prototype; p.slice = custom;",
        "class Array {}",
        "namespace Array {}",
        r"const Arr\u0061y = custom;",
        "eval(value);",
    ],
)
def test_collection_visible_builtin_replacement_abstains(statement):
    assert not observed(check(helper=statement + "\n" + HELPER))


def test_comments_and_strings_never_supply_context():
    source = (
        "export function endpoint(){\n const text = "
        + json.dumps(NUMERIC)
        + ";\n /* "
        + HELPER
        + " */\n return text;\n}"
    )
    assert not observed(numeric(source))
    assert not observed(check(source))


def test_resolver_requires_literal_unambiguous_source_mapping():
    caller = CALLER.replace("'./helper'", "'@/helper'")
    assert not observed(check(caller))
    config = '{"compilerOptions":{"paths":{"@/*":["./src/*"]}}}'
    (record,) = observed(check(caller, extra={"tsconfig.json": config}))
    assert (
        record["source_binding"]["resolution"]["configuration"]["source_sha256"]
        == hashlib.sha256(config.encode()).hexdigest()
    )
    assert not observed(check(extra={"src/helper.tsx": HELPER}))
    assert not observed(check(helper="export {sanitizeFacts} from './other';", extra={"src/other.ts": HELPER}))
    assert not observed(check(extra={"tsconfig.json": '{"extends":"./base"}'}))


def test_unsafe_duplicate_symlink_unsupported_encoding_and_parse_failures_abstain():
    for mode in ("duplicate", "symlink", "invalid", "parse", "oversize", "missing"):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as z:
            z.writestr("src/consumer.ts", CALLER)
            if mode == "symlink":
                info = zipfile.ZipInfo("src/helper.ts")
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                z.writestr(info, HELPER)
            elif mode == "duplicate":
                z.writestr("src/helper.ts", HELPER)
                with pytest.warns(UserWarning):
                    z.writestr("src/helper.ts", HELPER)
            elif mode != "missing":
                z.writestr(
                    "src/helper.ts",
                    {
                        "invalid": b"\xff",
                        "parse": "export function broken(",
                        "oversize": " " * (c.imported.MAX_FILE_BYTES + 1),
                    }[mode],
                )
        assert not observed(c.SourceLimitVerifier(stream).checks_for(finding()))
    assert not observed(check(raw=finding("../src/consumer.ts")))
    assert not observed(check(raw=finding("src/consumer.ts", 400)))
    assert not observed(check(raw=finding("tests/consumer.ts")))


@pytest.mark.parametrize("field, value", [("reads", c.imported.MAX_FILES), ("remaining", 1), ("remaining_nodes", 0)])
def test_source_loader_budget_exhaustion_is_explicit(field, value):
    verifier = c.SourceLimitVerifier(archive({"src/consumer.ts": CALLER, "src/helper.ts": HELPER}))
    setattr(verifier.loader, field, value)
    results = verifier.checks_for(finding())
    assert not observed(results)
    assert any("budget" in r["detail"].lower() for r in results)


@pytest.mark.parametrize(
    "field, value", [("checks", c.MAX_CHECKS), ("calls", c.MAX_TOTAL_CALLS), ("remaining_work", 0)]
)
def test_local_per_audit_budgets_abstain(field, value):
    verifier = c.SourceLimitVerifier(archive({"src/consumer.ts": CALLER, "src/helper.ts": HELPER}))
    setattr(verifier, field, value)
    results = verifier.checks_for(finding())
    assert not observed(results)
    assert any("budget" in r["detail"].lower() for r in results)


def test_independent_instances_and_cached_records_cannot_contaminate_audits():
    sources = archive({"src/consumer.ts": CALLER, "src/helper.ts": HELPER})
    first, second = c.SourceLimitVerifier(sources), c.SourceLimitVerifier(sources)
    result = first.checks_for(finding())
    reads, calls = first.loader.reads, first.calls
    result[0]["source_binding"]["upper"] = 99999
    assert observed(first.checks_for(finding()))[0]["source_binding"]["upper"] == 40
    assert (first.loader.reads, first.calls) == (reads, calls)
    first.loader.remaining = first.remaining_work = 0
    assert observed(second.checks_for(finding()))[0]["source_binding"]["upper"] == 40
    assert second.loader is not first.loader


def test_context_does_not_refute_compound_claims_or_change_scoring():
    records = check(
        raw={**finding(), "explanation": "The database read has no LIMIT. Separately, all facts reach the model."}
    )
    assert observed(records)
    evidence = {"version": 1, "context_checks": records}
    assert not syntax_contradicted(evidence) and not partial_contradicted(evidence)
    kwargs = {
        "rule_id": "llm-risk",
        "title": "The facts count is unbounded",
        "category": "Security",
        "severity": "high",
        "confidence": 1,
    }
    assert compute_scores([ScoredFinding(**kwargs, claim_evidence=evidence)]) == compute_scores(
        [ScoredFinding(**kwargs)]
    )
    assert compute_scores([ScoredFinding(**kwargs)]) != compute_scores([])


@pytest.mark.parametrize(
    "statement",
    [
        "const changed = opts.__defineGetter__('maxFacts', () => 1000);",
        "const alias = opts.valueOf(); const changed = Object.assign(alias, {maxFacts: 1000});",
        "const proto = opts.__proto__; const changed = Object.assign(proto, {maxFacts: 1000});",
        "const changed = Object.defineProperty(opts, 'maxFacts', {value: 1000});",
        "const alias = opts.maxFacts; const changed = call(alias);",
    ],
)
def test_options_side_effects_and_method_aliases_do_not_masquerade_as_default(statement):
    helper = HELPER.replace(" const maxFacts", " " + statement + "\n const maxFacts")
    assert not observed(check(helper=helper))


@pytest.mark.parametrize(
    "statement",
    [
        "Object.prototype.maxFacts = 1000;",
        "Object.defineProperty(Object.prototype, 'maxFacts', {value: 1000});",
        "const proto = Object.prototype; proto.maxFacts = 1000;",
        "Array.prototype.slice = custom;",
    ],
)
def test_visible_caller_or_helper_builtin_prototype_changes_abstain(statement):
    assert not observed(check(statement + "\n" + CALLER))
    assert not observed(check(helper=statement + "\n" + HELPER))


@pytest.mark.parametrize(
    "before, after",
    [
        ("Number.isFinite(rawLimit)", "Number.isFinite?.(rawLimit)"),
        ("Math.min(100", "Math.min?.(100"),
        ("db.rpc(", "db.rpc?.("),
        ("db.rpc(", "db?.rpc("),
    ],
)
def test_optional_numeric_calls_do_not_establish_direct_execution(before, after):
    assert not observed(numeric(NUMERIC.replace(before, after)))


@pytest.mark.parametrize(
    "before, after",
    [
        (".slice(0, maxFacts)", ".slice?.(0, maxFacts)"),
        (".slice(0, maxFacts)", "?.slice(0, maxFacts)"),
        ("opts.maxFacts ?? MAX_FACTS", "opts?.maxFacts ?? MAX_FACTS"),
    ],
)
def test_optional_helper_paths_abstain(before, after):
    assert not observed(check(helper=HELPER.replace(before, after)))


@pytest.mark.parametrize(
    "limit, value", [("MAX_FUNCTION_NODES", 1), ("MAX_LOCALS", 0), ("MAX_CALLS", 0), ("MAX_RECORDS", 1)]
)
def test_local_structural_budgets_abstain_or_explicitly_mark_truncation(monkeypatch, limit, value):
    monkeypatch.setattr(c, limit, value)
    results = check()
    if limit == "MAX_RECORDS":
        assert len(observed(results)) == 1
        assert any("output budget" in r["detail"] for r in results)
    else:
        assert not observed(results)
        assert any("budget" in r["detail"] for r in results)


@pytest.mark.parametrize(
    "statement",
    [
        "const changed = change({opts});",
        "const changed = change({facts});",
        "const changed = change({maxFacts});",
    ],
)
def test_shorthand_property_escape_of_tracked_bindings_abstains(statement):
    helper = HELPER.replace(" const maxLen", " " + statement + "\n const maxLen")
    assert not observed(check(helper=helper))


@pytest.mark.parametrize(
    "statement",
    [
        "Number.__defineGetter__('isFinite', () => () => true);",
        "Math.__defineGetter__('min', () => () => 1000);",
        "Math.__defineSetter__('min', () => replacement);",
        "change({Math});",
        "change({Number});",
    ],
)
def test_visible_native_method_mutation_and_shorthand_escape_abstain(statement):
    assert not observed(numeric(NUMERIC.replace(" const rawLimit", " " + statement + "\n const rawLimit")))


@pytest.mark.parametrize("key", ["__proto__", "constructor", "toString", "valueOf"])
def test_inherited_standard_object_properties_do_not_use_the_fallback(key):
    assert not observed(check(helper=HELPER.replace("opts.maxFacts", "opts." + key)))


@pytest.mark.parametrize(
    "statement",
    [
        "globalThis.Math.min = replacement;",
        "globalThis[namespace] = replacement;",
        "const world = globalThis; world.Math.min = replacement;",
        "window.Math.min = replacement;",
        "Reflect.set(globalThis, name, replacement);",
    ],
)
def test_visible_global_object_replacement_paths_abstain(statement):
    assert not observed(numeric(statement + "\n" + NUMERIC, raw=finding(line=4, title="Negative query limit")))
    assert not observed(check(helper=statement + "\n" + HELPER))


@pytest.mark.parametrize("name", ["__proto__", "constructor", "toString", "valueOf"])
def test_other_option_reads_cannot_escape_an_inherited_object_via_coalesce(name):
    statement = "const alias = opts." + name + " ?? {}; const changed = change(alias);"
    assert not observed(check(helper=HELPER.replace(" const maxFacts", " " + statement + "\n const maxFacts")))

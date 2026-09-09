"""Counterevidence must follow the cited binding rather than nearby defenses."""

import hashlib
import io
import json
import zipfile
from copy import deepcopy

import pytest

from app.scan import source_claim_assessment as c

HELPER = """export const MAX_FACTS = 40;
export function sanitizeFacts(facts: Array<{content: string}>, opts: {maxFacts?: number} = {}) {
 const maxFacts = opts.maxFacts ?? MAX_FACTS;
 return (facts ?? []).map(f => f.content.trim()).filter(Boolean).slice(0, maxFacts);
}
export function buildFactBlock(facts: string[]) {
 if (!facts.length) return '';
 return 'PRIVATE_PREFIX' + `<facts>${facts.map(f => `- ${f}`).join('\\n')}</facts>`;
}
"""
CALLER = """import { sanitizeFacts, buildFactBlock } from './helper';
export async function handler(db) {
 const {data: facts} = await db.from('PRIVATE_TABLE').select('content');
 const factList = sanitizeFacts(facts ?? []);
 const prefix = buildFactBlock(factList);
 return prefix;
}
"""
TIMEZONE = """import {z} from 'zod';
const BodySchema = z.object({time_zone: z.string().min(1).max(64).optional()}).refine(
 b => b.time_zone !== undefined, {message: 'PRIVATE_MESSAGE'});
function isValidTz(tz: string) {
 try {
  new Intl.DateTimeFormat('PRIVATE_LOCALE', {timeZone: tz});
  return true;
 } catch {
  return false;
 }
}
export async function handler(req) {
 const body = await req.json().catch(() => null);
 const parsed = BodySchema.safeParse(body);
 if (!parsed.success) return {error: 'PRIVATE_ERROR'};
 if (parsed.data.time_zone && !isValidTz(parsed.data.time_zone)) return {error: 'PRIVATE_ERROR'};
 return {ok: true};
}
"""


def archive(sources):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as zf:
        for path, source in sources.items():
            zf.writestr(path, source)
    return stream


def finding(source=CALLER, *, marker="{data: facts", title="All facts are injected into every model prompt"):
    line = next(i for i, text in enumerate(source.splitlines(), 1) if marker in text)
    return {"file": "src/caller.ts", "line_start": line, "line_end": line, "title": title}


def checks(source=CALLER, helper=HELPER, *, raw=None, extra=None):
    verifier = c.SourceClaimVerifier(archive({"src/caller.ts": source, "src/helper.ts": helper, **(extra or {})}))
    return verifier.checks_for(raw or finding(source))


def contradicted(records, kind=None):
    return [r for r in records if r["result"] == "contradicted" and (kind is None or r["kind"] == kind)]


def timezone(
    source=TIMEZONE, *, title="Intl timezone validation has no error handling; empty string passes", marker=None
):
    raw = finding(source, marker=marker or "if (parsed.data.time_zone", title=title)
    return checks(source, raw=raw)


def test_fact_cap_is_bound_to_query_and_verified_consumer_and_leaves_composite_open():
    original = finding()
    snapshot = deepcopy(original)
    (record,) = contradicted(checks(raw=original))
    bound = record["source_binding"]
    assert record["kind"] == c.FACT_KIND
    assert record["whole_finding"] is False
    assert record["method"] == "source_ast"
    assert original == snapshot
    assert bound["upper"] == 40
    assert bound["database_read_bound"] == bound["total_prompt_bound"] == "not_checked"
    assert bound["source_sha256"] == hashlib.sha256(CALLER.encode()).hexdigest()
    assert bound["consumer"]["source_sha256"] == hashlib.sha256(HELPER.encode()).hexdigest()
    assert CALLER.encode()[slice(*bound["consumer_call"]["span"])] == b"buildFactBlock(factList)"
    assert HELPER.encode()[slice(*bound["consumer"]["mapped_input"]["span"])] == b"facts.map(f => `- ${f}`)"
    assert "preceding database read is not capped" in record["detail"]
    assert "PRIVATE_" not in json.dumps(record)


@pytest.mark.parametrize("cap", [0, 3, 100])
def test_explicit_collection_cap_overrides_are_used(cap):
    source = CALLER.replace("sanitizeFacts(facts ?? [])", f"sanitizeFacts(facts ?? [], {{maxFacts: {cap}}})")
    (record,) = contradicted(checks(source))
    assert record["source_binding"]["upper"] == cap


def test_capped_input_can_be_part_of_concatenation_without_claiming_entire_prompt_bound():
    source = CALLER.replace("= buildFactBlock(factList)", "= unrelatedContext(ctx) + buildFactBlock(factList)")
    (record,) = contradicted(checks(source))
    assert record["source_binding"]["total_prompt_bound"] == "not_checked"


def test_later_raw_query_use_is_not_a_proof_of_model_input_safety():
    source = CALLER.replace(
        " return prefix;", " const knownFacts = new Set((facts ?? []).map(f => f.content));\n return prefix;"
    )
    (record,) = contradicted(checks(source))
    assert record["whole_finding"] is False
    assert record["source_binding"]["total_prompt_bound"] == "not_checked"


@pytest.mark.parametrize(
    "before,after",
    [
        ("sanitizeFacts(facts ?? [])", "sanitizeFacts(other ?? [])"),
        ("buildFactBlock(factList)", "buildFactBlock(facts)"),
        ("buildFactBlock(factList)", "buildFactBlock([...factList, ...other])"),
        ("buildFactBlock(factList)", "buildFactBlock(factList, other)"),
        ("buildFactBlock(factList)", "buildFactBlock?.(factList)"),
        ("buildFactBlock(factList)", "other(factList)"),
        ("buildFactBlock(factList)", "flag ? buildFactBlock(factList) : other"),
        ("buildFactBlock(factList)", "(() => buildFactBlock(factList))()"),
        (" const prefix", " factList.push(other);\n const prefix"),
        (" const prefix", " const alias = factList;\n alias.push(other);\n const prefix"),
        (" const prefix", " facts.push(other);\n const prefix"),
        (" const prefix", " const alias = facts;\n alias.push(other);\n const prefix"),
        (" const prefix", " replace(facts);\n const prefix"),
        ("const factList", "let factList"),
        ("const {data: facts}", "let {data: facts}"),
        ("const {data: facts}", "const {data: facts, ...rest}"),
        ("handler(db)", "handler(db, buildFactBlock)"),
        ("handler(db)", "handler(db, sanitizeFacts)"),
        (" const prefix", " buildFactBlock = other;\n const prefix"),
        (" const prefix", " sanitizeFacts = other;\n const prefix"),
        ("sanitizeFacts(facts ?? [])", "sanitizeFacts(facts ?? [], opts)"),
        ("sanitizeFacts(facts ?? [])", "sanitizeFacts(facts ?? [], {maxFacts: incoming})"),
        ("sanitizeFacts(facts ?? [])", "sanitizeFacts(facts ?? [], {get maxFacts() {return 1;}})"),
        ("sanitizeFacts(facts ?? [])", "sanitizeFacts(facts ?? [], {...opts})"),
        ("sanitizeFacts(facts ?? [])", "sanitizeFacts(facts ?? [], {maxFacts: -1})"),
        ("sanitizeFacts(facts ?? [])", "sanitizeFacts(facts ?? [], {maxFacts: Infinity})"),
    ],
)
def test_collection_wrong_or_escaped_bindings_abstain(before, after):
    assert not contradicted(checks(CALLER.replace(before, after)))


@pytest.mark.parametrize(
    "before,after",
    [
        (".slice(0, maxFacts)", ".slice(0, maxFacts).concat(facts)"),
        (".slice(0, maxFacts)", ".slice(0, other)"),
        (" const maxFacts", " const alias = opts;\n const maxFacts"),
        (" const maxFacts", " opts.maxFacts = 999;\n const maxFacts"),
        ("return (facts ?? [])", "if (flag) return facts; return (facts ?? [])"),
        ("buildFactBlock(facts: string[])", "buildFactBlock(facts: string[], other)"),
        ("export function buildFactBlock", "export async function buildFactBlock"),
        (" if (!facts.length) return '';", " if (!facts.length) return getOtherFacts();"),
        (" if (!facts.length) return '';", " facts.push(other);"),
        (" if (!facts.length) return '';", " const alias = facts; alias.push(other);"),
        ("facts.map(f => `- ${f}`)", "other.map(f => `- ${f}`)"),
        ("facts.map(f => `- ${f}`)", "facts.flatMap(f => `- ${f}`)"),
        ("facts.map(f => `- ${f}`)", "facts.map?.(f => `- ${f}`)"),
        (".join(", ".join?.("),
        ("facts.map(f => `- ${f}`)", "facts.map(f => getOtherFacts())"),
        ("facts.map(f => `- ${f}`)", "facts.map(f => `- ${other}`)"),
        ("facts.map(f => `- ${f}`)", "facts.map(f => `- ${f}`).concat(other)"),
        ("'PRIVATE_PREFIX' +", "getAllFacts() +"),
    ],
)
def test_mutated_caps_or_unproved_consumer_abstain(before, after):
    assert not contradicted(checks(helper=HELPER.replace(before, after)))


def test_fact_cap_does_not_refute_only_database_row_limit_claim_or_another_anchor():
    assert checks(raw=finding(title="The facts database query has no row limit")) == []
    assert not contradicted(checks(raw=finding(marker="return prefix")))


def test_capped_array_without_a_consumer_definition_is_not_counterevidence():
    assert not contradicted(checks(helper=HELPER.split("export function buildFactBlock")[0]))


def test_imported_alias_and_wrong_or_ambiguous_module_resolution_abstain():
    assert not contradicted(
        checks(
            CALLER.replace("buildFactBlock }", "buildFactBlock as render }").replace(
                "buildFactBlock(factList)", "render(factList)"
            )
        )
    )
    assert not contradicted(checks(extra={"src/helper.js": HELPER}))
    assert not contradicted(
        checks(helper="export {sanitizeFacts, buildFactBlock} from './other';", extra={"src/other.ts": HELPER})
    )


def test_intl_helper_and_optional_nonempty_field_both_have_exact_counterevidence():
    records = contradicted(timezone())
    assert {r["kind"] for r in records} == {c.INTL_KIND, c.EMPTY_KIND}
    assert all(r["whole_finding"] is False for r in records)
    assert all(r["source_sha256"] == hashlib.sha256(TIMEZONE.encode()).hexdigest() for r in records)
    intl, empty = records
    assert TIMEZONE.encode()[slice(*intl["source_binding"]["caught_return"]["span"])] == b"return false;"
    assert empty["source_binding"]["minimum_length"] == 1
    assert "optional wrapper allows omission, not an empty string" in empty["detail"]
    assert "PRIVATE_" not in json.dumps(records)


@pytest.mark.parametrize(
    "before,after",
    [
        ("} catch {\n  return false;\n }", "} finally {\n  return false;\n }"),
        ("return false;", "throw new Error();"),
        ("} catch {", "} catch ({message}) {"),
        ("return false;", "return recover();"),
        ("return false;", "log(); return false;"),
        ("return false;", "return true;"),
        (" } catch", " } finally { throw new Error(); } catch"),
        (" } catch {\n  return false;\n }", " } catch {\n  return false;\n } finally {throw new Error();}"),
        ("function isValidTz", "async function isValidTz"),
        ("timeZone: tz", "timeZone: other"),
        ("timeZone: tz", "timeZone: tz, ...opts"),
        (" const body", " Intl.DateTimeFormat = other;\n const body"),
        (" const body", " const Intl = other;\n const body"),
        (" const body", " const alias = Intl; alias.DateTimeFormat = other;\n const body"),
        (" const body", " globalThis.Intl = other;\n const body"),
        (" const body", " isValidTz = other;\n const body"),
        ("handler(req)", "handler(req, isValidTz)"),
        ("!isValidTz(parsed.data.time_zone)", "!other(parsed.data.time_zone)"),
        ("!isValidTz(parsed.data.time_zone)", "!isValidTz?.(parsed.data.time_zone)"),
    ],
)
def test_intl_unguarded_rethrow_shadowing_or_other_helper_does_not_refute(before, after):
    assert not contradicted(timezone(TIMEZONE.replace(before, after)), c.INTL_KIND)


def test_intl_constructor_outside_try_and_catch_inside_callback_abstain():
    outside = TIMEZONE.replace(
        " try {\n  new Intl.DateTimeFormat('PRIVATE_LOCALE', {timeZone: tz});",
        " new Intl.DateTimeFormat('PRIVATE_LOCALE', {timeZone: tz});\n try {",
    )
    assert not contradicted(timezone(outside), c.INTL_KIND)
    deferred = TIMEZONE.replace(
        "new Intl.DateTimeFormat('PRIVATE_LOCALE', {timeZone: tz});",
        "later(() => new Intl.DateTimeFormat('PRIVATE_LOCALE', {timeZone: tz}));",
    )
    assert not contradicted(timezone(deferred), c.INTL_KIND)


@pytest.mark.parametrize(
    "before,after",
    [
        ("min(1)", "min(0)"),
        ("z.string()", "z.string?.()"),
        ("z.object({", "z.object?.({"),
        (".min(1)", ".min?.(1)"),
        (".min(1)", ""),
        ("min(1)", "min(incoming)"),
        ("min(1)", "min(-1)"),
        (".optional()", ".catch('')"),
        (".optional()", ".transform(() => '')"),
        (".optional()", ".or(z.literal(''))"),
        (".optional()", ".default('')"),
        ("}).refine(", "}).optional().refine("),
        ("b => b.time_zone !== undefined", "b => (b.time_zone = '', true)"),
        ("b => b.time_zone !== undefined", "b => mutate(b)"),
        (" const parsed", " BodySchema.safeParse = other;\n const parsed"),
        ("BodySchema.safeParse(body)", "BodySchema.safeParse?.(body)"),
        ("BodySchema.safeParse(body)", "BodySchema?.safeParse(body)"),
        (" const parsed", " const alias = BodySchema; alias.safeParse = other;\n const parsed"),
        (" const parsed", " z.string = other;\n const parsed"),
        (" const parsed", " const z = other;\n const parsed"),
        (" const parsed", " const alias = z; alias.string = other;\n const parsed"),
        (" if (parsed.data.time_zone", " parsed.data.time_zone = '';\n if (parsed.data.time_zone"),
        (" if (parsed.data.time_zone", " const alias = parsed.data; alias.time_zone = '';\n if (parsed.data.time_zone"),
        (" if (parsed.data.time_zone", " mutate(parsed.data);\n if (parsed.data.time_zone"),
        (" if (!parsed.success) return", " if (!parsed.success) log"),
        (" if (!parsed.success) return", " if (parsed.success) return"),
        ("if (!parsed.success)", "if (!other.success)"),
        ("!isValidTz(parsed.data.time_zone)", "!isValidTz(body.time_zone)"),
        ("!isValidTz(parsed.data.time_zone)", "!isValidTz(parsed.data.other)"),
    ],
)
def test_empty_string_counterevidence_does_not_survive_unsupported_schema_or_guard(before, after):
    source = TIMEZONE.replace(before, after)
    assert not contradicted(timezone(source), c.EMPTY_KIND)


def test_nonempty_guard_before_use_is_required_and_whitespace_is_not_claimed():
    source = TIMEZONE.replace(" if (!parsed.success) return {error: 'PRIVATE_ERROR'};\n", "")
    source = source.replace(
        " return {ok: true};", " if (!parsed.success) return {error: 'PRIVATE_ERROR'};\n return {ok: true};"
    )
    assert not contradicted(timezone(source), c.EMPTY_KIND)
    record = contradicted(timezone(), c.EMPTY_KIND)[0]
    assert "not whitespace policy" in record["detail"]


def test_unrelated_anchor_does_not_inherit_timezone_helper_counterevidence():
    assert not contradicted(timezone(marker="return {ok: true}"))


def test_results_are_cached_by_selection_and_return_independent_copies():
    verifier = c.SourceClaimVerifier(archive({"src/caller.ts": TIMEZONE}))
    raw = finding(TIMEZONE, marker="if (parsed.data.time_zone", title="Intl timezone has no error handling")
    one = verifier.checks_for(raw)
    one[0]["source_binding"]["callee"]["line_start"] = 999
    assert verifier.checks_for(raw)[0]["source_binding"]["callee"]["line_start"] != 999
    raw["title"] = "An empty string bypasses validation"
    assert [r["kind"] for r in verifier.checks_for(raw)] == [c.EMPTY_KIND]


@pytest.mark.parametrize(
    "field,value", [("file", "../caller.ts"), ("file", "src/caller.test.ts"), ("line_start", True), ("line_end", 9999)]
)
def test_invalid_or_nonproduction_anchors_abstain(field, value):
    raw = finding()
    raw[field] = value
    assert not contradicted(checks(raw=raw))


def test_work_and_check_budgets_abstain_without_source_execution(monkeypatch):
    verifier = c.SourceClaimVerifier(archive({"src/caller.ts": CALLER, "src/helper.ts": HELPER}))
    verifier.remaining_work = 0
    assert not contradicted(verifier.checks_for(finding()))
    monkeypatch.setattr(c, "MAX_CHECKS", 0)
    assert "budget exhausted" in checks()[0]["detail"]


@pytest.mark.parametrize(
    "mutation",
    [
        "Array.prototype.map = other;",
        "Array.prototype.slice = other;",
        "const native = Array; native.prototype.map = other;",
        "globalThis.Array = other;",
        "Object.assign(Array.prototype, replacement);",
    ],
)
def test_visible_array_runtime_replacement_abstains(mutation):
    assert not contradicted(checks(CALLER.replace(" const prefix", mutation + "\n const prefix")))
    assert not contradicted(checks(helper=mutation + "\n" + HELPER))


def test_simple_named_catch_parameter_and_required_nonempty_field_are_supported():
    source = TIMEZONE.replace("} catch {", "} catch (error) {").replace(".optional()", "")
    assert {r["kind"] for r in contradicted(timezone(source))} == {c.INTL_KIND, c.EMPTY_KIND}

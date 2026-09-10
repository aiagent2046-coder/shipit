"""Real guard shapes, paired omissions and deliberately unsupported claims."""
import io
import json
import stat
import zipfile

import pytest

from app.scan import guard_context as context


def archive(files):
    result = io.BytesIO()
    with zipfile.ZipFile(result, "w") as zf:
        for path, source in files.items():
            zf.writestr(path, source)
    result.seek(0)
    return result


def scan(source, path="app/api/route.ts"):
    return context.collect_guard_context(archive({path: source}))


def checks(source, kind=None):
    return [c for r in scan(source)["records"] for c in r["checks"] if kind is None or c["kind"] == kind]


def finding(source, title, marker, end_marker=None, path="app/api/route.ts"):
    lines = source.splitlines()
    start = next(i + 1 for i, line in enumerate(lines) if marker in line)
    end = next(i + 1 for i, line in enumerate(lines) if end_marker in line) if end_marker else start
    return {"file": path, "title": title, "line_start": start, "line_end": end}


def syntax(source, title, marker):
    return context.guard_syntax_check(finding(source, title, marker), {"guards": scan(source)})


OAUTH = '''export async function GET(req) {
  const code = req.nextUrl.searchParams.get('code');
  const state = req.nextUrl.searchParams.get('state');
  const cookieStore = await cookies();
  const savedState = cookieStore.get('secret-cookie-name')?.value;
  if (!code || !state || !savedState || state !== savedState) {
    return backToAgents('private-error-text');
  }
  const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST', body: JSON.stringify({ code, client_secret: 'do-not-persist' }),
  });
  return tokenRes;
}'''


def test_actual_oauth_guard_precedes_exchange_and_broad_claim_keeps_context():
    c, = checks(OAUTH, "oauth_state_return_guard")
    assert c["line"] == 6 and c["exchange_lines"] == [9] and c["before_exchange"]
    f = finding(OAUTH, "OAuth state parameter not validated before use", "const state")
    attached, = context.guard_finding_context(f, {"guards": scan(OAUTH)})
    assert "strict inequality" in attached["summary"] and "Cookie origin" in attached["summary"]
    assert context.guard_syntax_check(f, {"guards": scan(OAUTH)}) is None


def test_oauth_late_guard_is_not_reported_as_before_exchange():
    guard = OAUTH[OAUTH.index("  if (!code"):OAUTH.index("  const tokenRes")]
    late = OAUTH.replace(guard, "").replace("  return tokenRes;", guard + "  return tokenRes;")
    c, = checks(late, "oauth_state_return_guard")
    assert not c["before_exchange"]
    assert "does not precede every" in c["summary"]


@pytest.mark.parametrize("source", [
    OAUTH.replace("state !== savedState", "state === savedState"),
    OAUTH.replace("!state || ", ""),
    OAUTH.replace("return backToAgents", "backToAgents"),
    OAUTH.replace("if (!code", "if (enabled && (!code").replace("state !== savedState)", "state !== savedState))"),
    OAUTH.replace("GET(req)", "GET(req, state)"),
    OAUTH.replace("  return tokenRes;", "  function nested(state) {}\n  return tokenRes;"),
    OAUTH.replace("  return tokenRes;", "  state = other;\n  return tokenRes;"),
    OAUTH.replace("const savedState = cookieStore.get('secret-cookie-name')?.value;", ""),
    OAUTH.replace("const code = req.nextUrl.searchParams.get('code');", ""),
    OAUTH.replace("  if (!code", "  function helper() { if (!code").replace(
        "  const tokenRes", "  }\n  const tokenRes"),
    "const fetch = custom;\n" + OAUTH,
    "import {fetch} from 'other';\n" + OAUTH,
])
def test_oauth_omissions_wrong_order_scopes_shadowing_and_unknown_bindings(source):
    assert not checks(source, "oauth_state_return_guard")


DOMAIN = '''const LAB_DOMAIN = 'private-domain.example';
function filterUsers(users) {
  return users.filter(u => (u.email ?? '').endsWith(`@${LAB_DOMAIN}`));
}'''


@pytest.mark.parametrize("argument", ["`@${LAB_DOMAIN}`", "'@' + LAB_DOMAIN", "'@private-domain.example'"])
def test_domain_separator_shape_and_atomic_absence(argument):
    source = DOMAIN.replace("`@${LAB_DOMAIN}`", argument)
    c, = checks(source)
    assert c["separator"] == "present" and c["domain_binding"] == "constant"
    assert syntax(source, "The domain suffix check has no @ separator", "endsWith")["result"] == "contradicted"
    broad = finding(source, "Lab domain filter uses simple string matching without validation", "endsWith")
    attached, = context.guard_finding_context(broad, {"guards": scan(source)})
    assert "@ separator shape: present" in attached["summary"]
    assert context.guard_syntax_check(broad, {"guards": scan(source)}) is None


@pytest.mark.parametrize("argument, separator", [
    ("LAB_DOMAIN", "absent"), ("'private-domain.example'", "absent"),
    ("'x@' + LAB_DOMAIN", "unresolved"), ("`${LAB_DOMAIN}@`", "unresolved"),
    ("`@${unknown}`", "present"), ("`@${literal}`", "present"),
    ("'\\x40private-domain.example'", "unresolved"),
])
def test_unsafe_or_unresolved_domain_suffix_is_not_disproved(argument, separator):
    source = DOMAIN.replace("`@${LAB_DOMAIN}`", argument)
    c, = checks(source)
    assert c["separator"] == separator
    assert syntax(source, "The domain suffix check has no @ separator", "endsWith")["result"] == "not_checked"


@pytest.mark.parametrize("source", [
    DOMAIN.replace("u =>", "(u, LAB_DOMAIN) =>"),
    DOMAIN.replace("function filterUsers", "LAB_DOMAIN = external;\nfunction filterUsers"),
    DOMAIN.replace("const LAB_DOMAIN", "let LAB_DOMAIN"),
    DOMAIN.replace("const LAB_DOMAIN = 'private-domain.example';", ""),
])
def test_ambiguous_domain_binding_does_not_contradict(source):
    c, = checks(source)
    assert c["domain_binding"] == "unresolved"
    assert syntax(source, "The suffix argument omits the @ separator.", "endsWith")["result"] == "not_checked"


CLAMP = '''export async function GET(req) {
  const rawLimit = parseInt(req.nextUrl.searchParams.get('limit') ?? '20', 10);
  const matchCount = Number.isFinite(rawLimit) ? Math.min(100, Math.max(1, rawLimit)) : 20;
  return query.limit(matchCount);
}'''


def test_actual_finite_clamp_is_counterevidence_to_negative_limit_claim():
    c, = checks(CLAMP)
    assert c["nonnegative_lower_bound"] and c["fallback_within_bounds"]
    f = finding(CLAMP, "Query parameter limit not validated for negative values", "const rawLimit")
    attached, = context.guard_finding_context(f, {"guards": scan(CLAMP)})
    assert "nonnegative" in attached["summary"]
    assert context.guard_syntax_check(f, {"guards": scan(CLAMP)}) is None
    result = syntax(CLAMP, "The limit clamp has no nonnegative lower bound.", "const matchCount")
    assert result["result"] == "contradicted"


def test_negative_lower_bound_and_unbounded_fallback_are_distinct_observations():
    negative = CLAMP.replace("Math.max(1,", "Math.max(-100,")
    c, = checks(negative)
    assert not c["nonnegative_lower_bound"]
    result = syntax(negative, "The limit clamp has no nonnegative lower bound", "const matchCount")
    assert result["result"] == "not_checked"
    fallback = CLAMP.replace(": 20;", ": -10;")
    c, = checks(fallback)
    assert c["nonnegative_lower_bound"] and not c["fallback_within_bounds"]
    # The narrow clamp syntax says nothing about all return/input cases.
    assert syntax(fallback, "Negative limits bypass validation", "const matchCount") is None


@pytest.mark.parametrize("source", [
    CLAMP.replace("Math.max(1, rawLimit)", "rawLimit"),
    CLAMP.replace("Number.isFinite(rawLimit)", "Number.isFinite(other)"),
    CLAMP.replace("Math.max(1, rawLimit)", "Math.max(1, other)"),
    CLAMP.replace("GET(req)", "GET(req, Math)"),
    CLAMP.replace("GET(req)", "GET(req, {Number})"),
    CLAMP.replace("  return query", "  const nested = (rawLimit) => rawLimit;\n  return query"),
    CLAMP.replace("  return query", "  rawLimit = other;\n  return query"),
    CLAMP.replace("  return query", "  Math.max = other;\n  return query"),
    "import { Number } from 'custom';\n" + CLAMP,
    CLAMP.replace("  const rawLimit = parseInt(req.nextUrl.searchParams.get('limit') ?? '20', 10);", ""),
])
def test_omitted_or_mismatched_clamp_and_shadowed_builtins_stay_unknown(source):
    assert not checks(source, "finite_limit_clamp")


INTL = '''function isValidTz(tz) {
  try {
    new Intl.DateTimeFormat('secret-locale', {timeZone: tz});
    return true;
  } catch {
    return false;
  }
}'''


def test_actual_intl_catch_has_context_without_claiming_all_timezones_validated():
    c, = checks(INTL)
    assert c["catch_line"] == 5 and c["catch_returns_false"]
    f = finding(INTL, "Timezone validation uses Intl API which may not catch all invalid timezones", "new Intl")
    attached, = context.guard_finding_context(f, {"guards": scan(INTL)})
    assert "catch at line 5" in attached["summary"]
    assert context.guard_syntax_check(f, {"guards": scan(INTL)}) is None
    result = syntax(INTL, "The cited Intl.DateTimeFormat call is outside any try/catch", "new Intl")
    assert result["result"] == "contradicted"


@pytest.mark.parametrize("source", [
    "function isValidTz(tz) { new Intl.DateTimeFormat('x',{timeZone:tz}); }",
    "function isValidTz(tz) { try { okay(); } finally { new Intl.DateTimeFormat('x',{timeZone:tz}); } }",
    "function isValidTz(tz) { try { okay(); } catch { new Intl.DateTimeFormat('x',{timeZone:tz}); } }",
    "function isValidTz(tz) { try { const later = () => new Intl.DateTimeFormat('x',{timeZone:tz}); } catch {} }",
])
def test_intl_outside_try_body_or_deferred_callback_has_no_enclosing_catch(source):
    c, = checks(source)
    assert c["catch_line"] is None
    result = syntax(source, "Intl.DateTimeFormat constructor has no enclosing try/catch", "new Intl")
    assert result["result"] == "not_checked"


@pytest.mark.parametrize("source", [INTL.replace("isValidTz(tz)", "isValidTz(tz, Intl)"),
                                    "import Intl from 'other';\n" + INTL,
                                    "Intl.DateTimeFormat = custom;\n" + INTL])
def test_unknown_intl_binding_is_not_linked(source):
    assert not checks(source)


SCHEMA = '''import {z} from 'zod';
const BehavioralSchema = z.object({content: z.string().min(1)});
export async function POST(req) {
  const body = await req.json().catch(() => null);
  const parsed = BehavioralSchema.safeParse(body?.behavioral_profile);
  if (!parsed.success) {
    return Response.json({error: 'private-error'}, {status: 400});
  }
  await update({behavioral_profile: parsed.data});
}'''


def test_actual_json_null_fallback_is_followed_by_mandatory_schema_return():
    c, = checks(SCHEMA)
    assert c["mandatory_object_schema"] and c["data_accesses_after_guard"]
    assert (c["line"], c["schema_line"], c["guard_line"]) == (4, 5, 6)
    f = finding(SCHEMA, "JSON parsing error silently returns null without validation", "const body")
    attached, = context.guard_finding_context(f, {"guards": scan(SCHEMA)})
    assert "mandatory Zod object" in attached["summary"]
    assert context.guard_syntax_check(f, {"guards": scan(SCHEMA)}) is None


def test_direct_body_refinements_and_zod_alias_preserve_observation():
    source = SCHEMA.replace("{z}", "{z as schema}").replace("z.", "schema.")
    source = source.replace("body?.behavioral_profile", "body").replace("min(1)});", "min(1)}).refine(checkFields);")
    c, = checks(source)
    assert c["mandatory_object_schema"]


@pytest.mark.parametrize("change", [".optional()", ".nullable()", ".nullish()", ".default({})", ".catch({})",
                                    ".transform(transform)", ".pipe(other)"])
def test_nullish_or_transforming_schema_is_not_claimed_mandatory(change):
    source = SCHEMA.replace("min(1)});", "min(1)})" + change + ";")
    c, = checks(source)
    assert not c["mandatory_object_schema"]
    assert "Schema acceptance is unresolved" in c["summary"]


@pytest.mark.parametrize("source", [
    SCHEMA.replace("'zod'", "'custom'"),
    SCHEMA.replace("import {z}", "import type {z}"),
    SCHEMA.replace("import {z}", "import {type z}"),
    SCHEMA.replace("POST(req)", "POST(req, BehavioralSchema)"),
    SCHEMA.replace("const BehavioralSchema = z.object({content: z.string().min(1)});", ""),
    SCHEMA + "\nz.object = custom;",
])
def test_unresolved_schema_binding_remains_observation_only(source):
    c, = checks(source)
    assert not c["mandatory_object_schema"]


@pytest.mark.parametrize("source", [
    SCHEMA.replace("!parsed.success", "parsed.success"),
    SCHEMA.replace("return Response", "Response"),
    SCHEMA.replace("body?.behavioral_profile", "other?.behavioral_profile"),
    SCHEMA.replace("  await update", "  body = other;\n  await update"),
    SCHEMA.replace("  await update", "  const helper = parsed => parsed;\n  await update"),
    SCHEMA.replace("  const body", "  function helper() { const body").replace("  const parsed", "  }\n  const parsed"),
    SCHEMA.replace("catch(() => null)", "catch(() => ({}))"),
])
def test_json_omissions_shadowing_other_function_and_different_fallback_are_not_linked(source):
    assert not checks(source, "json_schema_return_guard")


def test_schema_guard_after_use_is_explicitly_not_ordered():
    source = SCHEMA.replace("  if (!parsed.success)", "  await use(parsed.data);\n  if (!parsed.success)")
    c, = checks(source)
    assert not c["data_accesses_after_guard"]
    assert "Ordering before all" in c["summary"]


def test_same_name_other_function_or_file_does_not_supply_counterevidence():
    source = INTL + "\nfunction unrelated(tz) { return tz; }"
    f = finding(source, "The cited Intl.DateTimeFormat call is outside any try/catch", "function unrelated")
    assert not context.guard_finding_context(f, {"guards": scan(source)})
    assert context.guard_syntax_check(f, {"guards": scan(source)})["result"] == "not_checked"
    f = finding(INTL, "The cited Intl.DateTimeFormat call is outside any try/catch", "new Intl", path="other.ts")
    assert not context.guard_finding_context(f, {"guards": scan(INTL)})


@pytest.mark.parametrize("suffix", [" and accepts dangerous domains", " or allows a bypass", "; authentication fails",
                                    " causing account takeover", "\nDuplicate requests race"])
def test_compound_race_and_consequence_titles_never_discard_findings(suffix):
    assert syntax(DOMAIN, "The domain suffix check has no @ separator" + suffix, "endsWith") is None


def test_wrong_ranges_and_same_line_multiple_calls_are_not_guessed():
    facts = {"guards": scan(INTL)}
    f = finding(INTL, "Intl.DateTimeFormat call has no enclosing try/catch", "new Intl")
    for change in [{"line_start": True}, {"line_start": 0}, {"line_start": "3"}, {"line_end": 999}, {"line_end": None}]:
        assert not context.guard_finding_context(f | change, facts)
    doubled = INTL.replace("new Intl.DateTimeFormat('secret-locale', {timeZone: tz});",
                           "new Intl.DateTimeFormat('a'); new Intl.DateTimeFormat('b');")
    assert syntax(doubled, f["title"], "new Intl")["result"] == "not_checked"
    assert context.guard_syntax_check(f | {"line_start": 1, "line_end": 8}, facts)["result"] == "not_checked"


@pytest.mark.parametrize("unsupported", [
    "const unsafe=Number.isFinite(raw)?Math.min(100,raw):20;",
    "const unsafe=Number.isFinite(raw)?Math['min'](100,raw):20;",
    "const unsafe=Number.isFinite(raw)?other.min(100,raw):20;",
    "const unsafe=raw>100?100:raw;",
    "const unsafe=customClamp(raw);",
])
def test_checked_clamp_cannot_dismiss_unsupported_neighbor_on_shared_line(unsupported):
    safe = "const safe=Number.isFinite(raw)?Math.min(100,Math.max(1,raw)):20;"
    shared = "function f() { const raw=1; " + safe + " " + unsupported + " }"
    title = "The limit clamp has no nonnegative lower bound"
    check, = checks(shared, "finite_limit_clamp")
    assert not check["syntax_target_unambiguous"]
    assert syntax(shared, title, "const safe")["result"] == "not_checked"
    # Separate source coordinates select the safe initializer unambiguously.
    split = "function f() {\nconst raw=1;\n" + safe + "\n" + unsupported + "\n}"
    assert syntax(split, title, "const safe")["result"] == "contradicted"
    assert syntax(split, title, "const unsafe")["result"] == "not_checked"


@pytest.mark.parametrize("unsupported", [
    "email.endsWith?.('example');", "email['endsWith']('example');", "email[unknown]('example');",
])
def test_supported_suffix_cannot_supply_counterevidence_for_unsupported_neighbor(unsupported):
    source = "function f(email) { email.endsWith('@example'); " + unsupported + " }"
    title = "The domain suffix check has no @ separator"
    assert syntax(source, title, "@example")["result"] == "not_checked"
    source = source.replace("; " + unsupported, ";\n" + unsupported)
    assert syntax(source, title, "@example")["result"] == "contradicted"
    assert syntax(source, title, unsupported)["result"] == "not_checked"


@pytest.mark.parametrize("unsupported", [
    "Intl.DateTimeFormat('other');", "new Intl['DateTimeFormat']('other');", "new other[unknown]('other');",
])
def test_supported_intl_constructor_cannot_dismiss_unsupported_neighbor(unsupported):
    source = "function f() { try { new Intl.DateTimeFormat('first'); " + unsupported + " } catch {} }"
    title = "Intl.DateTimeFormat constructor has no enclosing try/catch"
    assert syntax(source, title, "first")["result"] == "not_checked"
    source = source.replace("; " + unsupported, ";\n" + unsupported)
    assert syntax(source, title, "first")["result"] == "contradicted"
    assert syntax(source, title, unsupported)["result"] == "not_checked"


@pytest.mark.parametrize("body, title, marker", [
    ("return email.endsWith('@example');", "The suffix comparison has no @ separator", "endsWith"),
    ("const raw=1; const limit=Number.isFinite(raw)?Math.min(100,Math.max(1,raw)):20;",
     "The limit clamp has no nonnegative lower bound", "const limit"),
    ("try { new Intl.DateTimeFormat('first'); } catch {}",
     "Intl.DateTimeFormat call has no enclosing try/catch", "new Intl"),
])
def test_same_line_sibling_without_checks_is_still_ambiguous(body, title, marker):
    one = "function f(email) { " + body + " }"
    assert syntax(one, title, marker)["result"] == "contradicted"
    assert syntax(one + " function other() {}", title, marker)["result"] == "not_checked"
    assert syntax("function other() {} " + one, title, marker)["result"] == "not_checked"
    assert syntax(one + "\nfunction other() {}", title, marker)["result"] == "contradicted"


def test_nested_empty_function_on_target_line_is_not_guessed_but_ancestor_scope_is_allowed():
    title = "Intl.DateTimeFormat call has no enclosing try/catch"
    same_line = INTL.replace("{timeZone: tz});", "{timeZone: tz}); function other() {}")
    assert syntax(same_line, title, "new Intl")["result"] == "not_checked"
    # The ordinary arrow callback has a containing function, not a sibling target.
    assert syntax(DOMAIN, "The domain suffix check has no @ separator", "endsWith")["result"] == "contradicted"


def test_comments_strings_and_literal_values_are_not_evidence_or_output():
    fake = "function fake() {\n// " + INTL.replace("\n", " ") + "\nconst text=" + json.dumps(OAUTH) + ";\n}"
    assert not checks(fake)
    output = json.dumps(scan(OAUTH + "\n" + DOMAIN + "\n" + INTL + "\n" + SCHEMA))
    for secret in ["private-domain.example", "secret-cookie-name", "private-error-text", "do-not-persist",
                   "secret-locale", "private-error", "https://github.com/login/oauth/access_token"]:
        assert secret not in output


@pytest.mark.parametrize("extension", ["js", "jsx", "ts", "tsx"])
def test_javascript_and_typescript_extensions(extension):
    assert scan(INTL, "src/timezone." + extension)["parsed_files"] == 1


def test_excluded_paths_ambiguous_paths_symlinks_and_parse_failures():
    files = {"tests/helper.ts": INTL, "src/timezone.test.ts": INTL, "docs/example.ts": INTL,
             "vendor/timezone.ts": INTL, "node_modules/helper.ts": INTL, "dist/out.js": INTL,
             "../outside.ts": INTL, "/absolute.ts": INTL, "src/./alias.ts": INTL,
             "src/alias.ts": INTL, "bad.ts": b"\xff", "invalid.ts": "function bad( {", "src/ok.ts": INTL}
    z = archive(files)
    with zipfile.ZipFile(z, "a") as zf:
        link = zipfile.ZipInfo("link.ts")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(link, INTL)
    r = context.collect_guard_context(z)
    assert r["parsed_files"] == 1 and r["excluded_files"] == 7
    assert r["limitations"] == ["ambiguous_archive_path", "unparseable_js_ts", "unsafe_or_noncanonical_path"]
    assert r["records"][0]["file"] == "src/ok.ts"


@pytest.mark.parametrize("budget, value, limitation", [
    ("MAX_FILE_BYTES", 8, "file_size_or_path_limit"),
    ("MAX_TOTAL_BYTES", 8, "scan_budget_reached"),
    ("MAX_FILES", 0, "scan_budget_reached"),
    ("MAX_NODES", 3, "node_limit_reached"),
    ("MAX_FUNCTION_NODES", 3, "function_node_limit_reached"),
    ("MAX_WORK_NODES", 3, "function_work_limit_reached"),
    ("MAX_FUNCTIONS", 0, "function_limit_reached"),
    ("MAX_RECORDS", 0, "record_limit_reached"),
])
def test_explicit_budgets_keep_absence_unknown(monkeypatch, budget, value, limitation):
    monkeypatch.setattr(context, budget, value)
    r = scan(INTL)
    assert not r["records"] and limitation in r["limitations"]
    f = finding(INTL, "Intl.DateTimeFormat call has no enclosing try/catch", "new Intl")
    assert context.guard_syntax_check(f, {"guards": r})["result"] == "not_checked"


def test_local_and_check_budgets_are_reported(monkeypatch):
    monkeypatch.setattr(context, "MAX_LOCALS", 1)
    assert "local_binding_limit_reached" in scan(CLAMP)["limitations"]
    monkeypatch.setattr(context, "MAX_CHECKS", 1)
    source = INTL.replace("    return true;", "    new Intl.DateTimeFormat('other');\n    return true;")
    r = scan(source)
    assert "checks_per_function_limit" in r["limitations"] and len(r["records"][0]["checks"]) == 1

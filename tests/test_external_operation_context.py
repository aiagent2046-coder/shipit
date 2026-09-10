"""Adversarial boundaries for cost premises, source roles and imported defaults."""
import io
import json
import zipfile

import pytest

from app.scan.external_call_assessment import ExternalCallVerifier
from tests.test_external_call_assessment import (
    CALLER, CLASSIFIED, COUNT, DUPLICATE, HELPER, POLL, WRAPPER, archive, check, finding, kind,
)


def review(records, premise):
    return [r for r in records if r.get("narrative_review", {}).get("premise") == premise]


def test_nearby_comment_and_guard_share_bound_operation_but_other_statement_does_not():
    source = DUPLICATE.replace("  if (match?.id)", "  // Auto-reply follows this result guard.\n  if (match?.id)")
    by_comment = check(source, "// Auto-reply", "Auto-reply fires again unconditionally")
    by_guard = check(source, "if (match?.id)", "Auto-reply fires again unconditionally")
    assert by_comment == by_guard
    assert review(by_comment, "duplicate_request_dispatch")
    assert by_comment[0]["result"] == "observed" and by_comment[0]["whole_finding"] is False
    source = source.replace("  // Auto-reply", "  logOtherOperation();\n  // Auto-reply")
    assert check(source, "logOtherOperation", "Auto-reply fires again unconditionally") == []


def test_comment_for_unrelated_statement_cannot_select_later_dispatch():
    source = DUPLICATE.replace("  if (match?.id)", "  // An unrelated statement.\n  other();\n  if (match?.id)")
    assert check(source, "// An unrelated", "Auto-reply fires again unconditionally") == []


@pytest.mark.parametrize("mutation", [
    lambda s: s.replace(" const likes", " generateAutoReply(db, peer);\n const likes").replace(
        "   generateAutoReply(db, match.id).catch(handleError);", ""),
    lambda s: s.replace("generateAutoReply(db, match.id)", "generateAutoReply(db, another.id)"),
    lambda s: s.replace(" if (writeError)", " writeError = otherError;\n if (writeError)"),
    lambda s: s.replace("  if (match?.id)", "  const match = another;\n  if (match?.id)"),
])
def test_changed_duplicate_path_or_argument_cannot_review_dispatch(mutation):
    assert check(mutation(DUPLICATE), "if (match?.id)", "Auto-reply fires again unconditionally") == []


def test_duplicate_after_dispatch_does_not_claim_dispatch_is_guarded():
    source = DUPLICATE
    begin, end = source.index(" if (writeError)"), source.index(" const likes")
    guard = source[begin:end]
    source = source[:begin] + source[end:]
    source = source.replace("   generateAutoReply(db, match.id).catch(handleError);",
                            "   generateAutoReply(db, match.id).catch(handleError);\n" + guard)
    assert check(source, "if (match?.id)", "Auto-reply fires again unconditionally") == []


def test_count_review_is_explicitly_conditional_and_unknown_runtime_is_retained():
    record, = check(COUNT, "after(async", "Both callbacks see count=2 and both may trigger a Claude auto-reply")
    assert record["result"] == "observed" and record["source_binding"]["assumptions_verified"] is False
    assert record["narrative_review"]["premise"] == "conditional_insert_count_schedule"
    assert "Both callbacks can skip" in record["narrative_review"]["reason"]


@pytest.mark.parametrize("title", [
    "Concurrent external requests lack provider idempotency",
    "Both callbacks may see count=2; duplicate AI calls are not established",
    "Both concurrent callbacks see count=2 and therefore skip dispatch",
    "Verify whether both concurrent callbacks see count=1",
])
def test_count_never_reviews_an_unasserted_schedule(title):
    records = check(COUNT, "after(async", title)
    assert records and not any(r.get("narrative_review") for r in records)


@pytest.mark.parametrize("title", [
    "Retry handles transport failure; JSON parsing is not inside its callback",
    "Retry handles timeouts. JSON parsing happens afterwards",
    "Verify whether JSON errors are retried",
    "Retry: JSON parsing happens outside the callback",
    "Retry keeps HTTP 400 outside the callback",
])
def test_unrelated_json_mention_is_not_a_reentry_counterclaim(title):
    record, = check(WRAPPER + HELPER + CALLER, title=title)
    assert record["result"] == "observed"


def test_poll_review_separates_deadline_from_verified_waits():
    records = check(CLASSIFIED + POLL, "let attempts", "Polling loop uses up to 40 seconds of wall-clock time")
    assert review(records, "poll_wait_wall_clock")
    assert not review(records, "retry_error_multiplier")
    assert all(r["result"] == "observed" and not r["whole_finding"] for r in records)
    honest = check(CLASSIFIED + POLL, "let attempts", "Polling sleeps total 40 seconds; deadline remains unverified")
    assert not any(r.get("narrative_review") for r in honest)


def test_changed_classifier_does_not_receive_native_error_or_fixed_retry_review():
    source = (CLASSIFIED + POLL).replace("const isLast = attempt === maxAttempts;", "const isLast = false;")
    records = check(source, "let attempts", "Polling retries this entire sequence up to 4 times on failure")
    assert not kind(records, "retry_classifier_terminal_error")
    assert not review(records, "retry_error_multiplier")


def test_honest_retry_classifier_qualification_is_not_disputed():
    records = check(CLASSIFIED + POLL, "let attempts",
                    "Polling retry executes up to 4 times when errors have retryable HTTP status 429")
    assert records and not any(r.get("narrative_review") for r in records)


ROLE_POLL = POLL.replace("await createPrediction()",
                         "await fetch('https://api.replicate.com/v1/predictions', {method: 'POST'})").replace(
    "fetch('PRIVATE_URL')", "fetch(`https://api.replicate.com/v1/predictions/${result.id}`)")


def test_get_request_roles_never_claim_gets_are_unbilled_or_prices_verified():
    records = check(CLASSIFIED + ROLE_POLL, "let attempts", "Polling can produce 168 paid Replicate calls")
    record, = kind(records, "request_role_billing_boundary")
    assert record["result"] == "observed" and record["source_binding"]["billing_verified"] is False
    assert {op["role"] for op in record["source_binding"]["operations"]} == {
        "prediction_creation_post", "prediction_status_get"}
    assert "GET syntax does not prove free requests" in record["detail"]
    assert "api.replicate" not in json.dumps(record)


@pytest.mark.parametrize("before,after", [
    ("{method: 'POST'}", "{method: dynamicMethod}"),
    ("{method: 'POST'}", "{method: 'POST', ...otherOptions}"),
    ("{method: 'POST'}", "{method: 'POST', method: 'GET'}"),
    ("{method: 'POST'}", "{method: 'POST', 'method': 'GET'}"),
    ("{method: 'POST'}", "{method: 'POST', [option]: value}"),
    ("${result.id}`)", "${result.id}`, {method})"),
    ("`https://api.replicate.com/v1/predictions/${result.id}`",
     "`${base}https://api.replicate.com/v1/predictions/${result.id}`"),
    ("await fetch('https://api.replicate.com/v1/predictions'", "await wrapper('https://api.replicate.com/v1/predictions'"),
    ("export async function embedding() {", "export async function embedding(fetch) {"),
])
def test_request_role_abstains_on_ambiguous_method_or_fetch_binding(before, after):
    records = check((CLASSIFIED + ROLE_POLL).replace(before, after), "let attempts",
                    "Polling can produce 168 paid Replicate calls")
    assert not kind(records, "request_role_billing_boundary")


@pytest.mark.parametrize("helper", [
    HELPER.replace("url, init)", "url, init = {method: 'POST'})"),
    HELPER.replace(" try {", " const alias = init; if (alias) alias.method = 'GET'; try {"),
    HELPER.replace(" try {", " if (init) Object.assign(init, {method: 'GET'}); try {"),
])
def test_helper_option_defaults_aliasing_or_mutation_cannot_supply_request_roles(helper):
    source = helper + CLASSIFIED + ROLE_POLL.replace("await fetch(", "await fetchWithTimeout(")
    records = check(source, "let attempts", "Polling can produce 168 paid Replicate calls")
    assert not kind(records, "request_role_billing_boundary")


@pytest.mark.parametrize("before,after", [
    ("match_id: matchId", "match_id: matchId, 'match_id': otherId"),
    ("match_id: matchId", "match_id: matchId, [field]: otherId"),
    ("count: 'exact', head: true", "count: 'exact', head: true, ...opts"),
    ("count: 'exact', head: true", "count: 'exact', head: true, 'count': 'planned'"),
])
def test_ambiguous_insert_filter_or_count_options_do_not_supply_schedule(before, after):
    source = COUNT.replace(before, after)
    assert check(source, "after(async", "Both concurrent requests see count one and call Claude") == []


def test_honest_billing_disclaimer_is_not_reviewed_and_cache_is_narrative_specific():
    source = CLASSIFIED + ROLE_POLL
    verifier = ExternalCallVerifier(archive(source))
    raw = finding(source, "let attempts", "Polling can produce 168 paid Replicate calls")
    assert review(verifier.checks_for(raw), "request_count_as_paid_operations")
    raw["title"] = "Polling: 168 paid Replicate calls are not established"
    assert not review(verifier.checks_for(raw), "request_count_as_paid_operations")


@pytest.mark.parametrize("title", [
    "Polling: 40 polls do not bound time or establish 168 paid Replicate calls",
    "Polling: HTTP requests are not paid operations",
    "Polling does not take at most 40 seconds of wall-clock time",
    "Polling taking up to 40 seconds is NOT established",
    "Polling: add a deadline of 40 seconds",
    "Polling: verify a deadline of 40 seconds before claiming a bound",
])
def test_acknowledged_cost_and_time_limits_never_invent_disputed_claim(title):
    records = check(CLASSIFIED + ROLE_POLL, "let attempts", title)
    assert records and not any(r.get("narrative_review") for r in records)


@pytest.mark.parametrize("title", [
    "Duplicate return prevents another auto-reply call",
    "Duplicate return prevents auto-reply from firing again unconditionally",
    "Auto-reply is not called unconditionally after duplicate errors",
    "Duplicate: auto-reply fires again only after a successful insert; the duplicate return exits early",
])
def test_acknowledged_duplicate_guard_never_invents_disputed_claim(title):
    records = check(DUPLICATE, "if (match?.id)", title)
    assert records and not any(r.get("narrative_review") for r in records)


RATE_HELPER = """import { Ratelimit } from '@upstash/ratelimit';
export async function checkLimit(key: string, maxRequests: number = 10, window: string = '60 s') {
 try {
  const limiter = new Ratelimit({limiter: Ratelimit.slidingWindow(maxRequests, window)});
  const {success} = await limiter.limit(key);
  return success;
 } catch (error) { return true; }
}
"""
RATE_CALLER = """import { checkLimit } from '../../lib/rate-limit';
import { computeEmbedding } from '../../lib/embedding';
export async function POST() {
 // 5 requests per minute: the comment is stale.
 const allowed = await checkLimit('PRIVATE_KEY');
 if (!allowed) { return fail(); }
 const result = await computeEmbedding('PRIVATE_TEXT');
 return result;
}
"""
RATE_TARGET = """export async function computeEmbedding(text) {
 return await fetch('PRIVATE_URL');
}
"""


def rate_fixture(caller=RATE_CALLER, helper=RATE_HELPER, target=RATE_TARGET, *,
                 path="app/api/route.ts", needle="const result"):
    stream = io.BytesIO()
    files = {"app/api/route.ts": caller, "lib/rate-limit.ts": helper, "lib/embedding.ts": target}
    with zipfile.ZipFile(stream, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    raw = finding(files[path], needle, "computeEmbedding: rate limit is 5 requests per 60 seconds")
    raw["file"] = path
    return ExternalCallVerifier(stream), raw


def test_imported_default_overrides_comment_without_claiming_enforced_runtime_limit():
    verifier, raw = rate_fixture()
    record, = verifier.checks_for(raw)
    assert record["kind"] == "imported_rate_limit_configuration" and record["result"] == "contradicted"
    binding = record["source_binding"]
    assert (binding["maximum_requests"], binding["window_seconds"]) == (10, 60)
    assert binding["maximum_mode"] == "parameter_default"
    assert record["whole_finding"] is False
    assert "fail-open" in record["detail"] and "runtime request ceiling" in record["narrative_review"]["reason"]
    assert "PRIVATE_" not in json.dumps(record)


def test_exported_helper_finding_links_only_actual_caller_import():
    verifier, raw = rate_fixture(path="lib/embedding.ts", needle="return await fetch")
    record, = verifier.checks_for(raw)
    assert record["source_binding"]["selected_export"]["file"] == "lib/embedding.ts"
    assert record["source_binding"]["operation"]["file"] == "app/api/route.ts"


@pytest.mark.parametrize("before,after", [
    ("checkLimit('PRIVATE_KEY')", "checkLimit('PRIVATE_KEY', 5)"),
    ("checkLimit('PRIVATE_KEY')", "checkLimit('PRIVATE_KEY', config.limit)"),
    ("checkLimit('PRIVATE_KEY')", "otherLimit('PRIVATE_KEY')"),
    (" if (!allowed) { return fail(); }", " if (!allowed) { logFailure(); }"),
    (" if (!allowed)", " allowed = true; if (!allowed)"),
    ("export async function POST()", "export async function POST(checkLimit)"),
    ("import { computeEmbedding }", "import { computeEmbedding as otherEmbedding }"),
    ("const result = await computeEmbedding", "const result = await differentOperation"),
])
def test_wrong_limiter_call_guard_or_argument_cannot_supply_default(before, after):
    verifier, raw = rate_fixture(caller=RATE_CALLER.replace(before, after))
    assert verifier.checks_for(raw) == []


@pytest.mark.parametrize("before,after", [
    ("Ratelimit.slidingWindow(maxRequests, window)", "Ratelimit.slidingWindow(5, window)"),
    (" try {", " maxRequests = 5; try {"),
    (" try {", " const window = '1 s'; try {"),
    ("{limiter: Ratelimit.slidingWindow(maxRequests, window)}",
     "{limiter: Ratelimit.slidingWindow(maxRequests, window), ...other}"),
    ("{limiter: Ratelimit.slidingWindow(maxRequests, window)}",
     "{limiter: Ratelimit.slidingWindow(maxRequests, window), 'limiter': anotherLimiter}"),
    ("{limiter: Ratelimit.slidingWindow(maxRequests, window)}",
     "{limiter: Ratelimit.slidingWindow(maxRequests, window), [keyName]: anotherLimiter}"),
    ("await limiter.limit(key)", "await anotherLimiter.limit(key)"),
    ("return success;", "return true;"),
    (" try {", " if (false) { return true; } else try {"),
    ("@upstash/ratelimit", "./other-ratelimit"),
])
def test_wrong_default_consumer_or_mutated_parameter_abstains(before, after):
    verifier, raw = rate_fixture(helper=RATE_HELPER.replace(before, after))
    assert verifier.checks_for(raw) == []


def test_actual_literal_override_is_recorded_instead_of_default():
    verifier, raw = rate_fixture(caller=RATE_CALLER.replace("checkLimit('PRIVATE_KEY')",
                                                          "checkLimit('PRIVATE_KEY', 7, '2 m')"))
    record, = verifier.checks_for(raw)
    assert (record["source_binding"]["maximum_requests"], record["source_binding"]["window_seconds"]) == (7, 120)
    assert record["source_binding"]["maximum_mode"] == "literal_call_override"


def test_limiter_after_selected_operation_does_not_get_linked():
    caller = RATE_CALLER.replace(" const result = await computeEmbedding('PRIVATE_TEXT');\n", "")
    caller = caller.replace(" // 5 requests", " const result = await computeEmbedding('PRIVATE_TEXT');\n // 5 requests")
    verifier, raw = rate_fixture(caller=caller)
    assert verifier.checks_for(raw) == []


CLIENT = """export async function swipe() {
 const response = await fetch('/api/swipe', {method: 'POST'});
 return response;
}
"""


def client_fixture(route=DUPLICATE, client=CLIENT):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("project/app/app/discover/page.tsx", client)
        archive.writestr("project/app/api/swipe/route.ts", route)
    raw = finding(client, "const response", "Duplicate swipe: auto-reply logic runs twice before duplicate-key error")
    raw["file"] = "project/app/app/discover/page.tsx"
    return ExternalCallVerifier(stream), raw


def test_client_server_dispatch_relation_keeps_distinct_ui_scope():
    verifier, raw = client_fixture()
    record, = verifier.checks_for(raw)
    assert record["source_binding"]["client_fetch"]["file"] == raw["file"]
    assert record["file"] == "project/app/api/swipe/route.ts"
    assert record["result"] == "observed" and record["whole_finding"] is False
    assert "operation_identity" not in record
    assert "Client duplicate requests and state updates are separate" in record["narrative_review"]["reason"]
    assert "deployed routing is not verified" in record["narrative_review"]["reason"]


@pytest.mark.parametrize("route,client", [
    (DUPLICATE.replace("return response();", "logDuplicate();"), CLIENT),
    (DUPLICATE.replace("generateAutoReply(db, match.id)", "generateAutoReply(db, other.id)"), CLIENT),
    (DUPLICATE, CLIENT.replace("swipe()", "swipe(fetch)")),
    (DUPLICATE, CLIENT.replace("'/api/swipe'", "'/api/another-operation'")),
    (DUPLICATE, CLIENT.replace("{method: 'POST'}", "{method: 'GET'}")),
])
def test_client_link_abstains_on_different_route_method_binding_or_guard(route, client):
    verifier, raw = client_fixture(route, client)
    assert verifier.checks_for(raw) == []

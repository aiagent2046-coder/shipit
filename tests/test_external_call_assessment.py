"""Source-only boundaries for external retry, duplicate paths and count schedules."""

import hashlib
import io
import json
import zipfile

import pytest

from app.scan import external_call_assessment as e

WRAPPER = """async function withRetry<T>(fn: () => Promise<T>): Promise<T> {
 for (let attempt = 1; attempt <= 2; attempt++) {
  try { return await fn(); }
  catch (err: any) {
   if (attempt === 2) { throw new Error('PRIVATE_FAILURE'); }
   await new Promise(r => setTimeout(r, 1000));
  }
 }
 throw new Error('PRIVATE_END');
}
"""
HELPER = """async function fetchWithTimeout(url, init) {
 try {
  const res = await fetch(url, init);
  return res;
 } finally { clearTimeout(timer); }
}
"""
CALLER = """export async function POST(req) {
 const res = await withRetry(() => fetchWithTimeout('PRIVATE_URL', {}));
 if (!res.ok) { return fail(); }
 const data = await res.json();
 return data;
}
"""
CLASSIFIED = """async function withRetry<T>(fn: () => Promise<T>, maxAttempts = 4): Promise<T> {
 for (let attempt = 1; attempt <= maxAttempts; attempt++) {
  try { return await fn(); }
  catch (err: any) {
   const isLast = attempt === maxAttempts;
   const isAbort = err?.name === 'AbortError' || err?.message?.includes('aborted');
   const status = (err instanceof AIServiceError) ? err.status : 0;
   const isRateLimit = status === 429;
   const isUpstream5xx = status >= 500 && status < 600;
   const retryable = isAbort || isRateLimit || isUpstream5xx;
   if (isLast || !retryable) {
    if (err instanceof AIServiceError) throw err;
    if (isAbort) throw new AIServiceError('PRIVATE_TIMEOUT', 504, true);
    throw new AIServiceError('PRIVATE_FAILURE', 502, true);
   }
   await new Promise(r => setTimeout(r, 1000));
  }
 }
 throw new Error('PRIVATE_END');
}
"""
POLL = """export async function embedding() {
 return withRetry(async () => {
  let result = await createPrediction();
  let attempts = 0;
  while (result.status === 'starting' && attempts < 40) {
   await new Promise(r => setTimeout(r, 1000));
   const response = await fetch('PRIVATE_URL');
   result = await response.json();
   attempts++;
  }
  if (result.status !== 'succeeded') { throw new Error(`PRIVATE_POLL: ${result.error}`); }
  return result.output;
 });
}
"""
DUPLICATE = """export async function POST(db, peer) {
 const {error: writeError} = await db.from('swipes').insert({peer});
 if (writeError) {
  if (writeError.code === '23505' || writeError.message?.includes('duplicate key')) {
   return response();
  }
  return fail();
 }
 const likes = await db.from('swipes').select('id');
 if (likes) {
  const {data: match} = await db.from('matches').upsert({peer}).select('id').single();
  if (match?.id) {
   generateAutoReply(db, match.id).catch(handleError);
  }
 }
}
async function generateAutoReply(db, id) {
 const response = await fetch('PRIVATE_URL');
 return response;
}
"""
COUNT = """export async function POST(db, admin, matchId) {
 const {data: message, error: insErr} = await db.from('messages')
  .insert({match_id: matchId, content: 'PRIVATE_CONTENT'}).select().single();
 if (insErr) { return fail(); }
 after(async () => {
  try {
   const {count} = await admin.from('messages').select('*', {count: 'exact', head: true}).eq('match_id', matchId);
   if (count !== null && count <= 1) {
    const response = await fetch('PRIVATE_URL');
   }
  } catch (err) { handleError(err); }
 });
}
"""


def archive(source, path="src/route.ts"):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as zf:
        zf.writestr(path, source)
    return stream


def finding(source, needle, title="Retry on any error or JSON parsing failure"):
    line = next(i for i, value in enumerate(source.splitlines(), 1) if needle in value)
    return {"file": "src/route.ts", "line_start": line, "line_end": line, "title": title}


def check(source, needle="const res = await withRetry", title=None):
    raw = finding(source, needle, title) if title else finding(source, needle)
    return e.ExternalCallVerifier(archive(source)).checks_for(raw)


def kind(records, name):
    return [r for r in records if r["kind"] == name]


def test_response_checks_outside_callback_have_exact_bindings_and_total_attempt_count():
    source = WRAPPER + HELPER + CALLER
    (record,) = check(source)
    assert record["kind"] == "retry_callback_scope"
    assert record["result"] == "contradicted" and record["whole_finding"] is False
    b = record["source_binding"]
    assert b["maximum_attempts"] == 2 and b["maximum_additional_attempts"] == 1
    assert record["source_sha256"] == hashlib.sha256(source.encode()).hexdigest()
    assert source.encode()[slice(*b["response_status_checks"][0]["span"])] == b"res.ok"
    assert source.encode()[slice(*b["response_json_calls"][0]["span"])] == b"res.json()"
    assert "PRIVATE_" not in json.dumps(record)


def test_wrapper_citation_binds_only_its_unique_call():
    source = WRAPPER + HELPER + CALLER
    assert check(source, "async function withRetry")[0]["kind"] == "retry_callback_scope"
    assert check(source + CALLER.replace("POST", "OTHER"), "async function withRetry") == []


def test_unrelated_retry_premise_is_only_observed():
    assert check(WRAPPER + HELPER + CALLER, title="Retry handles network timeouts")[0]["result"] == "observed"


@pytest.mark.parametrize(
    "before,after",
    [
        (
            "const res = await withRetry(() => fetchWithTimeout('PRIVATE_URL', {}));",
            "const res = await withRetry(async () => { const res = await fetchWithTimeout('PRIVATE_URL', {}); "
            "if (!res.ok) throw new Error('bad'); return await res.json(); });",
        ),
        ("res.json()", "other.json()"),
        ("if (!res.ok)", "if (!other.ok)"),
        ("const data = await res.json();", "const otherScope = () => res.json();"),
        ("if (!res.ok)", "res = other; if (!res.ok)"),
        ("fetchWithTimeout('PRIVATE_URL', {})", "unknownWrapper('PRIVATE_URL', {})"),
        ("return res;\n } finally", "if (!res.ok) throw new Error('bad'); return res;\n } finally"),
        ("return res;\n } finally", "return res.json();\n } finally"),
        ("attempt <= 2", "attempt <= req.limit"),
        ("attempt++", "attempt += 2"),
        ("return await fn();", "return await wrapped(fn);"),
        ("throw new Error('PRIVATE_FAILURE');", "return await fn();"),
        ("await new Promise(r => setTimeout(r, 1000));", "fn(); await new Promise(r => setTimeout(r, 1000));"),
    ],
)
def test_retry_unsupported_wrappers_inside_callback_or_unrelated_responses_abstain(before, after):
    source = (WRAPPER + HELPER + CALLER).replace(before, after)
    assert not kind(check(source), "retry_callback_scope")


def test_shadowed_retry_binding_abstains():
    assert check(WRAPPER + HELPER + CALLER.replace(" const res", " const withRetry = other;\n const res")) == []


def test_poll_classifier_does_not_treat_every_ordinary_error_as_retryable_or_terminal():
    source = CLASSIFIED + POLL
    records = check(source, "let attempts", "Polling exhaustion retries four times and costs 160 seconds")
    classifier, wait = records
    assert classifier["kind"] == "retry_classifier_terminal_error"
    assert classifier["result"] == "observed"
    assert classifier["source_binding"]["maximum_attempts"] == 4
    assert classifier["source_binding"]["maximum_additional_attempts"] == 3
    assert classifier["source_binding"]["terminal_error_message"] == "dynamic_not_evaluated"
    assert "dynamic message can still match" in classifier["detail"]
    assert wait["kind"] == "poll_wait_not_deadline"
    assert "not request durations" in wait["detail"]
    assert "PRIVATE_" not in json.dumps(records)


@pytest.mark.parametrize("override,bound", [("1", 1), ("2", 2), ("8", 8)])
def test_actual_max_attempts_override_is_recorded(override, bound):
    source = CLASSIFIED + POLL.replace(" });", " }, " + override + ");")
    record = check(source, "let attempts", "Polling retries")[0]
    assert record["source_binding"]["maximum_attempts"] == bound
    assert record["source_binding"]["attempt_bound_mode"] == "literal_call_override"


@pytest.mark.parametrize(
    "before,after",
    [
        (" }, 4);", " }, 4);"),
        ("const retryable = isAbort || isRateLimit || isUpstream5xx;", "const retryable = true;"),
        ("status === 429", "status >= 400"),
        ("err?.message?.includes('aborted')", "classify(err)"),
        ("if (isLast || !retryable)", "if (isLast && !retryable)"),
        ("throw new Error(`PRIVATE_POLL: ${result.error}`)", "throw new AIServiceError('bad', 503)"),
    ],
)
def test_unknown_error_classifier_or_terminal_type_is_not_classified(before, after):
    if before == " }, 4);":
        source = CLASSIFIED + POLL.replace(" });", " }, unknownAttempts);")
    else:
        source = (CLASSIFIED + POLL).replace(before, after)
    assert not kind(check(source, "let attempts", "Polling retries"), "retry_classifier_terminal_error")


def test_other_call_in_same_function_does_not_inherit_poll_context():
    source = CLASSIFIED + POLL.replace("let attempts = 0;", "await otherOperation();\n  let attempts = 0;")
    assert check(source, "await otherOperation", "Polling retries") == []


def test_duplicate_key_return_has_selected_upsert_and_later_fetch_helper_only():
    (record,) = check(DUPLICATE, "if (match?.id)", "Duplicate mutual-match Claude call")
    assert record["kind"] == "duplicate_key_before_external_call"
    assert record["result"] == "observed" and record["whole_finding"] is False
    b = record["source_binding"]
    assert b["duplicate_guard"]["line_end"] < b["selected_upsert"]["line_start"]
    assert b["selected_upsert"]["line_end"] < b["later_call"]["line_start"]
    assert "returned-row semantics are not established" in record["detail"]


@pytest.mark.parametrize(
    "before,after",
    [
        ("return response();", "logDuplicate();"),
        ("writeError.code === '23505'", "otherError.code === '23505'"),
        ("if (writeError)", "if (unrelatedFlag)"),
        ("if (writeError)", "if (flag) { if (writeError)"),
        ("generateAutoReply(db, match.id)", "generateAutoReply(db, unrelated.id)"),
        ("if (match?.id)", "if (unrelated?.id)"),
        (".from('swipes').select('id')", ".from('other').select('id')"),
    ],
)
def test_unrelated_duplicate_branch_or_helper_argument_abstains(before, after):
    source = DUPLICATE.replace(before, after)
    if after.startswith("if (flag)"):
        source = source.replace(" const likes", " }\n const likes")
    needle = "if (unrelated?.id)" if after == "if (unrelated?.id)" else "if (match?.id)"
    assert check(source, needle, "Duplicate mutual-match Claude call") == []


def test_await_insert_then_count_records_all_unverified_concurrency_assumptions():
    (record,) = check(COUNT, "after(async", "Both concurrent requests see count one and call Claude")
    assert record["kind"] == "insert_before_count_schedule"
    assert record["result"] == "observed" and record["whole_finding"] is False
    b = record["source_binding"]
    assert b["assumptions_verified"] is False and b["assumptions"] == e.COUNT_ASSUMPTIONS
    assert b["insert"]["line_end"] < b["registration"]["line_start"] < b["count_query"]["line_start"]
    assert b["count_guard"]["line_start"] <= b["external_call"]["line_start"]
    assert "PRIVATE_" not in json.dumps(record)


def test_counter_citation_can_extend_into_its_immediately_following_poll_loop():
    source = CLASSIFIED + POLL
    raw = finding(source, "let attempts = 0", "Poll loop has four retries and forty seconds of waits")
    raw["line_end"] = next(i for i, line in enumerate(source.splitlines(), 1) if "attempts++;" in line)
    records = e.ExternalCallVerifier(archive(source)).checks_for(raw)
    assert {r["kind"] for r in records} == {"retry_classifier_terminal_error", "poll_wait_not_deadline"}
    raw["line_end"] += 2  # The subsequent terminal branch is outside this counter/loop anchor.
    assert e.ExternalCallVerifier(archive(source)).checks_for(raw) == []


@pytest.mark.parametrize(
    "before,after",
    [
        ("await db.from('messages')", "db.from('messages')"),
        (".eq('match_id', matchId)", ".eq('match_id', otherId)"),
        ("admin.from('messages')", "admin.from('filtered_messages')"),
        ("count: 'exact'", "count: 'estimated'"),
        ("count <= 1", "count <= 2"),
        ("if (insErr) { return fail(); }", "if (insErr) { logFailure(); }"),
        ("content: 'PRIVATE_CONTENT'", "content: 'PRIVATE_CONTENT', ...override"),
        ("match_id: matchId", "match_id: matchId, match_id: otherId"),
        ("   if (count", "   count = 1; if (count"),
        (" after(async", " if (flag) after(async"),
        ("const response = await fetch", "const later = () => fetch"),
    ],
)
def test_unsupported_insert_count_and_external_call_relationships_abstain(before, after):
    source = COUNT.replace(before, after)
    assert check(source, "after(async", "Both concurrent requests see count one and call Claude") == []


def test_same_function_unrelated_line_does_not_inherit_count_assessment():
    assert check(COUNT, "const response", "Both concurrent requests see count one and call Claude") == []


def test_concurrency_word_alone_does_not_contradict_a_different_premise():
    record = check(COUNT, "after(async", "Concurrent external requests lack provider idempotency")
    assert record[0]["result"] == "observed"


def test_cache_keeps_narrative_specific_result_and_returns_copies():
    source = WRAPPER + HELPER + CALLER
    verifier = e.ExternalCallVerifier(archive(source))
    raw = finding(source, "const res = await withRetry")
    first = verifier.checks_for(raw)
    first[0]["detail"] = "changed"
    assert verifier.checks_for(raw)[0]["detail"] != "changed"
    raw["title"] = "Retry handles network timeouts"
    assert verifier.checks_for(raw)[0]["result"] == "observed"


def test_parser_and_archive_failures_produce_no_source_conclusion():
    for source in ["export async function BROKEN {", "export function fine() {}"]:
        assert check(source, "export") == []
    raw = {"file": "../route.ts", "line_start": 1, "line_end": 1, "title": "Retry on any error"}
    assert e.ExternalCallVerifier(archive("code", "../route.ts")).checks_for(raw) == []


def test_visible_delete_conflicting_with_schedule_assumptions_abstains():
    source = COUNT.replace(" after(async", " await db.from('messages').delete();\n after(async")
    assert check(source, "after(async", "Both concurrent requests see count one and call Claude") == []


def test_shadowed_error_constructor_does_not_get_native_error_classification():
    source = "const Error = customError;\n" + CLASSIFIED + POLL
    assert check(source, "let attempts", "Polling retries") == []

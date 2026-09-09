"""Source operations distinguish real duplicate hypotheses from nearby issues."""
import io
import json
import zipfile

import pytest

from app.scan.issue_identity import SourceIssueResolver


def _archive(source, path="route.ts"):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as target:
        target.writestr(path, source)
    archive.seek(0)
    return archive


def _identity(resolver, title, start=2, end=None, **extra):
    return resolver.identity({"file": "route.ts", "title": title,
                              "line_start": start, "line_end": end or start, **extra})


@pytest.mark.parametrize("source, left, right, starts", [
    ("""async function login() {
  const password = crypto.createHmac('sha256',
    process.env.SUPABASE_SERVICE_ROLE_KEY).update(userId).digest('hex');
}
""", "Service-role key used as HMAC secret for deterministic password derivation",
     "Telegram synthetic password derived from service role key", (2, 3)),
    ("""async function chat() {
  const db = createClient(url,
    process.env.SUPABASE_SERVICE_ROLE_KEY);
  return db.from('facts').select('*');
}
""", "Chat reads/written with service-role key, bypassing RLS ownership check",
     "Chat uses service role key for all database operations", (2, 3)),
    ("""async function stats(req) {
  const token = req.headers.get('x-lab-token');
  if (!process.env.LAB_TOKEN || token !== process.env.LAB_TOKEN) return;
}
""", "Timing-unsafe string comparison for secret token",
     "Bearer token comparison is not constant-time", (2, 3)),
    ("""async function identity(req) {
  const base = req.headers.get('x-forwarded-host')
    ? `https://${req.headers.get('x-forwarded-host')}` : 'https://fallback';
  return fetch(`${base}/recompute`);
}
""", "SSRF via user-controlled x-forwarded-host header",
     "SSRF via forwarded-host header used in fetch", (2, 4)),
    ("""async function embedding() {
  const result = await createPrediction();
  const res = await fetch(`https://provider/predictions/${result.id}`);
}
""", "Prediction ID used in URL without validation",
     "Prediction ID used directly in polling URL without validation", (2, 3)),
    ("""async function chat() {
  const matches = [];
  const rows = await db.from('matches')
    .select('*').eq('user_id', user.id);
  const peers = await db.from('profiles').select('*');
}
""", "Matches query has no LIMIT", "Matches query has no LIMIT", (2, 4)),
    ("""async function messages() {
  after(async () => {
    const {count} = await db.from('messages').select('*', {count: 'exact'});
    if (count <= 1) await reply();
  });
}
""", "Auto-reply race condition: count check and reply insert are not atomic",
     "Auto-reply first-message check is a non-atomic read-then-act", (2, 3)),
    ("""async function version() {
  const res = await fetch('https://provider/models/model');
  return res.json();
}
""", "Model version fetched on every embedding computation",
     "Model version lookup is called on every recompute", (2, 3)),
    ("""async function embedding() {
  return withRetry(async () => {
    let result = await createPrediction();
    while (result.pending) {
      result = await fetch(`https://provider/predictions/${result.id}`);
    }
  });
}
""", "Prediction polling loop runs up to 40 iterations",
     "Prediction poll loop has 40 iterations inside retries", (2, 4)),
])
def test_duplicate_titles_identify_the_same_actual_operation(source, left, right, starts):
    resolver = SourceIssueResolver(_archive(source))
    a = _identity(resolver, left, starts[0])
    b = _identity(resolver, right, starts[1])
    assert a is not None and a == b
    assert a["method"] == "source_ast"
    assert "https://" not in json.dumps(a)
    assert "SUPABASE_SERVICE_ROLE_KEY" not in json.dumps(a)


@pytest.mark.parametrize("source,title,first,second", [
    ("""async function chat() {
  const left = await db.from('matches').select('*');
  const right = await db.from('matches').select('*');
}
""", "Matches query has no LIMIT", 2, 3),
    ("""async function stats() {
  if (left !== process.env.FIRST_TOKEN) return;
  if (right !== process.env.SECOND_TOKEN) return;
}
""", "Token comparison is not constant-time", 2, 3),
    ("""async function login() {
  const first = crypto.createHmac('sha256', key);
  const second = crypto.createHmac('sha256', key);
}
""", "HMAC used for password derivation", 2, 3),
    ("""async function embed() {
  const first = await fetch('https://provider/models/first');
  const second = await fetch('https://provider/models/second');
}
""", "Model version fetched on every computation", 2, 3),
    ("""async function identities(req) {
  const base = req.headers.get('x-forwarded-host');
  await fetch(`${base}/first`);
  await fetch(`${base}/second`);
}
""", "SSRF via forwarded-host header", 3, 4),
])
def test_same_mechanism_and_scope_do_not_merge_different_operations(source, title, first, second):
    resolver = SourceIssueResolver(_archive(source))
    a, b = _identity(resolver, title, first), _identity(resolver, title, second)
    assert a is not None and b is not None and a != b
    # A function-wide citation that identifies neither operation stays unknown.
    assert _identity(resolver, title, 1, len(source.splitlines())) is None


def test_sibling_functions_and_identical_operation_text_remain_separate():
    resolver = SourceIssueResolver(_archive("""async function first() {
  return db.from('matches').select('*');
}
async function second() {
  return db.from('matches').select('*');
}
"""))
    a = _identity(resolver, "Matches query has no LIMIT", 2)
    b = _identity(resolver, "Matches query has no LIMIT", 5)
    assert a and b and a != b


@pytest.mark.parametrize("title", [
    "Service-role client bypasses RLS and rate limiter is fail-open",
    "Token comparison is timing-unsafe and token leaks in URL",
    "HTTP status error and network failure are not handled",
    "Missing authentication and no rate limiting",
    "Generic concern at the same source position",
])
def test_compound_or_unsupported_title_cannot_select_one_convenient_mechanism(title):
    resolver = SourceIssueResolver(_archive("""function check() {
  const db = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY);
  if (token !== process.env.SECRET_TOKEN) return;
}
"""))
    assert _identity(resolver, title) is None


def test_source_identifiers_are_not_accepted_from_model_fields():
    resolver = SourceIssueResolver(_archive("""async function chat() {
  return db.from('matches').select('*');
}
"""))
    forged = {"mechanism": "service_role_access", "operation_span": [0, 1]}
    actual = _identity(resolver, "Matches query has no LIMIT", source_issue_identity=forged,
                       claim_evidence={"source_issue_identity": forged})
    assert actual and actual["mechanism"] == "query_row_bound"
    assert actual["operation_span"] != [0, 1]


def test_malformed_duplicate_and_symlink_archive_entries_fail_closed():
    source = "function f() { return db.from('matches').select('*'); }"
    for mode in ("duplicate", "symlink", "malformed"):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as target:
            info = zipfile.ZipInfo("route.ts")
            if mode == "symlink":
                info.external_attr = 0o120777 << 16
            target.writestr(info, "function broken( {" if mode == "malformed" else source)
            if mode == "duplicate":
                with pytest.warns(UserWarning, match="Duplicate name"):
                    target.writestr("route.ts", source)
        assert _identity(SourceIssueResolver(archive), "Matches query has no LIMIT", 1) is None


def test_parse_and_request_budgets_are_bounded_and_document_cache_reused(monkeypatch):
    import app.scan.issue_identity as module
    source = "function f() { return db.from('matches').select('*'); }"
    resolver = SourceIssueResolver(_archive(source))
    first = _identity(resolver, "Matches query has no LIMIT", 1)
    remaining = resolver.remaining
    assert first and _identity(resolver, "Matches query has no LIMIT", 1) == first
    assert resolver.remaining == remaining
    resolver.remaining = 0
    assert _identity(resolver, "Matches query has no LIMIT", 1) == first
    resolver.checks = module.MAX_CHECKS
    assert _identity(resolver, "Matches query has no LIMIT", 1) is None
    monkeypatch.setattr(module, "MAX_FILE_BYTES", 4)
    assert _identity(SourceIssueResolver(_archive(source)), "Matches query has no LIMIT", 1) is None


def test_local_reassignment_and_ambiguous_header_builders_do_not_guess_ssrf_identity():
    for source in ("""async function identity(req) {
  let base = req.headers.get('x-forwarded-host');
  base = replacement;
  return fetch(`${base}/path`);
}
""", """async function identity(req) {
  const first = req.headers.get('x-forwarded-host');
  const second = req.headers.get('x-forwarded-host');
  return fetch(`${first}/${second}`);
}
"""):
        assert _identity(SourceIssueResolver(_archive(source)), "SSRF via forwarded-host header") is None


def test_one_fetch_with_multiple_id_entities_is_ambiguous():
    resolver = SourceIssueResolver(_archive("""async function poll() {
  return fetch(`https://provider/predictions/${first.id}/${second.id}`);
}
"""))
    assert _identity(resolver, "Prediction ID used in polling URL without validation") is None


def test_node_depth_and_cumulative_scope_budgets_fail_closed(monkeypatch):
    import app.scan.issue_identity as module
    source = "function f() { return db.from('matches').select('*'); }"
    resolver = SourceIssueResolver(_archive(source))
    resolver.remaining_nodes = 0
    assert _identity(resolver, "Matches query has no LIMIT", 1) is None
    monkeypatch.setattr(module, "MAX_DEPTH", 2)
    assert _identity(SourceIssueResolver(_archive(source)), "Matches query has no LIMIT", 1) is None


def test_service_role_client_choice_cannot_absorb_a_peer_query_authorization_gap():
    resolver = SourceIssueResolver(_archive("""async function matches() {
  const client = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY);
  const own = await client.from('matches').select('*').eq('user_id', user.id);
  const peers = await client.from('profiles').select('*');
  return {own, peers};
}
"""))
    general = _identity(resolver, "Service-role client used for matches list — RLS bypassed, "
                        "ownership enforced only by application logic")
    assert general and general["mechanism"] == "service_role_access"
    for title in [
        "matches/list uses service-role client; peer founder profiles fetched without ownership constraint",
        "Service-role client fetches peer profiles without ownership constraint",
        "Service-role client queries have no user_id filter",
    ]:
        assert _identity(resolver, title) is None


def test_range_starting_on_first_query_but_covering_second_query_is_ambiguous():
    resolver = SourceIssueResolver(_archive("""async function chat() {
  const first = await db.from('matches').select('*');
  const second = await db.from('matches').select('*');
}
"""))
    assert _identity(resolver, "Matches query has no LIMIT", 2) is not None
    assert _identity(resolver, "Matches query has no LIMIT", 2, 3) is None


def test_range_crossing_sibling_function_cannot_select_the_first_functions_query():
    resolver = SourceIssueResolver(_archive("""async function first() {
  return db.from('matches').select('*');
}
async function second() {
  return db.from('profiles').select('*');
}
"""))
    assert _identity(resolver, "Matches query has no LIMIT", 2) is not None
    assert _identity(resolver, "Matches query has no LIMIT", 2, 5) is None
